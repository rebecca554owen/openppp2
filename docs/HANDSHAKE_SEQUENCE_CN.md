# 握手序列与会话建立

[English Version](HANDSHAKE_SEQUENCE.md)

## 文档范围

本文聚焦 `ppp/transmissions/ITransmission.cpp` 中实现的握手逻辑。重点解释：真实握手顺序是什么、dummy 包起什么作用、`session_id`、`ivv`、`nmux` 的先后关系是什么、握手成功前后对象状态发生了什么变化。

## 为什么这个握手必须单独成文

OPENPPP2 的握手不是一个极简的“hello，我是谁，现在开始传数据”的过程。它同时完成：

- 通过 NOP 包制造握手前奏噪声
- 传递真实 `session_id`
- 交换连接级工作密钥派生所需的 `ivv`
- 通过 `nmux` 传递 mux 标记
- 把 transmission 对象从预握手状态切到握手后状态

因此，握手不是一个可忽略的小前言，而是安全模型和流量形态模型的重要组成部分。

## 核心函数

关键函数如下：

- `Transmission_Handshake_Pack_SessionId(...)`
- `Transmission_Handshake_Unpack_SessionId(...)`
- `Transmission_Handshake_SessionId(...)` 发送重载
- `Transmission_Handshake_SessionId(...)` 接收重载
- `Transmission_Handshake_Nop(...)`
- `ITransmission::InternalHandshakeClient(...)`
- `ITransmission::InternalHandshakeServer(...)`
- `ITransmission::InternalHandshakeTimeoutSet(...)`
- `ITransmission::InternalHandshakeTimeoutClear(...)`

## 全部握手流程

从代码可见的逻辑流程如下：

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    C->>S: NOP 握手包
    S->>C: NOP 握手包
    S->>C: 真实 session_id
    C->>S: ivv
    S->>C: nmux
    Note over C,S: 双方都用 base key + ivv 重建 protocol_ 和 transport_
    Note over C,S: handshaked_ 置为 true
```

如果结合函数体看，会发现客户端和服务端的代码顺序是轻微不对称的，但语义是一致的。

### 客户端侧顺序

`InternalHandshakeClient(...)` 的动作是：

1. 执行 `Transmission_Handshake_Nop(...)`
2. 接收 `sid`
3. 生成 `ivv`
4. 发送 `ivv`
5. 接收 `nmux`
6. 设置 `handshaked_ = true`
7. 从 `nmux & 1` 提取 mux 标记
8. 用 `ivv` 重建 cipher

### 服务端侧顺序

`InternalHandshakeServer(...)` 的动作是：

1. 执行 `Transmission_Handshake_Nop(...)`
2. 发送真实 `session_id`
3. 生成随机 `nmux`
4. 强制 `nmux` 最低位反映 mux 状态
5. 发送 `nmux`
6. 接收 `ivv`
7. 设置 `handshaked_ = true`
8. 用 `ivv` 重建 cipher

## 握手超时包装层

两个公共入口都把内部握手放在“设定超时 -> 执行内部握手 -> 清除超时”这个包装层之内：

- `HandshakeClient(...)`
- `HandshakeServer(...)`

因此 transmission 只会在有限时间内处于“不明确的握手中”状态。

```mermaid
flowchart TD
    A[HandshakeClient 或 HandshakeServer] --> B[设置超时]
    B --> C[运行内部握手]
    C --> D[清除超时]
    D --> E[返回结果]
```

如果计时器先到期，则 transmission 会被销毁。

## NOP 在这里到底是什么意思

名字叫 NOP，很容易让人误以为这只是“发一点空白字节”。实际上不是。

`Transmission_Handshake_Nop(...)` 会根据 `key.kl` 和 `key.kh` 计算一段轮数，然后反复发送值为 `0` 的 session-id 样式包。值为 `0` 的这些包不会被当作真实 session，而会在打包时被标记成 dummy 包，接收侧根据首字节最高位识别后丢弃。

所以它的真实效果是：

- 握手前奏并不是空白
- 这些包在语法上是合法握手对象
- 但在语义上是有意可丢弃的扰动流量

这与“随便发几个无结构字节”完全不是一回事。

### NOP 包的详细工作流程

NOP 操作用的就是 session-id 那一套 pack 机制，但故意传入 `session_id = 0`，从而触发 dummy 包路径。

```mermaid
flowchart TD
    A[Transmission_Handshake_Nop] --> B[key.kl 和 key.kh 计算轮数]
    B --> C{轮数 > 0?}
    C -->|是| D[循环发送 NOP 包]
    D --> E[session_id = 0 传入 pack]
    E --> F[进入 dummy 包路径]
    F --> G[首字节最高位置 1]
    G --> H[生成随机 Int128 内容]
    H --> I[发送 dummy 包]
    I --> J[轮数--]
    J --> C
    C -->|否| K[结束]
```

### NOP 包与真实包的区别

|NOP 包|真实 session-id 包|
|------|------------------|
|`session_id == 0`|`session_id != 0`|
|首字节最高位 = 1|首字节最高位 = 0|
|内容为随机 Int128|内容为真实十进制整数|
|接收侧识别并丢弃|接收侧作为有效会话 ID|
|用于制造握手前奏扰动|承载真正的会话身份|

### 为什么需要 NOP

从流量分析防御角度看，NOP 的存在有几个重要意义：

- 打破“收到的第一个包就是真实控制信息”的可预测模式
- 在真实 session-id 交换之前增加一层流量噪声
- 增加被动监控者识别有效握手的难度

NOP 包的随机轮数（由 `key.kl` 和 `key.kh` 计算得出）使得每次握手的 NOP 包数量都不固定，这进一步增加了流量模式的不确定性。

## session-id 包如何构造

`Transmission_Handshake_Pack_SessionId(...)` 会先构造一个字符串 payload，然后再做变换。

这里分成两条路径。

### 真实包路径

当 `session_id` 非零时：

- 第一个字节取自 `0x00..0x7f`
- 最高位为 0
- 真实整数值会转成字符串，作为 payload 核心内容

### dummy 包路径

当 `session_id == 0` 时：

- 第一个字节取自 `0x80..0xff`
- 最高位为 1
- 核心整数串会换成一个随机的 `Int128` 风格值

两条路径之后都会继续追加：

- 另外三个随机非零字节
- 一个分隔字符
- 受 `key.kx` 影响的随机填充
- 到某个分支时追加 `/`
- 再继续追加随机可打印字符

最后，代码会用这四个前缀字节逐步扰动 `kf`，并反复对 payload 执行 XOR 变换。

也就是说，握手项本身就不是明文十进制整数直接裸发，即使还没进入后续更高层的传输帧化。

### session-id 打包详细流程

```mermaid
flowchart TD
    A[输入 session_id] --> B{session_id == 0?}
    B -->|是| C[dummy 包路径]
    B -->|否| D[真实包路径]
    C --> E[首字节 = 0x80..0xff]
    D --> F[首字节 = 0x00..0x7f]
    E --> G[核心整数换为随机 Int128]
    F --> H[核心整数转字符串]
    G --> I[追加 3 个随机非零字节]
    H --> I
    I --> J[追加分隔字符]
    J --> K[追加 kx 影响的填充]
    K --> L{是否需要分支?}
    L -->|是| M[追加 / ]
    L -->|否| N[跳过]
    M --> O[追加可打印字符]
    N --> O
    O --> P[四个前缀字节扰动 kf]
    P --> Q[循环 XOR 变换 payload]
    Q --> R[返回最终 payload 字符串]
```

## session-id 包如何解析

`Transmission_Handshake_Unpack_SessionId(...)` 会做逆向恢复。

步骤是：

1. 先做基础长度检查
2. 读取首字节
3. 如果最高位为 1，就把它标记为 dummy，`eagin = true`
4. 否则把四个前缀字节取出
5. 对 payload 逆向执行滚动 XOR 恢复
6. 把结果按十进制解析为 `Int128`

而接收版 `Transmission_Handshake_SessionId(...)` 会一直循环读取，直到拿到一个非 dummy 的真实项。

因此 NOP 前奏才能天然工作，因为接收侧本来就设计成“跳过 dummy，持续读到真实项”。

### session-id 解包详细流程

```mermaid
flowchart TD
    A[输入 payload 字符串] --> B[长度检查]
    B --> C[读取首字节]
    C --> D{首字节最高位 == 1?}
    D -->|是| E[标记为 dummy, eagin = true]
    D -->|否| F[取出四个前缀字节]
    E --> G[返回 dummy 标记]
    F --> G
    G --> H[逆向滚动 XOR 恢复]
    H --> I[解析为 Int128 整数]
    I --> J[返回结果]
```

### 接收端的持续读取机制

```mermaid
flowchart TD
    A[开始接收 session-id] --> B[读取包]
    B --> C[调用 unpack]
    C --> D{是 dummy?}
    D -->|是| E[丢弃, 继续读取下一个]
    D -->|否| F[返回真实 session_id]
    E --> B
```

## `ivv` 是如何交换的

客户端用 GUID 生成新的 `Int128` 作为 `ivv`，然后仍然复用 session-id 这套 pack/unpack 机制进行发送与接收。

这种实现方式很有意思，因为它让以下四类逻辑值共享了同一套握手编码器：

- dummy 包
- session id
- `ivv`
- `nmux`

于是握手层不需要为每一种逻辑值再单独发明一套新的二进制 grammar。

### 详细流程图

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    Note over C: 生成 ivv = GUID()
    C->>S: Pack(ivv) 作为 payload
    Note over S: 接收 payload
    S->>S: Unpack 得到 ivv
```

### ivv 的生成方式

客户端使用 GUID 来生成 128 位的随机整数作为 `ivv`。GUID 的特性保证了每次握手都会得到一个全局唯一（或至少是概率上唯一）的 128 位值。

### ivv 与 session-id 的区别

虽然在传输层用同一套 pack/unpack 机制，但 `ivv` 的语义完全不同：

|字段|用途|生成方|
|----|----|------|
|`session_id`|标识已建立的会话|服务端|
|`ivv`|派 生 working cipher 的输入|客户端|

## `nmux` 的语义

服务端会先生成一个随机的 128 位 `nmux`，然后再调整它的最低位，让这个最低位表达 mux 状态。

- 如果 mux 开启，就保证 `nmux` 为奇数
- 如果 mux 关闭，就保证 `nmux` 为偶数

客户端再通过：

- `mux = (nmux & 1) != 0`

来提取结果。

因此 `nmux` 不是纯粹无意义随机数，它是“随机值承载一个最低位状态标记”的设计。

### nmux 的处理流程

```mermaid
flowchart TD
    A[服务端生成 nmux] --> B{nmux % 2 == 0?}
    B -->|否| C{nmux % 2 == 1?}
    B -->|是| D[mux 开启?]
    C --> E[mux 关闭?]
    D -->|是| F[保持奇数]
    D -->|否| G[nmux++ 变偶数]
    E -->|是| H[保持偶数]
    E -->|否| I[nmux++ 变奇数]
    F --> J[发送 nmux]
    G --> J
    H --> J
    I --> J
    J --> K["客户端 mux = (nmux & 1) != 0"]
```

### 为什么不直接发一个布尔值

这种设计的精妙之处在于：

- mux 状态被隐蔽在随机数的最低位
- 单纯的截获流量无法直接看出 mux 开启还是关闭
- 需要完整知道 nmux 的完整 128 位值才能提取状态

这是一种最小信息泄露的设计实践。

## cipher 在何时重建

握手不是一开始就重建 cipher，而是在关键逻辑值齐备后才切换到连接级工作密钥状态。

### 客户端重建时机

客户端会在以下动作完成后重建 cipher：

- 收到 `sid`
- 发出 `ivv`
- 收到 `nmux`

### 服务端重建时机

服务端会在以下动作完成后重建 cipher：

- 发出 `session_id`
- 发出 `nmux`
- 收到 `ivv`

这意味着双方都是在逻辑控制交换基本完成后，才真正切换到 connection-specific working cipher state。

### 重建流程

```mermaid
flowchart TD
    A[收到/发出关键控制值] --> B{双方都完成?}
    B -->|否| C[等待]
    B -->|是| D[用 base key + ivv 重建 protocol_]
    D --> E[用 base key + ivv 重建 transport_]
    E --> F[切换到 working cipher 状态]
```

## 密钥派生序列

这是握手过程中最关键的安全机制之一。OPENPPP2 使用 `ivv` 作为连接级工作密钥派生的输入。

### 派 生过程详解

```mermaid
flowchart TD
    A[基础密钥 material] --> B[从配置或预共享密钥获取]
    B --> C[base key]
    C --> D{握手阶段}
    D -->|握手前| E[使用 base key 进行控制和 NOP]
    D -->|握手后| F[进入密钥派生]
    F --> G[ivv = 客户端生成的随机 128 位]
    G --> H[base key + ivv -> KDF]
    H --> I[派生出 protocol_ cipher]
    I --> J[派生出 transport_ cipher]
    J --> K[使用 working cipher 进行数据传输]
```

### KDF 工作原理

虽然代码中没有直接名为 KDF 的独立函数，但密钥派生的逻辑分散在以下函数中：

- 使用 `key.kl` 和 `key.kh` 计算 NOP 轮数
- 使用 `key.kx` 影响填充
- 使用 `kf` 对 payload 进行扰动

### 密钥派生与帧格式的关系

```mermaid
flowchart TD
    A[base key] --> B{handshaked_ 状态}
    B -->|false| C[使用保守帧格式路径]
    B -->|true| D[使用 working cipher 帧格式]
    C --> E[可能使用 base94 路径]
    D --> F[使用 ivv 重建的 cipher]
```

## `handshaked_` 在什么时刻翻转

`handshaked_` 非常关键，因为它不仅影响“会话有没有握成”，还会影响后续包格式路径。

在握手完成前：

- `safest = !handshaked_` 为真
- payload 会强制走更保守的变换路径
- 根据配置和状态，base94 路径也仍然可能继续被使用

在握手完成后：

- `handshaked_` 变为真
- transmission 开始使用基于 `ivv` 重建后的 working cipher
- 常规握手后二进制路径成为正常工作路径

因此，握手控制的是两类状态：

- cipher 状态
- 帧格式状态

## 失败条件

只要出现以下任意情况，握手就会失败：

- NOP 发送失败
- session-id 接收失败
- 在需要真实值时拿到的 `sid` 为零
- `ivv` 发送失败
- `nmux` 为零
- 在握手完成前超时
- transmission 中途已被 `Dispose()`

这说明代码是严格的。它不会尝试在一堆半残缺的握手状态上继续凑合运行。

## 顺序为什么重要

`sid`、`ivv`、`nmux` 的顺序不是任意的，因为三者的职责不同：

- `sid`：建立已接纳会��的逻辑身份
- `ivv`：提供连接级工作密钥派生的新输入
- `nmux`：承载 mux 状态，不必单独发一个裸布尔控制记录

所以这是一个紧凑但功能并不单薄的控制交换过程。

### 完整时序图

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server
    rect rgb(240, 248, 255)
        Note over C,S: 阶段一：NOP 前奏
    end
    C->>S: NOP 包 (轮数轮 = f(key.kl, key.kh))
    S->>C: NOP 包
    rect rgb(255, 250, 240)
        Note over C,S: 阶段二：Session ID 交换
    end
    S->>C: session_id (真实, 非零)
    rect rgb(240, 255, 240)
        Note over C,S: 阶段三：ivv 交换
    end
    C->>S: ivv (客户端生成)
    rect rgb(255, 240, 245)
        Note over C,S: 阶段四：nmux 交换
    end
    S->>C: nmux (服务端生成, 最低位含 mux 状态)
    rect rgb(230, 230, 250)
        Note over C,S: 阶段五：密钥派生
    end
    Note over C: 用 base key + ivv 重建 cipher
    Note over S: 用 base key + ivv 重建 cipher
    rect rgb(250, 255, 230)
        Note over C,S: 握手完成
    end
    Note over C,S: handshaked_ = true
    Note over C,S: 切换到 working cipher 模式
```

## 握手状态机

整个握手过程可以用状态机来描述。以下是客户端和服务端各自的状态转换。

### 客户端状态机

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> NopSent: HandshakeClient()
    NopSent --> WaitSid: 收到 NOP 响应
    WaitSid --> WaitIvv: 收到 session_id
    WaitIvv --> WaitNmux: 发送 ivv
    WaitNmux --> HandshakeComplete: 收到 nmux
    HandshakeComplete --> Established: 用 ivv 重建 cipher
    Established --> [*]
    NopSent --> Failed: 发送失败/超时
    WaitSid --> Failed: 收到 dummy/超时
    WaitIvv --> Failed: 发送失败/超时
    WaitNmux --> Failed: 超时
    Established --> Idle: Dispose()
```

### 服务端状态机

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> WaitNop: HandshakeServer()
    WaitNop --> SendSid: 收到 NOP
    SendSid --> SendNmux: 发送 session_id
    SendNmux --> WaitIvv: 发送 nmux
    WaitIvv --> HandshakeComplete: 收到 ivv
    HandshakeComplete --> Established: 用 ivv 重建 cipher
    Established --> [*]
    WaitNop --> Failed: 超时/错误
    SendSid --> Failed: 发送失败/超时
    SendNmux --> Failed: 发送失败/超时
    WaitIvv --> Failed: 超时/错误
```

### 状态详细解释

|状态|含义|
|----|----|
|Idle|初始状态，未进行任何握手|
|NopSent|已发送 NOP 包，等待响应|
|WaitSid|等待接收真实 session_id|
|WaitIvv|已发送 session_id，等待 ivv|
|WaitNmux|已发送 ivv，等待 nmux|
|SendSid|正在发送 session_id|
|SendNmux|正在发送 nmux|
|HandshakeComplete|所有关键值已交换完成|
|Established|握手成功，进入数据传输状态|
|Failed|握手失败|

## 各阶段变量状态变化

### 变量变化时序

```mermaid
sequenceDiagram
    participant Variables as 变量状态
    participant C as Client
    participant S as Server
    Note over Variables: handshaked_ = false
    Note over Variables: safest = true
    C->>S: NOP 轮换
    S->>C: NOP 响应
    S->>C: session_id
    Note over Variables: sid 已接收
    C->>S: ivv
    Note over Variables: ivv 已发送
    S->>C: nmux
    Note over Variables: nmux 已接收
    Note over C: mux = (nmux & 1) != 0
    Note over Variables: handshaked_ = true
    Note over Variables: safest = false
    Note over C,S: 用 ivv 重建 protocol_/transport_
```

### 关键变量对照表

|阶段|handshaked_|safest|mux 状态|
|----|------------|------|--------|
|握手前|false|true|未定义|
|握手后|false|true|已提取|
|完成后|false|false|已生效|

## 安全视角解读

从安全视角看，这个握手为 OPENPPP2 带来��几��非常重要的性质：

- 早期握手包并不都是语义明确的真实控制项
- 控制值不是未经处理的裸整数
- 每个连接都可以据 `ivv` 派生新的工作密钥状态
- 半开握手会被超时清理
- mux 状态被嵌入随机值而不是单独暴露成一个过于直白的小标记包

同样，要如实表述：这已经相当丰富，没有必要再超出代码事实做夸张宣传。

### 安全特性总结

```mermaid
mindmap
  root((安全特性))
    流量混淆
      NOP 前奏扰动
      dummy 包机制
    控制信息保护
      非明文传输
      XOR 变换
      多层扰动
    密钥管理
      每次连接唯一 ivv
      连接级密钥派生
      状态切换清晰
    状态标记隐蔽
      nmux 最低位
      非直接布尔值
    超时保护
      半开握手清理
      有限不确定窗口
```

## 与其他层的交互

### 与 Frame 层的关系

握手完成后，`handshaked_` 状态会影响帧格式的选择：

```mermaid
flowchart TD
    A[发送数据] --> B{handshaked_ == true?}
    B -->|是| C[使用 working cipher 帧格式]
    B -->|否| D[使用保守帧格式或 base94]
    C --> E[发送]
    D --> E
```

### 与 Timeout 层的关系

```mermaid
flowchart TD
    A[设置握手超时] --> B[启动定时器]
    B --> C{握手完成?}
    C -->|是| D[清除超时]
    C -->|否| E{超时?}
    E -->|是| F[销毁 transmission]
    E -->|否| G[继续等待]
```

## 开发者调试提示

调试或跟源码时，建议重点盯住以下变量：

- `handshaked_`
- `frame_rn_`
- `frame_tn_`
- `protocol_`
- `transport_`
- `timeout_`
- `ivv`
- `nmux`

这些变量把握手层和后续帧化层直接连了起来。

### 建议的调试流程

1. 先确认 NOP 发送/接收正常
2. 检查 session_id 是否非零
3. 确认 ivv 生成和交换成功
4. 验证 nmux 的最低位提取正确
5. 确认 cipher 重建成功
6. 检查 handshaked_ 状态翻转
7. 确认后续数据走正确的帧格式路径

### 常见问题排查

|现象|可能原因|NOP 相关?|排查方向|
|----|--------|--------|------|
|握手超时|NOP 发送失败|是|检查网络和 key 配置|
|stub 为零|NOP 或 session_id 问题|是|检查 pack/unpack 函数|
|ivv 交换失败|发送失败|否|检查 ivv 生成逻辑|
|mux 状态错误|nmux 最低位处理问题|否|检查 & 1 提取逻辑|
|cipher 不工作|ivv 未正确使用|否|检查重建函数|

## 相关文档

- [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)
- [`PACKET_FORMATS_CN.md`](PACKET_FORMATS_CN.md)
- [`SECURITY_CN.md`](SECURITY_CN.md)