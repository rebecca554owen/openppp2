# 系统架构

[English Version](ARCHITECTURE.md)

## 范围

本文是 OPENPPP2 的顶层架构地图，说明仓库如何分层、共享核心和宿主后果如何分开。

本文基于 `main.cpp`、`ppp/configurations/AppConfiguration.*`、`ppp/transmissions/*`、`ppp/app/protocol/*`、`ppp/app/client/*`、`ppp/app/server/*` 和各平台目录来说明系统边界。

---

## 核心思想

OPENPPP2 是一套虚拟以太网基础设施运行时。它由共享协议核心和宿主特化后果组成。

共享核心使用同一套隧道动作词汇（`VirtualEthernetLinklayer`）、同一套受保护传输抽象（`ITransmission`），以及同一套配置模型（`AppConfiguration`）。宿主后果——路由变更、DNS 变更、适配器生命周期、防火墙行为、socket 保护——被委托给平台相关的实现，共享核心通过良好定义的接口驱动它们。

---

## 核心布局

```mermaid
graph TD
    A[main.cpp] --> B[AppConfiguration]
    A --> C[ITransmission]
    A --> D[客户端运行时]
    A --> E[服务端运行时]
    B --> C
    C --> F[VirtualEthernetLinklayer]
    D --> G[VEthernetNetworkSwitcher]
    D --> H[VEthernetExchanger]
    E --> I[VirtualEthernetSwitcher]
    E --> J[VirtualEthernetExchanger]
    G --> K[平台层]
    I --> K
    I --> L[go/* 可选后端]
```

---

## 完整模块依赖图

```mermaid
graph TD
    subgraph 入口
        MAIN[main.cpp]
        APP[PppApplication]
    end

    subgraph 配置
        CFG[AppConfiguration]
    end

    subgraph 传输层
        ITRANS[ITransmission]
        TCP[ITcpipTransmission]
        WS[IWebsocketTransmission]
        ITRANS --> TCP
        ITRANS --> WS
    end

    subgraph 协议层
        LINKLAYER[VirtualEthernetLinklayer]
        PACKET[VirtualEthernetPacket]
        INFO[VirtualEthernetInformation]
        LINKLAYER --> PACKET
        LINKLAYER --> INFO
    end

    subgraph 客户端运行时
        CSWITCHER[VEthernetNetworkSwitcher]
        CEXCHANGER[VEthernetExchanger]
        CSWITCHER --> CEXCHANGER
    end

    subgraph 服务端运行时
        SSWITCHER[VirtualEthernetSwitcher]
        SEXCHANGER[VirtualEthernetExchanger]
        SSWITCHER --> SEXCHANGER
    end

    subgraph 平台适配层
        LINUX[linux/]
        WIN[windows/]
        ANDROID[android/]
        MACOS[darwin/]
    end

    subgraph 可选后端
        GO[go/ 管理后端]
    end

    MAIN --> APP
    APP --> CFG
    APP --> ITRANS
    APP --> CSWITCHER
    APP --> SSWITCHER
    CFG --> ITRANS
    ITRANS --> LINKLAYER
    LINKLAYER --> CEXCHANGER
    LINKLAYER --> SEXCHANGER
    CSWITCHER --> LINUX
    CSWITCHER --> WIN
    CSWITCHER --> ANDROID
    CSWITCHER --> MACOS
    SSWITCHER --> LINUX
    SSWITCHER --> WIN
    SSWITCHER --> GO
```

---

## 并发模型

OPENPPP2 使用 Boost.Asio `io_context` 作为事件循环核心，结合 Boost.Coroutine 实现异步-同步混合编程范式。

```mermaid
graph TD
    subgraph 线程池
        T1[io_context 线程 1]
        T2[io_context 线程 2]
        TN[io_context 线程 N]
    end

    subgraph 协程层
        CO1[boost::asio::spawn 协程]
        CO2[YieldContext 封装]
    end

    subgraph 任务分发
        POST[asio::post]
        STRAND[asio::strand]
    end

    T1 --> POST
    T2 --> POST
    TN --> POST
    POST --> CO1
    CO1 --> CO2
    CO2 --> STRAND
    STRAND --> T1
```

核心并发规则：
- 跨线程对象生命周期通过 `std::shared_ptr` 和 `std::weak_ptr` 管理。
- 跨线程状态标志使用 `std::atomic<bool>` 和 `compare_exchange_strong`。
- IO 线程严禁阻塞；阻塞操作通过 `asio::post` 投递。
- 协程在每个异步边界通过 `YieldContext` 挂起。

---

## 共享核心与宿主后果

最重要的分割是：

| 区域 | 责任 |
|---|---|
| 共享核心 | 配置、传输、握手、帧化、链路动作 |
| 宿主后果 | 适配器、路由、DNS、防火墙、平台 IPv6 与 socket 行为 |

共享核心可以复用。宿主后果不能假定跨系统一致。

```mermaid
flowchart LR
    SharedCore["共享核心\n（ppp/ 平台无关）"]
    HostConsequences["宿主后果\n（平台相关）"]
    SharedCore -->|"通过接口驱动"| HostConsequences
    SharedCore --> Protocol["协议：opcode 分发"]
    SharedCore --> Transport["传输：握手、分帧"]
    SharedCore --> Config["配置：规范化"]
    HostConsequences --> Route["路由表管理"]
    HostConsequences --> DNS["DNS 重定向"]
    HostConsequences --> Adapter["虚拟网卡生命周期"]
    HostConsequences --> Firewall["防火墙 / socket 保护"]
```

---

## 共享核心

共享核心负责 tunnel semantics：

- `AppConfiguration` 决定运行形态
- `ITransmission` 负责承载、握手、帧保护和密钥状态
- `VirtualEthernetLinklayer` 负责隧道动作词汇
- client/server exchanger 负责会话级行为

```mermaid
flowchart TD
    A[配置加载] --> B[规范化 AppConfiguration]
    B --> C[选择承载与角色]
    C --> D[ITransmission]
    D --> E[握手]
    E --> F[VirtualEthernetLinklayer]
    F --> G[客户端 exchanger]
    F --> H[服务端 exchanger]
```

---

## 宿主后果

平台层负责本地操作系统上的实际副作用：

- 虚拟网卡
- 路由表变更
- DNS 变更
- socket 保护
- 平台特化 IPv6

这些都不是"辅助代码"，而是可观测的运行时行为。

### 平台接口切入点

```mermaid
classDiagram
    class ITap {
        +Open() bool
        +Read(buffer) int
        +Write(buffer) int
        +Close()
    }
    class INetworkInterface {
        +AddRoute(cidr, gateway) bool
        +DeleteRoute(cidr) bool
        +SetDNS(servers) bool
    }
    class LinuxTap {
        +Open() bool
        +Read(buffer) int
    }
    class WindowsTap {
        +Open() bool
        +Read(buffer) int
    }
    ITap <|-- LinuxTap
    ITap <|-- WindowsTap
    INetworkInterface <|-- LinuxNetworkInterface
    INetworkInterface <|-- WindowsNetworkInterface
```

---

## 运行时入口

`main.cpp` 是 C++ 入口与进程协调器。流程是：

1. 解析参数
2. 加载配置
3. 规范化配置
4. 选择角色
5. 准备宿主环境
6. 启动 client 或 server
7. 运行维护 tick loop
8. 输出状态
9. 清理退出

```mermaid
stateDiagram-v2
    [*] --> 参数解析
    参数解析 --> 配置加载
    配置加载 --> 配置规范化
    配置规范化 --> 角色选择
    角色选择 --> 宿主准备
    宿主准备 --> 运行时启动
    运行时启动 --> 维护循环
    维护循环 --> 关闭
    关闭 --> [*]
```

---

## 对象所有权

| 层级 | 所有者 |
|---|---|
| 进程 | `PppApplication` |
| 环境 | `VEthernetNetworkSwitcher` 或 `VirtualEthernetSwitcher` |
| 会话 | `VEthernetExchanger` 或 `VirtualEthernetExchanger` |
| 连接 | `ITransmission` |

### 所有权转移时序

```mermaid
sequenceDiagram
    participant App as PppApplication
    participant Switcher as Switcher
    participant Exchanger as Exchanger
    participant Trans as ITransmission

    App->>Switcher: 创建并持有
    Switcher->>Trans: 创建承载连接
    Trans-->>Switcher: 握手完成
    Switcher->>Exchanger: 创建并转移所有权
    Exchanger->>Exchanger: 运行会话（协程）
    Exchanger->>Switcher: 会话结束（通知）
    Switcher->>Exchanger: 释放
```

---

## 角色非对称

client 和 server 不是对称的：

- client：宿主集成、路由、DNS、代理、映射、可选 static 和 mux
- server：监听、会话交换、转发、映射、IPv6、可选后端集成

```mermaid
graph LR
    A[客户端] --> B[路由/DNS steering]
    A --> C[本地代理入口]
    A --> D[远端会话交换]
    E[服务端] --> F[监听器设置]
    E --> G[会话交换]
    E --> H[转发]
    E --> I[可选管理后端]
```

### 操作码方向非对称

| 操作码 | 客户端发起 | 服务端发起 |
|--------|-----------|-----------|
| `SYN` | 是 | 否 |
| `SYNOK` | 否 | 是 |
| `PSH` | 双向 | 双向 |
| `FIN` | 双向 | 双向 |
| `SENDTO` | 是 | 是（响应） |
| `INFO` | 否 | 是 |
| `KEEPALIVED` | 是（echo） | 是（ack） |
| `FRP_ENTRY` | 是 | 否 |
| `FRP_CONNECT` | 否 | 是 |
| `MUX` | 是 | 否 |
| `MUXON` | 否 | 是 |

---

## 配置即架构

`AppConfiguration` 是架构组件，不只是解析器。它决定哪些传输启用、哪些监听器打开、密钥怎么用，以及 client/server 策略如何落地。

### AppConfiguration 关键字段

| 字段 | 效果 |
|------|------|
| `mode` | `client` 或 `server` |
| `key.kf`、`key.kx`、`key.kl`、`key.kh` | 会话密钥参数 |
| `ip`、`mask`、`gw` | 客户端虚拟网络分配 |
| `dns.redirect` | DNS 是否重定向到隧道 |
| `server.node` | 服务器地址和端口 |
| `server.protocol` | `tcp`、`websocket`、`websocket-ssl` |
| `tcp.turbo` | TCP 性能调优 |
| `udp.static.*` | Static UDP 路径配置 |

---

## 传输层与协议层

| 层 | 负责什么 |
|---|---|
| Transmission | 承载选择、握手、帧保护、密钥状态 |
| Protocol | 会话语义、opcode 语义、隧道动作语义 |

```mermaid
flowchart TD
    A[ITransmission：承载 + 握手 + 分帧 + 外层密钥]
    B[VirtualEthernetLinklayer：opcode 分发 + Do/On 方法 + 内层会话密钥]
    C[VEthernetExchanger / VirtualEthernetExchanger：角色专属行为]
    A --> B
    B --> C
```

---

## 数据流：客户端到服务端

```mermaid
sequenceDiagram
    participant App as 宿主应用
    participant TAP as 虚拟 TAP 设备
    participant lwIP as lwIP 协议栈
    participant Exchanger as VEthernetExchanger
    participant Linklayer as VirtualEthernetLinklayer
    participant Trans as ITransmission
    participant Server as 服务端

    App->>TAP: IP 数据包
    TAP->>lwIP: 注入帧
    lwIP->>Exchanger: 新 TCP 连接（SYN）
    Exchanger->>Linklayer: DoConnect
    Linklayer->>Trans: 写入 SYN 帧
    Trans->>Server: 加密 + 分帧字节
    Server-->>Trans: SYNOK 帧
    Trans-->>Linklayer: 读取帧
    Linklayer-->>Exchanger: OnConnectOK
    Exchanger-->>lwIP: 连接已建立
    lwIP->>Exchanger: 数据（PSH）
    Exchanger->>Linklayer: DoPush
    Linklayer->>Trans: 写入 PSH 帧
    Trans->>Server: 加密 + 分帧字节
```

---

## 数据流：服务端到互联网

```mermaid
sequenceDiagram
    participant Client as 客户端
    participant Trans as ITransmission
    participant Linklayer as VirtualEthernetLinklayer
    participant Switcher as VirtualEthernetSwitcher
    participant Socket as 真实 TCP/UDP socket
    participant Internet as 互联网

    Client->>Trans: SYN 帧
    Trans->>Linklayer: 解码后的帧
    Linklayer->>Switcher: OnConnect
    Switcher->>Socket: TCP 连接到目标
    Socket-->>Switcher: 已连接
    Switcher->>Linklayer: DoConnectOK
    Linklayer->>Trans: SYNOK 帧
    Trans->>Client: 加密字节
    Client->>Trans: PSH 帧
    Trans->>Linklayer: 解码后的帧
    Linklayer->>Switcher: OnPush
    Switcher->>Socket: 转发数据
    Socket->>Internet: 真实 TCP 包
    Internet-->>Socket: 响应
    Socket-->>Switcher: 数据
    Switcher->>Linklayer: DoPush
    Linklayer->>Trans: PSH 帧
    Trans->>Client: 加密字节
```

---

## 错误码参考

架构层面的错误码（来自 `ppp/diagnostics/Error.h`）：

| ErrorCode | 说明 |
|-----------|------|
| `ConfigurationInvalid` | AppConfiguration 归一化失败 |
| `RoleConflict` | 同时请求了 client 和 server 角色 |
| `TransmissionHandshakeFailed` | ITransmission 握手未完成 |
| `SessionEstablishFailed` | 链路层 INFO 交换失败 |
| `PlatformSetupFailed` | 宿主适配器 / 路由 / DNS 设置失败 |
| `BackendConnectionFailed` | 可选后端不可达（非致命） |
| `ShutdownTimeout` | 优雅关闭超时 |

---

## 相关文档

- [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)
- [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)
- [`TUNNEL_DESIGN_CN.md`](TUNNEL_DESIGN_CN.md)
- [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md)
- [`ENGINEERING_CONCEPTS_CN.md`](ENGINEERING_CONCEPTS_CN.md)
- [`CONCURRENCY_MODEL_CN.md`](CONCURRENCY_MODEL_CN.md)
- [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
