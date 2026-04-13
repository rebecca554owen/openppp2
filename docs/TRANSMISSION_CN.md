# 传输与隧道模型

[English Version](TRANSMISSION.md)

## 文档目的

OPENPPP2 将隧道拆分为三个层次：

- 承载传输层：TCP、UDP、WS、WSS
- 受保护的传输层：带帧结构的读写、协议层密钥、传输层密钥
- 虚拟以太网控制与数据层：LAN、NAT、TCP、UDP、回显、映射、静态模式、MUX 等隧道动作

对应代码位置：

- `ppp/transmissions/ITransmission.*`
- `ppp/transmissions/ITcpipTransmission.*`
- `ppp/transmissions/IWebsocketTransmission.*`
- `ppp/app/protocol/VirtualEthernetLinklayer.*`

## 承载传输类型

运行时可以在多种 Socket 风格上承载隧道：

- 原生 TCP
- 原生 UDP
- WebSocket
- WebSocket over TLS

承载层只决定字节如何在两端移动。会话标识、帧结构、保活、加密和隧道动作都在其上层完成。

## 握手模型

`ITransmission` 持有握手入口：

- `HandshakeClient(...)`
- `HandshakeServer(...)`

握手阶段建立以下状态：

- 会话标识
- 帧状态
- 可选的多路复用标记
- 协议层与传输层密钥状态

`ITransmission` 内部还包含超时保护逻辑，避免半开会话长期占用资源。

## 保护层

工程中存在两个逻辑分离的密钥槽位：

- 协议层密钥：保护隧道元数据帧与协议级负载处理
- 传输层密钥：保护实际传输字节流

相关配置位于 `key`：

- `protocol`
- `protocol-key`
- `transport`
- `transport-key`
- `masked`
- `plaintext`
- `delta-encode`
- `shuffle-data`
- `kf`、`kh`、`kl`、`kx`、`sb`

这里的设计目标不只是保密，还包括控制帧形态、负载格式和早期建链阶段的兼容行为。

## 帧化读写流程

在传输层，数据流大致如下：

1. 上层向 `Write(...)` 提交负载
2. `ITransmission` 应用帧结构与已启用的变换
3. 承载层通过当前 Socket 类型发送字节
4. 对端通过 `Read(...)` 读取带帧字节流
5. `ITransmission` 逆向恢复已启用的变换
6. 解码后的隧道负载交给链路层包处理逻辑

这使得上层协议基本无需关心底层实际跑在 TCP、UDP 还是 WebSocket 上。

## 虚拟以太网动作集

`VirtualEthernetLinklayer` 定义了隧道内动作集合，主要分组包括：

- 信息与保活：`INFO`、`KEEPALIVED`
- 三层与虚拟 LAN 动作：`LAN`、`NAT`、`SENDTO`、`ECHO`、`ECHOACK`
- TCP 中继动作：`SYN`、`SYNOK`、`PSH`、`FIN`
- 反向访问动作：`FRP_ENTRY`、`FRP_CONNECT`、`FRP_CONNECTOK`、`FRP_PUSH`、`FRP_DISCONNECT`、`FRP_SENDTO`
- 静态路径动作：`STATIC`、`STATICACK`
- 多路复用动作：`MUX`、`MUXON`

这些能力不是分散的多个产品，而是在同一会话与分组模型下统一承载的。

## 设计支持的隧道玩法

### 1. 标准客户端/服务端隧道

客户端创建虚拟网卡，并通过一种承载传输将流量送往服务端。

### 2. 分流隧道

客户端只把指定前缀、域名或 DNS 流量送入覆盖网络，其余流量继续走本地网络。

### 3. 反向访问 / 服务暴露

通过映射与 FRP 风格控制消息，客户端可以把本地 TCP 或 UDP 服务暴露到服务端侧。

### 4. 静态 UDP 模式

代码中包含静态 UDP 通路、保活逻辑以及可选多服务器支持，适合更偏向稳定报文路径的部署方式。

### 5. MUX 多路复用隧道

MUX 可以在一条已建立链路上承载多个逻辑通道，降低重复握手成本，并复用健康的现有连接。

### 6. WebSocket 前置隧道

隧道可以跑在 WS 或 WSS 内部，适合部署在反向代理、HTTP 基础设施或 TLS 终止层之后。

## WebSocket 集成

`websocket` 配置块控制以下内容：

- `listen.ws`
- `listen.wss`
- `host`
- `path`
- `ssl.certificate-file`
- `ssl.certificate-key-file`
- `ssl.certificate-chain-file`
- `ssl.ciphersuites`
- 请求头与响应头修饰

这样可以在不改变上层隧道协议的前提下，对接 HTTP 风格边缘入口。

## MUX 的设计意图

MUX 是隧道效率特性，不是另一种完全不同的传输族。

它的目标是：

- 复用已建立会话
- 降低多逻辑流的建链开销
- 比开启大量独立会话更易于保持控制面简洁

关键入口在：

- `VirtualEthernetLinklayer::DoMux(...)`
- `VirtualEthernetLinklayer::DoMuxON(...)`
- 创建和维护 `vmux_net` 的客户端 / 服务端 exchanger 实现

## 静态 UDP 与聚合

`udp.static` 配置段控制长生命周期 UDP 风格路径：

- `keep-alived`
- `dns`
- `quic`
- `icmp`
- `aggligator`
- `servers`

这一部分设计用于让数据报型部署显式可配置，尤其适合存在多个上游 UDP 服务器的场景。

## IPv6 传输扩展

IPv6 是作为会话与信息模型的扩展来承载的，不是单独分叉的一条产品线。

关键实现位于：

- `VirtualEthernetInformationExtensions`
- `VirtualEthernetSwitcher` 中的 IPv6 租约与路由处理
- `VEthernetNetworkSwitcher` 中的 IPv6 应用与恢复流程

当前服务端 IPv6 数据面主要在 Linux 上实现得最完整。

## 工程取舍

该传输模型优先考虑：

- 一个协议核心，而不是很多彼此割裂的数据通路
- 清晰分层，而不是隐藏耦合
- 可恢复的超时和重连，而不是隐式长时间阻塞
- 把路由与隧道策略放进配置，而不是写死在实现里

代价是功能面较宽。运维侧应根据实际需要启用功能，而不是把所有开关全部打开。

## 相关文档

- [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
- [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md)
- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
- [`SECURITY_CN.md`](SECURITY_CN.md)
