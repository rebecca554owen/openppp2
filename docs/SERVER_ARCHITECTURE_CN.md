# 服务端架构

[English Version](SERVER_ARCHITECTURE.md)

## 核心类型

服务端主要围绕以下类型展开：

- `VirtualEthernetSwitcher`
- `VirtualEthernetExchanger`
- `VirtualEthernetNetworkTcpipConnection`
- static 数据报辅助逻辑
- namespace cache 和管理后端客户端

其中 switcher 是会话交换机，每个 exchanger 表示一个客户端会话。

## 服务端职责

服务端远不只是“接个 socket”。

从代码看，它同时负责：

- 监听器创建
- 传输接入
- 握手与会话建立
- 可选后端认证  
- NAT 与 UDP 转发
- 反向 mapping 支持
- MUX 支持
- static UDP 路径支持
- 会话统计
- IPv6 请求、租约和 transit 状态
- 防火墙与 namespace cache 集成

## 监听模型

服务端可以暴露多类监听入口：

- TCP
- WebSocket
- WebSocket over TLS
- CDN / SNI proxy 风格监听
- UDP static socket 路径

这让服务端成为一个多入口的覆盖网络节点，而不是单端口隧道守护进程。

## 接入路径

承载连接被接受之后，服务端会先将其包装为 `ITransmission` 并执行握手。

此后这条连接会变成两类之一：

- 主会话建立路径
- 额外的 TCP 中继 / mux 相关连接路径

这一点在 `Establish(...)` 和 `Connect(...)` 中体现得很清楚。

## 为什么服务端要叫 Switcher

这个名字是准确的。`VirtualEthernetSwitcher` 不只是监听器容器，它还要切换和维护：

- 会话
- 连接
- NAT 状态
- IPv6 租约状态
- 管理面交互

这正是覆盖网络服务端节点应有的形态。

## 会话建立

服务端为一个客户端建立新会话时，大致做这些事：

1. 为该 session id 创建或替换 exchanger
2. 获取会话策略信息
3. 构造信息信封
4. 在需要时安装 IPv6 状态
5. 把会话信息发给客户端
6. 运行该会话的 exchanger 循环

代码还支持一种本地启动路径：在没有管理后端时，由服务端本地给出默认会话信息。

## 与管理后端协作

当配置了 `server.backend` 后，服务端可以通过 `VirtualEthernetManagedServer` 把会话认证交给外部管理系统。

这很重要，因为整个架构明确区分了：

- C++ 进程内的数据面
- 外部可委托的准入和计量逻辑

这种拆分比把全部网络逻辑塞进管理服务更干净。

## NAT 与 UDP 转发

服务端 exchanger 会接收 `NAT`、`SENDTO` 等动作，并把它们转发到真实网络。

因此服务端需要持有：

- datagram port 表
- NAT 信息表
- 防火墙引用

它在远端客户端看来，实际上就是连接真实网络的边缘节点。

## 为什么某些入站动作会被立即拒绝

服务端 exchanger 会显式拒绝某些方向不合法的控制动作，例如来自错误方向的 TCP 中继控制。

这是一种防御性设计：协议动作词汇是共享的，但并不是每个动作在任意方向上都合法。

## 反向 Mapping 支持

当 mapping 启用时，服务端会参与 FRP 风格的反向服务暴露。

这意味着服务端不仅把客户端流量向外转发，还可以作为客户端注册服务的外部访问面。

## 服务端上的 MUX

服务端可以为会话构造并维护 `vmux_net` 实例。

这样额外逻辑流就能在既有会话关系上复用，但仍然必须经过明确的 mux 建立与确认过程。

## 服务端上的 Static UDP 路径

服务端也拥有 static 模式的另一半：

- static 分配上下文
- static echo 绑定端口
- static 数据报转发
- 基于会话的分组解密和加密行为

这就是为什么服务端会在常规流式传输路径之外，还保留一套单独的 static socket 状态。

## IPv6 状态

服务端 IPv6 支持是整个工程中非常“基础设施化”的部分之一。

服务端维护：

- IPv6 请求表
- IPv6 租约表
- 地址到会话的关联
- transit TAP 状态
- 可选邻居代理状态

它可以基于会话身份生成稳定地址、支持静态绑定，并为这些地址安装数据面支持。

这不是边缘能力，而是一个真正的控制与转发子系统。

## Namespace Cache 与 DNS

服务端内部包含一套面向 DNS 风格数据的 namespace cache。这样服务端不仅是包转发节点，还承担部分名称处理与策略协作职责。

## 为什么服务端这么像网络基础设施

服务端被设计成一个覆盖网络节点，具备：

- 多种接入入口
- 显式会话交换
- 本地转发状态
- 可选策略后端
- IPv6 服务逻辑

因此它应当被当作网络节点来理解，而不是普通应用服务器。
