# 客户端架构

[English Version](CLIENT_ARCHITECTURE.md)

## 核心类型

客户端主要围绕以下类型展开：

- `VEthernetNetworkSwitcher`
- `VEthernetExchanger`
- `VEthernetNetworkTcpipStack`
- `VEthernetNetworkTcpipConnection`
- 各类代理 switcher 和本地代理连接

其中 switcher 负责宿主机环境，exchanger 负责远端会话。

## 客户端职责

从代码看，客户端不只是一个“拨号器”，它同时负责：

- 虚拟网卡生命周期
- 路由安装与清理
- bypass 和 route-list 逻辑
- DNS 分流与 DNS 重定向
- 本地 HTTP / SOCKS 代理暴露
- 反向 mapping 注册
- static UDP 模式行为
- MUX 协商与使用
- 可选 IPv6 应用

## 启动路径

客户端启动过程大致是：

1. 解析配置和 CLI 覆盖参数
2. 创建 TUN/TAP
3. 构造 `VEthernetNetworkSwitcher`
4. 注入 static、mux、vnet、protect 等运行标志
5. 加载 bypass 列表和 route 列表
6. 加载 DNS 规则
7. 调用 `Open(tap)`
8. 创建 `VEthernetExchanger`
9. 由 exchanger 建立并维持远端隧道关系

## 为什么客户端要拆成 Switcher 和 Exchanger

这种拆分在代码职责中非常清楚：

- `VEthernetNetworkSwitcher` 处理宿主网络状态
- `VEthernetExchanger` 处理远端会话状态

这是正确的边界。因为路由表和 DNS 策略的生命周期，通常长于一次具体远端连接尝试。

## 虚拟网卡集成

switcher 基于 `ITap` 工作，因此把虚拟网卡视为平台抽象。

一旦虚拟网卡打开，客户端就必须负责：

- 从虚拟网卡接收分组
- 判断它们是否应进入隧道
- 将返回流量重新注入虚拟网卡

## IPv4 报文路径

对于虚拟子网流量，来自 TUN 的 IPv4 报文会由 `OnPacketInput(...)` 检查。

这里的逻辑是有选择性的：

- 只关注 TCP、UDP、ICMP
- 流量必须处于预期虚拟子网语境内
- 发往本地网关的流量会单独处理

满足条件后，报文通过 `Nat(...)` 交给 exchanger。

## UDP 路径

UDP 路径比一般 NAT 转发更复杂，因为客户端同时支持：

- DNS 拦截与重定向
- QUIC 屏蔽
- static UDP 模式
- 按端点维持的数据报状态

这就是为什么 UDP 通过显式 datagram-port 对象处理，而不是只靠一个通用转发器。

## ICMP 路径

ICMP 路径包含以下特殊处理：

- echo 行为
- 合成应答
- TTL 相关响应

这对运维可见性很重要。一个不能正确处理 ICMP 的虚拟网络，很难调试，也不具备路由器式行为。

## TCP 路径

客户端的 TCP 处理之所以拆成专门类型，是因为 TCP 不只是“转发包”这么简单。

实现需要处理：

- 逻辑 connect/open
- 流数据转发
- close 语义
- 可选 mux 参与
- 本地 bypass 行为

因此 TCP 走 `VEthernetNetworkTcpipStack` 和 `VEthernetNetworkTcpipConnection`，而不是沿用 UDP 的简单路径。

## 路由控制

客户端是高度路由感知的。

从代码和配置结构看，路由逻辑包括：

- 首选 NIC 与网关
- bypass 文件加载
- 本地 route-list 文件加载
- 远端 route-list 刷新支持
- 默认路由保护
- hosted-network 偏好

这正是工程更像覆盖网络边缘节点，而不是薄客户端的重要原因之一。

## DNS 控制

DNS 被当作一类一等公民的控制能力。

客户端侧 DNS 能力包括：

- DNS 规则加载
- DNS 服务器覆盖
- 在隧道路径中的 DNS 重定向
- 与整体运行时协作的 DNS 缓存行为

这很关键，因为在覆盖网络系统里，名称解析策略往往就决定了实际流量分流策略。

## 本地代理能力

客户端可以暴露：

- HTTP 代理
- SOCKS 代理

这意味着本地应用即使不直接使用虚拟网卡，也可以通过代理进入覆盖网络。

这是一种部署模式能力，而不是单纯的便利功能。

## 反向 Mapping 注册

客户端还是反向 mapping 的注册侧。

配置中的 `client.mappings` 会被注册到隧道控制面，使服务端侧可以建立对应的远程访问入口。

这说明客户端不只是流量源头，也是一个服务暴露端点。

## Static 模式

Static 模式为客户端提供一条独立于主控制传输的、偏数据报的路径。

客户端会分配 static echo 状态、导出会话密钥，并按配置把选定的 UDP、DNS、QUIC 或 ICMP 流量送入该路径。

## MUX

客户端的 MUX 主要用于在一条已建立关系上复用多个逻辑流。

从代码看，MUX 更主要服务于额外逻辑 TCP/IP 中继，而不是替代主控制会话。

## IPv6 应用

客户端可以请求特定 IPv6，也可以应用服务端分配的 IPv6 状态。

可应用状态包括：

- 地址
- 网关
- 路由前缀
- DNS 服务器

代码还会校验发出的 IPv6 报文源地址是否等于分配地址，从而避免客户端在受管覆盖网络中随意使用其他 IPv6 源身份。

## 为什么客户端会长成这样

客户端架构的核心现实是：它必须同时扮演“宿主网络集成层”和“隧道端点”两个角色。

如果这两类关注点不被明确分开，整个实现会极难理解和维护。
