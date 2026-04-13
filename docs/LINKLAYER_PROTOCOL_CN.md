# 链路层协议指南

[English Version](LINKLAYER_PROTOCOL.md)

## 文档范围

本文描述由 `VirtualEthernetLinklayer` 实现的内部隧道动作协议。

## 为什么需要这一层

OPENPPP2 需要一套共享的协议词汇来表达：

- 会话信息
- 保活
- 虚拟子网转发
- UDP 中继
- TCP 中继
- 反向映射
- static 路径协商
- mux 协商

`VirtualEthernetLinklayer` 就是这套共享语义。

## 主要动作族

### 信息与保活

- `INFO`
- `KEEPALIVED`

用于会话信息下发、健康维护和会话保活。

### 数据与转发动作

- `LAN`
- `NAT`
- `SENDTO`
- `ECHO`
- `ECHOACK`

用于子网信令、分组转发、UDP 中继和 ICMP 相关行为。

### TCP 中继动作

- `SYN`
- `SYNOK`
- `PSH`
- `FIN`

用于在隧道内建立逻辑 TCP 连接。

### Static 路径动作

- `STATIC`
- `STATICACK`

用于分配并确认 static UDP 风格路径。

### MUX 动作

- `MUX`
- `MUXON`

用于协商和确认多路复用逻辑通道。

### FRP 风格反向映射动作

- `FRP_ENTRY`
- `FRP_CONNECT`
- `FRP_CONNECTOK`
- `FRP_PUSH`
- `FRP_DISCONNECT`
- `FRP_SENDTO`

用于把客户端服务通过服务端侧对外暴露。

## 信息载荷

`INFO` 同时携带：

- 一个打包后的 `VirtualEthernetInformation` 基础对象
- 一个可选扩展 JSON 字符串

扩展 JSON 目前主要承载 IPv6 分配和状态字段。

这种设计很有价值：稳定二进制部分保持紧凑，而可扩展部分可以继续增长，不破坏基础布局。

## TCP 中继语义

逻辑 TCP 中继在隧道内部表现为一个小型控制协议：

1. 请求方发送 `SYN`
2. 响应方尝试连接目标地址
3. 响应方返回 `SYNOK`
4. 流数据通过 `PSH` 传递
5. 关闭通过 `FIN` 完成

这就是为什么 TCP 中继必须是一个带会话语义的子系统，而不是简单的包复制。

## UDP 中继语义

UDP 中继是按端点组织的：

- 源端点和目的端点被编码进动作载荷
- 数据报状态由 datagram-port 对象维护
- 返回流量可以回送到已有隧道状态对象，也可以重构后重新注入 TUN

## ICMP 语义

`ECHO` 和 `ECHOACK` 为隧道提供了回显健康和合成应答机制。

这对运维很有价值，因为它让虚拟网络更像一个可路由网络，而不是一个黑盒用户态 socket 隧道。

## FRP Mapping 语义

FRP 风格动作让隧道具备受控反向暴露能力。

高层流程大致是：

1. 客户端用 `FRP_ENTRY` 注册 mapping
2. 服务端为该 mapping 接受外部访问
3. 连接建立使用 `FRP_CONNECT` 和 `FRP_CONNECTOK`
4. 数据通过 `FRP_PUSH` 或 `FRP_SENDTO` 传递
5. 关闭使用 `FRP_DISCONNECT`

## Static 路径语义

Static 路径是在 opcode 协议层协商的，但后续实际分组承载走的是 `VirtualEthernetPacket`。

这种拆分是有意为之：

- `STATIC` / `STATICACK` 属于控制面
- `VirtualEthernetPacket` 属于该路径上的分组承载格式

## MUX 语义

MUX 是显式协商的，而不是默认假设的。

这很重要，因为 mux 不只是一个优化开关，它意味着双方都要接受另一种逻辑流组织方式。

## 方向约束的防御性设计

实现里一个很重要的特征是：双方都不会在任意方向接受任意动作。

代码中可以看到：

- 服务端拒绝不该由客户端发起的 TCP 控制方向
- 客户端拒绝不该由服务端主动发起的 connect/push 方向

这使得共享协议在运行时更安全，因为角色合法性在 handler 层被显式执行。

## 为什么这一层值得单独写文档

如果不先理解 `VirtualEthernetLinklayer`，就很难理解为什么整个运行时会拆成这么多类型。

这一层就是系统控制面与数据面语义的中心。
