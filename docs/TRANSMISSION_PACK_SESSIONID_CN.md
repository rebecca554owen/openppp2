# 会话与控制面模型

[English Version](TRANSMISSION_PACK_SESSIONID.md)

## 文档目的

旧文件名沿用了 `PACK_SESSIONID` 的称呼，但真正有工程价值的话题更宽：OPENPPP2 如何标识会话、交换隧道元信息，并在传输建好之后驱动控制动作。

本文聚焦这一控制面模型。

## 核心对象

相关主要类型包括：

- `ppp/transmissions/ITransmission.*`
- `ppp/app/protocol/VirtualEthernetInformation.*`
- `ppp/app/protocol/VirtualEthernetLinklayer.*`
- `ppp/app/server/VirtualEthernetSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetManagedServer.*`

## 会话标识

会话标识以 `Int128` 为中心，在客户端、服务端和管理面流程中贯穿使用。

该标识用于：

- 将一个逻辑隧道交换绑定到一个传输会话
- 在服务端定位对应 exchanger
- 关联流量计费与认证状态
- 管理 IPv6 请求、租约与控制回调

使用宽位标识符合工程目标：长生命周期会话在同一部署域内应尽可能全局唯一。

## 信息交换对象

`VirtualEthernetInformation` 承载会话级的额度与有效性信息：

- `BandwidthQoS`
- `IncomingTraffic`
- `OutgoingTraffic`
- `ExpiredTime`

这是一种最小但足够的会话策略单元，用于告诉客户端还能做什么、还能持续多久。

它与原始包转发逻辑分离，使策略交换本身保持轻量。

## IPv6 扩展

`VirtualEthernetInformationExtensions` 在基础信息对象之上补充 IPv6 状态：

- 分配的 IPv6 模式
- 分配的 IPv6 地址与前缀长度
- 网关与路由前缀
- DNS 服务器
- 请求/响应状态与状态消息

这样同一套控制消息族即可同时承载通用会话策略与 IPv6 下发结果。

## 握手后的控制动作

传输握手完成后，链路层可以继续交换多种控制动作：

- 信息同步
- 保活
- TCP connect/push/disconnect
- UDP sendto
- echo / echo reply
- 静态路径建立
- mux 建立
- FRP 风格映射注册与数据转发

关键点在于，OPENPPP2 并没有把这些当成彼此无关的子系统，而是统一建模为同一隧道控制面中的动作。

## 客户端流程

高层流程如下：

1. 构建配置与本地网络上下文
2. 打开虚拟网卡并准备路由策略
3. 创建 `VEthernetExchanger`
4. 向远端服务端建立传输会话
5. 完成握手并取得会话标识
6. 交换 `VirtualEthernetInformation`
7. 应用路由、DNS、mux、代理、映射和可选 IPv6 状态
8. 进入稳态包转发与保活循环

`VEthernetExchanger` 是传输会话与客户端虚拟网络状态之间的运行桥梁。

## 服务端流程

高层流程如下：

1. 为启用的传输类型打开监听器
2. 接收新的传输连接
3. 完成服务端握手
4. 创建或附着对应的 `VirtualEthernetExchanger`
5. 接纳会话并构造信息信封
6. 在启用时通过管理后端校验或补充状态
7. 维护隧道流量、IPv6 租约、NAT 状态、映射和统计信息

`VirtualEthernetSwitcher` 扮演会话交换机与生命周期协调器的角色。

## 管理面的角色

`VirtualEthernetManagedServer` 是可选组件。它通过 WebSocket 或安全 WebSocket 把隧道服务端接入外部控制系统。

其职责包括：

- 异步认证
- 流量上报与统计
- 后端可达性检查
- 管理链路重连

这样数据面仍留在 C++ 进程内，而策略、计费、用户管理则可以位于外部系统。

## 额度、过期与准入

会话模型内置了以下显式约束点：

- 流量额度
- 到期时间
- 带宽 QoS 限制
- 后端介入式认证

这对于 SD-WAN 和受管 VPN 场景很重要，因为即便外部后端短时变慢或不可用，隧道运行时也仍应在本地执行基本策略。

## 映射与反向访问

控制面同时承载映射状态。客户端侧通过 `client.mappings` 定义需要暴露的服务，对应的 FRP 风格动作负责：

- 注册
- 建链
- 数据推送
- 断开
- UDP sendto 中继

因此该覆盖网络不仅能做远程接入，也能做受控的反向暴露通道。

## Static Echo 路径

客户端和服务端 exchanger 中都包含 static echo 机制，其意义是运行层面的，而不是装饰性的：

- 维持静态 UDP 风格路径的活性
- 验证可达性
- 维持数据报型会话状态

它属于控制面，因为它表达的是会话健康状态，而不是普通业务负载。

## 失败与恢复模型

会话设计默认会发生失败，并内置了明确恢复钩子：

- 握手超时
- 重连超时
- 传输释放与清理
- 基于保活的健康检测
- 客户端 exchanger 的状态迁移
- 服务端管理链路的重连行为

这符合网络基础设施对自治性和低运维惊扰的要求。

## 设计哲学

该控制面体现了几条稳定原则：

- 身份、策略、包转发相互关联，但不混杂实现
- 会话状态应体现在类型中，而不是散落在零碎 socket 代码里
- 一个 exchange 对象应尽量负责一条逻辑客户端/服务端关系的生命周期
- 外部管理应是可选能力，而不是让数据面强依赖它

## 相关文档

- [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)
- [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
- [`SECURITY_CN.md`](SECURITY_CN.md)
