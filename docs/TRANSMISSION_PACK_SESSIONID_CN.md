# 会话与控制面模型

[English Version](TRANSMISSION_PACK_SESSIONID.md)

## 目的

旧文件名保留了 `PACK_SESSIONID` 的痕迹，但真正有用的主题是：OPENPPP2 如何在握手后承载会话标识、会话信息和控制动作。

## 核心对象

- `ppp/transmissions/ITransmission.*`
- `ppp/app/protocol/VirtualEthernetInformation.*`
- `ppp/app/protocol/VirtualEthernetLinklayer.*`
- `ppp/app/server/VirtualEthernetSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetManagedServer.*`

## 会话标识

会话标识以 `Int128` 为中心。它用于把逻辑隧道交换绑定到传输会话，并关联服务端 exchanger、流量统计和控制回调。

## 信息交换

`VirtualEthernetInformation` 承载会话层策略数据，包括：

- `BandwidthQoS`
- `IncomingTraffic`
- `OutgoingTraffic`
- `ExpiredTime`

它的目标是把策略交换和原始转发分开。

## IPv6 扩展

IPv6 扩展会补充分配模式、地址、前缀长度、网关、DNS 和结果状态。这样同一类消息就能同时承载通用策略和 IPv6 下发结果。

## 握手后的控制动作

握手完成后，链路层可以继续传递这些动作：

- 信息同步
- 保活
- TCP connect / push / disconnect
- UDP sendto
- echo / echo reply
- 静态路径建立
- mux 建立
- FRP 风格映射注册与转发

## 客户端流程

1. 构建配置和本地网络上下文
2. 打开虚拟网卡和路由策略
3. 创建 `VEthernetExchanger`
4. 建立传输连接
5. 完成握手并获得会话标识
6. 交换 `VirtualEthernetInformation`
7. 应用路由、DNS、mux、代理、映射和可选 IPv6 状态
8. 进入稳态转发和保活

## 服务端流程

1. 为启用的传输打开监听器
2. 接收新连接
3. 完成握手
4. 创建或附着 `VEthernetExchanger`
5. 构造信息信封
6. 必要时咨询管理后端
7. 维护流量、租约、映射和统计

`VirtualEthernetSwitcher` 负责协调服务端生命周期。

## 管理面

`VirtualEthernetManagedServer` 是可选项。它通过 WebSocket 或安全 WebSocket 把隧道服务端接到外部控制系统，用于认证、计费、可达性检查和重连。

## 额度与过期

会话模型显式支持额度、过期时间、带宽限制和后端认证。这样即使后端短时不可用，运行时也仍能本地执行基本策略。

## 映射与反向访问

客户端 `mappings` 驱动 FRP 风格的注册、建链、数据推送、断开和 UDP 中继。因此这个覆盖网既能做远程接入，也能做受控反向暴露。

## 失败模型

设计里预期会失败，因此提供了握手超时、重连超时、清理、保活检查和管理链路重连钩子。

## 相关文档

- `TRANSMISSION_CN.md`
- `ARCHITECTURE_CN.md`
- `CONFIGURATION_CN.md`
- `SECURITY_CN.md`
