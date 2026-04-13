# 源码阅读指南

[English Version](SOURCE_READING_GUIDE.md)

## 目标

这份指南面向想真正读懂 OPENPPP2 源码的工程师，目的是避免过早陷入平台细节而迷失整体结构。

## 第一步：从进程入口开始

先读：

- `main.cpp`

重点看：

- 模式如何选择
- 配置如何加载
- 运行时网络参数如何解析
- 客户端和服务端对象在何处创建
- 进程周期性维护逻辑有哪些

## 第二步：理解配置模型

再读：

- `ppp/configurations/AppConfiguration.h`
- `ppp/configurations/AppConfiguration.cpp`

重点看：

- 默认值
- 顶层配置组
- 哪些行为是配置驱动而不是写死的
- IPv6 相关规范化逻辑

## 第三步：理解受保护的传输层

再读：

- `ppp/transmissions/ITransmission.h`
- `ppp/transmissions/ITransmission.cpp`
- `ppp/transmissions/ITcpipTransmission.*`
- `ppp/transmissions/IWebsocketTransmission.*`

重点看：

- 握手
- 基于 `ivv` 的重建密钥
- 帧化与读写流水线
- 承载传输与受保护传输之间的区别

## 第四步：理解隧道动作协议

再读：

- `ppp/app/protocol/VirtualEthernetLinklayer.h`
- `ppp/app/protocol/VirtualEthernetLinklayer.cpp`
- `ppp/app/protocol/VirtualEthernetInformation.*`

重点看：

- 动作枚举
- 控制面与数据面动作
- 信息交换
- TCP、UDP、ICMP、FRP、static、mux 如何统一建模在同一协议族中

## 第五步：理解辅助分组格式

再读：

- `ppp/app/protocol/VirtualEthernetPacket.h`
- `ppp/app/protocol/VirtualEthernetPacket.cpp`

重点看：

- static UDP 分组格式
- 基于会话的分组加密
- 校验和混淆流水线
- 为什么这个格式与 `VirtualEthernetLinklayer` 分开存在

## 第六步：阅读客户端运行时

再读：

- `ppp/app/client/VEthernetNetworkSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`
- `ppp/app/client/VEthernetNetworkTcpipStack.*`
- `ppp/app/client/VEthernetNetworkTcpipConnection.*`

重点看：

- TUN 输入处理
- 路由和 DNS 管理
- 本地代理暴露
- 建链与重连
- static、mux、mapping、IPv6 应用

## 第七步：阅读服务端运行时

再读：

- `ppp/app/server/VirtualEthernetSwitcher.*`
- `ppp/app/server/VirtualEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetNetworkTcpipConnection.*`

重点看：

- 监听器建立
- 会话接入与建立
- NAT 转发
- UDP 转发
- mappings 与 static 模式
- IPv6 分配与 transit 处理

## 第八步：阅读平台特化层

只有在核心协议清楚之后再读平台层。

Windows：

- `windows/ppp/tap/*`
- `windows/ppp/win32/network/*`

Linux：

- `linux/ppp/tap/*`
- `linux/ppp/net/*`

macOS：

- `darwin/ppp/tun/*`
- `darwin/ppp/tap/*`

Android：

- `android/*`

重点看：

- 各操作系统如何提供虚拟网卡能力
- 路由和 DNS 如何被修改
- 各平台为避免路由环路和 socket 失效做了哪些保护

## 第九步：最后再读 Go 后端

再读：

- `go/main.go`
- `go/ppp/*`
- `go/io/*`

重点看：

- 后端如何认证节点
- 用户和流量额度如何存储
- C++ 服务端如何通过 WebSocket 与它交互

## 常见阅读误区

- 在理解共享协议核心之前就陷入平台代码
- 把 `ITransmission` 的帧化与 `VirtualEthernetPacket` 混为一谈
- 把客户端 exchanger 与服务端 exchanger 当成完全无关的实现
- 误以为 Go 后端是数据面
- 误以为路由 / DNS 行为只是边角能力而不是系统核心组成部分

## 最好的配套文档

- [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
- [`TUNNEL_DESIGN_CN.md`](TUNNEL_DESIGN_CN.md)
- [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)
- [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)
- [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
