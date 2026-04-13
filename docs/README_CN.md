# 文档总索引

[English Version](README.md)

这里是 OPENPPP2 的文档中心。

OPENPPP2 不是一个很小的单用途隧道工具。这个工程同时组合了：

- 隧道传输
- 虚拟以太网转发
- 路由与 DNS 控制
- 反向访问与代理能力
- 可选多路复用与静态 UDP 通道
- 平台特化网卡集成
- 可选管理后端对接

因此文档必须按层组织，而不能只用一篇总说明草草带过。

## 推荐阅读顺序

### 如果你想从基础设施产品角度理解整个系统

1. [`../README_CN.md`](../README_CN.md)
2. [`ENGINEERING_PHILOSOPHY_CN.md`](ENGINEERING_PHILOSOPHY_CN.md)
3. [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
4. [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md)
5. [`TUNNEL_DESIGN_CN.md`](TUNNEL_DESIGN_CN.md)
6. [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)
7. [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)
8. [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
9. [`MANAGEMENT_BACKEND_CN.md`](MANAGEMENT_BACKEND_CN.md)

### 如果你想高效阅读源码

1. [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md)
2. [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
3. [`TUNNEL_DESIGN_CN.md`](TUNNEL_DESIGN_CN.md)
4. [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md)
5. `main.cpp`
6. `ppp/configurations/*`
7. `ppp/transmissions/*`
8. `ppp/app/protocol/*`
9. `ppp/app/client/*`
10. `ppp/app/server/*`
11. 各平台目录
12. `go/*`

### 如果你主要关心部署与运维

1. [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
2. [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
3. [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)
4. [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
5. [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
6. [`SECURITY_CN.md`](SECURITY_CN.md)

## 文档地图

### 系统级文档

- [`ENGINEERING_PHILOSOPHY_CN.md`](ENGINEERING_PHILOSOPHY_CN.md)：为什么项目被设计成基础设施，而不是消费级 VPN 工具
- [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)：总结构、主要模块、数据面与控制面的边界
- [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md)：进程启动、配置装载、运行时所有权和周期性维护逻辑
- [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md)：仓库源码的推荐阅读路径

### 隧道与协议文档

- [`TUNNEL_DESIGN_CN.md`](TUNNEL_DESIGN_CN.md)：隧道为什么分层、握手如何工作、为什么这样实现
- [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)：传输与隧道模型的简明综述
- [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md)：会话标识、信息对象、控制面行为
- [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md)：NAT、TCP、UDP、ICMP、FRP、静态模式、MUX 的协议级说明

### 运行时文档

- [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)：客户端虚拟网卡、路由、DNS、代理、映射、MUX、静态模式
- [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)：服务端监听器、会话交换机、NAT、IPv6、映射、后端协作
- [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)：路由分流、bypass、vBGP 风格路由列表、DNS 重定向与缓存

### 平台与后端文档

- [`PLATFORMS_CN.md`](PLATFORMS_CN.md)：Windows、Linux、macOS、Android 与构建系统集成
- [`MANAGEMENT_BACKEND_CN.md`](MANAGEMENT_BACKEND_CN.md)：Go 后端角色、WebSocket 协议与 HTTP 管理接口

### 运维文档

- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)：配置模型与关键字段
- [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)：部署模式与各种 VPN/SD-WAN 用法
- [`OPERATIONS_CN.md`](OPERATIONS_CN.md)：运行验证与故障排查
- [`SECURITY_CN.md`](SECURITY_CN.md)：信任边界、本地执行点与加固建议

## 阅读原则

阅读 OPENPPP2 时，务必把以下四层分开：

- 承载传输层
- 受保护的传输与握手层
- 隧道控制/数据协议层
- 平台网络集成层

这个项目最容易让人困惑的地方，就是把这四层混在一起理解。
