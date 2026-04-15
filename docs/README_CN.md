# 文档总索引

[English Version](README.md)

这里是 OPENPPP2 的文档中心。

整套文档采用分层组织，因为 OPENPPP2 本身不是单一功能，而是同时组合了：

- protected transport
- tunnel action protocol
- client-side host integration
- server-side session switching 与 forwarding
- route 与 DNS steering
- 可选 static packet 与 MUX 路径
- 平台特化宿主网络行为
- 可选外部 management backend

因此，最有效的阅读方式不是只看文件名，而是按目标选择阅读路径。

## 阅读路径

### 如果你想整体理解系统

1. [`../README_CN.md`](../README_CN.md)
2. [`ENGINEERING_CONCEPTS_CN.md`](ENGINEERING_CONCEPTS_CN.md)
3. [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
4. [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md)
5. [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)
6. [`HANDSHAKE_SEQUENCE_CN.md`](HANDSHAKE_SEQUENCE_CN.md)
7. [`PACKET_FORMATS_CN.md`](PACKET_FORMATS_CN.md)
8. [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)
9. [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)
10. [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)
11. [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
12. [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
13. [`OPERATIONS_CN.md`](OPERATIONS_CN.md)

### 如果你想高效阅读源码

1. [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md)
2. [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
3. [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)
4. [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md)
5. `main.cpp`
6. `ppp/configurations/*`
7. `ppp/transmissions/*`
8. `ppp/app/protocol/*`
9. `ppp/app/client/*`
10. `ppp/app/server/*`
11. 各平台目录
12. 若 managed deployment 重要，再看 `go/*`

### 如果你主要关心部署与运行

1. [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
2. [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md)
3. [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
4. [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)
5. [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
6. [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
7. [`SECURITY_CN.md`](SECURITY_CN.md)

## 文档地图

### 基础文档

- [`ENGINEERING_CONCEPTS_CN.md`](ENGINEERING_CONCEPTS_CN.md)：工程理念、系统定位，以及整套文档使用的术语
- [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)：顶层架构地图、主要边界、角色与 plane
- [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md)：启动、角色分流、环境准备、tick loop、shutdown

### 传输与协议

- [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)：protected transport、framing、cipher layering 与 runtime transport model
- [`HANDSHAKE_SEQUENCE_CN.md`](HANDSHAKE_SEQUENCE_CN.md)：真实 handshake 顺序与 connection-level key shaping
- [`PACKET_FORMATS_CN.md`](PACKET_FORMATS_CN.md)：packet 结构、static packet format 与 wire-level framing 事实
- [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md)：session identity、control-plane 语义与 information envelope 背景
- [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md)：client/server 之间使用的 tunnel action vocabulary
- [`SECURITY_CN.md`](SECURITY_CN.md)：trust boundary、enforcement point、真实安全结论与边界

### 运行时

- [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)：客户端 switcher、exchanger、路由、DNS、代理、mapping、MUX、static、managed IPv6
- [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)：服务端 acceptor、session switch、forwarding、mapping、static、IPv6、backend cooperation
- [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)：route steering、bypass、DNS redirect、namespace cache、vBGP 风格 route input

### 平台与管理后端

- [`PLATFORMS_CN.md`](PLATFORMS_CN.md)：Windows、Linux、macOS、Android 的宿主集成差异
- [`MANAGEMENT_BACKEND_CN.md`](MANAGEMENT_BACKEND_CN.md)：Go backend 的角色、依赖、API 与交互模型

### 配置、使用与运维

- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)：配置模型、默认值、规范化逻辑与关键字段
- [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md)：按通用、角色、平台分组的命令行参考
- [`USER_MANUAL_CN.md`](USER_MANUAL_CN.md)：面向操作者的使用说明
- [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)：真实部署模型、宿主要求、可选 backend 与 Linux IPv6 server 前提
- [`OPERATIONS_CN.md`](OPERATIONS_CN.md)：可观测性、restart 逻辑、cleanup、故障分类与排障顺序
- [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md)：面向开发者的源码阅读顺序

## 阅读原则

阅读 OPENPPP2 时，务必把这些层分开：

- carrier transport
- protected transmission 与 handshake
- tunnel action protocol
- client 或 server runtime behavior
- platform-specific host integration
- 可选 management backend

这个项目最容易让人困惑的地方，就是把这些层混在一起理解。
