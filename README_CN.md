# OPENPPP2

[English](README.md) | 简体中文

OPENPPP2 是一套源码驱动、跨平台的网络运行时，围绕一个名为 `ppp` 的 C++ 主二进制构建，并带有一个可选的 Go 管理后端。

它不能只被理解成 VPN client、VPN server 或 custom transport 中的某一种。整个代码库同时组合了：

- 多种承载上的 protected transport
- 一个 role-aware 的 tunnel action protocol
- 客户端侧虚拟网卡、路由与 DNS 集成
- 服务端侧会话交换、转发、映射与 IPv6 逻辑
- 可选的 static packet 与 MUX 路径
- Windows、Linux、macOS、Android 的平台特化宿主网络行为
- 用于 managed deployment 的可选 Go backend

仓库中的文档已经按“从代码事实出发”的方式重写，不再是概述式宣传说明，而是面向理解系统、部署系统、继续开发系统而组织的长篇文档体系。

## 从这里开始

- 文档总索引：[`docs/README_CN.md`](docs/README_CN.md)
- English documentation index：[`docs/README.md`](docs/README.md)
- 顶层架构：[`docs/ARCHITECTURE_CN.md`](docs/ARCHITECTURE_CN.md)
- 源码阅读指南：[`docs/SOURCE_READING_GUIDE_CN.md`](docs/SOURCE_READING_GUIDE_CN.md)

## 推荐阅读路径

### 如果你想整体理解这套系统

1. [`docs/ENGINEERING_CONCEPTS_CN.md`](docs/ENGINEERING_CONCEPTS_CN.md)
2. [`docs/ARCHITECTURE_CN.md`](docs/ARCHITECTURE_CN.md)
3. [`docs/STARTUP_AND_LIFECYCLE_CN.md`](docs/STARTUP_AND_LIFECYCLE_CN.md)
4. [`docs/TRANSMISSION_CN.md`](docs/TRANSMISSION_CN.md)
5. [`docs/HANDSHAKE_SEQUENCE_CN.md`](docs/HANDSHAKE_SEQUENCE_CN.md)
6. [`docs/PACKET_FORMATS_CN.md`](docs/PACKET_FORMATS_CN.md)
7. [`docs/CLIENT_ARCHITECTURE_CN.md`](docs/CLIENT_ARCHITECTURE_CN.md)
8. [`docs/SERVER_ARCHITECTURE_CN.md`](docs/SERVER_ARCHITECTURE_CN.md)
9. [`docs/ROUTING_AND_DNS_CN.md`](docs/ROUTING_AND_DNS_CN.md)
10. [`docs/PLATFORMS_CN.md`](docs/PLATFORMS_CN.md)
11. [`docs/DEPLOYMENT_CN.md`](docs/DEPLOYMENT_CN.md)
12. [`docs/OPERATIONS_CN.md`](docs/OPERATIONS_CN.md)

### 如果你想高效阅读源码

1. [`docs/SOURCE_READING_GUIDE_CN.md`](docs/SOURCE_READING_GUIDE_CN.md)
2. `main.cpp`
3. `ppp/configurations/*`
4. `ppp/transmissions/*`
5. `ppp/app/protocol/*`
6. `ppp/app/client/*`
7. `ppp/app/server/*`
8. 各平台目录
9. 若 managed deployment 相关，再看 `go/*`

### 如果你主要关心部署与运行

1. [`docs/CONFIGURATION_CN.md`](docs/CONFIGURATION_CN.md)
2. [`docs/CLI_REFERENCE_CN.md`](docs/CLI_REFERENCE_CN.md)
3. [`docs/PLATFORMS_CN.md`](docs/PLATFORMS_CN.md)
4. [`docs/ROUTING_AND_DNS_CN.md`](docs/ROUTING_AND_DNS_CN.md)
5. [`docs/DEPLOYMENT_CN.md`](docs/DEPLOYMENT_CN.md)
6. [`docs/OPERATIONS_CN.md`](docs/OPERATIONS_CN.md)
7. [`docs/SECURITY_CN.md`](docs/SECURITY_CN.md)

## 核心文档

### 架构与运行时

- [`docs/ARCHITECTURE_CN.md`](docs/ARCHITECTURE_CN.md)：顶层系统地图、主要边界、各 plane 之间的关系
- [`docs/STARTUP_AND_LIFECYCLE_CN.md`](docs/STARTUP_AND_LIFECYCLE_CN.md)：启动、配置加载、角色分流、tick loop、cleanup
- [`docs/CLIENT_ARCHITECTURE_CN.md`](docs/CLIENT_ARCHITECTURE_CN.md)：客户端 switcher、exchanger、路由、DNS、代理、映射、MUX、static、IPv6 apply
- [`docs/SERVER_ARCHITECTURE_CN.md`](docs/SERVER_ARCHITECTURE_CN.md)：服务端 listener、session switch、mapping、static、IPv6、backend integration
- [`docs/PLATFORMS_CN.md`](docs/PLATFORMS_CN.md)：Windows、Linux、macOS、Android 的宿主集成与构建/部署差异

### 传输与协议

- [`docs/TRANSMISSION_CN.md`](docs/TRANSMISSION_CN.md)：protected transport、framing family、cipher layering、runtime transport model
- [`docs/HANDSHAKE_SEQUENCE_CN.md`](docs/HANDSHAKE_SEQUENCE_CN.md)：真实的 client/server handshake 顺序与连接级 key shaping
- [`docs/PACKET_FORMATS_CN.md`](docs/PACKET_FORMATS_CN.md)：wire-level packet form、header、framing、static packet structure
- [`docs/TRANSMISSION_PACK_SESSIONID_CN.md`](docs/TRANSMISSION_PACK_SESSIONID_CN.md)：session identity、control-plane 语义与 envelope 解释
- [`docs/LINKLAYER_PROTOCOL_CN.md`](docs/LINKLAYER_PROTOCOL_CN.md)：tunnel action vocabulary 与 opcode-level runtime behavior
- [`docs/SECURITY_CN.md`](docs/SECURITY_CN.md)：信任边界、本地执行点、真实安全结论与边界

### 配置、部署与运维

- [`docs/CONFIGURATION_CN.md`](docs/CONFIGURATION_CN.md)：配置模型、默认值、规范化逻辑与关键分组
- [`docs/CLI_REFERENCE_CN.md`](docs/CLI_REFERENCE_CN.md)：按角色和平台组织的命令行参考
- [`docs/ROUTING_AND_DNS_CN.md`](docs/ROUTING_AND_DNS_CN.md)：route steering、bypass、DNS redirect、namespace cache、vBGP 风格输入
- [`docs/DEPLOYMENT_CN.md`](docs/DEPLOYMENT_CN.md)：真实部署模型、宿主要求、可选管理后端、Linux IPv6 server 前提
- [`docs/OPERATIONS_CN.md`](docs/OPERATIONS_CN.md)：运行时证据、restart 逻辑、cleanup、故障分类与排障顺序

### 工程与源码阅读

- [`docs/ENGINEERING_CONCEPTS_CN.md`](docs/ENGINEERING_CONCEPTS_CN.md)：工程理念与设计立场
- [`docs/SOURCE_READING_GUIDE_CN.md`](docs/SOURCE_READING_GUIDE_CN.md)：源码阅读顺序与路径
- [`docs/USER_MANUAL_CN.md`](docs/USER_MANUAL_CN.md)：面向操作者的使用手册
- [`docs/MANAGEMENT_BACKEND_CN.md`](docs/MANAGEMENT_BACKEND_CN.md)：Go backend 的角色、依赖与交互模型

## 仓库结构

- `main.cpp`：统一入口与顶层生命周期
- `ppp/`：共享配置、传输、协议、客户端、服务端运行时代码
- `windows/`：Windows adapter、route、DNS、proxy 与 host integration 代码
- `linux/`：Linux adapter、protect、route、IPv6 与系统集成代码
- `darwin/`：macOS `utun` 与 Darwin 平台集成代码
- `android/`：Android shared-library 与 VPN-host integration 代码
- `go/`：可选管理后端与持久化相关服务
- `docs/`：中英双语系统文档

## 构建说明

### Windows

- 主脚本：`build_windows.bat`
- 预期工具链：Visual Studio 2022、Ninja、vcpkg

示例：

```bat
build_windows.bat Release x64
```

### Linux / WSL

- 根构建入口是普通 CMake 流程
- 额外打包和交叉构建辅助脚本位于 `build-openppp2-by-builds.sh` 与 `build-openppp2-by-cross.sh`

示例：

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j32
```

### macOS 与 Android

- 仓库内已包含对应平台代码
- Android 以 shared library 形式构建，并嵌入宿主应用
- 平台特化改动应在对应工具链中验证后再发布

## 必须明确的边界

- 这不是消费级一键式 VPN 应用。
- Go backend 是可选的，且不是主数据面。
- 当前最完整的 server-side IPv6 data plane 是 Linux-centric 实现。
- client 与 server 共享消息词汇，但并不是对称 peer。
- route、DNS、adapter 与平台副作用都是系统真实行为的一部分，不是附带细节。

## 说明

- 仓库中的示例配置值可能包含本地地址、端口或凭据，应视为示例，而不是生产默认值。
- 当前整套文档采用长篇、实现导向、中英双语写法，目标是让读者真正理解系统后再继续开发或部署。
