# OPENPPP2

[English](README.md) | 简体中文

OPENPPP2 是一个基于 C++17 的虚拟以太网 VPN/SD-WAN 系统。它围绕统一的数据包、会话和传输模型构建 Layer 2 / Layer 3 覆盖网络，并针对 Windows、Linux、macOS、Android 提供平台特化实现。

整个工程围绕单一可执行程序 `ppp` 展开，运行时分为两种模式：

- 服务端模式：接受隧道会话、分配虚拟网络状态、执行策略，并在需要时接入管理后端。
- 客户端模式：创建虚拟网卡、执行路由和 DNS 策略、连接远端服务端，并可提供本地代理与端口映射能力。

## 文档导航

文档总入口：

- 总索引：[`docs/README_CN.md`](docs/README_CN.md)
- English Index：[`docs/README.md`](docs/README.md)

核心架构文档：

- 系统架构：[`docs/ARCHITECTURE_CN.md`](docs/ARCHITECTURE_CN.md)
- 启动与生命周期：[`docs/STARTUP_AND_LIFECYCLE_CN.md`](docs/STARTUP_AND_LIFECYCLE_CN.md)
- 客户端架构：[`docs/CLIENT_ARCHITECTURE_CN.md`](docs/CLIENT_ARCHITECTURE_CN.md)
- 服务端架构：[`docs/SERVER_ARCHITECTURE_CN.md`](docs/SERVER_ARCHITECTURE_CN.md)
- 平台架构：[`docs/PLATFORMS_CN.md`](docs/PLATFORMS_CN.md)
- 管理后端：[`docs/MANAGEMENT_BACKEND_CN.md`](docs/MANAGEMENT_BACKEND_CN.md)

隧道与协议文档：

- 隧道设计详解：[`docs/TUNNEL_DESIGN_CN.md`](docs/TUNNEL_DESIGN_CN.md)
- 传输与隧道模型：[`docs/TRANSMISSION_CN.md`](docs/TRANSMISSION_CN.md)
- 会话与控制面：[`docs/TRANSMISSION_PACK_SESSIONID_CN.md`](docs/TRANSMISSION_PACK_SESSIONID_CN.md)
- 链路层协议：[`docs/LINKLAYER_PROTOCOL_CN.md`](docs/LINKLAYER_PROTOCOL_CN.md)
- 路由与 DNS：[`docs/ROUTING_AND_DNS_CN.md`](docs/ROUTING_AND_DNS_CN.md)

工程与运维文档：

- 工程理念：[`docs/ENGINEERING_CONCEPTS_CN.md`](docs/ENGINEERING_CONCEPTS_CN.md)
- 用户手册：[`docs/USER_MANUAL_CN.md`](docs/USER_MANUAL_CN.md)
- 命令行参考：[`docs/CLI_REFERENCE_CN.md`](docs/CLI_REFERENCE_CN.md)
- 源码阅读指南：[`docs/SOURCE_READING_GUIDE_CN.md`](docs/SOURCE_READING_GUIDE_CN.md)
- 配置参考：[`docs/CONFIGURATION_CN.md`](docs/CONFIGURATION_CN.md)
- 部署模式：[`docs/DEPLOYMENT_CN.md`](docs/DEPLOYMENT_CN.md)
- 运维与排障：[`docs/OPERATIONS_CN.md`](docs/OPERATIONS_CN.md)
- 安全模型：[`docs/SECURITY_CN.md`](docs/SECURITY_CN.md)

英文版文档位于同目录下对应的无 `_CN` 文件。

## 推荐阅读路径

面向架构师和维护者：

1. [`docs/README_CN.md`](docs/README_CN.md)
2. [`docs/ENGINEERING_CONCEPTS_CN.md`](docs/ENGINEERING_CONCEPTS_CN.md)
3. [`docs/ARCHITECTURE_CN.md`](docs/ARCHITECTURE_CN.md)
4. [`docs/STARTUP_AND_LIFECYCLE_CN.md`](docs/STARTUP_AND_LIFECYCLE_CN.md)
5. [`docs/TUNNEL_DESIGN_CN.md`](docs/TUNNEL_DESIGN_CN.md)
6. [`docs/CLIENT_ARCHITECTURE_CN.md`](docs/CLIENT_ARCHITECTURE_CN.md)
7. [`docs/SERVER_ARCHITECTURE_CN.md`](docs/SERVER_ARCHITECTURE_CN.md)
8. [`docs/PLATFORMS_CN.md`](docs/PLATFORMS_CN.md)
9. [`docs/MANAGEMENT_BACKEND_CN.md`](docs/MANAGEMENT_BACKEND_CN.md)

面向源码读者：

1. [`docs/SOURCE_READING_GUIDE_CN.md`](docs/SOURCE_READING_GUIDE_CN.md)
2. `main.cpp`
3. `ppp/configurations/*`
4. `ppp/transmissions/*`
5. `ppp/app/protocol/*`
6. `ppp/app/client/*`
7. `ppp/app/server/*`
8. 各平台目录
9. `go/*`

## 工程实际能力

- Layer 2 / Layer 3 虚拟以太网覆盖网络
- 单一二进制同时支持客户端与服务端角色
- TCP、UDP、WebSocket、WebSocket over TLS 多种承载传输
- 协议层与传输层双层密钥保护
- 基于 TUN/TAP 的虚拟网卡接入
- 通过 bypass 列表、路由文件、DNS 规则实现分流
- 通过映射与 FRP 风格控制动作实现反向访问
- 可选的 MUX、多路静态 UDP 和带宽聚合挂载点
- 服务端管理的 IPv6 分配扩展
- 可选的 Go 管理后端，用于节点、用户、流量管理

## 仓库结构

- `ppp/`：核心协议、会话、隧道、加密、路由、客户端、服务端逻辑
- `common/`：公共库与内嵌第三方组件
- `windows/`：Windows TAP/Wintun、Win32 路由、防火墙、代理集成
- `linux/`：Linux TAP、路由保护、诊断、系统网络辅助逻辑
- `darwin/`：macOS `utun` 与平台适配
- `android/`：Android 平台特化代码
- `go/`：管理后端与持久化相关服务
- `docs/`：中英双语工程文档

## 架构摘要

核心运行时围绕以下关键类型展开：

- `main.cpp`：统一入口、模式选择、命令行解析、运行时启动
- `ppp/configurations/AppConfiguration.*`：JSON 配置模型与规范化处理
- `ppp/transmissions/ITransmission.*`：握手、帧化 I/O、协议层密钥、传输层密钥
- `ppp/app/protocol/VirtualEthernetLinklayer.*`：NAT、TCP、UDP、信息交换、回显、MUX、映射等隧道动作集合
- `ppp/app/server/VirtualEthernetSwitcher.*`：服务端会话交换机、监听器、防火墙、IPv6 租约管理
- `ppp/app/client/VEthernetNetworkSwitcher.*`：客户端虚拟网卡、路由、DNS、代理、转发逻辑
- `ppp/app/client/VEthernetExchanger.*`：客户端建链、重连、映射、静态回显、MUX 控制
- `ppp/app/server/VirtualEthernetManagedServer.*`：可选管理面 WebSocket 客户端

## 这个项目是什么

- 一个网络基础设施运行时
- 一个虚拟以太网覆盖网络引擎
- 一个可编排的 VPN / SD-WAN 基础能力底座
- 一个强调显式拓扑、显式策略和确定性运行控制的系统工程

## 这个项目不是什么

- 不是面向消费级一键易用性的 VPN 客户端
- 不是只有简单隧道而没有路由、DNS、会话策略体系的二进制
- 不是对单一操作系统 VPN API 的薄包装
- 不是管理后端优先、数据面反而次要的系统

## 支持的构建环境

### Windows

- 工具链：Visual Studio 2022、CMake、Ninja、vcpkg
- 构建脚本：`build_windows.bat`
- 工程文件：`ppp.sln`、`ppp.vcxproj`

示例：

```bat
build_windows.bat Release x64
```

### Linux / WSL

- 工具链：GCC 7.5+ 或兼容 Clang、CMake、Make
- `CMakeLists.txt` 默认第三方依赖路径：`/root/dev`

示例：

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j32
```

仓库内还提供：

- `build-openppp2-by-builds.sh`
- `build-openppp2-by-cross.sh`

### macOS 与 Android

- 仓库中已存在对应平台代码。
- 按常规 CMake / NDK 流程接入，并在对应平台工具链中完成发布前验证。

## 运行模式

### 服务端

典型职责：

- 监听 TCP、UDP、WS、WSS
- 认证或接纳会话
- 分配隧道侧地址与可选 IPv6 状态
- 应用防火墙、子网转发和映射策略
- 在启用时向管理后端上报状态

### 客户端

典型职责：

- 创建并配置虚拟网卡
- 连接远端隧道入口
- 维护路由、bypass 集、DNS 分流和宿主网络优先策略
- 按需暴露本地 HTTP / SOCKS 代理服务
- 注册反向映射与可选静态 / MUX 数据通路

## 常见部署玩法

- 全隧道远程接入
- 企业分流接入
- 站点到站点子网互联
- 客户端边缘代理网关
- 内网服务反向暴露
- 通过反向代理或 CDN 前置的 WebSocket / WSS 隧道
- 基于服务端前缀分配的 IPv6 覆盖网络

更完整的部署分析见 [`docs/DEPLOYMENT_CN.md`](docs/DEPLOYMENT_CN.md)。

## 配置入口

默认配置文件：

```text
./appsettings.json
```

主要配置分组：

- `key`：加密与帧行为
- `tcp`、`udp`、`mux`、`websocket`：传输行为
- `server`：节点行为、管理后端、IPv6 服务
- `client`：远端地址、重连、本地代理、映射、路由文件
- `vmem`：虚拟内存工作区
- `ip`：公网地址与接口地址提示

详见 [`docs/CONFIGURATION_CN.md`](docs/CONFIGURATION_CN.md)。

## 关键命令行入口

程序支持大量命令行参数，最重要的一组包括：

- `--mode=[client|server]`
- `--config=<path>`
- `--dns=<ip-list>`
- `--nic=<interface>`
- `--ngw=<ip>`
- `--tun=<name>`
- `--tun-ip=<ip>`
- `--tun-ipv6=<ip>`
- `--tun-gw=<ip>`
- `--tun-mask=<bits>`
- `--tun-vnet=[yes|no]`
- `--tun-host=[yes|no]`
- `--tun-static=[yes|no]`
- `--tun-mux=<connections>`
- `--tun-mux-acceleration=<mode>`
- `--bypass=<file>`
- `--bypass-ngw=<ip>`
- `--dns-rules=<file>`
- `--firewall-rules=<file>`

完整帮助：

```bash
ppp --help
```

## 工程原则

- 单一二进制，双角色复用同一协议核心
- 尽量依赖明确的本地策略，而不是重型外部编排
- 包处理路径应尽量确定、可恢复、可诊断
- 传输层、链路控制层、平台网络集成层职责分离
- 路由、DNS、访问控制尽量显式配置，避免隐藏副作用

完整设计立场见 [`docs/ENGINEERING_CONCEPTS_CN.md`](docs/ENGINEERING_CONCEPTS_CN.md)。

## 说明

- 仓库中的示例配置文件包含环境相关地址与凭据，应视为本地样例，不应直接作为生产默认值。
- 本次文档重写以代码结构和运行逻辑为依据，已去除与工程事实无关、夸张或误导性的内容。
