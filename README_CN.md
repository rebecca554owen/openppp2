# OPENPPP2

[English](README.md) | 简体中文

OPENPPP2 是一套源码驱动、跨平台的网络运行时，围绕 C++ 主程序 `ppp` 构建，并提供一个可选的 Go 管理后端。它的真实实现边界分布在 `main.cpp`、`ppp/configurations`、`ppp/transmissions`、`ppp/app/protocol`、`ppp/app/client`、`ppp/app/server` 以及各平台宿主集成目录中。

它不能只被理解成 VPN client、VPN server 或 custom transport 中的某一种。代码实际组合的是一个分层系统：

| 层级 | 真实作用 | 主要代码区 |
|------|----------|------------|
| 受保护传输 | 负责分帧、加密、混淆与握手形态塑造 | `ppp/transmissions/*` |
| 隧道协议 | 定义会话标识、link-layer opcode、包语义 | `ppp/app/protocol/*` |
| 客户端运行时 | 对接虚拟网卡、路由、DNS、代理、MUX | `ppp/app/client/*` |
| 服务端运行时 | 接入会话、交换、转发、IPv6、静态路径 | `ppp/app/server/*` |
| 平台集成 | 绑定 Windows/Linux/macOS/Android 的宿主网络 API | `windows/*`、`linux/*`、`darwin/*`、`android/*` |
| 管理后端 | 可选 Go 服务，用于 managed deployment | `go/*` |

文档采用从代码事实出发的写法，目标是解释系统为什么这样设计、每个层次实际负责什么、以及部署和继续开发时应该如何理解这些边界。

## 从这里开始

| 文档 | 用途 |
|------|------|
| [`docs/README_CN.md`](docs/README_CN.md) | 文档总索引与阅读路径 |
| [`docs/README.md`](docs/README.md) | English 文档总索引 |
| [`docs/ARCHITECTURE_CN.md`](docs/ARCHITECTURE_CN.md) | 顶层架构地图 |
| [`docs/SOURCE_READING_GUIDE_CN.md`](docs/SOURCE_READING_GUIDE_CN.md) | 源码阅读顺序 |

## 推荐阅读路径

### 想整体理解系统

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

### 想高效阅读源码

1. [`docs/SOURCE_READING_GUIDE_CN.md`](docs/SOURCE_READING_GUIDE_CN.md)
2. `main.cpp`
3. `ppp/configurations/*`
4. `ppp/transmissions/*`
5. `ppp/app/protocol/*`
6. `ppp/app/client/*`
7. `ppp/app/server/*`
8. 各平台目录
9. 需要 managed deployment 时再看 `go/*`

### 主要关心部署与运行

1. [`docs/CONFIGURATION_CN.md`](docs/CONFIGURATION_CN.md)
2. [`docs/CLI_REFERENCE_CN.md`](docs/CLI_REFERENCE_CN.md)
3. [`docs/PLATFORMS_CN.md`](docs/PLATFORMS_CN.md)
4. [`docs/ROUTING_AND_DNS_CN.md`](docs/ROUTING_AND_DNS_CN.md)
5. [`docs/DEPLOYMENT_CN.md`](docs/DEPLOYMENT_CN.md)
6. [`docs/OPERATIONS_CN.md`](docs/OPERATIONS_CN.md)
7. [`docs/SECURITY_CN.md`](docs/SECURITY_CN.md)

## 文档总表

仓库中共有 20 组英中文档配对，加上根目录 README 双语对照。每一份中文文档都有一份一对一英文文档。

| 领域 | English | 中文 |
|------|---------|------|
| 基础 | `ENGINEERING_CONCEPTS.md` | `ENGINEERING_CONCEPTS_CN.md` |
| 基础 | `ARCHITECTURE.md` | `ARCHITECTURE_CN.md` |
| 基础 | `STARTUP_AND_LIFECYCLE.md` | `STARTUP_AND_LIFECYCLE_CN.md` |
| 传输 | `TRANSMISSION.md` | `TRANSMISSION_CN.md` |
| 传输 | `HANDSHAKE_SEQUENCE.md` | `HANDSHAKE_SEQUENCE_CN.md` |
| 传输 | `PACKET_FORMATS.md` | `PACKET_FORMATS_CN.md` |
| 传输 | `TRANSMISSION_PACK_SESSIONID.md` | `TRANSMISSION_PACK_SESSIONID_CN.md` |
| 协议 | `LINKLAYER_PROTOCOL.md` | `LINKLAYER_PROTOCOL_CN.md` |
| 运行时 | `CLIENT_ARCHITECTURE.md` | `CLIENT_ARCHITECTURE_CN.md` |
| 运行时 | `SERVER_ARCHITECTURE.md` | `SERVER_ARCHITECTURE_CN.md` |
| 运行时 | `ROUTING_AND_DNS.md` | `ROUTING_AND_DNS_CN.md` |
| 平台 | `PLATFORMS.md` | `PLATFORMS_CN.md` |
| 配置 | `CONFIGURATION.md` | `CONFIGURATION_CN.md` |
| 配置 | `CLI_REFERENCE.md` | `CLI_REFERENCE_CN.md` |
| 运维 | `DEPLOYMENT.md` | `DEPLOYMENT_CN.md` |
| 运维 | `OPERATIONS.md` | `OPERATIONS_CN.md` |
| 安全 | `SECURITY.md` | `SECURITY_CN.md` |
| 管理 | `MANAGEMENT_BACKEND.md` | `MANAGEMENT_BACKEND_CN.md` |
| 使用 | `USER_MANUAL.md` | `USER_MANUAL_CN.md` |
| 阅读 | `SOURCE_READING_GUIDE.md` | `SOURCE_READING_GUIDE_CN.md` |

## 代码事实决定的文档边界

| 事实 | 文档必须说明的结果 |
|------|--------------------|
| `main.cpp` 负责启动、角色分流、生命周期和宿主环境准备 | 必须把启动/运行/关闭拆开写 |
| `AppConfiguration` 会在加载后做归一化 | 必须说明默认值、纠偏、无效配置如何被修正 |
| `ITransmission` 负责握手、分帧、mask、delta、cipher layering | 必须按实现讲传输，而不是按抽象名词讲传输 |
| `VirtualEthernetLinklayer` 定义 opcode 驱动的隧道语义 | 必须说明每个动作的实际消息角色 |
| 客户端与服务端共享词汇但职责不同 | 必须避免把两端写成对称 peer |
| 平台代码会改变路由、DNS、适配器与防火墙 | 必须明确平台副作用是系统行为的一部分 |
| Go 后端是可选项 | 必须单独描述 managed deployment |

## 仓库结构

```text
.
├── main.cpp
├── ppp/
│   ├── configurations/
│   ├── transmissions/
│   ├── app/
│   │   ├── protocol/
│   │   ├── client/
│   │   └── server/
│   └── ...
├── windows/
├── linux/
├── darwin/
├── android/
├── go/
└── docs/
    ├── *.md
    └── *_CN.md
```

## 边界说明

| 不是 | 实际情况 |
|------|----------|
| 消费级一键 VPN | 面向开发者的网络运行时 |
| 对称的 client/server | 职责不同的双角色运行时 |
| 纯传输库 | 带宿主系统集成的完整系统 |
| 必须依赖 Go | Go 后端可选 |
| 路由只是附加功能 | 路由和 DNS 是一级运行时行为 |

## 构建说明

| 平台 | 说明 |
|------|------|
| Windows | `build_windows.bat`、Visual Studio 2022、Ninja、vcpkg |
| Linux | CMake、GCC/Clang、系统库 |
| macOS | CMake、Xcode、macOS SDK |
| Android | CMake + NDK，构建为 shared library |

## 快速参考

| 命令 | 作用 |
|------|------|
| `ppp --help` | 查看真实 CLI 帮助 |
| `ppp --mode=client` | 以 client 模式启动 |
| `ppp --mode=server` | 以 server 模式启动 |
| `ppp --config=./config.json` | 加载显式配置文件 |
| `ppp --pull-iplist [file/country]` | 下载 IP list 后退出 |

## 说明

- 仓库中的示例配置值可能包含本地地址、端口或凭据，应视为示例而不是生产默认值。
- Linux 是当前最完整的 server-side IPv6 data plane 目标。
- 文档采用长篇双语写法，是因为系统本身实现重、边界多、术语密集。
- `main.cpp` 是最快建立全局认知的入口。
