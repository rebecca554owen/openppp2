# 平台集成

> **状态：**当前实现边界
> **类型：**指南
> **最后核对：**根/平台 CMake 与平台网络源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[Platform Integration](PLATFORMS.md)

## 共享部分与平台特定部分

共享运行时主要位于 `ppp/`，负责配置、会话/传输行为、隧道策略和 `ITap` 等平台无关抽象。平台目录负责无法天然跨平台的宿主网络工作：虚拟接口、路由、DNS 集成以及特定平台的 socket/隧道行为。

根 CMake 创建 `ppp` 可执行文件，并依据目标系统选择 Windows、Darwin 或 Linux 源文件集。Android 和 iOS 有随附的平台工程及各自的 CMake/应用集成；它们不是可互换的桌面构建。

| 表面 | 当前实现边界 |
|---|---|
| Windows | 源码位于 `windows/`；虚拟适配器和宿主网络集成为 Windows 特定实现。 |
| Linux | 源码位于 `linux/`；客户端 TUN/路由集成和已支持的服务端 IPv6 数据平面在这里。 |
| macOS | 源码位于 `darwin/`；utun 与 BSD 风格宿主集成为平台特定实现。 |
| Android | 随附应用通过 `VpnService` 获取 VPN 接口，并把描述符交给原生代码。 |
| iOS | 随附应用使用 packet-tunnel 集成；不能由此推断 Linux/Android 服务端能力。 |

## 运维含义

- 普通客户端可能通过平台实现创建或使用虚拟接口，并修改路由/DNS。权限要求和实际宿主行为随 OS 而异。
- 桌面 CLI proxy 模式特意不同：它使用 `TapStub`，跳过普通客户端 TUN 路由/DNS 规则/bypass 初始化。参阅 [Proxy-only 模式](PROXY_MODE_CN.md)。
- Linux 服务端 IPv6 数据平面在源码中限定为 Linux 且排除 Android；它不是 Windows、macOS、Android 或 iOS 的可移植服务端功能。
- Android proxy-only 仍使用 VPN 接口，并有 Android 特定的路由/DNS 处理。

## 构建与读源码边界

仓库提供 CMake 源码选择和平台工程，但不提供统一安装器或服务部署流程。请按当前开发文档配置工具链，并实际验证目标平台；不要照抄旧文档中的本机路径或命令。

有用的源码锚点：

- `CMakeLists.txt`：`ppp` 目标和平台源文件选择；
- `ppp/tap/ITap.h`：共享隧道接口抽象；
- `windows/`、`linux/`、`darwin/`：平台实现；
- `android/`、`ios/`：随附应用/平台集成。

## 部署到宿主机前

1. 核对目标构建和所需虚拟接口权限。
2. 明确角色是普通客户端、服务端还是桌面 proxy 模式。
3. 在隔离环境或维护窗口测试路由/DNS 副作用。
4. 宿主机防火墙、DNS 服务和服务管理器策略仍由运维负责；它们不是 `ppp` 的统一配置表面。
5. 服务端 IPv6 请遵循[IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)中的 Linux 限制。

## 相关页面

- [部署模型](../operations/DEPLOYMENT_CN.md)
- [路由与 DNS](ROUTING_AND_DNS_CN.md)
- [IPv6 中继平面](IPV6_TRANSIT_PLANE_CN.md)