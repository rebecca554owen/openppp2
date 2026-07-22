# 项目接口全景图
> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [参考索引](README_CN.md)
> Peer link: [English](PROJECT_INTERFACE_MAP.md)

> **用途：**盘点本仓库可发现的调用面和序列化边界，区分当前面向用户的行为、实验接口、内部实现和已知缺口。
> **适用对象：**用户、运维人员、客户端作者、集成人员和维护者。
> **范围：**只记录当前源码和仓库内测试证据。本发现索引不是公共 SDK、ABI、发布、支持或兼容性承诺。

## 如何阅读本页

本页是源码清单，不是外部接口规范。字段级语义仍由链接的专项文档说明；文档与实现不一致时，以列出的源码路径为事实依据。

| 标记 | 含义 |
|---|---|
| **当前** | 当前树中存在，且由面向用户的路径或内置 companion 使用；这不构成兼容性、发布或支持承诺。 |
| **实验** | 当前存在，但证据有限或行为边界尚未确定。 |
| **内部** | 仓库组件或内置 companion 之间的边界；为维护者记录，不作为第三方 SDK。 |
| **废弃** | 为兼容保留，且源码或专项参考中给出了替代项的路径。 |
| **缺口** | 缺少契约、存在危险歧义、实现缺陷或缺少测试的边界。 |

C++ 类中的 `public` 只表示仓库代码可以访问，并不等于外部 API。根 CMake 没有 `install()` 规则或导出的 C++ target；仓库没有声明安装式头文件集、ABI 版本或原生 SDK。

## 接口总览

| 领域 | 提供方 | 主要调用方 | 输入 / 输出 | 边界 / 证据 | 详细文档 |
|---|---|---|---|---|---|
| `ppp` 进程和 CLI | C++ 可执行文件 | 用户、服务管理器、脚本 | 参数和文件 / 退出状态、日志、TUI | **当前**可执行行为；无正式退出码表 | [CLI 参考](CLI_REFERENCE_CN.md) |
| `appsettings.json` | C++ 配置加载器 | 用户和内置配置档生产方 | JSON / 归一化运行策略 | **当前**、与实现耦合的序列化输入 | [配置模型](CONFIGURATION_CN.md) |
| 连接 URI | C++ 客户端 | 用户、配置档和订阅生成器 | `ppp://`、`ppp://ws/`、`ppp://wss/` | **当前**对端输入；与实现耦合 | [配置模型](CONFIGURATION_CN.md) |
| 隧道线上协议 | C++ 客户端/服务端 | OPENPPP2 对端 | 帧、握手、操作码、INFO JSON | **内部**对端行为；没有版本协商 | [包格式](PACKET_FORMATS_CN.md)、[链路层](LINKLAYER_PROTOCOL_CN.md) |
| Runtime Snapshot v1 | C++ 运行时 | 进程内 TUI、内置 Android/iOS 读取端、部分桌面 stats 读取端 | C++ 对象、JSON 与嵌入式统计字段 | 带跨语言 fixture 的**内部**序列化契约；不是原生 SDK | [UI Runtime 契约](UI_RUNTIME_CONTRACT_CN.md) |
| Go 管理器后台 API | `go/ppp` | 内嵌 `/admin/`、运维人员 | HTTP JSON 和订阅 JSON | **当前**仓库内服务面；旧路由仍为内部接口 | [管理后端](../guides/MANAGEMENT_BACKEND_CN.md) |
| C++–Go 控制链路 | C++ 服务端和 `go/ppp` | 仓库内部服务组件 | WebSocket 上的长度前缀 JSON | **内部** | [管理后端](../guides/MANAGEMENT_BACKEND_CN.md) |
| Guardian API | `go/guardian` | Guardian WebUI 和运维人员 | HTTP JSON、SSE | **实验** | `go/guardian/api/router.go` |
| 桌面 Client（Tauri） | `desktop/client` | Windows/macOS 终端用户 | Tauri 命令/事件、本地文件、子进程 `ppp` | **实验** companion；不是 SDK | [Client 设计](../design/SUB_CLIENT_DESIGN_CN.md)、`desktop/client/src-tauri/src/desktop.rs` |
| Android Flutter 桥 | Flutter/Kotlin/JNI | 内置 Android App | MethodChannel、Intent、JNI、私有 snapshot 文件 | **内部**内置 companion | `android/lib/vpn_service.dart`、`android/libopenppp2.cpp` |
| iOS Packet Tunnel 桥 | Swift/C ABI | 内置 iOS App 和扩展 | Provider 消息、C 回调、App Group 文件 | **内部**内置 companion | `ios/OpenPPP2PacketTunnelBridge.h` |
| TUI 命令 | `ConsoleUI` | 交互式运维人员 | 行命令 / 终端渲染状态 | **实验**，仅本地进程 | `ppp/app/ConsoleUI.cpp` |
| 平台适配器 | Windows、Linux、Darwin、移动端代码 | C++ 运行时 | TAP/TUN、路由、DNS、socket protect | **内部** | 平台目录和[平台指南](../guides/PLATFORMS_CN.md) |

## 1. 进程入口与模式

| 入口 | 契约 | 生命周期 / 权限 | 边界 / 证据 | 源码依据 | 已知缺口 |
|---|---|---|---|---|---|
| `ppp` 可执行文件 | `--mode=server`（默认）、`client` 或 `proxy`；加载配置并启动 `PppApplication` | 完整隧道通常需要 root/Administrator；桌面 proxy 模式不操作 TUN/路由 | **当前**可执行行为 | `main.cpp`、`ppp/app/ApplicationConfig.cpp`、`ppp/app/PppApplication.*` | 没有正式退出码表 |
| Go 管理器 | 可选配置文件参数（默认 `appsettings.json`）；仅在 `database.master` 和 Redis 配置完整时进入托管模式，否则运行本地独立订阅管理器 | 长期运行 HTTP/WebSocket 服务；独立模式状态在本地持久化 | **当前**仓库内服务 | `go/main.go`、`go/ppp/Configuration.go`、`go/ppp/ManagedServer.go` | 停机和数据迁移契约未集中定义 |
| Guardian | 管理二进制、配置档、实例、日志和系统服务 | 可能需要主机管理权限 | **实验** | `go/guardian/main.go`、`api/router.go` | 主机路径访问和多数 handler 缺少直接 API 测试 |
| 桌面 Client 应用 | Tauri 壳运行本地 UI，管理订阅/手动节点，并拉起 `ppp --mode=client` | 完整隧道需要子进程 `ppp` 的 Administrator/root；UI 本身在用户会话运行 | **实验**内置 companion | `desktop/client/`、`desktop/client/src-tauri/src/desktop.rs` | 不是第三方 SDK；IPC 面可能无通知变更 |
| Android `VpnService` | 内置 Flutter UI 在 `:vpn` 进程启动/停止 native 隧道 | 需要用户批准 VPN 和前台服务；Service 不导出 | **内部**内置 companion | `PppVpnService.kt` | release 布局的跨进程设备覆盖仍是缺口，见缺口总表 |
| iOS Packet Tunnel 扩展 | App 保存 `NETunnelProviderManager` 配置并启动扩展 | 需要 Network Extension entitlement 和用户授权 | **内部**内置 companion | `ios/App/OpenPPP2/VPNController.swift`、`PacketTunnelProvider.swift` | Actions 未真实构建扩展和原生库集成 |

### 原生与 companion 构建证据

CMake 和 CI 只描述构建路径，不代表发布支持：

| 表面 | 当前证据 | 边界 / 缺口 |
|---|---|---|
| 原生 `ppp` | 根 `CMakeLists.txt` 构建静态 `openppp2_lib` 和 `ppp` 可执行文件；Linux、Windows、macOS workflow 构建原生工件。 | 没有 install/export target 或 C++ ABI 契约。 |
| Android companion | `android/CMakeLists.txt` 构建共享 `libopenppp2.so`；`build-android.yml` 构建 ABI 并运行 debug 模拟器测试。 | debug 会移除 Service 的独立进程，因此没有测试 release 跨进程布局。 |
| iOS companion | `ios/CMakeLists.txt` 定义静态 `libopenppp2_ios.a`；`test.yml` 对 Packet Tunnel 代码做 typecheck 并运行 Swift logic test。 | Actions 不会调用原生 iOS CMake 构建，也没有真实 Packet Tunnel/原生库集成测试。 |
| 桌面 Client 和 Go 工具 | 源码与本地 test/build 入口存在；Guardian 有专用 build workflow，manager 检查在 unit workflow 中运行。 | 源码存在和 CI 构建证据不构成 SDK、打包、签名或支持承诺。 |

## 2. 命令行接口

下表列出当前解析的命令面。别名、默认值、解析规则、示例和平台限制见 [CLI 参考](CLI_REFERENCE_CN.md)。

| 分组 | 接受的开关 | 当前边界 / 说明 |
|---|---|---|
| 角色与配置 | `--mode`、`--config`、`--proxy-http-port`、`--proxy-socks-port` | **当前**解析器行为 |
| 运行策略 | `--rt`、`--dns`、`--tun-flash`、`--auto-restart`、`--link-restart`、`--block-quic`、`--firewall-rules`、`--lwip`、`--vbgp` | **当前**解析器行为 |
| 网卡与地址 | `--nic`、`--ngw`、`--tun`、`--tun-ip`、`--tun-ipv6`、`--tun-gw`、`--tun-mask` | **当前**解析器行为 |
| 隧道行为 | `--tun-vnet`、`--tun-host`、`--tun-static`、`--tun-promisc`、`--tun-ssmt`、`--tun-route`、`--tun-protect`、`--tun-lease-time-in-seconds` | 平台条件化的解析器行为 |
| MUX | `--tun-mux`、`--tun-mux-acceleration`、`--mux-mode`、`--mux-mode-turbo` | `compat`、`flow`、`balance` 和 `stripe` 是当前 mode token；`stripe` 在 companion 展示中仍为**实验**。 |
| 实时 MUX 调试 | `--debug-key`、`--mux-mode-set` | **实验**；没有单独版本化的控制/鉴权接口 |
| 路由和 DNS 输入 | `--bypass`、`--bypass-nic`、`--bypass-ngw`、`--virr`、`--dns-rules` | 当前解析器行为；文件格式没有完整 schema |
| 工具 | `--help`、`--pull-iplist` | 当前解析器行为 |
| Windows 辅助操作 | 驱动、路由、DNS、代理和网络重置命令，包括解析器接受的 `--set-http-proxy` | 仅 Windows 的解析器行为；许多操作会在 helper 后退出 |

**缺口：**生成的帮助横幅不是完整的解析器契约。它遗漏解析器接受的 `--mux-mode-turbo` 和 Windows `--set-http-proxy`；详细[命令行参考](CLI_REFERENCE_CN.md)已记录这种漂移，但在拥有机器可读的选项注册表前，自动化仍必须核对解析源码。

## 3. JSON 配置

`appsettings.json` 被加载为 `AppConfiguration`；`Load(Json::Value&)` 会先重置字段，并在返回前调用 `Loaded()`。随后应用程序准备阶段再应用 CLI 覆盖。未知字段处理、迁移行为和 schema 版本尚未正式定义。

| 顶层块 | 职责 | 调用方 | 稳定性 | 源码依据 |
|---|---|---|---|---|
| `concurrent`、`vmem` | 执行并发和内存策略 | 核心运行时 | **当前** | `ppp/configurations/AppConfiguration.*` |
| `key` | 密码名称、密钥材料、掩码、shuffle、delta 和 plaintext 模式 | 两端 | **当前**，安全敏感 | 同上 |
| `tcp`、`udp`、`websocket`、`cdn` | 载体监听、连接策略、TLS/WS 和端口模式 | 传输层 | **当前** | 同上 |
| `mux` | 多路复用模式与限制 | 传输/运行时 | `compat`/`flow`/`balance` 事实**当前**；`stripe` 和实时控制为**实验** | 同上 |
| `server` | 地址池、映射、后端、策略、IPv6、计费身份 | 服务端运行时 | **当前** | 同上 |
| `client` | 服务端 URI、重连、带宽、代理、路由行为 | 客户端运行时 | **当前** | 同上 |
| `ip`、`virr`、`vbgp` | 地址、路由/规则和路由传播输入 | 网络切换器 | 事实上的**当前** | 同上 |
| `dns` | resolver、拦截、fallback、cache 和 policy | 客户端/服务端 DNS 运行时 | 事实上的**当前** | 同上 |
| `telemetry` | 启用状态、级别、count/span 开关、endpoint、日志文件和控制台过滤器 | 诊断/平台桥 | **实验** | 同上 |
| `p2p` | 直连发现、信令、传输和 fallback | 客户端/服务端 P2P 运行时 | **实验** | 同上 |
| `geo-rules` | 地理路由/规则来源与行为 | 路由/DNS policy | **实验** | 同上 |

字段和安全示例见 [配置模型](CONFIGURATION_CN.md)。平台配置档存储会包装这份 JSON，但不会取代其契约。

**缺口：**完整配置没有公开 JSON Schema、`schema_version`、迁移/未知字段策略，也没有覆盖桌面、Android 和 iOS 配置生产方的自动兼容 fixture。

## 4. 连接和文件 URI

| 形式 | 含义 | 鉴权 / 安全 | 稳定性 |
|---|---|---|---|
| `ppp://host:port/` | 原生 TCP 隧道 | 隧道密钥配置；载体无 TLS | **当前** |
| `ppp://ws/host:port/` | WebSocket 隧道 | 隧道密钥配置；载体无 TLS | **当前** |
| `ppp://wss/host:port/` | TLS WebSocket 隧道 | TLS 加隧道密钥配置 | **当前** |
| `ws://.../ppp/webhook`、`wss://...` | C++ 服务端到 Go 管理器控制链路 | 共享 backend key | **内部** |
| `https://.../sub/{token}` | Android/iOS 订阅文档；其 HTTP 仅允许 loopback 开发环境 | 路径中的 capability token | **当前** |
| `http(s)://...` 订阅 URL | 桌面 Client 的订阅文档 | 路径中的 capability token | 桌面 Client 的**实验**行为 |
| 本地配置档导入/导出文件 | iOS 配置档 bundle JSON | 用户选择文件；包含敏感信息 | 内置 iOS App 的**当前**接口 |

## 5. 传输、握手、链路层和包协议

| 边界 | 输入 / 输出 | 兼容状态 | 源码依据 | 验证 |
|---|---|---|---|---|
| 保护帧 | 首帧/后续帧头、加密载荷、掩码和 delta 状态 | 事实上的**当前**；两端必须匹配 | `ppp/transmissions/ITransmission.*` | [包格式](PACKET_FORMATS_CN.md)和 native 构建；无直接帧兼容测试 |
| 握手 | NOP 交换、session ID、`ivv`、`nmux`、重建密码器 | 事实上的**当前** | 同上 | [会话与控制面模型](TRANSMISSION_PACK_SESSIONID_CN.md) |
| 载体 | TCP、WS、WSS 字节流 | **当前** | `ITcpipTransmission.*`、`IWebsocketTransmission.*` | native 构建/测试 |
| 链路层操作码 | 一字节动作和对应载荷 | 事实上的**当前** | `VirtualEthernetLinklayer.h` | [链路层协议](LINKLAYER_PROTOCOL_CN.md) |
| INFO envelope | JSON 会话/能力信息和扩展 | 基础字段**当前**；较新扩展为**实验** | `VirtualEthernetInformation.*` | 已存在的协议测试 |
| Runtime Snapshot | 必需 `schema_version`、`generation`、`monotonic_ms` 与 `phase`；Android/iOS 使用独立 JSON，TUI 使用进程内 C++ 对象，桌面统计只使用嵌入的选定字段 | **当前** | `RuntimeSnapshot*.h`、schema 与 `RuntimeStatsJson.h` | C++/Dart/Swift 共享 JSON fixture；桌面读取端是部分读取 |

**缺口：**隧道没有显式协议版本协商、保留操作码注册表、正式扩展协商、直接 protected-frame/handshake golden test 或跨发布版本兼容矩阵。因此，事实稳定的线上行为仍与实现版本耦合。

## 6. C++–Go 控制协议

可选管理控制链路使用 WebSocket 路径 `/ppp/webhook`。每条消息由 8 个十六进制长度字符和 JSON 组成：

```text
[8 个十六进制字符][{"Id":1,"Node":7,"Guid":"...","Cmd":1002,"Data":"..."}]
```

| 命令 | 方向 | 用途 | 稳定性 |
|---|---|---|---|
| `1000` ECHO | 双向 | 保活 / 延迟 | **内部** |
| `1001` CONNECT | C++ → Go 及回复 | 建立后端控制会话 | **内部** |
| `1002` AUTHENTICATION | C++ → Go 及回复 | 授权 VPN 用户 | **内部** |
| `1003` TRAFFIC | C++ → Go 及回复 | 上报流量计费 | **内部** |

鉴权使用管理器 `key`，与 C++ `server.backend-key` 匹配。源码依据：`go/ppp/Packet.go`、`Handler.go`、`ManagedServer.go` 和 `VirtualEthernetManagedServer.*`。

**缺口：**没有 envelope 版本、能力协商、最大帧契约、正式错误对象或跨语言 golden frame 测试；WebSocket origin 检查当前允许全部来源。

## 7. Go 管理器 HTTP API

### 当前 JSON API

所有 `/api/v1/*` 都要求 admin bearer token。`/sub/{token}` 是独立的公开 capability URL。内嵌 UI 默认位于 `/admin/`；`OPENPPP2_ADMIN_TOKEN` 可覆盖配置 token。独立模式会把生成的 token 持久化到 `manager-data.json`；托管模式未配置 token 时只生成进程期 token。

| 方法和路径 | 用途 | 稳定性 |
|---|---|---|
| `GET /api/v1/status` | 计数与管理器状态 | **当前** |
| `GET, POST /api/v1/users` | 托管模式列出/创建 VPN 用户；独立模式返回空列表并拒绝写入 | **当前**，模式相关 |
| `PUT, DELETE /api/v1/users/{guid}` | 托管模式更新/删除用户；独立模式返回 404 | **当前**，仅托管模式 |
| `GET, POST /api/v1/servers` | 列出/创建服务端记录 | **当前** |
| `PUT, DELETE /api/v1/servers/{id}` | 更新/删除服务端记录 | **当前** |
| `GET, POST /api/v1/subscriptions` | 列出/创建订阅 | **当前** |
| `PUT, DELETE /api/v1/subscriptions/{id}` | 更新/删除订阅 | **当前** |
| `POST /api/v1/subscriptions/{id}/rotate-token` | 失效并替换公开 token | **当前** |
| `GET /api/v1/subscriptions/{id}/preview` | 预览生成文档 | **当前** |
| `GET /sub/{token}` | 发布订阅 JSON | **当前** capability URL |

权威路由表是 `go/ppp/Admin.go`；持久化实现位于 `LocalStore.go` 和 `Subscription.go`。

### 旧内部 API

| 路由 | 状态 | 首选接口 / 风险 |
|---|---|---|
| `/ppp/consumer/set`、`/new`、`/reload`、`/load` | **内部**，旧兼容接口 | 首选 `/api/v1/users`；handler 接受任意方法，业务错误放在 HTTP 200 内 |
| `/ppp/server/all`、`/get`、`/load` | **内部**，旧兼容接口 | 首选 `/api/v1/servers`；与 consumer 路由一样要求共享 `key` 查询参数 |

控制 WebSocket 和全部 `/ppp/*` 路由只在托管模式存在。源码当前没有移除时间表或正式弃用政策。

**缺口：**origin 策略宽松；admin UI 可收到敏感 server key；缺少正式 OpenAPI 和完整的响应/错误 schema。

## 8. 订阅和管理 UI 契约

Android、iOS 和桌面 Client 使用的公开订阅载荷为：

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "nodes": []
}
```

`type` 与 `version` 组合为**当前**契约。node 被转换为完整 native 配置档。Android parser 测试位于 `android/test/remote_subscription_test.dart`；iOS parser 位于 `AppModels.swift`，但缺少对应 fixture 测试。

`/admin/` WebUI 是管理 API 的调用方，不是独立的受支持 API；其存储、路由和鉴权行为必须服从后端契约。

管理器、Android、iOS 和桌面端实现当前都将订阅文档限制为 2 MiB。Android/iOS 接受 HTTPS 来源（HTTP 仅允许 loopback 开发环境）；桌面 Client 接受 HTTP 和 HTTPS。**缺口：**仍缺少公开的共享策略、对齐的重定向/信任行为、重复 node 策略和 Android/iOS 共享 fixture。订阅 URL 中的 token 可能通过日志和 referrer 泄漏。

## 9. 桌面 Client Tauri 桥

Windows/macOS Client 管理器位于 `desktop/client/`。Svelte UI 只与本地 Tauri 壳通信，不调用 Guardian 或 Sub 管理 API。壳负责拉取订阅、保存偏好、合并手动节点，并启动现有 `ppp` 二进制。

| 命令 | 作用 | 稳定性 |
|---|---|---|
| `client_bootstrap` | 加载订阅缓存、合并节点、配置、启动参数和设置 | **实验** |
| `subscription_refresh` | 拉取 HTTP(S) 订阅 URL、缓存并持久化 URL | **实验** |
| `client_probe_latency` | 对所选节点做 TCP 探测；同时发出 `client://latency` | **实验** |
| `client_connect` / `client_disconnect` | 生成配置并启动/停止本地 `ppp --mode=client` | **实验** |
| `client_update_config` / `client_update_client_config` | 持久化原始 appsettings / 客户端侧配置编辑 | **实验** |
| `client_upsert_manual_node` / `client_delete_manual_node` | 本地 `manual:` 节点增删改 | **实验** |
| `client_update_launch_options` / `client_update_setting` | 持久化启动参数和应用设置 | **实验** |
| `client_toggle_favorite` | 切换收藏节点 ID 列表 | **实验** |

事件：`client://process`（进程生命周期/日志行）、`client://latency`、`client://tray-error`。持久化：应用数据目录下的 `preferences.json`（手动节点、启动参数、设置、原始配置、收藏）和 `subscription-cache.json`；运行时为子进程写入 `runtime/appsettings.json` 与 `runtime/stats.ndjson`。源码：`desktop/client/src-tauri/src/desktop.rs`、`preferences.rs`、`manual_nodes.rs`、`launch_options.rs`。设计：[手动节点](../design/CLIENT_MANUAL_PROFILES_DESIGN_CN.md)、[UI/UX](../design/CLIENT_UIUX_DESIGN_CN.md)。

**缺口：**无公开 IPC schema 或版本字段；打包/安装/签名流程未完成（`bundle.active` 为 false）。`autostart` 当前只是持久化偏好，尚未实现操作系统启动注册。壳会直接启动 `ppp`，因此提权行为仍依赖平台/manifest，且未完成验证。

## 10. Guardian HTTP 和 SSE API

Guardian 路由整体为**实验**。启用鉴权时，普通 `/api/*` 路由要求 `Authorization: Bearer <token>`。auth 路由和 `GET /api/v1/status` 绕过通用中间件。SSE 也绕过该中间件，但会在 handler 中用 query token 或 Bearer token 单独校验 TokenStore/JWT；只有关闭鉴权时才公开。CORS 当前允许 `*`。

| 分组 | 路由 |
|---|---|
| 鉴权 | `POST /api/v1/auth/login`、`POST /api/v1/auth/refresh`、`PUT /api/v1/auth/password` |
| 实例 | `GET, POST /api/v1/instances`；`GET, PUT, DELETE /api/v1/instances/{name}`；`POST .../{name}/start|stop|restart`；`GET .../{name}/logs` |
| 配置档 | `GET /api/v1/profiles`；`GET, PUT, DELETE /api/v1/profiles/{name}`；`POST .../{name}/validate`；`GET .../{name}/backups`；`POST .../{name}/restore/{backupId}` |
| 二进制 | `GET /api/v1/binaries`、`GET /api/v1/binaries/discover`、`POST /api/v1/binaries`、`DELETE /api/v1/binaries/{id}` |
| Guardian/服务 | `GET /api/v1/status`、`PUT /api/v1/guardian/config`、`GET /api/v1/service/status`、`POST /api/v1/service/install`、`POST /api/v1/service/uninstall` |
| 流式 | `GET /api/v1/sse/logs/{name}`、`GET /api/v1/sse/events` |
| UI | `GET /` catch-all 静态文件服务；没有 SPA history fallback |

源码依据：`go/guardian/api/router.go`、`middleware.go`、各 handler 和 `webui/src/lib/api.js`。

Guardian 配置和实例状态以 `0600` 模式写入 JSON；profiles/backups 是 `0644` 普通文件；binary 注册表仅在内存中，重启后依赖重新发现。

**缺口：**discover/register 可访问任意主机路径；`PUT /api/v1/guardian/config` 当前忽略请求体；多数 handler 没有直接 API 测试；SSE 凭据可能出现在 URL；WebUI token 存在 `localStorage`；配置档保存/恢复不是原子操作；binary 注册不会持久化。关闭鉴权时，修改密码也是未鉴权的首次初始化入口，因此首次设置只能放在 loopback 或可信网络。

## 11. Android 桥

以下 Android 接口都是内置 Flutter App 的**内部**边界。Channel 名属于内部 ABI，不是第三方集成承诺。

| 边界 | 操作 / 载荷 | 生命周期 | 源码依据 |
|---|---|---|---|
| Flutter MethodChannel `supersocksr.ppp/vpn` | `connect`、`disconnect`、`getRuntimeSnapshot`、`getLastError`、`readLog`、`getLogPath`、`clearLog`、`getVpnHeartbeatAgeMs`、`getInstalledApps`、`getAppIcon`、`getTelemetryIdentity`、`requestPermission` | UI 进程；异步调用 | `vpn_service.dart`、`MainActivity.kt` |
| Activity → Service Intent | connect/disconnect action，extras 为 `config_json`、`vpn_options_json` | 启动前台、不导出的 `:vpn` Service | `MainActivity.kt`、`PppVpnService.kt` |
| Kotlin → JNI | native 配置/run/stop、link-state/error/runtime-snapshot 查询、socket protect、telemetry HTTP 回调；流量由 runtime snapshot 承载 | `run()` 阻塞后台线程；回调依赖 Service 存活 | `android/android/app/src/main/kotlin/supersocksr/ppp/android/c/libopenppp2.kt`、`android/libopenppp2.cpp` |
| JNI → Kotlin | `runtime_snapshot`、`protect`、`start_exec`、`post_exec`、telemetry HTTP | `libopenppp2` 上的静态回调；由任意 runtime 线程触发，因此每次调用自行 attach JVM，且不缓存 `JNIEnv*` | 同上 |
| 配置档存储 | `profiles_v2`、active ID、options、有限历史 | App 私有 SharedPreferences | `profile_store.dart` |
| 跨进程状态 | `openppp2-heartbeat.txt`、`openppp2-linkstate.txt`、`openppp2-runtime-snapshot.json`、`openppp2-lasterror.txt` | snapshot、link-state 与 error 值用临时文件替换；heartbeat 通过文件 mtime 以 30 秒阈值判断新鲜度 | `PppStateStore.kt`、`MainActivity.kt` |

`PppVpnService` 运行在 `:vpn`。已移除的 EventChannel 路径已替换为 snapshot/error 文件镜像和可见 UI 轮询。native 侧的发布经 `runtime_snapshot` JNI 回调抵达 Service，并按 snapshot 自身的 `generation` 与 `monotonic_ms` 排序。

**缺口：**debug 构建会去掉 Service 的 `android:process`（`app/src/debug/AndroidManifest.xml`），因此 instrumentation 在单进程运行，不能演练 release 的跨进程布局。该布局目前由 `tests/tooling/test_runtime_ui_wiring.py` 的源码级检查覆盖，而非设备测试。

其他缺口：没有统一的 Channel/JNI ABI 版本、完整的方法/错误 schema、Service kill/recreate 覆盖、完整 JNI 签名测试，配置档存储也没有显式迁移版本。

## 12. iOS 桥

除特别说明外，以下 iOS 接口都是内置 App 与 Packet Tunnel 扩展的**内部**边界。

| 边界 | 操作 / 载荷 | 生命周期 | 源码依据 |
|---|---|---|---|
| App → Network Extension | 保存/加载 manager、启动/停止隧道、provider configuration | 系统授权和 `NETunnelProviderManager` 生命周期 | `VPNController.swift` |
| Provider 消息 | `linkState`、`lastError`、`diagnostics`、`crashReports`、`deleteCrashReports`、JSON `uploadCrashReports` | 只有 connected `NETunnelProviderSession` 可交换消息 | `VPNController.swift`、`PacketTunnelProvider.swift` |
| Swift → C ABI | `openppp2_ios_version`；tap create/destroy/start/stop/input；link/snapshot/stage；last error；telemetry；P2P datagram 回调 | tap 和 callback 所有权明确；provider close 必须同步停止回调 | `OpenPPP2PacketTunnelBridge.h` |
| App Group 状态 | link heartbeat、runtime snapshot、diagnostics、defaults | App 和扩展共享 entitlement 容器；原子文件写 | `TunnelSharedState.swift` |
| 配置档 bundle | `type=openppp2-profile-export`、`version=1`、active ID 和 profiles | 用户选择 security-scoped 文件；2 MiB 限制；包含 secret | `ProfileImportExport.swift` |

配置档导出 v1 对内置 iOS App 是**当前**契约；C ABI 和 provider-message 命令仍为**内部**。

**缺口：**provider 消息使用未版本化裸字符串，并以 `nil` 表示多种失败；C struct 没有 ABI version 或 `struct_size`；buffer 截断约定不完整；Actions 没有构建 native iOS static library，也没有真实 Packet Tunnel 集成测试。

## 13. Runtime Snapshot 和 TUI

Runtime Snapshot v1 必需包含 `schema_version`、`generation`、`monotonic_ms` 与 `phase`。排序使用 `generation`，再使用 `monotonic_ms`；解析器拒绝不支持的 schema，publisher 拒绝带排序信息的过时更新。`capabilities` 是字符串数组。TUI 消费进程内 C++ `RuntimeSnapshot`；Android 和 iOS 解码独立 JSON；桌面 Client 消费 `ppp-stats` 记录中嵌入的选定 `runtime` 字段，不校验嵌入 snapshot 的版本。共享 JSON fixture 覆盖 C++、Dart、Swift。TUI 内置命令使用 `openppp2` 命名空间；裸 `openppp2` 是 help 别名。

| TUI 命令 | 效果 | 稳定性 |
|---|---|---|
| `openppp2 [help]`、`openppp2 info`、`openppp2 clear` | 查看或清除控制台状态 | **实验** |
| `openppp2 restart|reload|exit` | 重启/重新加载/停止应用 | **实验**；`reload` 当前等价 restart |
| `openppp2 telemetry [status|help]` | 查看当前 telemetry 控制台设置 | **实验** |
| `openppp2 telemetry log|metric|span on|off|toggle` | 修改进程内控制台过滤器 | **实验** |
| `openppp2 telemetry level 0|1|2|3`、`all`、`quiet`、`clear` | 修改进程内 telemetry 最低级别、过滤器或事件缓冲区 | **实验** |

TUI 依赖 TTY，并受 `PPP_NO_TUI` 控制。命令在 ConsoleUI 生命周期线程中运行，不是远程控制 API；未知输入会显示为未知命令，绝不会由 shell 执行。源码：`ConsoleUI.cpp`、`TuiRuntimeAdapter.h`。

**缺口：**专门针对 ConsoleUI 命令解析、生命周期和并发停机的覆盖仍有限；schema 未列出序列化器输出的部分可选字段。

## 14. C/C++ 头文件与扩展点

| 接口 | 作用 | 分类 | 为什么不是外部 SDK |
|---|---|---|---|
| `AppConfiguration` | 解析并归一化运行策略 | **内部** | 布局和字段可随源码变化 |
| `ITransmission` | 保护载体和握手基类 | **内部** | 无安装头文件或 ABI 契约 |
| `VirtualEthernetLinklayer` / information 类型 | 隧道操作码和 INFO 实现 | **内部**；基础 INFO/线上字段事实稳定，较新扩展 JSON 为**实验** | C++ 对象布局不是线上契约 |
| `PppApplication`、生命周期/快照类型 | composition root 和状态发布 | **内部** | 仓库所有的生命周期 |
| DNS、路由、MUX、TAP 抽象 | 子系统扩展点 | **内部** | 平台/构建相关，未导出 |
| Error handler 和 telemetry facade | 仓库内回调 | **内部**；数字诊断可外部观察 | 没有 SDK target 或 callback ABI 保证 |
| `OpenPPP2PacketTunnelBridge.h` | iOS 扩展 C 边界 | **内部** | 只供内置桥使用，无安装/导出包 |

若要建立受支持的原生 SDK，至少需要刻意收缩的安装头文件、导出可见性、所有权规则、ABI 版本/能力查询、语义版本策略、打包、示例和跨版本二进制测试；当前均不存在。

## 15. 平台适配器

| 平台 | 内部边界 | 权限 / 所有权 | 主要源码 | 主要缺口 |
|---|---|---|---|---|
| Windows | Wintun/TAP、路由/DNS/代理辅助、服务/进程辅助 | 网卡和网络修改需要 Administrator | `windows/`、`TapWindows.*` | 辅助命令退出/错误行为缺少统一表 |
| Linux | TUN、route/rule/DNS、可选 io_uring/SYSNAT | root/CAP_NET_ADMIN | `linux/`、`TapLinux.*` | 发行版相关命令/回滚需要集成覆盖 |
| macOS | utun、route/DNS | 桌面隧道需要 root | `darwin/`、`TapDarwin.*` | macOS 构建不等于 iOS 扩展验证 |
| Android | `VpnService`、protected socket、JNI callback | 用户批准 VPN；Service 持有 TUN fd | `android/` | 跨进程 Runtime Snapshot 缺陷和设备测试不足 |
| iOS | Packet Tunnel、C callback 桥、App Group | entitlement 和 provider 持有包流 | `ios/` | CI 未端到端构建 native library 和 provider IPC |

## 16. 错误、诊断、Telemetry 与持久化

| 边界 | 格式 / 行为 | 稳定性 | 源码依据 | 缺口 |
|---|---|---|---|---|
| 诊断错误码 | 数字 enum、文本、thread-local/atomic last-error snapshot | 事实上的**当前** | `ErrorCodes.def`、[错误码](ERROR_CODES_CN.md) | append-only 和删除规则未自动执行 |
| Error callback | 进程内 handler dispatch | **内部** | `ErrorHandler.*` | 无外部 callback ABI |
| 运行统计/link state | 各平台使用 JSON/text/file/channel | 除 snapshot v1 外为**实验** | 平台桥 | 生命周期/新鲜度规则不一致 |
| Telemetry facade | log、metric、span、OTLP HTTP callback | **实验** | `ppp/diagnostics/Telemetry.h`、平台桥 | 文档与构建对默认启用状态描述不一致 |
| 管理器状态 | 带 `version: 1` 的 `manager-data.json` | 独立管理器的**当前持久化格式** | `LocalStore.go` | 无公开 JSON Schema、迁移策略或损坏恢复契约 |
| 桌面 Client 偏好 | `preferences.json`、`subscription-cache.json` | **内部持久化格式** | `desktop/client/src-tauri/src/preferences.rs` | 无 schema 版本或迁移策略 |
| Guardian 配置/实例 | 以 `0600` 写入的 JSON | **内部持久化格式** | `go/guardian/config.go`、`guardian.go` | 无公开 schema 或迁移契约 |
| Guardian profiles/backups | 以 `0644` 写入的文件 | **内部持久化格式** | `go/guardian/profile/manager.go` | 保存/恢复不是原子操作 |
| Guardian binary 注册表 | 内存注册加重新发现 | **内部运行状态** | `go/guardian/binary/manager.go` | 显式注册不会跨重启保留 |
| Android 配置档 | SharedPreferences JSON | **内部** | `profile_store.dart` | 无显式存储 schema/迁移 |
| iOS 配置档导出 | 版本化 JSON bundle | **当前** | `ProfileImportExport.swift` | 无独立 JSON Schema |
| Runtime fixture | JSON 加 hash manifest | **稳定测试契约** | `tests/contracts/runtime-snapshot/`、hash 工具 | schema 未枚举全部可选生产字段 |

## 17. 构建、测试、工具和 CI 接口

| 入口 | 输出 / 用途 | 稳定性 | 覆盖缺口 |
|---|---|---|---|
| 根 CMake；`build-openppp2-by-builds.sh` | 根 CMake 构建原生 `ppp`；variant 脚本打包 Linux 变体 | **开发接口** | variant 脚本会临时重写根 `CMakeLists.txt` 并删除 `build/`；仅应在干净、可丢弃的工作树中运行 |
| `build_windows.bat` | Windows x86/x64/ARM64 Ninja 构建 | **稳定开发接口** | 环境/toolchain 发现依赖机器 |
| `android/CMakeLists.txt`、构建脚本 | 四个 Android `libopenppp2.so` ABI | **内部构建接口** | 硬编码第三方默认路径；无 JNI export 检查 |
| `ios/CMakeLists.txt` | `libopenppp2_ios.a` | **实验构建接口** | 当前 Actions 不构建 |
| `cd go && go test ./ppp/... && go build .`；`cd go/guardian && go test ./... && go build .` | 独立的 manager 与 Guardian module 检查 | **稳定开发接口** | Guardian handler 覆盖稀疏；需要时另行构建 `./cmd/tui` |
| `flutter test`；`cd ios/App && swift test` | Android Flutter/Dart 测试；独立 iOS Swift 逻辑测试 | **稳定开发接口** | PR 不跑 Android VPN 生命周期设备测试 |
| `cd desktop/client && npm test && npm run build` | 桌面 Client 前端测试/构建 | **实验开发接口** | Tauri 壳打包/签名未纳入门禁 |
| `scripts/run-cpp-tests.sh` | 独立 C++ CTest | **稳定开发接口** | 完整平台网络仍需集成测试 |
| `scripts/test-runtime-contract.sh` | `hashes`、`cpp`、`dart`、`swift` 契约检查 | **稳定测试接口** | hash check 是各语言间接重复执行，而非单独 CI gate |
| `tools/check_docs.py` | metadata、相对链接、中英文映射 | **稳定治理接口** | 不校验 anchor 或外部 URL |
| Wave-B 回归/bench 脚本 | 正确性和与主机绑定的性能 baseline | **实验** | baseline 不可跨主机/toolchain 比较 |

## 新接口兼容规则

1. 稳定文档必须同时更新中英文版本。
2. 字节序列、JSON 字段、路由/方法组合、Channel 方法名和持久化文件即使属于内部实现，也应视为契约。
3. 不兼容的序列化变更必须先增加 version 或 capability 字段。
4. 可行时保留未知字段；无法保留时明确拒绝行为。
5. 不得从 C++ access modifier 推断 SDK 支持。
6. 跨语言契约必须增加 producer/consumer fixture。
7. 每个新接口都要记录鉴权、敏感信息暴露、生命周期/线程所有权、错误行为、源码依据和测试。

## 缺口总表

| 优先级 | 缺口 | 影响面 | 完成证据 |
|---|---|---|---|
| P1 | Android 跨进程运行时投递缺少设备测试，因为 debug 构建把 `:vpn` 合并进 App 进程 | Android 运行 UI | 保留 `android:process` 的 instrumentation 变体，或等价的多进程测试装置 |
| P1 | 隧道没有协议版本/操作码注册表/跨版本矩阵 | 线上协议 | 版本协商、注册表和兼容 fixture |
| P1 | Guardian binary 路径可暴露任意主机路径；config PUT 忽略 body | Guardian | 路径策略、正确更新行为和 API 测试 |
| P1 | iOS native bridge/Packet Tunnel 未端到端 CI 构建 | iOS | static library 构建和 provider-message 集成测试 |
| P1 | 完整配置无 schema/version/migration 策略 | 配置/配置档存储 | 发布 schema、version、fixture 和迁移测试 |
| P1 | Go API 缺少 OpenAPI 和完整错误/响应 schema | Manager、Guardian | 生成并校验包含鉴权/错误模型的 OpenAPI |
| P2 | CLI parser 与 help 可漂移 | CLI | 生成 parser/help/tests 的单一选项注册表 |
| P2 | JNI/provider-message/C ABI 缺少一致版本和错误契约 | 移动端桥 | ABI query/envelope version 和集成测试 |
| P2 | 错误编号和 telemetry 默认值缺少强制兼容策略 | 诊断/telemetry | 自动 enum 策略和唯一经验证默认值 |
| P2 | 持久化格式缺少原子迁移和 schema 契约 | Go/Android/iOS/桌面 Client | 版本化格式、原子替换和损坏恢复测试 |
| P2 | 桌面 Client IPC 无版本化 schema 或打包门禁；`autostart` 只是保存的偏好 | 桌面 Client Tauri 桥 | 命令/事件 schema、打包签名、提权启动验收和操作系统启动注册 |

本表记录当前证据，不代表允许把未鉴权或主机级操作暴露到不可信网络。
