# 配置参考
> Status: Active
> Type: Reference
> Last verified: 82643dc
> Parent index: [参考索引](README_CN.md)
> Peer link: [English](CONFIGURATION.md)

## 范围与事实来源

`AppConfiguration` 使用 **JsonCpp**（`Json::Value`），不是通用的 JSON 对象合并器。本文只记录当前实现，不构成公开 JSON Schema、迁移策略或兼容性承诺。以下实现是唯一事实来源：

- `ppp/configurations/AppConfiguration.cpp` — 默认值、加载/规范化与 JSON 输出
- `ppp/configurations/AppConfiguration.h` — 配置模型
- `ppp/app/ApplicationConfig.cpp` — 配置文件选择与启动期 CLI 覆盖

完整的当前 JSON 结构应以 `AppConfiguration.cpp` 中的 `AppConfiguration::ToJson()`（或 `ToString()`）为准；手工维护的示例不是 schema 的权威来源。

## 加载流程

`Load(Json::Value&)` 的顺序为：

1. `Clear()` 将可序列化的配置字段重置为默认值。
2. 输入必须是 JSON 对象；加载器反序列化其中已知字段。
3. `Loaded()` 校验并规范化结果。

这**不是** merge 或稀疏 patch 操作。再次调用 `Load()` 会重新构建可序列化的配置字段，而非保留上一次加载的值。buffer allocator 和远程 MUX runtime override 等仅运行期状态不属于这次可序列化重置。部分字段直接接受 JSON 转换结果，只有部分布尔值和值使用“字段存在”辅助函数，因此缺失字段的行为在整个模型中并不统一。应从当前 `ToJson()` 输出开始，或提供完整且已按源码核对的配置，并检查加载结果。

## 规范输出结构

`ToJson()` 输出以下顶层块：

```text
concurrent, cdn, ip, vmem, udp, tcp, mux, websocket, key, server,
client, virr, vbgp, telemetry, p2p, dns, geo-rules
```

关键结构如下：

| 块 | 规范字段 / 说明 |
|---|---|
| `websocket` | `listen.ws` 与 `listen.wss` 是整数端口，不是 `{ "port": ... }` 对象。 |
| `websocket.ssl` | `certificate-file`、`certificate-key-file`、`certificate-chain-file`、`certificate-key-password`、`ciphersuites`、`verify-peer`。 |
| `mux` | `mode`、`turbo`、`flow`、`tx` 和可选的 `debug.key`；嵌套字段拼写以 `ToJson()` 为准。 |
| `server.ipv6` | `mode`、`cidr`、`gateway`、`dns1`、`dns2`、`lease-time`、`static-addresses`；前缀长度包含在 CIDR 内。 |
| `server.session_resume` | `enabled` 与 `grace_ms`；服务端总开关和挂起会话宽限期。 |
| `client.session_resume` | `enabled`；客户端认证 L3 roaming 总开关。 |
| `key` | `kf`、`kh`、`kl`、`kx`、`sb`、cipher 名称/密钥与变换开关。 |
| `client` | mappings、routes、代理设置、重连超时、身份、服务端和带宽。 |

为兼容旧格式，`ToJson()` 还会输出 `websocket.verify-peer`，同时输出规范的嵌套字段 `websocket.ssl.verify-peer`；也会同时输出 `udp.static.servers` 与旧字段 `udp.static.server`。新配置应使用 `websocket.ssl.verify-peer`。

### MUX 配置与启动覆盖

`mux.mode` 会归一化为 `compat`、`flow`、`balance` 或 `stripe` 之一；为空或无法识别的输入会变为 `compat`。`mux.turbo` 是持久 JSON 字段。`mux.debug.key` 从 JSON 读取，且仅在非空时由 `ToJson()` 输出。`mux.debug.set_mode` 是由 `--mux-mode-set` 写入的进程内启动请求，不会从此 JSON 结构读取，也不会输出到其中。协商和证据边界见 [VMUX 验证](VMUX_VALIDATION_CN.md)。

## 重要默认值

`Clear()` 在加载前设置下列默认值：

| 字段 | 默认值 |
|---|---:|
| `mux.mode` / `mux.turbo` | `compat` / `false` |
| `websocket.listen.ws` / `websocket.listen.wss` | `0` / `0`（关闭） |
| `websocket.ssl.verify-peer` | `true` |
| `websocket.ssl.ciphersuites` | `GetDefaultCipherSuites()` |
| `client.session_resume.enabled` / `server.session_resume.enabled` | `false` / `false` |
| `server.session_resume.grace_ms` | `60000` 毫秒 |
| `key.kf` | `154543927` |
| `key.kh` | `12` |
| `key.kl` | `10` |
| `key.kx` | `128` |
| `key.sb` | `0` |
| `key.masked` / `key.delta-encode` / `key.shuffle-data` | `true` / `true` / `true` |
| `key.plaintext` | **`true`** |
| `server.ipv6.mode` | 关闭（内部为 `none`；输出时为空字符串） |
| `virr.update-interval` / `virr.retry-interval` | `86400` / `300` 秒 |
| `vbgp.update-interval` | `3600` 秒 |

`plaintext=true` 会使握手后的 base94 封装继续生效，启动安全诊断也明确说明数据包是在未加密状态下发送。它不适用于不可信网络。实际部署必须设为 `false`，并替换两项默认密钥；两端还必须一致使用影响分帧的 key 开关。

## 认证 L3 会话漫游

`client.session_resume.enabled` 与 `server.session_resume.enabled` 是相互独立的总开关，默认均为 `false`。只有双方启用并在 WSS 上协商 v1 capability，且具体 `ISslWebsocketTransmission` 提供认证 TLS session exporter 时才启用 roaming。plain TCP、plain WebSocket、CDN、无 exporter 的 WSS 与 capability 不一致都 fail closed，回到普通 fresh-session 行为。

`server.session_resume.grace_ms` 限制服务端在合格 carrier 故障后只保留 L3 session/IP/NAT/UDP-manager 状态的时长；FRP mapping 和 VMUX 仍会关闭。认证 root 只驻留进程内且不序列化，因此服务端重启必然 fresh authenticate。启用 roaming 时，WSS listener 固定到 switcher owner `io_context`，以避免跨 executor handoff，但可能降低 accept/handshake 并行度。协议、威胁模型与 rollout 限制见 [认证 L3 会话漫游](../design/session-recovery/l3-roaming.md)。

## 安全相关示例片段

以下是**片段**，不是可直接运行的完整配置。尖括号内均为非秘密占位符，必须替换；不得把它们当作真实密钥部署。

```json
{
  "key": {
    "kf": 154543927,
    "kh": 12,
    "kl": 10,
    "kx": 128,
    "sb": 0,
    "protocol": "aes-256-cfb",
    "protocol-key": "<REPLACE_WITH_UNIQUE_PROTOCOL_SECRET>",
    "transport": "aes-256-cfb",
    "transport-key": "<REPLACE_WITH_UNIQUE_TRANSPORT_SECRET>",
    "masked": true,
    "plaintext": false,
    "delta-encode": true,
    "shuffle-data": true,
    "simd-auto": true
  },
  "websocket": {
    "host": "vpn.example.invalid",
    "path": "/openppp2",
    "listen": { "ws": 0, "wss": 443 },
    "ssl": {
      "certificate-file": "<PATH_TO_CERTIFICATE_PEM>",
      "certificate-key-file": "<PATH_TO_PRIVATE_KEY_PEM>",
      "certificate-chain-file": "<PATH_TO_CHAIN_PEM>",
      "certificate-key-password": "<REPLACE_ONLY_IF_KEY_IS_ENCRYPTED>",
      "ciphersuites": "",
      "verify-peer": true
    }
  }
}
```

私钥文件和真实口令不得提交到版本库。`verify-peer` 控制对端证书校验，应按部署的认证模型明确选择。

## WebSocket 校验

- `ws` 与 `wss` 都是整数端口；`0` 关闭对应监听器。
- 非法端口会规范化为 `0`。
- host 无效、path 为空，或 path 不以 `/` 开头时，规范化会关闭两个 WebSocket 监听器。
- WSS 证书材料无效时会关闭 WSS。

请使用上文列出的精确 TLS 字段名。`certificate`、`certificate-key`、`ca-certificate` 等旧名称不是当前规范输出结构。

## 服务端 IPv6

仅支持以下已启用模式：

| `server.ipv6.mode` | 含义 |
|---|---|
| `nat66` | 使用 IPv6 前缀池的 NAT66 |
| `gua` | 直接委派全局单播地址（GUA） |

其他输入都会规范化为关闭。`ToJson()` 将关闭状态输出为 `""`；不要添加单独的 `prefix-length` JSON 字段——`Load()` 会从 `server.ipv6.cidr` 推导内部前缀长度，例如 `2001:db8:1234::/64`。

已启用的服务端 IPv6 有平台校验：当前加载器仅在原生 Linux 构建（`_LINUX` 且非 `_ANDROID`）中接受其数据面，因此 Android、Windows 和 macOS 构建会在加载时拒绝已启用的 `nat66` 或 `gua`。应在目标 Linux 环境验证，而不能假定其他平台的行为相同。`nat66` 的 CIDR 为空时会使用内部 ULA 默认值；`gua` 必须使用有效的全局单播（`2000::/3`）前缀。已启用的 IPv6 配置无效时，规范化会按失败类型清理该配置或导致加载失败。

## JSON 与 CLI

JSON 是持久配置来源。CLI 会在配置加载之后应用本次启动专用行为，不会回写配置文件。启动顺序、模式选择、TUN 覆盖、统计输出和路由列表工具见 [命令行参考](CLI_REFERENCE_CN.md)。

## 源码锚点

- `AppConfiguration::Clear()` — `ppp/configurations/AppConfiguration.cpp`
- `AppConfiguration::Load(Json::Value&)` — `ppp/configurations/AppConfiguration.cpp`
- `AppConfiguration::Loaded()` — `ppp/configurations/AppConfiguration.cpp`
- `AppConfiguration::ToJson()` — `ppp/configurations/AppConfiguration.cpp`
- 握手后的 plaintext 分帧 — `ppp/transmissions/ITransmission.cpp`
