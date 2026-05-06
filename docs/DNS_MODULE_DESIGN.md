# DNS 模块设计文档

## 概述

在现有 DNS 拦截/缓存架构上扩展多协议上游支持（UDP / TCP / DoH / DoT），配合 EDNS Client Subnet 优化国内 CDN 解析。目标是**默认零破坏性变更**：完全兼容现有 `dns-rules.txt` 和 `vdns` 缓存；所有会改变未命中规则处理行为的能力必须通过显式配置开启。

## 实现状态总览

| 功能 | 状态 | 说明 |
|------|------|------|
| UDP/TCP/DoH/DoT 四协议 | ✅ 已实现 | 全部异步，`DnsResolver.cpp` 中完整实现 |
| 12 个内置提供商 | ✅ 已实现 | 代码硬编码于 `Providers()` 静态表中 |
| dns-rules.txt 扩展（提供商名称） | ✅ 已实现 | `Rule::Load()` 扩展，`ProviderName` 字段 |
| `intercept-unmatched` 配置 | ✅ 已实现 | 未命中规则时走 `dns.servers.foreign` |
| `verify-peer` TLS 证书校验 | ✅ 已实现 | 可选，使用 `cacert.pem` / 内置根证书 / 系统 CA |
| ECS IPv4 /24 注入 | ✅ 已实现 | `InjectEcsOptRr()` 内联实现 |
| ClientExitIP 服务器→客户端传递 | ✅ 已实现 | 优先级 2 的出口 IP 来源 |
| 协议降级故障转移 | ✅ 已实现 | `TryProtocols()` 按条目顺序尝试 |
| 多提供商级联故障转移 | ✅ 已实现 | `ResolveAsyncWithFallback()` 支持三级提供商 |
| Socket protect（Android VPN） | ✅ 已实现 | `SetProtectSocketCallback()` 已接线 |
| STUN 出口 IP 检测 | ✅ 已实现 | `DetectExitIPViaStun()` 已接入 ECS fallback，支持多候选与轮询；限制见下文 |
| object/array 配置解析 | ✅ 已实现 | `ParseDnsServerSpec()` 支持 string/object/array 三种形式；含 `protocol`、`url`、`hostname`、`address`、`bootstrap` 字段 |
| structured entries 主路径 | ✅ 已实现 | `ResolveAsyncWithEntries()` 接入 `RedirectDnsServer` unmatched 路径，array/object 配置会真实生效 |
| Bootstrap DNS helper | ⚠️ helper 已有 | `ResolveHostnameAsync()` 已实现，但主路径尚未使用；提供商表中已硬编码 IP，无需动态解析 |
| OPT RR 合并（ARCOUNT > 0） | ✅ 已实现 | `InjectEcsOptRr()` 完整实现 OPT RR 扫描与 ECS option 合并 |
| TLS 连接池 | ❌ 未实现 | 每请求新建 TLS 连接，无复用 |
| ECS IPv6 支持 | ❌ 未实现 | 首版仅 IPv4，IPv6 地址会被跳过 |
| DoQ（DNS over QUIC） | ❌ 未来 | 无 QUIC 传输；配置层 `doq` 值会归一化为 `dot`（见下文） |
| DoH3（DNS over HTTP/3） | ❌ 未来 | 无代码、无引用 |
| 遥测（Telemetry） | ✅ 已实现 | `DnsResolver` 内部记录解析开始/成功/失败、协议 fallback、STUN 结果；外部继续记录 DNS 配置应用事件 |

---

## 核心原则

| 原则 | 说明 |
|------|------|
| **最大兼容** | `dns-rules.txt` 格式不变、`vdns` 缓存接口不变、`RedirectDnsServer()` 入口不变 |
| **性能优先** | 减少不必要拷贝、支持后续连接复用、优先使用服务器返回的出口 IP 候选值 |
| **分阶段实现** | 先 UDP/TCP + provider 规则闭环，再 DoT/DoH，最后 ECS/STUN/连接池优化 |
| **平台安全** | 新建 UDP/TCP/TLS/STUN/bootstrap socket 必须复用现有 Linux/Android tunnel protect 边界 |
| **不实现 DoQ** | QUIC 库依赖过重，普及度低，标记为未来扩展；配置层做 `doq→dot` 归一化 |

## 协议支持

| 协议 | 端口 | 加密 | 状态 | 说明 |
|------|------|------|------|------|
| **UDP** | 53 | ❌ | ✅ 已实现 | 最快，复用现有转发路径 |
| **TCP** | 53 | ❌ | ✅ 已实现 | 防 UDP 欺骗，支持大响应 |
| **DoH** | 443 | ✅ | ✅ 已实现 | DNS over HTTPS，HTTP/1.1，基于 `boost::beast::http`；HTTP/2 不作为首版目标 |
| **DoT** | 853 | ✅ | ✅ 已实现 | DNS over TLS，基于 `boost::asio::ssl` |
| **DoQ** | 784/853 | ✅ | ❌ 未来 | 需引入 QUIC 库，暂不实现；配置层 `doq` 值自动归一化为 `dot`（`NormalizeDnsProtocol()`） |
| **DoH3** | 443 (QUIC) | ✅ | ❌ 未来 | DNS over HTTP/3，依赖 QUIC 库，暂不实现 |

> **关于 DoQ 自动降级**：`AppConfiguration.cpp` 中的 `NormalizeDnsProtocol()` 函数会在配置解析阶段将 `"doq"` 协议值归一化为 `"dot"`。这意味着如果用户在 object/array 配置中指定 `"protocol": "doq"`，该条目会被当作 DoT 处理，而非报错或被忽略。由于没有 QUIC 传输实现，这不是真正的 DoQ→DoT 降级，而是配置层面的归一化。DoH3 不做任何归一化（无对应协议枚举值）。

---

## 与现有架构的关系

### 保留不动的组件

| 组件 | 文件 | 说明 |
|------|------|------|
| `vdns` 缓存 | `ppp/net/asio/vdns.h/cpp` | `QueryCache`/`QueryCache2`/`AddCache`/`UpdateAsync` 完全复用 |
| `dns::Rule` | `ppp/app/client/dns/Rule.h/cpp` | 三级匹配（full→regexp→suffix）完全保留 |
| `RedirectDnsServer` | `VEthernetNetworkSwitcher.cpp` | 现有 UDP 转发路径完全保留 |
| `dns-rules.txt` | 配置文件 | 格式不变：`domain /server_ip/nic` |

### 扩展的组件

| 组件 | 变更类型 | 说明 |
|------|---------|------|
| `dns::Rule::Load` | 扩展 | `server_ip` 字段新增识别提供商简写名称 |
| `RedirectDnsServer` | 扩展 | 当匹配到提供商名称时走 `DnsResolver` 路径；未命中规则默认保持旧行为 |
| `appsettings.json` | 扩展 | 新增 `dns.servers.domestic`/`dns.servers.foreign`/`dns.intercept-unmatched` 配置 |
| `VirtualEthernetInformationExtensions` | 扩展 | 新增 `ClientExitIP` 字段，服务器填充，客户端读取用于 ECS |

### 新增的组件

| 文件 | 说明 |
|------|------|
| `ppp/dns/DnsResolver.h` | 配置结构 + 提供商表 + 统一异步解析接口 + socket protect 回调声明 |
| `ppp/dns/DnsResolver.cpp` | UDP/TCP/DoT/DoH 实现 + ECS 构造 + STUN 检测 + bootstrap helper（1880 行） |

---

## 工作流程

```
客户端 DNS 请求（UDP:53）
  │
  ▼
┌──────────────────────────────────────────────────────────┐
│ RedirectDnsServer() — 现有入口，签名不变                   │
│                                                          │
│  1. dns::Message::decode() 解码 DNS 包                    │
│  2. vdns::QueryCache2() 检查缓存 → 命中则直接返回          │
│  3. dns::Rule::Get() 匹配 dns_rules.txt                   │
│     ├─ 命中且 Rule->Server 是 IP 地址                     │
│     │  → 走现有 UDP 转发路径（零修改）                      │
│     └─ 命中且 Rule->ProviderName 非空（如 "doh.pub"）      │
│        → 走新 DnsResolver 路径                            │
│  4. 未命中任何规则 → 默认保持旧行为；仅 intercept-unmatched │
│     显式开启时才走 dns.servers.foreign                     │
│                                                          │
│  新路径:                                                  │
│  4a. DnsResolver::ResolveAsync()                          │
│      ├─ 若 domestic && ecs_enabled →                     │
│      │    ├─ GetEcsIp() 有可用 IP → InjectEcsOptRr()     │
│      │    └─ GetEcsIp() 无可用 IP →                      │
│      │         DetectExitIPViaStun() → 注入 ECS → Try    │
│      ├─ 按条目顺序尝试协议：DoH → DoT → TCP → UDP          │
│      ├─ 发送异步请求                                      │
│      └─ 回调返回原始 DNS 响应                              │
│  4b. vdns::AddCache() 写入缓存                            │
│  4c. DatagramOutput() 注入响应                            │
└──────────────────────────────────────────────────────────┘
```

---

## 配置格式

### JSON key 与 C++ 字段命名对照

本模块的 JSON 配置 key 统一使用 **kebab-case**（如 `intercept-unmatched`、`override-ip`、`verify-peer`），与项目其余配置风格一致。C++ 内部结构体字段使用 **snake_case**（如 `intercept_unmatched`、`override_ip`、`verify_peer`），这是 C++ 惯例。序列化/反序列化代码负责两种命名之间的映射。

### 最简配置（推荐，2 行即可）

```json
{
    "dns": {
        "servers": {
            "domestic": "doh.pub",
            "foreign": "cloudflare"
        }
    }
}
```

### 完整配置

```json
{
    "dns": {
        "servers": {
            "domestic": "doh.pub",
            "foreign": "cloudflare"
        },
        "intercept-unmatched": false,
        "ecs": {
            "enabled": true,
            "override-ip": ""
        },
        "tls": {
            "verify-peer": true
        }
    }
}
```

### object/array 配置形式（✅ 已实现）

`domestic`/`foreign` 字段支持三种形式：

- **string**：提供商简写或 IP 地址，如 `"cloudflare"` 或 `"1.1.1.1:53"`
- **object**：单个结构化条目，含 `protocol`、`url`、`hostname`、`address`、`bootstrap` 字段
- **array**：混合字符串和对象的数组

解析代码位于 `AppConfiguration.cpp` 的 `ParseDnsServerSpec()` 和 `ParseDnsServerEntry()` 函数中。

```json
{
    "dns": {
        "servers": {
            "domestic": [
                { "protocol": "doh", "url": "https://doh.pub/dns-query", "hostname": "doh.pub", "address": "119.29.29.29:443", "bootstrap": ["119.29.29.29"] },
                { "protocol": "dot", "hostname": "dot.pub", "address": "119.29.29.29:853" },
                { "protocol": "udp", "address": "119.29.29.29:53" }
            ],
            "foreign": [
                { "protocol": "doh", "url": "https://cloudflare-dns.com/dns-query", "hostname": "cloudflare-dns.com", "address": "1.1.1.1:443", "bootstrap": ["1.1.1.1"] },
                { "protocol": "dot", "hostname": "cloudflare-dns.com", "address": "1.1.1.1:853" },
                { "protocol": "tcp", "address": "1.1.1.1:53" }
            ]
        }
    }
}
```

> **注意**：当 `domestic`/`foreign` 传入 object/array 时，解析后的结构化条目存储在 `dns.servers.domestic_entries`/`foreign_entries` 中，并在 `dns.intercept-unmatched=true` 的未命中规则路径中通过 `DnsResolver::ResolveAsyncWithEntries()` 直接使用。未命中规则优先使用 `foreign_entries`（不注入 ECS）；如果只配置了 `domestic_entries`，则按国内查询处理并在 `dns.ecs.enabled=true` 时注入 ECS。`dns-rules.txt` 中命中的提供商名称仍走内置提供商表。

### 配置字段说明

| JSON key | C++ 字段 | 类型 | 默认值 | 状态 | 说明 |
|----------|----------|------|--------|------|------|
| `dns.servers.domestic` | `dns.servers.domestic` | string | `""` | ✅ 已实现 | 国内 DNS 服务器提供商简写名 |
| `dns.servers.domestic` | `dns.servers.domestic_entries` | object/array | `[]` | ✅ 已实现 | 国内 DNS 结构化条目列表（支持 object/array 形式） |
| `dns.servers.foreign` | `dns.servers.foreign` | string | `""` | ✅ 已实现 | 海外 DNS 服务器提供商简写名 |
| `dns.servers.foreign` | `dns.servers.foreign_entries` | object/array | `[]` | ✅ 已实现 | 海外 DNS 结构化条目列表（支持 object/array 形式） |
| `dns.intercept-unmatched` | `dns.intercept_unmatched` | bool | `false` | ✅ 已实现 | 未命中 `dns-rules.txt` 时是否默认拦截并走 `dns.servers.foreign`；默认 false 保持旧行为 |
| `dns.ecs.enabled` | `dns.ecs.enabled` | bool | `false` | ✅ 已实现 | 启用 ECS（仅国内查询）；涉及隐私，默认关闭 |
| `dns.ecs.override-ip` | `dns.ecs.override_ip` | string | `""` | ✅ 已实现 | 手动指定出口 IP（最高优先，跳过自动检测） |
| `dns.tls.verify-peer` | `dns.tls.verify_peer` | bool | `true` | ✅ 已实现 | DoH/DoT 是否校验证书链与主机名；默认开启，使用 `cacert.pem`、内置根证书和系统默认 CA 路径 |
| `dns.stun.candidates` | `dns.stun.candidates` | string[] | `[]` | ✅ 已实现 | STUN 出口 IP 检测候选；当前运行时仅接受 IP literal，可带端口；hostname 会被日志提示后跳过 |

缓存 TTL 和开关复用现有配置，不再重复定义：

| 现有字段 | 作用 | 说明 |
|----------|------|------|
| `udp.dns.ttl` | 缓存 TTL（秒） | 对应 `vdns::ttl` |
| `udp.dns.turbo` | 启用 vdns 缓存 | 对应 `vdns::enabled` |

### 协议配置字段（object/array 形式）

以下字段在 object/array 配置解析中已实现，由 `ParseDnsServerEntry()` 解析：

| 字段 | 类型 | 状态 | 说明 |
|------|------|------|------|
| `protocol` | string | ✅ 已解析 | `udp` / `tcp` / `doh` / `dot`；`doq` 归一化为 `dot`；省略时按优先级自动选择 |
| `url` | string | ✅ 已解析 | DoH 端点 URL |
| `hostname` | string | ✅ 已解析 | DoT SNI 主机名 |
| `address` | string | ✅ 已解析 | UDP/TCP 服务器地址（`IP` 或 `IP:Port`） |
| `bootstrap` | string[] | ✅ 已解析 | Bootstrap DNS IP（当前存储于 `DnsServerEntry.bootstrap`，主路径未消费） |

---

## dns-rules.txt 兼容方案

### 现有格式（完全保留）

```
qq.com             /1.2.4.8/nic
google.com         /1.1.1.1/tun
```

此格式下，`server_ip` 是一个具体 IP，DNS 包直接 UDP 转发到该 IP（**现有逻辑不变**）。

### 扩展格式（已实现，向后兼容）

```
qq.com             /doh.pub/nic
google.com         /cloudflare/tun
baidu.com          /alidns/nic
```

当 `server_ip` 字段匹配内置提供商名称时，走 `DnsResolver` 多协议路径。

### 识别逻辑（已实现，`Rule::Load`）

```
segments[1] 解析流程：
  1. 尝试 StringToAddress() → 成功 → 现有逻辑，Rule->Server 存 IP
  2. 失败 → 检查是否匹配内置提供商名称（DnsResolver::HasProvider(segments[1])）
     ├─ 匹配 → Rule->ProviderName 存提供商名称字符串
     └─ 不匹配 → 跳过此规则（现有行为不变）
```

**实现方式**：在 `Rule` 结构中新增 `ProviderName` 字段（`ppp::string`），当非空时表示走新路径。`Server` 字段保持 `boost::asio::ip::address` 不变，用于旧路径兼容。代码位于 `ppp/app/client/dns/Rule.cpp` 第 176–206 行。

### 匹配优先级（不变）

1. `dns-rules.txt` 规则优先
2. 未匹配的域名默认保持旧路径；仅 `dns.intercept-unmatched=true` 时使用 `dns.servers.foreign`
3. ECS 仅对 `nic`（国内）查询添加，并且必须显式开启

---

## 内置提供商

代码在 `ppp/dns/DnsResolver.cpp` 的 `Providers()` 函数中硬编码了全部 12 个提供商，每个提供商包含 DoH/DoT/TCP/UDP 四种协议条目（部分提供商无 DoT）。**这些条目已预解析 IP 地址**，无需动态 bootstrap 解析。

### 国内（6 个）

| 简写 | DoH | DoT | UDP/TCP |
|------|-----|-----|---------|
| `doh.pub` | `https://doh.pub/dns-query` | `dot.pub` | `119.29.29.29` |
| `alidns` | `https://dns.alidns.com/dns-query` | `dns.alidns.com` | `223.5.5.5` |
| `baidu` | `https://doh.baidu.com/dns-query` | — | `180.76.76.76` |
| `360` | `https://doh.360.cn/dns-query` | `dns.360.cn` | `101.226.4.6` |
| `114` | `https://dns.114.com/dns-query` | — | `114.114.114.114` |
| `tuna` | `https://doh.tuna.tsinghua.edu.cn/dns-query` | `dns.tuna.tsinghua.edu.cn` | `101.6.6.6` |

### 海外（6 个）

| 简写 | DoH | DoT | UDP/TCP |
|------|-----|-----|---------|
| `cloudflare` | `https://cloudflare-dns.com/dns-query` | `cloudflare-dns.com` | `1.1.1.1` |
| `google` | `https://dns.google/dns-query` | `dns.google` | `8.8.8.8` |
| `quad9` | `https://dns.quad9.net/dns-query` | `dns.quad9.net` | `9.9.9.9` |
| `adguard` | `https://dns.adguard.com/dns-query` | `dns.adguard.com` | `94.140.14.14` |
| `nextdns` | `https://dns.nextdns.io/dns-query` | `dns.nextdns.io` | `45.90.28.0` |
| `mullvad` | `https://dns.mullvad.net/dns-query` | `dns.mullvad.net` | `194.242.2.2` |

### 简写协议选择策略

当用户使用简写（如 `"domestic": "doh.pub"`）时，代码按提供商表中的**条目顺序**尝试协议（每家提供商的条目顺序可能不同）：

```
1. DoH（最安全）
2. DoT（安全，专用端口）—— 部分提供商无 DoT 条目
3. TCP（防欺骗）
4. UDP（最快，兜底）
```

若当前协议失败（连接超时/TLS 握手失败），`TryProtocols()` 自动降级到下一个协议。此外，`ResolveAsyncWithFallback()` 支持跨提供商级联故障转移（最多 3 个提供商依次尝试）。

---

## EDNS Client Subnet (ECS)

### 工作原理

仅对国内（`nic`）查询添加 ECS OPT RR，帮助 CDN 返回最优节点。

### 出口 IP 来源（三级 fallback）

出口 IP 按以下优先级获取，首个成功即使用：

| 优先级 | 来源 | 延迟 | 外部依赖 | 状态 | 说明 |
|--------|------|------|----------|------|------|
| 1 | `override-ip` 配置 | 0 | 无 | ✅ 已实现 | 用户手动指定，最高优先 |
| 2 | 服务器返回 `ClientExitIP` | 0 | 无 | ✅ 已实现 | 复用会话握手，零额外流量 |
| 3 | STUN 查询 | ~1 RTT | 多个公网 STUN 候选 | ✅ 已实现 | 内置 Google/Cloudflare/Twilio IP 候选，支持 `dns.stun.candidates` 覆盖，3 秒超时，仅 IPv4 |

> **STUN fallback 已实现**：`DetectExitIPViaStun()` 发送 RFC 5389 STUN Binding Request 到候选 STUN 服务器，解析 XOR-MAPPED-ADDRESS 获取公网 IPv4。该方法已集成到 `ResolveAsync()` / `ResolveAsyncWithEntries()` 主路径中——当 ECS 已启用但 `GetEcsIp()` 返回 unspecified address 时，先尝试 STUN 检测，成功后注入 ECS 再继续协议降级链。
>
> **限制**：
> - 自定义 `dns.stun.candidates` 当前仅接受 IP literal（如 `1.2.3.4:3478`）；hostname 候选会被日志提示后跳过
> - 仅支持 IPv4
> - 3 秒超时（`PPP_DNS_RESOLVER_STUN_TIMEOUT_MS`）
> - STUN 检测会增加首次 ECS 查询的延迟（~1 RTT）

#### 优先级 1：手动配置

```json
{ "dns": { "ecs": { "override-ip": "123.45.67.89" } } }
```

直接使用，跳过后续检测。实现在 `DnsResolver::GetEcsIp()` 中。

#### 优先级 2：服务器返回

**机制**：
1. 客户端连接服务器时，服务器通过 `transmission->GetRemoteEndPoint()` 获取客户端的公网 IP 候选值
2. 服务器在 `InformationEnvelope.Extensions` 中填充 `ClientExitIP` 字段，随会话建立响应返回；该值通常可用，但在多 WAN、代理链、透明代理等场景下不保证等于实际 DNS 出口 IP
3. 客户端从 `extensions.ClientExitIP` 读取，调用 `dns_resolver_->SetExitIP()` 缓存供 ECS 使用

**实现改动**（均已实现）：
- `VirtualEthernetInformation.h` 第 128 行 — `Extensions` 新增 `ClientExitIP` 字段
- `VirtualEthernetInformation.cpp` 第 172–174 行 — 序列化为 JSON `"ClientExitIP"`
- `VirtualEthernetInformation.cpp` 第 259–265 行 — 反序列化
- 服务器 `VirtualEthernetSwitcher.cpp` 第 1709–1721 行 — 从 `GetRemoteEndPoint()` 填充
- 客户端 `VEthernetNetworkSwitcher.cpp` 第 955–959 行、980–982 行 — 缓存到 `DnsResolver`

#### 优先级 3：STUN Fallback（✅ 已实现）

当优先级 1 和 2 都不可用时，`ResolveAsync()` 自动调用 `DetectExitIPViaStun()` 作为最后手段。

**实现位置**：`DnsResolver.cpp` 第 1477–1657 行

**工作流程**：
1. 从内置候选或 `dns.stun.candidates` 配置中取得 STUN IP:port 列表
2. 使用原子轮询选择本次起始候选，失败时顺序尝试后续候选
3. 构造 20 字节 STUN Binding Request（RFC 5389 §6）
4. 等待响应（3 秒超时）
5. 解析响应中的 XOR-MAPPED-ADDRESS 属性，XOR 还原得到公网 IPv4
6. 回调返回检测到的 IP（全部失败返回 unspecified address）

**集成点**：`ResolveAsync()` 第 509–524 行 — 当 `ecs_enabled_ && domestic` 且 `GetEcsIp()` 无可用 IP 时触发 STUN，成功后注入 ECS 并继续 `TryProtocols()`。

### ECS 编码

在 DNS 查询的 Additional Section 追加 OPT RR（RFC 7871），直接在 `DnsResolver.cpp` 中实现（`InjectEcsOptRr()`，约 300 行，含 ARCOUNT > 0 合并路径）：

```
OPT RR 格式:
  NAME:   "" (root)
  TYPE:   41 (OPT)
  CLASS:  udp_payload_size (4096)
  TTL:    0
  RDATA:
    OPTION-CODE:  8 (Client Subnet)
    OPTION-LENGTH: 8
    FAMILY:       1 (IPv4)
    PREFIX-LENGTH: 24
    SCOPE-PREFIX: 0
    ADDRESS:      client_ip & 0xFFFFFF00（最后一字节清零）
```

**OPT RR 合并逻辑（ARCOUNT > 0，✅ 已实现）**：

当原 DNS 查询已有 Additional Records（ARCOUNT > 0）时，`InjectEcsOptRr()` 不会跳过，而是：
1. 安全遍历 QD、AN、NS 三个 section（使用 `SkipDnsQuestionSection()`/`SkipDnsRrSection()`）
2. 扫描 Additional Records section 寻找现有 OPT RR（TYPE=41，root label）
3. 如找到现有 OPT RR：
   - 在其 RDATA 中扫描 ECS option（option-code 8）
   - 如已有 ECS option → 替换为新的 ECS 数据
   - 如无 ECS option → 追加到 RDATA 末尾
   - 更新 RDLENGTH 和包尾部数据
4. 如未找到现有 OPT RR → 返回 false（保守策略，不追加第二个 OPT RR 以避免某些解析器问题）

**实现限制**：

| 限制 | 说明 | 后续 |
|------|------|------|
| 仅 IPv4 | `if (!ecs_ip.is_v4()) return false;` | IPv6 支持为后续 |
| 固定 /24 前缀 | 首版简化，不支持可配置前缀长度 | 后续可配置 |
| ARCOUNT > 0 时无 OPT RR | 当附加 section 中无现有 OPT RR 时返回 false（不追加新的） | 后续可追加 |
| 512 字节限制 | ARCOUNT == 0 快速路径确保注入后总大小不超过经典 UDP 限制 | 合理约束 |

---

## 技术实现

### 代码结构

```
ppp/dns/
├── DnsResolver.h       # 配置结构 + 提供商表 + 异步解析接口 + socket protect 回调
└── DnsResolver.cpp     # UDP/TCP/DoT/DoH 实现 + ECS 构造 + STUN 检测 + Bootstrap helper（1880 行）

修改的现有文件:
├── ppp/app/client/dns/Rule.cpp           # 扩展 Load() 支持提供商名称 ✅
├── ppp/app/client/dns/Rule.h             # Rule 新增 ProviderName 字段 ✅
├── ppp/app/client/VEthernetNetworkSwitcher.cpp  # RedirectDnsServer 增加新路径分支 ✅
├── ppp/app/protocol/VirtualEthernetInformation.h/cpp  # Extensions 新增 ClientExitIP 字段 ✅
├── ppp/configurations/AppConfiguration.h/cpp    # 新增 dns.* 配置解析 ✅
└── CMakeLists.txt 与 builds/openppp2-linux-amd64-*  # 新源文件加入所有构建变体 ✅
```

### 核心类设计（实际代码）

```cpp
namespace ppp::dns {

enum class Protocol {
    UDP,
    TCP,
    DoH,
    DoT,
    // 注意：无 DoQ 枚举值
};

struct ServerEntry {
    Protocol                protocol = Protocol::UDP;
    ppp::string             url;           // DoH
    ppp::string             hostname;      // DoT（SNI）
    ppp::string             address;       // UDP/TCP/DoH/DoT（预解析的 "IP:Port"）
    ppp::vector<boost::asio::ip::address> bootstrap_ips;  // 预留字段，当前未使用
};

class DnsResolver final : public std::enable_shared_from_this<DnsResolver> {
public:
    typedef ppp::function<bool(int native_handle)>  ProtectSocketCallback;
    typedef ppp::function<void(ppp::vector<Byte>)>  ResolveCallback;
    typedef ppp::function<void(boost::asio::ip::address)> ExitIpCallback;

    explicit DnsResolver(boost::asio::io_context& context) noexcept;

    void SetProtectSocketCallback(const ProtectSocketCallback& cb) noexcept;
    void SetExitIP(const boost::asio::ip::address& ip) noexcept;
    void SetEcsConfig(bool enabled, const ppp::string& override_ip) noexcept;
    void SetTlsVerifyPeer(bool verify_peer) noexcept;
    void SetDefaultProviders(const ppp::string& domestic, const ppp::string& foreign) noexcept;
    void SetStunCandidates(ppp::vector<StunCandidate> candidates) noexcept;

    // 单提供商解析（内部按 DoH→DoT→TCP→UDP 降级）
    void ResolveAsync(const ppp::string& provider_name, bool domestic,
                      const Byte* packet, int length,
                      const ResolveCallback& callback) noexcept;

    // 多提供商级联故障转移（最多 3 个提供商）
    void ResolveAsyncWithFallback(const ppp::string& provider_name,
                                  const ppp::string& fallback1,
                                  const ppp::string& fallback2,
                                  const Byte* packet, int length,
                                  const ResolveCallback& callback) noexcept;

    // 显式 structured entries 解析（用于 dns.servers object/array）
    void ResolveAsyncWithEntries(const ppp::vector<ServerEntry>& entries,
                                 bool domestic,
                                 const Byte* packet, int length,
                                 const ResolveCallback& callback) noexcept;

    static bool HasProvider(const ppp::string& name) noexcept;
    static const ppp::vector<ServerEntry>* GetProvider(const ppp::string& name) noexcept;

private:
    void TryProtocols(...);
    void SendUdp(...);
    void SendTcp(...);
    void SendDoh(...);
    void SendDot(...);
    bool ProtectSocket(int native_handle) noexcept;
    boost::asio::ip::address GetEcsIp() const noexcept;
    static bool InjectEcsOptRr(ppp::vector<Byte>& packet,
                               const boost::asio::ip::address& ecs_ip) noexcept;
    // STUN 检测（✅ 已实现，已接入 ResolveAsync/ResolveAsyncWithEntries 主路径）
    void DetectExitIPViaStun(const ExitIpCallback& callback) noexcept;
    void TryStunCandidate(const StunCandidate& candidate,
                          const ExitIpCallback& callback) noexcept;
    // Bootstrap DNS helper（✅ 已实现，但主路径未使用）
    static void ResolveHostnameAsync(
        boost::asio::io_context& context,
        const ppp::string& hostname,
        const ExitIpCallback& callback) noexcept;

    // 实际成员变量（无 ssl_contexts_ 连接池）
    boost::asio::io_context&    context_;
    ProtectSocketCallback       protect_socket_;
    ppp::string                 default_domestic_;
    ppp::string                 default_foreign_;
    boost::asio::ip::address    exit_ip_;
    bool                        ecs_enabled_ = false;
    ppp::string                 ecs_override_ip_;
    bool                        tls_verify_peer_ = true;
    ppp::vector<StunCandidate>  stun_candidates_;
    std::atomic<std::size_t>    stun_rotation_;
};

} // namespace ppp::dns
```

> **与早期设计文档的差异**：实际代码中**没有** `ssl_contexts_`（TLS 连接池），每请求新建 TLS 连接。但 `DetectExitIPViaStun()`（STUN）和 `ResolveHostnameAsync()`（bootstrap helper）**均已实现**。提供商表中已预解析 IP 地址，bootstrap helper 暂未接入主路径；object/array 配置则通过 `ResolveAsyncWithEntries()` 接入未命中规则路径。

### 关键实现细节

#### DoH（基于 boost::beast::http，异步，HTTP/1.1）

```cpp
void DnsResolver::SendDoh(const ServerEntry& entry, ..., const ResolveCallback& callback) noexcept {
    // 1. 从 entry.address 解析预置 IP（无需动态 DNS 解析）
    // 2. 建立 TLS 连接（boost::asio::ssl::stream<tcp::socket>）
    //    - 创建 ssl::context，调用 CreateClientSslContext(tls_verify_peer_)
    //    - 设置 SNI（entry.hostname 或 URL host）
    //    - 如 tls_verify_peer_，设置 host_name_verification
    //    - connect 前对 native_handle 调用 protect_socket_
    // 3. 构造 HTTP/1.1 POST 请求:
    //    POST /dns-query HTTP/1.1
    //    Host: doh.pub
    //    Content-Type: application/dns-message
    //    Accept: application/dns-message
    //    <binary DNS message>
    // 4. boost::beast::http::async_write / async_read
    // 5. 提取响应 body 作为原始 DNS message
    // 6. callback(response_bytes)
}
```

#### DoT（基于 boost::asio::ssl，异步）

```cpp
void DnsResolver::SendDot(const ServerEntry& entry, ..., const ResolveCallback& callback) noexcept {
    // 1. 从 entry.address 解析预置 IP
    // 2. 建立 TLS 连接，SNI 设置为 entry.hostname
    //    - connect 前对 native_handle 调用 protect_socket_
    // 3. 发送 2 字节长度前缀 + DNS message（RFC 7858）
    // 4. 先读 2 字节长度，再读完整响应
    // 5. callback(response_bytes)
}
```

#### UDP/TCP（复用 Asio，与现有逻辑一致）

```cpp
void DnsResolver::SendUdp(const ServerEntry& entry, ..., const ResolveCallback& callback) noexcept {
    // 直接 UDP send_to / async_receive_from
    // send 前对 native_handle 调用 protect_socket_
    // 5 秒超时
}

void DnsResolver::SendTcp(const ServerEntry& entry, ..., const ResolveCallback& callback) noexcept {
    // TCP 连接 + 2 字节长度前缀 + DNS message
    // 5 秒超时
}
```

#### STUN 检测（✅ 已实现，已接入主路径）

```cpp
void DnsResolver::DetectExitIPViaStun(const ExitIpCallback& callback) noexcept {
    // 1. 选择内置或配置的 STUN 候选列表
    // 2. 通过 stun_rotation_ 轮询本次起始候选
    // 3. 构造 20 字节 STUN Binding Request（RFC 5389 §6）
    //    - Message Type: 0x0001 (Binding Request)
    //    - Magic Cookie: 0x2112A442
    //    - Transaction ID: 12 字节静态模式
    // 4. UDP 发送到当前候选 IP:port
    // 5. socket 保护（protect_socket_）
    // 6. 3 秒超时，失败后尝试下一个候选
    // 7. 解析响应中的 XOR-MAPPED-ADDRESS (0x0020) 属性
    // 8. XOR 还原得到公网 IPv4 地址
    // 9. callback(ip) 或 callback(unspecified) on failure
}
```

**集成位置**：`ResolveAsync()` / `ResolveAsyncWithEntries()` 中，当 `ecs_enabled_ && domestic` 且 `GetEcsIp()` 无可用 IPv4 时触发。

#### Bootstrap DNS helper（⚠️ helper 已有，主路径未使用）

```cpp
static void DnsResolver::ResolveHostnameAsync(
    boost::asio::io_context& context,
    const ppp::string& hostname,
    const ExitIpCallback& callback) noexcept {
    // 1. 构造最小 DNS A-record 查询包
    // 2. UDP 发送到 8.8.8.8:53（硬编码 Google DNS）
    // 3. socket 保护
    // 4. 5 秒超时
    // 5. 解析第一个 A-record 应答
    // 6. callback(ip) 或 callback(unspecified) on failure
}
```

**当前状态**：该方法已完整实现（`DnsResolver.cpp` 第 1674–1877 行），作为 `static` 方法可独立于 DnsResolver 实例使用。但由于所有 12 个内置提供商条目都已包含硬编码 IP 地址，该 helper 在正常解析流程中**未被调用**。未来当 object/array 配置支持自定义提供商（用户指定域名形式的 `address`/`url`）时，该 helper 将用于解析 bootstrap 域名。

#### 故障转移

**协议级故障转移**（已实现）：

```cpp
void DnsResolver::TryProtocols(entries, index, packet, callback) noexcept {
    if (index >= entries->size()) {
        callback({});  // 全部失败
        return;
    }

    auto next = [this, entries, index, packet, callback]() {
        TryProtocols(entries, index + 1, packet, callback);
    };

    switch (entries[index].protocol) {
        case Protocol::DoH:
            SendDoh(entries[index], packet, [callback, next](ppp::vector<Byte> resp) {
                if (resp.empty()) next(); else callback(std::move(resp));
            });
            break;
        // DoT, TCP, UDP 同理
    }
}
```

**提供商级故障转移**（已实现）：

`ResolveAsyncWithFallback()` 接受最多 3 个提供商名称，按顺序尝试。每个提供商内部再走协议级降级。在 `RedirectDnsServer` 中，`intercept-unmatched` 路径使用 `foreign → domestic → cloudflare` 三级 fallback。

**结构化 entries 路径**（已实现）：

`ResolveAsyncWithEntries()` 接受 `dns.servers.domestic_entries` / `foreign_entries` 转换后的 `ServerEntry` 列表，不查内置 provider 表。`intercept-unmatched` 未命中规则时先使用 `foreign_entries`；如果未配置 foreign entries 但配置了 domestic entries，则以 `domestic=true` 调用并允许 ECS 注入。

---

## 修改现有代码的详细方案

### 1. `dns/Rule.h` — 新增 ProviderName 字段 ✅ 已实现

```cpp
struct Rule final {
    ppp::string                         Host;
    bool                                Nic = false;
    boost::asio::ip::address            Server;
    ppp::string                         ProviderName;  // 非空时走 DnsResolver 路径
    // ...
};
```

### 2. `dns/Rule.cpp` — 扩展 Load() 解析逻辑 ✅ 已实现

在现有 `StringToAddress` 失败后，增加提供商名称检查：

```cpp
boost::asio::ip::address address = StringToAddress(segments[1], ec);
if (ec) {
    // 新增：检查是否为内置提供商名称
    if (ppp::dns::DnsResolver::HasProvider(segments[1])) {
        Ptr rule = make_shared_object<Rule>(Rule{ host, nic, {}, segments[1] });
        // 根据 host 类型插入对应规则表
    }
    continue;  // 既不是 IP 也不是提供商名，跳过
}
```

### 3. `VEthernetNetworkSwitcher.cpp` — RedirectDnsServer 增加新路径 ✅ 已实现

```cpp
if (!rulePtr->ProviderName.empty()) {
    // 新路径：走 DnsResolver 多协议解析
    bool domestic = rulePtr->Nic;
    dns_resolver_->ResolveAsync(
        rulePtr->ProviderName, domestic,
        messages->Buffer.get(), messages->Length,
        [self, sourceEP, destEP](ppp::vector<Byte> response) {
            if (!response.empty()) {
                vdns::AddCache(response.data(), response.size());
                self->DatagramOutput(sourceEP, destEP, response.data(), response.size(), false);
            }
        });
    return true;
}
// 原有逻辑：rulePtr->Server 是 IP，直接 UDP 转发
```

### 4. `AppConfiguration.cpp` — DNS 配置解析 ✅ 已实现

`dns.servers.domestic`/`foreign` 支持三种 JSON 形式：

```cpp
// ParseDnsServerSpec() — string / object / array 统一入口
// ParseDnsServerEntry() — object 形式解析 protocol/url/hostname/address/bootstrap
// NormalizeDnsProtocol() — doq → dot 归一化
```

---

## 出口 IP 获取

```cpp
// 三级 fallback：override-ip > 服务器返回 > STUN
// DnsResolver 内部维护 exit_ip_ 成员

// 优先级 1：客户端在 OnInformation 回调中缓存服务器返回的出口 IP
if (NULLPTR != dns_resolver_ && !extensions.ClientExitIP.is_unspecified()) {
    dns_resolver_->SetExitIP(extensions.ClientExitIP);
}

// 优先级 2：服务器在 Establish() 中填充 ClientExitIP
// VirtualEthernetSwitcher::Establish():
{
    boost::asio::ip::tcp::endpoint remote_ep = transmission->GetRemoteEndPoint();
    if (!remote_ep.address().is_unspecified()) {
        envelope.Extensions.ClientExitIP = remote_ep.address();
    }
}

// GetEcsIp() 内部逻辑：
// 1. ecs_override_ip_ 非空 → 解析为 IPv4 地址 → 使用
// 2. exit_ip_ 是有效 IPv4 → 使用
// 3. 都不可用 → 返回 unspecified → 触发 DetectExitIPViaStun()
```

---

## 遥测（Telemetry）

`DnsResolver` 内部已接入轻量级 `ppp::telemetry::*` 计数与日志，外部组件（`VEthernetNetworkSwitcher`）仍保留 DNS 配置应用事件：

| 指标 | 类型 | 来源 | 说明 |
|------|------|------|------|
| `client.dns.apply` | Span | VEthernetNetworkSwitcher | DNS 配置应用耗时 |
| `client.dns.setup` | Count | VEthernetNetworkSwitcher | DNS 设置完成计数 |
| `client.ipv6.apply.us` | Histogram | VEthernetNetworkSwitcher | IPv6 应用耗时（含 DNS） |
| `dns.resolve.start` | Count | DnsResolver | 解析开始计数（provider 与 entries 路径） |
| `dns.resolve.success` | Count | DnsResolver | 任一协议/条目返回响应 |
| `dns.resolve.failure` | Count | DnsResolver | 所有条目耗尽仍失败 |
| `dns.resolve.fallback` | Count | DnsResolver | 单条目失败后进入下一条目/协议 |
| `dns.resolve.provider_miss` | Count | DnsResolver | provider 名称未命中内置表 |
| `dns.stun.start` | Count | DnsResolver | STUN 检测开始 |
| `dns.stun.success` | Count | DnsResolver | STUN 返回可用 XOR-MAPPED-ADDRESS |
| `dns.stun.timeout` / `send_fail` / `recv_fail` | Count | DnsResolver | STUN 单候选失败原因 |

后续可考虑继续细化的 DNS 专用遥测：

| 指标 | 类型 | 说明 |
|------|------|------|
| `dns.resolve.us` | Histogram | 单次 DNS 解析耗时（按协议分） |
| `dns.ecs.injected` | Count | ECS OPT RR 注入计数 |
| `dns.transport.connect_fail` | Count | TCP/DoT/DoH 连接失败细分 |
| `dns.transport.tls_fail` | Count | TLS 握手/证书校验失败细分 |
| `dns.transport.http_status` | Count | DoH HTTP 非 200 状态细分 |

---

## 后续阶段计划

### Phase A：自定义提供商接入主路径（✅ 已实现）

- `RedirectDnsServer` 已适配 `DnsServerEntry` 结构化条目
- object/array 配置中定义的自定义 DoH/DoT/TCP/UDP 端点可通过 `ResolveAsyncWithEntries()` 使用
- 未命中规则路径优先使用 `foreign_entries`；若仅配置 `domestic_entries`，按国内查询处理并允许 ECS
- 剩余 backlog：`ResolveHostnameAsync()` bootstrap helper 尚未接入 hostname 形式的自定义 endpoint 动态解析

### Phase B：TLS 连接池

- 按 hostname 复用 SSL context 和/或连接
- 减少 DoH/DoT 首次查询延迟
- 需评估连接生命周期管理复杂度

### Phase C：ECS IPv6 支持

- 支持 IPv6 地址的 ECS 注入
- PREFIX-LENGTH 48
- FAMILY 值 2

### Phase D：STUN 多服务器 fallback（✅ 已实现）

- 已增加 Google / Cloudflare / Twilio 等内置 IP 候选
- 已支持 `dns.stun.candidates` 覆盖候选列表
- 已使用 `stun_rotation_` 做简单轮询，单候选失败后尝试下一候选
- 剩余 backlog：hostname 候选目前不解析，只记录日志并跳过；可后续接入 bootstrap helper

### Phase E：DoQ / DoH3（远期）

- 需引入 QUIC 库（如 msquic 或 ngtcp2）
- 新增 `Protocol::DoQ` 枚举值
- 配置解析支持 `doh3` 协议值
- 实现 DoQ→DoT、DoH3→DoH 真正传输级降级

### Phase F：DNS 专用遥测（✅ 已实现，持续细化）

- `DnsResolver` 内部已添加解析开始、成功、失败、provider miss、协议/条目 fallback 计数
- STUN 检测已添加 start/success/no-candidates/timeout/send-fail/recv-fail/invalid-response/no-xmapped 计数
- 剩余 backlog：SendUdp/SendTcp/SendDoh/SendDot 内部失败原因可继续细分，例如连接拒绝、TLS 握手失败、HTTP 非 200、读写超时

---

## 推荐配置示例

### 国内用户（推荐）

```json
{
    "dns": {
        "servers": {
            "domestic": "doh.pub",
            "foreign": "cloudflare"
        },
        "ecs": { "enabled": true }
    }
}
```

dns-rules.txt:
```
qq.com             /doh.pub/nic
baidu.com          /alidns/nic
google.com         /cloudflare/tun
github.com         /cloudflare/tun
```

### 低延迟

```json
{
    "dns": {
        "servers": {
            "domestic": "114",
            "foreign": "cloudflare"
        }
    }
}
```

> 使用 `"114"` 简写时，代码按 DoH→TCP→UDP 顺序尝试（114 无 DoT）。如需纯 UDP，当前只能使用内置提供商的 UDP 条目（自动降级最终会到达 UDP）。

### 故障转移（使用内置提供商的多协议降级）

```json
{
    "dns": {
        "servers": {
            "domestic": "doh.pub",
            "foreign": "cloudflare"
        },
        "intercept-unmatched": true
    }
}
```

当 `doh.pub` 的 DoH 失败时，自动降级到 DoT→TCP→UDP。`intercept-unmatched: true` 确保所有未命中规则的查询也走多协议路径。

### 自定义 DoH 端点（object 形式）

```json
{
    "dns": {
        "servers": {
            "domestic": {
                "protocol": "doh",
                "url": "https://custom-dns.example.com/dns-query",
                "hostname": "custom-dns.example.com",
                "address": "203.0.113.1:443",
                "bootstrap": ["203.0.113.1"]
            },
            "foreign": "cloudflare"
        }
    }
}
```

---

## 参考资料

- [RFC 1035 - Domain Names](https://tools.ietf.org/html/rfc1035)
- [RFC 7766 - DNS over TCP](https://tools.ietf.org/html/rfc7766)
- [RFC 8484 - DNS over HTTPS](https://tools.ietf.org/html/rfc8484)
- [RFC 7858 - DNS over TLS](https://tools.ietf.org/html/rfc7858)
- [RFC 7871 - Client Subnet in DNS](https://tools.ietf.org/html/rfc7871)
- [RFC 5389 - STUN](https://tools.ietf.org/html/rfc5389)（STUN fallback 已实现参考）

---

## 标签

`dns` `doh` `dot` `ecs` `stun` `feature`
