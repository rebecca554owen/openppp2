# DNS 模块设计文档

## 概述

在现有 DNS 拦截/缓存架构上扩展多协议上游支持（UDP / TCP / DoH / DoT），配合 EDNS Client Subnet 优化国内 CDN 解析。目标是**默认零破坏性变更**：完全兼容现有 `dns-rules.txt` 和 `vdns` 缓存；所有会改变未命中规则处理行为的能力必须通过显式配置开启。

## 核心原则

| 原则 | 说明 |
|------|------|
| **最大兼容** | `dns-rules.txt` 格式不变、`vdns` 缓存接口不变、`RedirectDnsServer()` 入口不变 |
| **性能优先** | 减少不必要拷贝、支持后续连接复用、优先使用服务器返回的出口 IP 候选值 |
| **分阶段实现** | 先 UDP/TCP + provider 规则闭环，再 DoT/DoH，最后 ECS/STUN/连接池优化 |
| **平台安全** | 新建 UDP/TCP/TLS/STUN/bootstrap socket 必须复用现有 Linux/Android tunnel protect 边界 |
| **不实现 DoQ** | QUIC 库依赖过重，普及度低，标记为未来扩展 |

## 协议支持

| 协议 | 端口 | 加密 | 状态 | 说明 |
|------|------|------|------|------|
| **UDP** | 53 | ❌ | ✅ 实现 | 最快，复用现有转发路径 |
| **TCP** | 53 | ❌ | ✅ 实现 | 防 UDP 欺骗，支持大响应 |
| **DoH** | 443 | ✅ | ✅ 实现 | DNS over HTTPS，先实现 HTTP/1.1，复用 `boost::beast::http`；HTTP/2 不作为首版目标 |
| **DoT** | 853 | ✅ | ✅ 实现 | DNS over TLS，复用 `boost::asio::ssl` |
| **DoQ** | 784/853 | ✅ | ⏳ 未来 | 需引入 QUIC 库，暂不实现；配置 `doq` 时自动降级为 `dot` |

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
| `appsettings.json` | 扩展 | 新增 `dns.servers.domestic`/`dns.servers.foreign`/`dns.intercept_unmatched` 配置 |
| `VirtualEthernetInformationExtensions` | 扩展 | 新增 `ClientExitIP` 字段，服务器填充，客户端读取用于 ECS |

### 新增的组件

| 文件 | 说明 |
|------|------|
| `ppp/dns/DnsResolver.h` | 配置结构 + 提供商表 + 统一异步解析接口 + socket protect 回调声明 |
| `ppp/dns/DnsResolver.cpp` | UDP/TCP/DoT/DoH 协议实现 + bootstrap + ECS 构造 |

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
│     └─ 命中且 Rule->Server 是提供商名称（如 "doh.pub"）    │
│        → 走新 DnsResolver 路径                            │
│  4. 未命中任何规则 → 默认保持旧行为；仅 intercept_unmatched │
│     显式开启时才走 dns.servers.foreign                     │
│                                                          │
│  新路径:                                                  │
│  4a. 根据 nic/tun 标志选择 domestic/foreign 服务器组       │
│  4b. DnsResolver::ResolveAsync()                          │
│      ├─ 若 domestic && ecs_enabled → 添加 ECS OPT RR      │
│      ├─ 按优先级选择协议：DoH → DoT → TCP → UDP            │
│      ├─ 发送异步请求                                      │
│      └─ 回调返回原始 DNS 响应                              │
│  4c. vdns::AddCache() 写入缓存                            │
│  4d. DatagramOutput() 注入响应                            │
└──────────────────────────────────────────────────────────┘
```

---

## 配置格式

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
            "domestic": {
                "protocol": "doh",
                "url": "https://doh.pub/dns-query",
                "bootstrap": ["119.29.29.29"]
            },
            "foreign": {
                "protocol": "doh",
                "url": "https://cloudflare-dns.com/dns-query",
                "bootstrap": ["1.1.1.1", "1.0.0.1"]
            }
        },
        "ecs": {
            "enabled": true,
            "override_ip": ""
        }
    }
}
```

### 多协议故障转移配置

```json
{
    "dns": {
        "servers": {
            "domestic": [
                { "protocol": "doh", "url": "https://doh.pub/dns-query", "bootstrap": ["119.29.29.29"] },
                { "protocol": "dot", "hostname": "dot.pub", "bootstrap": ["119.29.29.29"] },
                { "protocol": "udp", "address": "119.29.29.29" }
            ],
            "foreign": [
                { "protocol": "doh", "url": "https://cloudflare-dns.com/dns-query", "bootstrap": ["1.1.1.1"] },
                { "protocol": "dot", "hostname": "cloudflare-dns.com", "bootstrap": ["1.1.1.1"] },
                { "protocol": "tcp", "address": "1.1.1.1" }
            ]
        }
    }
}
```

### 配置字段说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `dns.servers.domestic` | string/object/array | — | 国内 DNS 服务器（简写名、单配置、或数组） |
| `dns.servers.foreign` | string/object/array | — | 海外 DNS 服务器 |
| `dns.intercept_unmatched` | bool | `false` | 未命中 `dns-rules.txt` 时是否默认拦截并走 `dns.servers.foreign`；默认 false 保持旧行为 |
| `dns.ecs.enabled` | bool | `false` | 启用 ECS（仅国内查询）；涉及隐私，默认关闭 |
| `dns.ecs.override_ip` | string | `""` | 手动指定出口 IP（最高优先，跳过自动检测和 STUN） |
| `dns.tls.verify_peer` | bool | `true` | DoH/DoT 是否校验证书链与主机名；默认开启，使用 `cacert.pem`、内置根证书和系统默认 CA 路径 |

缓存 TTL 和开关复用现有配置，不再重复定义：

| 现有字段 | 作用 | 说明 |
|----------|------|------|
| `udp.dns.ttl` | 缓存 TTL（秒） | 对应 `vdns::ttl` |
| `udp.dns.turbo` | 启用 vdns 缓存 | 对应 `vdns::enabled` |

### 协议配置字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `protocol` | string | `udp` / `tcp` / `doh` / `dot`（省略时按优先级自动选择） |
| `url` | string | DoH 端点 URL |
| `hostname` | string | DoT SNI 主机名 |
| `address` | string | UDP/TCP 服务器地址（`IP` 或 `IP:Port`） |
| `bootstrap` | string[] | Bootstrap DNS IP（用于解析 DoH/DoT 域名） |

---

## dns-rules.txt 兼容方案

### 现有格式（完全保留）

```
qq.com             /1.2.4.8/nic
google.com         /1.1.1.1/tun
```

此格式下，`server_ip` 是一个具体 IP，DNS 包直接 UDP 转发到该 IP（**现有逻辑不变**）。

### 扩展格式（新增，向后兼容）

```
qq.com             /doh.pub/nic
google.com         /cloudflare/tun
baidu.com          /alidns/nic
```

当 `server_ip` 字段匹配内置提供商名称时，走 `DnsResolver` 多协议路径。

### 识别逻辑（扩展 `Rule::Load`）

```
segments[1] 解析流程：
  1. 尝试 StringToAddress() → 成功 → 现有逻辑，Rule->Server 存 IP
  2. 失败 → 检查是否匹配内置提供商名称（DnsProviders::Contains(segments[1])）
     ├─ 匹配 → Rule->Server 存提供商名称字符串（编码为特殊 IP 或新增字段）
     └─ 不匹配 → 跳过此规则（现有行为不变）
```

**实现方式**：在 `Rule` 结构中新增一个 `ProviderName` 字段（`ppp::string`），当非空时表示走新路径。`Server` 字段保持 `boost::asio::ip::address` 不变，用于旧路径兼容。

### 匹配优先级（不变）

1. `dns-rules.txt` 规则优先
2. 未匹配的域名默认保持旧路径；仅 `dns.intercept_unmatched=true` 时使用 `dns.servers.foreign`
3. ECS 仅对 `nic`（国内）查询添加，并且必须显式开启

---

## 内置提供商

### 国内

| 简写 | DoH | DoT | UDP/TCP |
|------|-----|-----|---------|
| `doh.pub` | `https://doh.pub/dns-query` | `dot.pub` | `119.29.29.29` |
| `alidns` | `https://dns.alidns.com/dns-query` | `dns.alidns.com` | `223.5.5.5` |
| `baidu` | `https://doh.baidu.com/dns-query` | — | `180.76.76.76` |
| `360` | `https://doh.360.cn/dns-query` | `dns.360.cn` | `101.226.4.6` |
| `114` | `https://dns.114.com/dns-query` | — | `114.114.114.114` |
| `tuna` | `https://doh.tuna.tsinghua.edu.cn/dns-query` | `dns.tuna.tsinghua.edu.cn` | `101.6.6.6` |

### 海外

| 简写 | DoH | DoT | UDP/TCP |
|------|-----|-----|---------|
| `cloudflare` | `https://cloudflare-dns.com/dns-query` | `cloudflare-dns.com` | `1.1.1.1` |
| `google` | `https://dns.google/dns-query` | `dns.google` | `8.8.8.8` |
| `quad9` | `https://dns.quad9.net/dns-query` | `dns.quad9.net` | `9.9.9.9` |
| `adguard` | `https://dns.adguard.com/dns-query` | `dns.adguard.com` | `94.140.14.14` |
| `nextdns` | `https://dns.nextdns.io/dns-query` | `dns.nextdns.io` | `45.90.28.0` |
| `mullvad` | `https://dns.mullvad.net/dns-query` | `dns.mullvad.net` | `194.242.2.2` |

### 简写协议选择策略

当用户使用简写（如 `"domestic": "doh.pub"`）时，按以下优先级自动选择首个可用协议：

```
1. DoH（最安全，复用 HTTP 连接池）
2. DoT（安全，专用端口）
3. TCP（防欺骗）
4. UDP（最快，兜底）
```

若首选协议失败（连接超时/TLS 握手失败），自动降级到下一个协议。

---

## EDNS Client Subnet (ECS)

### 工作原理

仅对国内（`nic`）查询添加 ECS OPT RR，帮助 CDN 返回最优节点。

### 出口 IP 来源（三级 fallback）

出口 IP 按以下优先级获取，首个成功即使用：

| 优先级 | 来源 | 延迟 | 外部依赖 | 说明 |
|--------|------|------|----------|------|
| 1 | `override_ip` 配置 | 0 | 无 | 用户手动指定，最高优先 |
| 2 | 服务器返回 `ClientExitIP` | 0 | 无 | 复用会话握手，零额外流量 |
| 3 | STUN 查询 | ~1 RTT | 公共 STUN 服务器 | 服务器未返回时的 fallback |

#### 优先级 1：手动配置

```json
{ "dns": { "ecs": { "override_ip": "123.45.67.89" } } }
```

直接使用，跳过后续检测。

#### 优先级 2：服务器返回

**机制**：
1. 客户端连接服务器时，服务器通过 `transmission->GetRemoteEndPoint()` 获取客户端的公网 IP 候选值
2. 服务器在 `InformationEnvelope.Extensions` 中新增 `ClientExitIP` 字段，随会话建立响应返回；该值通常可用，但在多 WAN、代理链、透明代理等场景下不保证等于实际 DNS 出口 IP
3. 客户端从 `information_extensions_.ClientExitIP` 读取，缓存供 ECS 使用

**实现改动**：
- `VirtualEthernetInformation.h` — `Extensions` 新增 `ClientExitIP` 字段
- `VirtualEthernetInformation.cpp` — 序列化/反序列化 `ClientExitIP`
- 服务器 `Establish()` 中从 `transmission->GetRemoteEndPoint()` 填充

#### 优先级 3：STUN Fallback

当服务器未返回 `ClientExitIP`（旧版本服务器、连接异常等）时，使用 STUN 协议（RFC 5389）获取公网 IP。

**为什么选 STUN 而不是 HTTP 探测**：
- 单个 UDP 包往返（~1 RTT），比 HTTP 快得多
- 协议极简：20 字节 Binding Request → 解析 XOR-MAPPED_ADDRESS
- 无 TLS 握手开销，无 TCP 连接建立
- 公共 STUN 服务器众多且免费

**STUN 服务器列表**：

| 服务器 | 地址 | 说明 |
|--------|------|------|
| Google | `stun.l.google.com:19302` | 最稳定 |
| Cloudflare | `stun.cloudflare.com:3478` | 隐私友好 |
| Twilio | `global.stun.twilio.com:3478` | 备用 |

**实现**（内联在 DnsResolver.cpp，~50 行）：

```cpp
void DnsResolver::DetectExitIPViaStun(const ppp::function<void(boost::asio::ip::address)>& callback) {
    // STUN Binding Request (RFC 5389 Section 6)
    // 固定 20 字节，随机 Transaction ID
    uint8_t request[20] = {
        0x00, 0x01,             // Binding Request
        0x00, 0x00,             // Length = 0 (no attributes)
        0x21, 0x12, 0xA4, 0x42, // Magic Cookie
        // Transaction ID (12 bytes random)
    };
    // Fill random transaction ID...
    // 发送到 STUN 服务器（随机选一个）
    // 解析响应中的 XOR-MAPPED-ADDRESS (0x0020) 属性
    // callback(ip);
}
```

**调用时机**：首次需要出口 IP 且服务器未返回时触发一次，结果缓存。

### ECS 编码

在 DNS 查询的 Additional Section 追加 OPT RR（RFC 7871），不引入独立 `ECSBuilder` 类，直接在 `DnsResolver.cpp` 中用 ~40 行代码构造：

```
OPT RR 格式:
  NAME:   "" (root)
  TYPE:   41 (OPT)
  CLASS:  udp_payload_size (4096)
  TTL:    0
  RDATA:
    OPTION-CODE:  8 (Client Subnet)
    OPTION-LENGTH: 4 + ceil(PREFIX-LENGTH / 8)
    FAMILY:       1 (IPv4) 或 2 (IPv6)
    PREFIX-LENGTH: 24 (IPv4) 或 48 (IPv6)
    ADDRESS:      client_ip & mask，仅编码 prefix 覆盖的字节数
```

实现注意事项：

- 必须更新 DNS Header 的 Additional Record Count。
- 若原请求已存在 OPT RR，应优先在现有 OPT RR 中追加或替换 ECS option，避免重复 OPT RR。
- 若原请求已存在 ECS option，应采用“替换为本地策略”或“保留原值”的明确策略，首版建议替换为本地策略。
- ECS 会暴露客户端网段信息，因此默认关闭。

---

## 技术实现

### 代码结构

```
ppp/dns/
├── DnsResolver.h       # 配置结构 + 提供商表 + 异步解析接口 + socket protect 回调
└── DnsResolver.cpp     # UDP/TCP/DoT/DoH 实现 + bootstrap + ECS 构造

修改的现有文件:
├── ppp/app/client/dns/Rule.cpp           # 扩展 Load() 支持提供商名称
├── ppp/app/client/dns/Rule.h             # Rule 新增 ProviderName 字段
├── ppp/app/client/VEthernetNetworkSwitcher.cpp  # RedirectDnsServer 增加新路径分支
├── ppp/app/protocol/VirtualEthernetInformation.h/cpp  # Extensions 新增 ClientExitIP 字段
├── ppp/configurations/AppConfiguration.h/cpp    # 新增 dns.* 配置解析
└── CMakeLists.txt 与 builds/openppp2-linux-amd64-*  # 新源文件加入所有构建变体
```

### 核心类设计

```cpp
namespace ppp::dns {

enum class Protocol {
    UDP,
    TCP,
    DoH,
    DoT,
};

struct ServerEntry {
    Protocol                protocol;
    ppp::string             url;           // DoH
    ppp::string             hostname;      // DoT
    ppp::string             address;       // UDP/TCP ("IP" 或 "IP:Port")
    ppp::vector<boost::asio::ip::address> bootstrap_ips;
};

class DnsResolver : public std::enable_shared_from_this<DnsResolver> {
public:
    explicit DnsResolver(boost::asio::io_context& context);

    // 加载配置（启动时调用一次）
    bool LoadConfig(const ppp::string& domestic_name,
                    const ppp::string& foreign_name);

    // 异步解析（主入口）
    void ResolveAsync(
        const ppp::string&           provider_name,  // "doh.pub" / "cloudflare" / ...
        bool                         domestic,        // true=国内, false=海外
        const Byte*                  packet,
        int                          length,
        const ppp::function<void(ppp::vector<Byte>)>& callback);

    // 设置出口 IP（从服务器返回的 Extensions.ClientExitIP 获取）
    void SetExitIP(const boost::asio::ip::address& ip) { exit_ip_ = ip; }

    // Linux/Android VPN 场景下，新建 UDP/TCP/TLS/STUN/bootstrap socket
    // 必须在 connect/send 前调用该回调，避免请求重新进入隧道。
    using ProtectSocketCallback = ppp::function<bool(int native_handle)>;
    void SetProtectSocketCallback(const ProtectSocketCallback& cb) { protect_socket_ = cb; }

    // 内置提供商查询
    static bool                                    HasProvider(const ppp::string& name);
    static const ppp::vector<ServerEntry>*         GetProvider(const ppp::string& name);

private:
    // 协议发送（全部异步）
    void SendDoh(const ServerEntry& entry, const Byte* packet, int length,
                 const ppp::function<void(ppp::vector<Byte>)>& callback);
    void SendDot(const ServerEntry& entry, const Byte* packet, int length,
                 const ppp::function<void(ppp::vector<Byte>)>& callback);
    void SendTcp(const ServerEntry& entry, const Byte* packet, int length,
                 const ppp::function<void(ppp::vector<Byte>)>& callback);
    void SendUdp(const ServerEntry& entry, const Byte* packet, int length,
                 const ppp::function<void(ppp::vector<Byte>)>& callback);

    // ECS 构造（内联，~40 行）
    ppp::vector<Byte> BuildEcsPacket(const Byte* packet, int length,
                                     const boost::asio::ip::address& client_ip);

    // Bootstrap 解析
    void ResolveHostnameWithBootstrap(
        const ppp::string& hostname,
        const ppp::vector<boost::asio::ip::address>& bootstrap_ips,
        const ppp::function<void(ppp::vector<boost::asio::ip::address>)>& callback);

    // STUN 出口 IP 检测（fallback，~50 行）
    void DetectExitIPViaStun(const ppp::function<void(boost::asio::ip::address)>& callback);

    // 按优先级尝试协议
    void TryProtocols(ppp::vector<ServerEntry>& entries, size_t index,
                      const Byte* packet, int length,
                      const ppp::function<void(ppp::vector<Byte>)>& callback);

    boost::asio::io_context& context_;

    // 内置提供商表（静态）
    static const ppp::unordered_map<ppp::string, ppp::vector<ServerEntry>> kProviders;

    // 用户配置的 domestic/foreign 提供商名
    ppp::string domestic_provider_;
    ppp::string foreign_provider_;

    // 客户端出口 IP（三级 fallback：override_ip > 服务器返回 > STUN）
    boost::asio::ip::address exit_ip_;

    // TLS 连接池（按 hostname 索引）
    ppp::unordered_map<ppp::string, std::shared_ptr<boost::asio::ssl::context>> ssl_contexts_;

    ProtectSocketCallback protect_socket_;
};

} // namespace ppp::dns
```

### 关键实现细节

#### DoH（基于 boost::beast::http，异步）

```cpp
void DnsResolver::SendDoh(const ServerEntry& entry, const Byte* packet,
                          int length, const ppp::function<void(ppp::vector<Byte>)>& callback) {
    // 1. 解析 bootstrap IP（若域名未缓存）
    // 2. 建立 TLS 连接（boost::asio::ssl::stream<tcp::socket>）
    //    在 connect 前对 native_handle 调用 protect_socket_（如存在）
    // 3. 构造 HTTP POST 请求:
    //    POST /dns-query HTTP/1.1
    //    Host: doh.pub
    //    Content-Type: application/dns-message
    //    Content-Length: <len>
    //    <binary DNS message>
    // 4. boost::beast::http::async_write / async_read
    // 5. 提取响应 body 作为原始 DNS message
    // 6. callback(response_bytes)
}
```

#### DoT（基于 boost::asio::ssl，异步）

```cpp
void DnsResolver::SendDot(const ServerEntry& entry, const Byte* packet,
                          int length, const ppp::function<void(ppp::vector<Byte>)>& callback) {
    // 1. 建立 TLS 连接，SNI 设置为 entry.hostname
    //    在 connect 前对 native_handle 调用 protect_socket_（如存在）
    // 2. 发送 2 字节长度前缀 + DNS message（RFC 7858）
    // 3. 先读 2 字节长度，再读完整响应
    // 4. callback(response_bytes)
}
```

#### UDP/TCP（复用 Asio，与现有逻辑一致）

```cpp
void DnsResolver::SendUdp(const ServerEntry& entry, const Byte* packet,
                          int length, const ppp::function<void(ppp::vector<Byte>)>& callback) {
    // 直接 UDP send_to / async_receive_from；send 前对 native_handle 调用 protect_socket_（如存在）
    // 与现有 RedirectDnsServer 逻辑基本一致
}

void DnsResolver::SendTcp(const ServerEntry& entry, const Byte* packet,
                          int length, const ppp::function<void(ppp::vector<Byte>)>& callback) {
    // TCP 连接 + 2 字节长度前缀 + DNS message
}
```

#### Bootstrap DNS 解析

DoH/DoT 的服务器域名本身需要 DNS 解析。使用配置中的 `bootstrap` IP 数组：

```cpp
void DnsResolver::ResolveHostnameWithBootstrap(const ppp::string& hostname,
                                               const ppp::vector<boost::asio::ip::address>& bootstrap_ips,
                                               ...) {
    // 1. 若 hostname 已是 IP，直接返回
    // 2. 若 bootstrap 为空，可按配置选择系统 DNS 或失败降级
    // 3. 用 bootstrap IP 进行简化 UDP A/AAAA 查询或受控复用 vdns::ResolveAsync()
    // 4. 缓存解析结果（TTL 与 vdns 一致）
}
```

> 注意：bootstrap 解析应避免和业务查询形成循环依赖，并且它创建的 socket 同样要执行 protect。

#### 故障转移

```cpp
void DnsResolver::TryProtocols(ppp::vector<ServerEntry>& entries, size_t index,
                               const Byte* packet, int length,
                               const ppp::function<void(ppp::vector<Byte>)>& callback) {
    if (index >= entries.size()) {
        callback({});  // 全部失败
        return;
    }

    auto next = [this, entries, index, packet, length, callback]() {
        TryProtocols(entries, index + 1, packet, length, callback);
    };

    switch (entries[index].protocol) {
        case Protocol::DoH:
            SendDoh(entries[index], packet, length, [callback, next](ppp::vector<Byte> resp) {
                if (resp.empty()) next(); else callback(std::move(resp));
            });
            break;
        // ... DoT, TCP, UDP 同理
    }
}
```

---

## 修改现有代码的详细方案

### 1. `dns/Rule.h` — 新增 ProviderName 字段

```cpp
struct Rule final {
    ppp::string                         Host;
    bool                                Nic = false;
    boost::asio::ip::address            Server;
    ppp::string                         ProviderName;  // 新增：非空时走 DnsResolver 路径
    // ...
};
```

### 2. `dns/Rule.cpp` — 扩展 Load() 解析逻辑

在现有 `StringToAddress` 失败后，增加提供商名称检查：

```cpp
// 现有代码（保留）:
boost::asio::ip::address address = StringToAddress(segments[1], ec);
if (ec) {
    // 新增：检查是否为内置提供商名称
    if (ppp::dns::DnsResolver::HasProvider(segments[1])) {
        // 创建规则，ProviderName 存提供商名
        Ptr rule = make_shared_object<Rule>(Rule{ host, nic, {}, segments[1] });
        rules[host] = rule;
    }
    continue;  // 既不是 IP 也不是提供商名，跳过
}
```

### 3. `VEthernetNetworkSwitcher.cpp` — RedirectDnsServer 增加新路径

在 `Rule::Get()` 返回结果后，检查是否走新路径：

```cpp
// 现有代码获取 rulePtr 后:
ppp::app::client::dns::Rule::Ptr rulePtr = ppp::app::client::dns::Rule::Get(...);
if (NULLPTR != rulePtr) {
    if (!rulePtr->ProviderName.empty()) {
        // 新路径：走 DnsResolver 多协议解析
        bool domestic = rulePtr->Nic;
        dns_resolver_->ResolveAsync(
            rulePtr->ProviderName, domestic,
            messages->Buffer.get(), messages->Length,
            [sourceEP, destinationEP, destinationIP, this](ppp::vector<Byte> response) {
                if (!response.empty()) {
                    DatagramOutput(sourceEP,
                        boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT),
                        response.data(), response.size(), false);
                }
            });
        return true;
    }
    // 原有逻辑：rulePtr->Server 是 IP，直接 UDP 转发
    serverIP = rulePtr->Server;
    // ...
}
```

---

## 出口 IP 获取

```cpp
// 三级 fallback：override_ip > 服务器返回 > STUN
// DnsResolver 内部维护 exit_ip_ 成员，首次使用时初始化

// 优先级 1：客户端在 OnInformation 回调中缓存服务器返回的出口 IP
bool VEthernetNetworkSwitcher::OnInformation(
    const std::shared_ptr<VirtualEthernetInformation>& info,
    const VirtualEthernetInformationExtensions& extensions) noexcept {
    // ... 现有逻辑 ...

    // 缓存出口 IP 供 DnsResolver 使用
    if (extensions.ClientExitIP.is_v4()) {
        dns_resolver_->SetExitIP(extensions.ClientExitIP);
    }

    // ...
}

// 优先级 2：服务器在 Establish() 中填充 ClientExitIP
// VirtualEthernetSwitcher::Establish():
InformationEnvelope envelope = BuildInformationEnvelope(session_id, *established_information);
boost::system::error_code ec;
boost::asio::ip::tcp::endpoint remote_ep = transmission->GetRemoteEndPoint();
if (!ec) {
    envelope.Extensions.ClientExitIP = remote_ep.address();
}
envelope.ExtendedJson = envelope.Extensions.ToJson();

// 优先级 3：STUN fallback（仅在服务器未返回时触发）
// ResolveAsync 内部逻辑：
if (exit_ip_.is_unspecified()) {
    // 服务器未返回出口 IP，尝试 STUN
    DetectExitIPViaStun([this, ...](boost::asio::ip::address ip) {
        if (ip.is_v4()) exit_ip_ = ip;
        // 继续执行 ECS + DNS 查询...
    });
    return;
}
```

---

## 实现步骤

### Phase 1: 基础框架与 UDP provider 闭环（1-2 天）

1. 创建 `ppp/dns/DnsResolver.h` — 配置结构、提供商表、接口声明、socket protect 回调
2. 创建 `ppp/dns/DnsResolver.cpp` — 先实现 UDP 协议与请求包复制
3. 扩展 `dns::Rule` — 新增 `ProviderName` 字段，扩展 `Load()`
4. `RedirectDnsServer` 匹配 provider 时走新路径，旧 IP 规则路径保持不变
5. 集成测试：UDP provider + 现有 dns-rules.txt 格式

### Phase 2: TCP DNS + 平台 socket protect（1-2 天）

1. 实现 TCP DNS 2 字节长度前缀协议
2. 增加响应大小上限和超时
3. 为 UDP/TCP/bootstrap/STUN/DoT/DoH 预留统一 protect socket 回调
4. 集成测试：UDP/TCP 协议 + 旧路径兼容

### Phase 3: DoT 实现（1-2 天）

1. 基于 `boost::asio::ssl::stream<tcp::socket>` 实现 DoT 客户端
2. Bootstrap DNS 解析
3. SNI 与证书校验策略
4. 集成测试

### Phase 4: DoH HTTP/1.1 实现（2-3 天）

1. 基于 `boost::beast::http` 实现异步 DoH 客户端
2. 首版仅 HTTP/1.1；HTTP/2 不纳入本阶段
3. Bootstrap DNS 解析（复用 Phase 2 逻辑）
4. 集成测试

### Phase 5: ECS + 出口 IP（1 天）

1. `VirtualEthernetInformation` 新增 `ClientExitIP` 字段（服务器填/客户端读）
2. STUN fallback 实现（~50 行，内联在 DnsResolver.cpp）
3. ECS OPT RR 构造（内联在 DnsResolver.cpp 中）
4. 国内查询自动添加 ECS
5. 集成测试

### Phase 6: 集成 + 故障转移 + 连接池优化（1 天+）

1. 修改 `RedirectDnsServer` 增加新路径分支
2. 实现协议降级故障转移
3. 端到端测试：dns-rules.txt → DoH/DoT → vdns 缓存 → 响应注入
4. 性能测试

---

## 性能优化

| 优化项 | 说明 |
|--------|------|
| **TLS 连接池** | 后续优化项：按 hostname 复用 SSL context 和连接，避免重复握手；首版可先每请求新建连接保证正确性 |
| **Bootstrap 缓存** | 解析结果缓存，与 vdns TTL 一致 |
| **减少拷贝** | 异步请求包必须复制以保证生命周期；响应路径尽量减少不必要复制 |
| **出口 IP 三级 fallback** | 服务器返回(0 RTT) > STUN(1 RTT) > 手动配置，绝大多数情况走第一条路径 |
| **协议降级** | 首选协议超时后立即尝试下一个，不等待太久 |
| **UDP 优先** | 简写配置时优先尝试 DoH，但若用户明确指定 `udp` 则跳过 TLS 开销 |

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
            "domestic": { "protocol": "udp", "address": "119.29.29.29" },
            "foreign": { "protocol": "udp", "address": "1.1.1.1" }
        }
    }
}
```

### 故障转移

```json
{
    "dns": {
        "servers": {
            "domestic": [
                { "protocol": "doh", "url": "https://doh.pub/dns-query", "bootstrap": ["119.29.29.29"] },
                { "protocol": "dot", "hostname": "dot.pub", "bootstrap": ["119.29.29.29"] },
                { "protocol": "udp", "address": "119.29.29.29" }
            ],
            "foreign": [
                { "protocol": "doh", "url": "https://cloudflare-dns.com/dns-query", "bootstrap": ["1.1.1.1"] },
                { "protocol": "dot", "hostname": "cloudflare-dns.com", "bootstrap": ["1.1.1.1"] },
                { "protocol": "tcp", "address": "1.1.1.1" }
            ]
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

---

## 标签

`dns` `doh` `dot` `ecs` `feature`
