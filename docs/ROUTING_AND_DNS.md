# Routing And DNS

[中文版本](ROUTING_AND_DNS_CN.md)

## Scope

This document explains the real routing and DNS steering model used by OPENPPP2.
In the code, these are not separate concerns. They form one traffic-classification system on the client,
with continued DNS handling on the server.

Main anchors:

- `ppp/app/client/VEthernetNetworkSwitcher.*`
- `ppp/app/client/dns/Rule.*`
- `ppp/app/server/VirtualEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetDatagramPort.*`
- `ppp/app/server/VirtualEthernetNamespaceCache.*`

---

## Architecture Overview

```mermaid
flowchart TD
    A[Client application traffic] --> B[VEthernetNetworkSwitcher]
    B --> C{Traffic classification}
    C -->|bypass list match| D[Direct path: local NIC]
    C -->|no bypass match| E[Tunnel path: VEthernetExchanger]
    
    F[DNS query] --> G{DNS rule match}
    G -->|rule: use resolver X| H[Route to resolver X]
    G -->|no rule| I[Default resolver]
    H --> J{Resolver reachable?}
    J -->|yes| K[Query resolver X]
    J -->|no| L[Fallback to default]
    
    E --> M[Server VirtualEthernetExchanger]
    M --> N{DNS redirect?}
    N -->|yes| O[VirtualEthernetNamespaceCache]
    N -->|no| P[Forward UDP to real destination]
    O --> Q{cache hit?}
    Q -->|yes| R[Return cached result]
    Q -->|no| S[Forward to upstream resolver]
```

---

## Core Idea

The client decides what goes local, what goes to the tunnel, and which DNS servers must remain reachable.

The server continues the DNS path by:
- answering from cache (fast path)
- redirecting to a configured upstream resolver
- forwarding normally when no special rule applies

---

## Client-Side Ownership

`VEthernetNetworkSwitcher` owns the client-side route and DNS state.

### Route Information Base

| Field | Description |
|-------|-------------|
| `rib_` | Route information base — all known routes |
| `fib_` | Forwarding information base — active lookup table |
| `ribs_` | Loaded IP-list sources (files, URLs) |
| `vbgp_` | Remote route sources (vBGP) |

### DNS State

| Field | Description |
|-------|-------------|
| `dns_rules_` | DNS rules (domain → resolver mapping) |
| `dns_serverss_` | DNS server route assignments |

Source: `ppp/app/client/VEthernetNetworkSwitcher.h`

---

## Route Construction

The client builds routes from multiple sources:

```mermaid
flowchart TD
    A[Virtual adapter subnet] --> F[RIB / FIB]
    B[Bypass IP-list files] --> F
    C[Remote IP-list URLs] --> F
    D[Tunnel server reachability] --> F
    E[DNS server reachability] --> F
    G[vBGP remote routes] --> F
    F --> H[FIB: active forwarding decisions]
```

### Key Methods

```cpp
/**
 * @brief Add all routes from all configured sources.
 * @param y  Yield context for async IP-list loading.
 * @return   true if all routes were applied successfully.
 */
bool AddAllRoute(YieldContext& y) noexcept;

/**
 * @brief Load and add routes from an IP-list source.
 * @param path_or_url  File path or HTTP/HTTPS URL of IP-list.
 * @return             Number of routes added.
 */
int AddLoadIPList(const ppp::string& path_or_url) noexcept;

/**
 * @brief Load IP-list from multiple file paths.
 * @param paths  Vector of file paths.
 * @return       Total routes loaded.
 */
int LoadAllIPListWithFilePaths(const ppp::vector<ppp::string>& paths) noexcept;

/**
 * @brief Add a reachability route for a remote endpoint.
 * @param endpoint  The remote endpoint (server or DNS server).
 * @return          true if route was added.
 */
bool AddRemoteEndPointToIPList(const IPEndPoint& endpoint) noexcept;

/**
 * @brief Add a route entry to the OS routing table.
 * @param network    Network address.
 * @param mask       Subnet mask.
 * @param gateway    Gateway address.
 * @return           true on success.
 */
bool AddRoute(UInt32 network, UInt32 mask, UInt32 gateway) noexcept;

/**
 * @brief Protect the default route from being overwritten by the tunnel.
 * @return true if default route was successfully protected.
 */
bool ProtectDefaultRoute() noexcept;
```

Source: `ppp/app/client/VEthernetNetworkSwitcher.h`

---

## DNS Rules

Client DNS rules decide which resolver to use for a domain or domain pattern.

### Rule Matching

```mermaid
flowchart TD
    A[DNS query for domain X] --> B[Check dns_rules_]
    B --> C{Rule match?}
    C -->|suffix match| D[Use resolver from rule]
    C -->|wildcard match| D
    C -->|exact match| D
    C -->|no match| E[Use default resolver]
    D --> F{Resolver reachable?}
    F -->|yes| G[Send query to matched resolver]
    F -->|no| E
```

The resolver decision is tied to route reachability:
a rule is only useful if the path to the resolver is actually available.

### DNS Rule Format

```json
"dns-rules": [
  "rules://path/to/dns-rules.txt"
]
```

The rules file format uses domain suffix / wildcard entries, each mapped to a resolver address.

Source: `ppp/app/client/dns/Rule.h`

---

## DNS Server Route Assignment

DNS servers are treated as reachability-sensitive endpoints.

When the client configures a DNS server:
1. A direct route to the DNS server is added via the physical NIC (not through the tunnel).
2. This ensures DNS queries to this server always reach it, regardless of default route changes.

```cpp
/**
 * @brief Add routes to make DNS servers reachable directly.
 * @return true if all DNS server routes were added.
 */
bool AddRouteWithDnsServers() noexcept;

/**
 * @brief Remove DNS server reachability routes.
 * @return true if routes were removed.
 */
bool DeleteRouteWithDnsServers() noexcept;
```

---

## Server-Side DNS Path

On the server side, DNS handling flows through:

```mermaid
sequenceDiagram
    participant Client as Client
    participant Exchanger as VirtualEthernetExchanger
    participant Cache as VirtualEthernetNamespaceCache
    participant Upstream as Upstream DNS

    Client->>Exchanger: UDP packet to port 53
    Exchanger->>Exchanger: RedirectDnsQuery()
    Exchanger->>Cache: NamespaceQuery(hostname)
    alt cache hit
        Cache-->>Exchanger: cached IP address
        Exchanger-->>Client: DNS response (synthesized)
    else cache miss
        Cache->>Upstream: Forward DNS query
        Upstream-->>Cache: DNS response
        Cache->>Cache: Store result with TTL
        Cache-->>Exchanger: IP address
        Exchanger-->>Client: DNS response
    end
```

### Server DNS API

```cpp
/**
 * @brief Redirect a DNS query through the namespace cache.
 * @param y          Yield context.
 * @param src        Source endpoint (client).
 * @param dns_data   Raw DNS query packet.
 * @param length     Length of DNS packet.
 * @return           true if query was handled.
 */
bool RedirectDnsQuery(YieldContext& y,
                      const IPEndPoint& src,
                      const Byte* dns_data,
                      int length) noexcept;
```

Source: `ppp/app/server/VirtualEthernetExchanger.h`

### Namespace Cache

`VirtualEthernetNamespaceCache` maintains a TTL-based DNS cache:

```cpp
/**
 * @brief Query the namespace cache for a hostname.
 * @param y         Yield context.
 * @param hostname  The hostname to resolve.
 * @return          Resolved IP address, or IPEndPoint::None on failure.
 */
IPEndPoint Query(YieldContext& y, const ppp::string& hostname) noexcept;

/**
 * @brief Insert a resolved entry into the cache.
 * @param hostname  The resolved hostname.
 * @param address   The IP address result.
 * @param ttl       Time-to-live in seconds.
 */
void Insert(const ppp::string& hostname, const IPEndPoint& address, int ttl) noexcept;
```

Source: `ppp/app/server/VirtualEthernetNamespaceCache.h`

---

## Path Model

```mermaid
flowchart TD
    A[Local packet or query] --> B[Classify]
    B --> C{bypass?}
    C -->|yes| D[Stay local: direct NIC]
    C -->|no| E[Send into tunnel]
    E --> F[Route / DNS steering at server]
    F --> G{DNS redirect rule?}
    G -->|yes| H[VirtualEthernetNamespaceCache]
    G -->|no| I[Forward to real destination]
    H --> J[Return cached or upstream result]
    I --> K[Destination responds]
    J --> L[Return path to client]
    K --> L
```

---

## IP-List Sources

OPENPPP2 supports loading IP bypass lists from multiple sources:

| Source type | Example | Description |
|-------------|---------|-------------|
| Local file | `/etc/openppp2/bypass.txt` | Plain text file, one CIDR per line |
| HTTP URL | `http://example.com/bypass.txt` | Fetched on startup |
| HTTPS URL | `https://cdn.example.com/bypass.txt` | TLS-fetched on startup |
| VIRR refresh | Configured `virr.update-interval` | Periodic automatic refresh |

### VIRR Configuration

```json
"virr": {
    "update-interval": 86400,
    "url": "https://example.com/bypass-list.txt"
}
```

When the bypass list is refreshed, the routing table is updated accordingly.

---

## vBGP Remote Routes

The vBGP subsystem allows loading route information from a remote BGP-style source:

```json
"vbgp": {
    "update-interval": 3600,
    "url": "https://example.com/bgp-routes.txt"
}
```

Routes from vBGP are merged into the client RIB.

---

## Operational Meaning

Routing and DNS are not separate knobs. They form a unified traffic classification policy:

| Concern | How it connects |
|---------|----------------|
| Bypass list | Determines which destinations skip the tunnel |
| DNS rules | Determines which resolver is used per domain |
| Resolver reachability | Resolver routes keep resolvers reachable even when default route is redirected |
| Server DNS cache | Reduces repeated upstream DNS lookups |
| IPv6 transit | Can alter what "reachable" means for IPv6 destinations |
| Static echo | Can provide a separate path that bypasses DNS decisions |

---

## Configuration Reference

| Config key | Default | Description |
|------------|---------|-------------|
| `client.dns-rules` | `[]` | DNS rules file paths or URLs |
| `client.bypass` | `[]` | IP bypass list file paths or URLs |
| `geo-rules.enabled` | `false` | Generate extra bypass and DNS-rule files from local text GeoIP/GeoSite inputs |
| `geo-rules.geoip-dat` | `GeoIP.dat` | Local cache path for downloaded GeoIP dat; currently downloaded but not parsed |
| `geo-rules.geosite-dat` | `GeoSite.dat` | Local cache path for downloaded GeoSite dat; currently downloaded but not parsed |
| `geo-rules.geoip-download-url` | `""` | Optional HTTP/HTTPS URL used to download/update `geoip-dat` |
| `geo-rules.geosite-download-url` | `""` | Optional HTTP/HTTPS URL used to download/update `geosite-dat` |
| `geo-rules.geoip` | `[]` | Local text CIDR source file path or array of paths |
| `geo-rules.geosite` | `[]` | Local text domain source file path or array of paths |
| `geo-rules.append-bypass` | `[]` | Extra inline CIDRs or local CIDR files appended after generated GeoIP CIDRs |
| `geo-rules.append-dns-rules` | `[]` | Extra inline DNS rules/domains or `rules://` local files appended after generated GeoSite rules |
| `virr.update-interval` | `86400` | Bypass list refresh interval (seconds) |
| `virr.url` | `""` | Bypass list URL for periodic refresh |
| `vbgp.update-interval` | `3600` | vBGP route refresh interval (seconds) |
| `vbgp.url` | `""` | vBGP route source URL |
| `server.dns` | system | Upstream DNS server for server-side queries |

---

## Error Code Reference

Routing and DNS `ppp::diagnostics::ErrorCode` values:

| ErrorCode | Description |
|-----------|-------------|
| `RouteAddFailed` | Failed to add a route to the OS routing table |
| `RouteDeleteFailed` | Failed to remove a route |
| `DnsConfigFailed` | DNS configuration failed |
| `DnsResolverUnreachable` | Configured DNS resolver not reachable |
| `IPListLoadFailed` | Failed to load IP bypass list |
| `DefaultRouteProtectionFailed` | Failed to protect the default route |
| `VirtualAdapterSubnetConflict` | Virtual adapter subnet overlaps with bypass list |

---

## Usage Examples

### Configuring a split-tunnel bypass list

```json
{
  "client": {
    "bypass": [
      "/etc/openppp2/china-cidr.txt",
      "https://raw.githubusercontent.com/user/repo/main/bypass.txt"
    ]
  }
}
```

### Configuring domain-based DNS rules

```json
{
  "client": {
    "dns-rules": [
      "rules:///etc/openppp2/dns-rules.txt"
    ]
  }
}
```

DNS rules file format example:

```
# Route these domains to the local DNS server
.example.com 192.168.1.1
.localnet.com 192.168.1.1

# Route these to a specific upstream
.google.com 8.8.8.8
.cloudflare.com 1.1.1.1
```

### Generating GeoIP / GeoSite split rules

`geo-rules` is optional and disabled by default. When enabled, OPENPPP2 reads local text GeoIP/GeoSite inputs, writes generated bypass and DNS-rule files, and then appends those files to the existing route/DNS loading paths. It does not replace `client.bypass` or `client.dns-rules`.

```json
{
  "geo-rules": {
    "enabled": true,
    "country": "cn",
    "geoip-dat": "/var/lib/openppp2/GeoIP.dat",
    "geosite-dat": "/var/lib/openppp2/GeoSite.dat",
    "geoip-download-url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    "geosite-download-url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    "geoip": [
      "/etc/openppp2/geoip-cn.txt"
    ],
    "geosite": [
      "/etc/openppp2/geosite-cn.txt"
    ],
    "dns-provider-domestic": "doh.pub",
    "dns-provider-foreign": "cloudflare",
    "output-bypass": "/var/lib/openppp2/generated/bypass-cn.txt",
    "output-dns-rules": "/var/lib/openppp2/generated/dns-rules-cn.txt",
    "append-bypass": [
      "10.0.0.0/8",
      "/etc/openppp2/custom-bypass.txt"
    ],
    "append-dns-rules": [
      "example.cn /doh.pub/nic",
      "internal.example.cn",
      "rules:///etc/openppp2/custom-dns-rules.txt"
    ]
  },
  "dns": {
    "servers": {
      "domestic": "doh.pub",
      "foreign": "cloudflare"
    }
  }
}
```

Supported input formats are intentionally simple:

```text
# geoip-cn.txt: one CIDR per line
1.0.1.0/24
1.0.2.0/23
2408:8000::/20
```

```text
# geosite-cn.txt: one domain or matcher per line
baidu.com
.qq.com
domain:taobao.com
suffix:jd.com
full:example.cn
regexp:^.*\.example\.cn$
```

Important details:

- `geoip-download-url` and `geosite-download-url` download dat files into `geoip-dat` and `geosite-dat` at startup.
- Downloaded binary `geoip.dat` / `geosite.dat` files are cached but not parsed yet; rule generation still uses local text `geoip` / `geosite` inputs and append lists.
- The parser also accepts snake_case compatibility keys (`geoip_dat`, `geosite_dat`, `geoip_download_url`, `geosite_download_url`), but kebab-case is the documented form.
- `geoip` and `geosite` currently support local text files only; URL sources in these fields are not parsed yet.
- Generated DNS rules use `/<dns-provider-domestic>/nic`; if unset, the provider falls back to `dns.servers.domestic`, then `doh.pub`.
- `dns-provider-foreign` is parsed and reserved for future non-CN or `geolocation-!cn` generation, but is not consumed by the current generator.
- `append-bypass` is merged after GeoIP CIDRs and can contain inline CIDRs or local CIDR files.
- `append-dns-rules` is merged after GeoSite rules and can contain full rules, plain domains normalized with the domestic provider, or `rules://` local files.
- Android/iOS clients currently do not run the generator, so existing mobile DNS-rule injection paths remain unchanged.

### Checking if a bypass route is active (code)

```cpp
// ppp/app/client/VEthernetNetworkSwitcher.cpp
bool VEthernetNetworkSwitcher::IsRoutedThroughTunnel(UInt32 dest_ip) noexcept {
    auto it = fib_.find(dest_ip & mask_);
    if (it != fib_.end()) {
        return false;  // bypass hit: use local NIC
    }
    return true;  // no bypass: use tunnel
}
```

---

## What To Watch For In Code

- Route entries are not just static tables; they are built from host, tunnel, and bypass inputs.
- DNS servers are treated like reachability-sensitive endpoints — they get their own route entries.
- Server-side DNS behavior depends on namespace cache and datagram port state.
- IPv6 transit and static echo can alter what "reachable" means for specific destinations.
- The bypass list and DNS rules are refreshed independently; both should be consistent.

---

## Related Documents

- [`CONFIGURATION.md`](CONFIGURATION.md)
- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
- [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md)
- [`DEPLOYMENT.md`](DEPLOYMENT.md)
