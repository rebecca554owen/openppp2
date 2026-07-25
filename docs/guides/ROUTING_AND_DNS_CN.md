# 路由与 DNS

> **状态：**当前有效
> **类型：**指南
> **最后核对：**人类可读路由规则、DNS 与 UDP 路由，2026-07-24
> **上一层索引：**[任务指南](README_CN.md) · **English：**[Routing and DNS](ROUTING_AND_DNS.md)

## 范围

普通客户端模式会根据 CLI 输入、已解析的配置、协商会话状态和宿主网络事实生成路由/DNS 计划。这是宿主机集成，并不是防火墙或防泄漏保证：不同平台、权限和网络状态下，路由/DNS 修改均可能失败或表现不同。

`--mode=proxy` 走另一条路径，会跳过普通 TUN 路由、bypass 列表、DNS 规则和 geo-rule 初始化。请参阅 [Proxy-only 模式](PROXY_MODE_CN.md)。

## 选择输入方式

| 需求 | 支持的接口 | 说明 |
|---|---|---|
| 加载人类可读路由策略 | `routing.rules` | 下文所述规则文件的路径。 |
| 加载本地 bypass 列表 | `--bypass=<path>` | CLI 默认路径为 `./ip.txt`。 |
| 加载本地 DNS 规则文件 | `--dns-rules=<path>` | CLI 默认路径为 `./dns-rules.txt`；启动时检查本地文件。 |
| 启动时指定 DNS 地址 | `--dns=<address>` | 接受形式见 CLI 参考。 |
| 在配置中定义路由列表输入 | `client.routes` | 每个可用来源包含 `ngw` 和 `path`；Linux 还接受 `nic`。 |
| 远程刷新路由列表 | `client.routes[].vbgp` | `vbgp` 是单条路由的远程 URL，不是顶层 `vbgp.url`。 |
| 启用 VIRR 路径 | `--virr=...` | 这是内置国家列表流程，不是任意 URL 设置。 |
| 启用 vBGP 刷新行为 | `--vbgp=yes|no` | 刷新时间由 `vbgp.update-interval` 配置。 |

不要使用 `client.bypass`、`client.dns-rules`、`virr.url` 或 `vbgp.url` 等 JSON 键：它们不是当前解析接口。

## 人类可读路由规则

`routing.rules` 是本地规则文件路径，不是内联规则文本。空值（默认值，trim 后判断）不会创建 human-rule 策略，并保留 legacy 路由输入。配置非空文件时，它仍与 `--bypass`、`--dns-rules`、`client.routes` 和平台提供的 legacy 列表共存。配置的规则文件无法打开、解析或编译时，客户端初始化失败，不会静默忽略。

最小 JSON 配置：

```json
{
  "routing": {
    "rules": "./routing.rules",
    "tcp-domain-sniff": true
  },
  "dns": {
    "fake-ip": {
      "enabled": true
    }
  }
}
```

简明 `routing.rules` 示例：

```text
default auto
dns direct doh.pub
dns proxy cloudflare

[direct]
lan
192.0.2.7
198.51.100.0/24
example.com
=login.example.com
*.internal.example.com
regexp:^api[0-9]+\.example\.com$

[proxy]
203.0.113.0/24
example.net
```

### 语法

- `default auto|direct|proxy` 是合法 IPv4 目标未命中任何 human CIDR 时的 fallback。`auto` 同时是隐式默认值，会把 IPv4 选择交回 legacy 行为。
- `dns direct|proxy <provider>` 分别为 `direct` 与 `proxy` domain action 选择一个内置 DNS provider；每种 action 最多一个 provider。
- `[direct]` 和 `[proxy]` 设置后续规则行的 action，直到下一个 section；section 外的规则无效。
- `lan` 展开为 `10.0.0.0/8`、`100.64.0.0/10`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12` 和 `192.168.0.0/16`。
- `geo:cc` 使用两字母国家代码，并同时编译该代码的 GeoIP 和 GeoSite 来源。
- 裸 IPv4 地址等价于 `/32`；IPv4 CIDR 前缀范围为 `0..32`，并规范化为网络地址。
- `example.com` 是 suffix 规则，匹配 apex 和子域；`=example.com` 是 exact；`*.example.com` 只匹配子域，不匹配 apex。
- `regexp:<pattern>` 是使用搜索语义（而非隐式全文匹配）的大小写不敏感 ECMAScript 正则表达式。

`default` 与 `dns` 是全局 directive，在有无 active section 时都可使用，且不会改变当前 section。每条 section rule 必须是一个 whitespace-delimited token，因此 regexp 不能包含 literal whitespace。Directive、section、国家代码和非 regexp domain 均不区分大小写。规范化后的非 regexp domain 最长 253 字符；每个 label 长度为 1–63，只能使用字母、数字和 `-` 且首尾不能是 `-`；可以有一个尾随点，不执行 IDNA 转换。行首尾空白会被忽略。`#` 仅在行首或前一个字符为空白时开始注释。

重复的等价规则会去重。action/provider 冲突的重复项、畸形行、无效 domain/CIDR/regexp 或未知 provider 会拒绝整个文件，不会部分接受规则。

### 匹配优先级

匹配不是全局“文件中第一条命中生效”：

- Domain 规则中，所有文件内显式规则都优先于所有 GeoSite 派生规则。每种来源内部依次为 exact、regexp、最长 suffix/subdomain；domain 长度相同时，严格 subdomain 规则优先于 suffix。只有其他条件完全相同时才按声明顺序决定。
- IPv4 先在显式规则中执行最长前缀匹配。完全没有显式 IPv4 命中时，才在 GeoIP 派生规则中执行最长前缀匹配；相同前缀保留先编译的规则。
- 合法 IPv4 目标未命中任何 CIDR 时应用 `default`；`default auto` 会把 IPv4 TCP/UDP 选择交回 legacy 行为。DNS domain 未命中则继续走 legacy/unmatched DNS 路径。Human domain 命中优先于 legacy DNS 规则。

Human IPv4 路由会与 legacy 路由输入合并。同 network/prefix 的 human route 通常覆盖 legacy route；但已有 legacy `/32` 会被保守保护，不会被 human、DNS 或 fake-IP `/32` route 覆盖。

### TCP domain 嗅探

`routing.tcp-domain-sniff` 默认为 `false`；按上面的 JSON 示例设为 `true` 才会启用。TCP 路由的实际优先级为：已有 fake-IP action > 嗅探命中的显式 domain 规则 > 真实目标的 IPv4 规则 > `default`。只有目标是真实（非 fake）IPv4 TCP、开关已开启，且加载的 human policy 含有 domain 规则时，才尝试嗅探。

客户端以不消费数据的方式检查当前 flow 开头的 TLS SNI 或 HTTP Host。显式 domain 命中只能覆盖当前 flow 的 IP/default 决策，不会生成或安装 domain-derived `/32` route。ECH、TLS 无 SNI、非 HTTP/TLS 流量、超时、畸形输入，以及其他不支持或未命中的结果，均保留 IP/default fallback。关闭嗅探时，TCP 只使用已有 fake-IP 状态或目标 IP/`default`。UDP 与 QUIC 始终使用目标 IP/`default`，不使用 domain 嗅探。

在支持的非 iOS 平台上，`Direct` 会在 connect 前对底层连接 socket 执行 per-socket binding/protection。`ForceDirect` 采用 fail-closed：必需 protector 缺失或 binding/protection 失败时拒绝该 flow，不会回退 tunnel。iOS 会拒绝 `Direct`。`Auto` 保持 legacy-compatible 的选择与 bypass 行为。

## DNS provider 与 fake IP

`dns` directive 中的 provider 必须是内置目录中的 short name。当前名称为 `doh.pub`、`alidns`、`baidu`、`360`、`114`、`tuna`、`cloudflare`、`google`、`quad9`、`adguard`、`nextdns`、`mullvad`。未知名称会使规则文件解析失败。

Human domain 命中时，`direct` 使用 `dns direct` 指定的 provider；没有该 directive 时回退到 `dns.servers.domestic`。`proxy` 同理使用 `dns proxy`，否则回退到 `dns.servers.foreign`。解析不会切换到另一个 provider：大多数 provider 依次尝试 DoH、DoT、TCP、UDP；`baidu` 与 `114` 不含 DoT。若回退值不是目录 short name，则产生 provider miss，不会自动改选其他 provider。`direct` lookup 会标记为 domestic，因此启用的 domestic ECS 处理会应用于它；`proxy` 不标记为 domestic。

Human domain 规则（包括 GeoSite 派生规则）在 `dns.fake-ip.enabled=false` 时仍然有效，启动不会拒绝。此模式下，命中的 A query 使用 domain action 配置的 provider（或 domestic/foreign fallback）并返回真实 A；不会请求 fake allocation，也不会创建 sticky mapping、fake cache entry 或 fake-IP route。`routing.tcp-domain-sniff` 不改变该 DNS 决策。

启用 `dns.fake-ip.enabled=true` 时，human domain action 通过合成 IPv4 地址应用于 A 查询。Fake allocation 会排除空名称、reverse-ARPA 名称、精确 `localhost`，以及以 `.local` 或 `.lan` 结尾的名称。Strict human 命中的 A query 采用 fail-closed：hostname 不适合 fake、allocation 失败或 response build 失败时都会拒绝，不回退真实或 legacy DNS answer。

Fake-IP allocation 会记录初始 action：

- 若 human domain 规则命中，该 action 是 sticky；之后的真实 IPv4 规则不会覆盖它；
- 若没有 human domain 命中，则由解析后的真实 IPv4 规则或 `default` 提供最终 action；
- 未解析的 fake IP 会被拒绝，不会做推测性路由。

被拦截的未命中 A query 也可能获得 fake IP；`default` 本身不是 allocation 触发条件。只有 `default direct|proxy` 不算 domain 命中，因此不会产生 domain-sticky action。

## GeoIP 与 GeoSite 数据

`geo:cc` 从 `geo-rules.geoip-dat` 和可选的 `geo-rules.geoip` 文本路径读取 GeoIP 来源，从 `geo-rules.geosite-dat` 和可选的 `geo-rules.geosite` 文本路径读取 GeoSite 来源。每个使用的国家代码都要求两类来源均有配置。`geo-rules.enabled` 不控制这条 human-rule 编译路径，`geo-rules.country` 也不是 selector；selector 是每条规则中的 `cc`。

Binary 路径默认为 `GeoIP.dat` 与 `GeoSite.dat`；只有非空 JSON 值才会覆盖这些默认值。增加文本路径不会关闭 binary source：每个非空配置来源都会读取，来源缺失或无法读取会导致初始化失败。

Binary reader 接受 v2ray/Xray/MetaCubeX protobuf `.dat` 文件，并按 `cc` 选择 country/category。GeoIP IPv4 CIDR 转为路由规则；binary IPv6 CIDR 可以解析，但会被仅 IPv4 的编译器跳过。GeoSite `Domain`、`Full`、`Regex` 分别转为 suffix、exact、regexp 规则；`Plain` 会跳过。Protobuf wire 数据畸形或截断、selector 缺失时为 fatal。单个不可用的 binary CIDR，以及 type 未知或 value 为空的 GeoSite 条目会跳过；已选中的 binary Domain/Full 不符合 human domain 语法，或 Regex 无法编译时为 fatal。

GeoIP 文本文件接受 IPv4/IPv6 地址或 CIDR，也接受可选的 `geoip:` 前缀；IPv6 项会跳过。GeoSite 文本文件接受 `domain:`/`suffix:`、`full:`、`regexp:`/`regex:` 和 `plain:`（plain 项跳过）；无前缀项默认为 suffix。文本来源没有国家分类，因此其条目会应用于每一条 `geo:cc` 声明。文本条目解析失败以及文本 domain/regexp 编译失败会跳过并计数；文件无法访问或读取时为 fatal。

## IPv4、IPv6 与 AAAA 限制

Human routing 当前只支持 IPv4 规则。Human 规则文件中的 IPv6 literal/CIDR 无效，GeoIP IPv6 条目会跳过，human IPv4 规则与 `default` 都不会应用于 IPv6 目标。

Fake IP 仅用于 A 查询。Human domain `direct` 或 `proxy` 规则命中 AAAA 查询时，客户端会合成 RCODE 为 NOERROR 且不含 AAAA answer 的响应；未命中的 domain 继续遵循 resolver 现有的 IPv6 response 策略。只有 human `default` 不算 domain 命中，也不会触发此 AAAA 行为。

## UDP action 矩阵

| Human action | Android IPv4 | 非 Android 或 IPv6 |
|---|---|---|
| `Direct` | 受保护的物理 UDP socket | 拒绝（fail closed） |
| `Proxy` | Tunnel | Tunnel |
| `Auto` | 仅 legacy bypass 命中时使用物理 socket；否则走 tunnel | Tunnel |

Android client initialization 在无法创建必需 protector 时直接失败。对于 direct 数据 UDP port，open 时 protector 缺失或 `Protect()` 失败都会在 flush 排队消息和启动 receive loop 前 dispose port，且不会回退 tunnel。Android IPv6 不使用物理 direct 路径。

此矩阵只描述客户端数据 UDP。Android `DnsUdpRelay` 在 protector pointer 缺失时只记录 warning 并继续；显式 `Protect()` 失败才进入该 relay 的 fallback/error 路径。

## 最小路由来源示例

配置形式需要网关（`ngw`）和本地路由列表路径。在验证宿主拓扑前，请只使用文档地址和相对路径。

```json
{
  "client": {
    "routes": [
      {
        "ngw": "192.0.2.1",
        "path": "./routes.txt"
      }
    ]
  }
}
```

普通客户端显式提供本地列表文件的启动方式：

```bash
./ppp --mode=client --config=./client.json \
  --bypass=./bypass.txt \
  --dns-rules=./dns-rules.txt
```

该命令只选择输入来源，并不证明每条路由或每项 resolver 修改都成功。连接后应检查宿主机路由/DNS 状态和运行时诊断。

## 已解析的 DNS 设置

当前解析器包含以下分组：

- `udp.dns.timeout`、`udp.dns.ttl`、`udp.dns.turbo`、`udp.dns.cache`、`udp.dns.redirect`；
- `dns.servers.domestic` 和 `dns.servers.foreign`（provider/server 条目）；
- `dns.intercept-unmatched`；
- `dns.ecs.enabled` 和 `dns.ecs.override-ip`；
- `dns.tls.verify-peer`、`dns.stun.candidates`、`dns.fake-ip.{enabled,range}`。

这些设置用于 DNS 策略和可达性规划。它们不表示每个 resolver 总会经固定物理网卡可达，也不能替代宿主机防火墙策略。

## 运维顺序

1. 用明确配置路径启动普通客户端，而不是 proxy 模式。
2. 将 bypass/DNS 规则文件保留在本地，并在启动前检查其权限和内容。
3. 确保 VPN 服务端/控制端点不会被正在修改的路由递归影响。
4. 连接后检查生成的宿主机路由、解析行为和 `ppp` 诊断。
5. 路由/DNS 操作失败应作为连通性问题处理，不能把它理解为已自动 fail-closed。

## 相关页面

- [配置参考](../reference/CONFIGURATION_CN.md)
- [CLI 参考](../reference/CLI_REFERENCE_CN.md)
- [Proxy-only 模式](PROXY_MODE_CN.md)
- [运维与故障排查](../operations/OPERATIONS_CN.md)