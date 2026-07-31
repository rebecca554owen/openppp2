# Routing and DNS

> **Status:** Current
> **Type:** Guide
> **Last verified:** Human-readable routing rules, DNS, and UDP routing, 2026-07-24
> **Parent index:** [Task Guides](README.md) · **Chinese:** [路由与 DNS](ROUTING_AND_DNS_CN.md)

## Scope

Normal client mode builds a route/DNS plan from CLI inputs, parsed configuration, negotiated session state, and host-network facts. This is host integration, not a firewall or leak-prevention guarantee: route/DNS changes can fail or differ by platform and privilege.

`--mode=proxy` follows a different path and skips normal TUN route, bypass-list, DNS-rule, and geo-rule setup. See [Proxy-only mode](PROXY_MODE.md).

## Select an input surface

| Need | Supported surface | Notes |
|---|---|---|
| Load human-readable routing policy | `routing.rules` | Path to the rules file described below. |
| Load a local bypass list | `--bypass=<path>` | The default CLI path is `./ip.txt`. |
| Load a local DNS rule file | `--dns-rules=<path>` | The default CLI path is `./dns-rules.txt`; startup checks a local file. |
| Set a DNS address at launch | `--dns=<address>` | Use the CLI reference for accepted forms. |
| Define route-list inputs in configuration | `client.routes` | Each usable route source has `ngw` and `path`; Linux also accepts `nic`. |
| Refresh a route list remotely | `client.routes[].vbgp` | `vbgp` is the per-route remote URL; it is not a top-level `vbgp.url` field. |
| Enable the VIRR path | `--virr=...` | This is the built-in country-list workflow, not an arbitrary URL setting. |
| Enable vBGP refresh behavior | `--vbgp=yes|no` | Refresh timing is configured through `vbgp.update-interval`. |

Do not use JSON keys such as `client.bypass`, `client.dns-rules`, `virr.url`, or `vbgp.url`: they are not the current parsed interface.

## Human-readable routing rules

`routing.rules` is the path to a local rules file; it is not inline rule text. An empty value (the default, after trimming) does not create a human-rule policy and preserves the legacy routing inputs. A non-empty file coexists with `--bypass`, `--dns-rules`, `client.routes`, and platform-provided legacy lists. Failure to open, parse, or compile the configured rules file fails client initialization instead of silently ignoring it.

Minimal JSON configuration:

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

Compact `routing.rules` example:

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

### Syntax

- `default auto|direct|proxy` is the fallback for a valid IPv4 destination that matches no human CIDR. `auto`, also the implicit default, hands IPv4 selection back to legacy behavior.
- `dns direct|proxy <provider>` selects one built-in DNS provider for each of the `direct` and `proxy` domain actions. Each action may have at most one provider.
- `[direct]` and `[proxy]` select the action for following rule lines until the next section. A rule outside a section is invalid.
- `lan` expands to `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, and `192.168.0.0/16`.
- `geo:cc` uses a two-letter country code and compiles both GeoIP and GeoSite sources for that code.
- A bare IPv4 address is `/32`; IPv4 CIDR prefixes are `0..32` and are canonicalized to their network address.
- `example.com` is a suffix rule matching the apex and subdomains. `=example.com` is exact. `*.example.com` matches subdomains but not the apex.
- `regexp:<pattern>` is a case-insensitive ECMAScript regular expression evaluated with search semantics, not an implicit full-string match.

`default` and `dns` are global directives: they are accepted inside or outside a section and do not change the current section. Each section rule is one whitespace-delimited token, so a regexp cannot contain literal whitespace. Directives, sections, country codes, and non-regexp domains are case-insensitive. A normalized non-regexp domain is at most 253 characters, has labels of 1–63 characters using letters, digits, and `-` without leading/trailing `-`, may have one trailing dot, and receives no IDNA conversion. Leading/trailing whitespace is ignored. `#` starts a comment only at the start of a line or when preceded by whitespace.

Duplicate equivalent rules are deduplicated. Conflicting duplicate actions/providers, malformed lines, invalid domains/CIDRs/regexps, or unknown providers reject the entire file; rules are not partially accepted.

### Matching priority

Matching is not global “first line wins”:

- Domain rules prefer every explicit file rule over every GeoSite-derived rule. Within either origin, priority is exact, then regexp, then the longest matching suffix/subdomain; at equal domain length a strict subdomain rule wins over a suffix rule. Declaration order resolves only otherwise-equal matches.
- IPv4 rules first search explicit rules, using longest-prefix match within them. GeoIP-derived rules are searched only if no explicit IPv4 rule matches, again by longest prefix. Equal-prefix ties retain the first compiled rule.
- For a valid IPv4 destination with no CIDR match, `default` applies; `default auto` returns IPv4 TCP/UDP selection to legacy behavior. An unmatched DNS domain instead continues through the legacy/unmatched DNS path. Human domain matches take precedence over legacy DNS rules.

Human IPv4 routes are merged with legacy route inputs. A human route normally overlays the same legacy network/prefix, but an existing legacy `/32` is conservatively protected from replacement by human, DNS, or fake-IP `/32` routes.

### TCP domain sniffing

`routing.tcp-domain-sniff` defaults to `false`; set it to `true` as in the JSON example above to enable it. The effective TCP routing priority is: an existing fake-IP action, then a sniffed explicit domain rule, then the real destination's IPv4 rule, then `default`. Sniffing is attempted only for a real (non-fake) IPv4 TCP destination when the switch is enabled and the loaded human policy contains domain rules.

The client non-destructively inspects the beginning of the current flow for a TLS SNI or HTTP Host. An explicit domain match may replace the IP/default decision for this flow only. It does not generate or install a domain-derived `/32` route. ECH, TLS without SNI, non-HTTP/TLS traffic, timeout, malformed input, and any other unsupported or unmatched result all preserve the IP/default fallback. With sniffing off, TCP uses only fake-IP state or the destination IP/`default`. UDP and QUIC always use destination IP/`default`; they never use domain sniffing.

For `Direct` on supported non-iOS platforms, the client applies per-socket binding/protection to the underlying connection socket before connecting. `ForceDirect` is fail closed: if the required protector is missing or binding/protection fails, the flow is rejected rather than sent through the tunnel. iOS rejects `Direct`. `Auto` keeps legacy-compatible selection and bypass behavior.

## DNS providers and fake IP

The provider in a `dns` directive must be a short name in the built-in catalog. The current names are `doh.pub`, `alidns`, `baidu`, `360`, `114`, `tuna`, `cloudflare`, `google`, `quad9`, `adguard`, `nextdns`, and `mullvad`. Unknown names fail rules-file parsing.

For a human domain match, `direct` uses its `dns direct` provider, or falls back to `dns.servers.domestic` if the directive is absent; `proxy` similarly uses `dns proxy` or `dns.servers.foreign`. Resolution does not switch to another provider: most providers try DoH, DoT, TCP, then UDP, while `baidu` and `114` omit DoT. A fallback value that is not a catalog short name produces a provider miss rather than an automatic alternative. A `direct` lookup is marked domestic, so enabled domestic ECS processing applies; `proxy` is not marked domestic.

Human domain rules, including GeoSite-derived rules, are valid with `dns.fake-ip.enabled=false`; startup does not reject them. In that mode a matched A query uses the domain action's configured provider (or domestic/foreign fallback) and returns the real A answer. It does not request fake allocation or create a sticky mapping, fake cache entry, or fake-IP route. `routing.tcp-domain-sniff` does not change this DNS decision.

With `dns.fake-ip.enabled=true`, human domain actions apply to A queries through a synthetic IPv4 address. Fake allocation excludes empty names, reverse-ARPA names, exact `localhost`, and names ending in `.local` or `.lan`. A strict human-matched A query is fail closed: an ineligible hostname, allocation failure, or response-build failure is rejected rather than falling back to a real or legacy DNS answer.

The fake-IP allocation records its initial action:

- if a human domain rule matched, that action is sticky and a later real-IPv4 rule does not replace it;
- if no human domain rule matched, the resolved real IPv4 rule or `default` supplies the final action;
- an unresolved fake IP is rejected rather than routed speculatively.

Intercepted unmatched A queries may also receive fake IPs; `default` itself is not the allocation trigger. `default direct|proxy` alone is not a domain match and therefore does not create a domain-sticky action.

## GeoIP and GeoSite data

`geo:cc` reads GeoIP sources from `geo-rules.geoip-dat` plus optional `geo-rules.geoip` text paths, and GeoSite sources from `geo-rules.geosite-dat` plus optional `geo-rules.geosite` text paths. Each used country requires configured sources in both categories. `geo-rules.enabled` does not gate this human-rule compilation, and `geo-rules.country` is not the selector; the `cc` in each rule is.

The binary paths default to `GeoIP.dat` and `GeoSite.dat`; only non-empty JSON values replace those defaults. Adding text paths does not disable binary sources: every non-empty configured source is read, and a missing or unreadable source fails initialization.

The binary readers accept v2ray/Xray/MetaCubeX protobuf `.dat` files and select their country/category by `cc`. GeoIP IPv4 CIDRs become routing rules; binary IPv6 CIDRs are parsed but skipped by the IPv4-only compiler. GeoSite `Domain`, `Full`, and `Regex` entries become suffix, exact, and regexp rules respectively; `Plain` entries are skipped. Malformed/truncated protobuf wire data or a missing selector is fatal. Individual unusable binary CIDRs and GeoSite entries with unknown type or empty value are skipped; a selected binary Domain/Full that violates the human-domain grammar or an unbuildable Regex is fatal.

Text GeoIP files accept IPv4/IPv6 addresses or CIDRs, optionally prefixed with `geoip:`; IPv6 entries are skipped. Text GeoSite files accept `domain:`/`suffix:`, `full:`, `regexp:`/`regex:`, and `plain:` (plain entries are skipped); an unprefixed entry is a suffix. Text sources have no country categories, so their entries are applied for every `geo:cc` declaration. Malformed text entries and text domain/regexp compile failures are skipped and counted, but file access or stream failures are fatal.

## IPv4, IPv6, and AAAA limits

Human routing currently supports IPv4 rules only. IPv6 literals/CIDRs are invalid in the human rules file, GeoIP IPv6 entries are skipped, and human IPv4 rules plus `default` are not applied to an IPv6 destination.

Fake IP is A-only. When a human domain `direct` or `proxy` rule matches an AAAA query, the client synthesizes a NOERROR response with no AAAA answers; unmatched domains continue to follow the resolver's existing IPv6-response policy. A human `default` alone does not count as a domain match and does not trigger this AAAA behavior.

## UDP action matrix

| Human action | Android IPv4 | Non-Android or IPv6 |
|---|---|---|
| `Direct` | Protected physical UDP socket | Reject (fail closed) |
| `Proxy` | Tunnel | Tunnel |
| `Auto` | Physical socket only when legacy bypass matches; otherwise tunnel | Tunnel |

Android client initialization fails if the required protector cannot be created. For a direct data-UDP port, a missing protector at open time or a failed `Protect()` call disposes the port before queued-message flush or receive-loop startup; it never falls back to the tunnel. Android IPv6 does not use the physical direct path.

This matrix is specific to client data UDP. Android `DnsUdpRelay` instead warns and continues when its protector pointer is absent; an explicit `Protect()` failure enters that relay's fallback/error path.

## Minimal route-source example

The configuration form names a gateway (`ngw`) and a local route-list path. Use documentation-only addresses and paths until you have validated the host topology.

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

For a regular client launch that supplies local list files explicitly:

```bash
./ppp --mode=client --config=./client.json \
  --bypass=./bypass.txt \
  --dns-rules=./dns-rules.txt
```

The command selects sources; it does not prove that every route or resolver change succeeded. Inspect the host routing/DNS state and runtime diagnostics after startup.

## DNS settings that are parsed

The current parser includes these groups:

- `udp.dns.timeout`, `udp.dns.ttl`, `udp.dns.turbo`, `udp.dns.cache`, and `udp.dns.redirect`;
- `dns.servers.domestic` and `dns.servers.foreign` (provider/server entries);
- `dns.intercept-unmatched`;
- `dns.ecs.enabled` and `dns.ecs.override-ip`;
- `dns.tls.verify-peer`, `dns.stun.candidates`, and `dns.fake-ip.{enabled,range}`.

These settings feed DNS policy and reachability planning. They do not mean every resolver is always reachable over one fixed physical interface, nor do they replace a host firewall policy.

## Operational sequence

1. Start a normal client, not proxy mode, with an explicit configuration path.
2. Keep bypass/DNS-rule files local and review their ownership and contents before startup.
3. Ensure the VPN server/control endpoint remains reachable outside the routes being changed.
4. Check the resulting host routes, resolver behavior, and `ppp` diagnostics after connection.
5. Treat a failed route/DNS operation as a connectivity issue to resolve, not as proof of fail-closed behavior.

## Related pages

- [Configuration reference](../reference/CONFIGURATION.md)
- [CLI reference](../reference/CLI_REFERENCE.md)
- [Proxy-only mode](PROXY_MODE.md)
- [Operations and troubleshooting](../operations/OPERATIONS.md)