# Proxy-only mode
> Status: Active
> Type: Guide
> Last verified: 63fc030

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-31.
> **Parent index:** [Back to index](README.md) · **Chinese:** [纯代理模式](PROXY_MODE_CN.md)


Proxy-only mode connects to an OpenPPP2 server and exposes **local HTTP and SOCKS5 forward proxies** without installing host-system route entries or system DNS settings. It still loads the canonical routing policy into the native client. Desktop startup uses `TapStub`; mobile platforms keep only the minimal tunnel interface needed by the runtime. Not installing a host rule does not disable the corresponding native policy.

## Quick start

```bash
./ppp --mode=proxy --config=./appsettings.json
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

## Configuration

Prefer the canonical `client.routing` object for IP/DNS policy. When present, it is authoritative for those policy sources; runtime mode remains independent:

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://your-server:20000/",
    "proxy-only": true,
    "routing": {
      "ip": {
        "bypass": [],
        "routes": [],
        "peer-routes": []
      },
      "dns": {
        "rules": []
      }
    },
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
```

`client.proxy-only` is an independent top-level runtime flag and is read even when `client.routing` is present. Legacy `client.routes` and `client.peer-routes` are fallback inputs only when the canonical object is absent; an old nested mode key is ignored and never serialized. Use `--mode=client` or `--mode=proxy` to select the command-line runtime mode; `--mode=proxy` is equivalent to enabling proxy-only behavior.

When ports or bind addresses are omitted, defaults are applied automatically:

| Listener | Default bind | Default port |
|----------|--------------|--------------|
| HTTP     | 127.0.0.1    | 8080         |
| SOCKS5   | 127.0.0.1    | 1080         |

## Platform behavior

| Platform | TUN / host installation | Native policy and proxy-only boundary | Privilege / permission |
|----------|-------------------------|----------------------------------------|------------------------|
| Linux / macOS / Windows | TUN may project native policy to the host; proxy-only uses `TapStub` and installs no host route platform or system DNS | Both modes load native bypass, ordinary routes, peer-prefix routes, and DNS rule table; local HTTP/SOCKS proxies remain available | No root/admin for proxy-only |
| Android | `VpnService.Builder` installs the configured TUN routes and tunnel DNS in TUN mode | Both modes load native bypass, ordinary routes, peer-prefix routes, and DNS policy; proxy-only Builder installs only the VPN interface subnet route | VpnService permission |
| iOS | `PacketTunnelProvider` installs included/excluded routes and tunnel DNS in TUN mode | Both modes load native routing and DNS policy; proxy-only provider installs only the tunnel subnet route, without bypass exclusions or tunnel DNS | Network Extension permission |

Proxy-only limits only host/platform installation. TUN and proxy-only both load and use `routing.ip.bypass`, `routing.ip.routes`, `routing.ip.peer-routes`, and `routing.dns.rules` in the native route/RIB/FIB and DNS policy/rule table. Desktop bootstrap also runs `GeoRuleGenerator` when enabled and loads canonical sources in both modes; proxy-only uses a native loopback gateway to build that state but does not install host routes. Android and iOS builders/providers install only their minimal interface or tunnel-subnet route. See [Routing And DNS](ROUTING_AND_DNS.md) for the normalized policy model.

On Android, enable **仅代理模式** in profile options (`vpnOptions.proxyOnly=true`). The app still creates a minimal TUN for `protect()`, while the native client loads bypass, ordinary routes, peer-prefix routes, and DNS rules in both modes. `android/libopenppp2.cpp` also runs `GeoRuleGenerator` and loads generated and canonical sources in both modes; proxy-only only disables the Builder-side IPv6 capture, tunnel DNS, and mobile default route.

On iOS, `PacketTunnelProvider` reads the independent top-level `client.proxy-only` flag from the prepared JSON. The extension installs only the tunnel-subnet included route, not a default route, and does not configure host bypass exclusions or `NEDNSSettings` in proxy-only mode. `OpenPPP2PacketTunnelBridge.cpp` still loads the canonical native routing and DNS policy in both modes; the iOS bridge does not invoke `GeoRuleGenerator`.

## Static transport boundary

Proxy-only startup forces static transport off, including when `--tun-ip` would otherwise enable it. It therefore does not initiate the `STATIC`/`STATICACK` exchange. When server-side IPv4 allocation is configured, proxy-only requests automatic IPv4 allocation instead of submitting the local TUN address as a manual request.

## CLI flags

| Flag | Description |
|------|-------------|
| `--mode=proxy` | Select proxy-only runtime |
| `--proxy-http-port=N` | Override HTTP listen port |
| `--proxy-socks-port=N` | Override SOCKS listen port |

See [CLI_REFERENCE.md](../reference/CLI_REFERENCE.md) and [CONFIGURATION.md](../reference/CONFIGURATION.md) for full details.

## Related docs

- [Routing And DNS](ROUTING_AND_DNS.md) — normalized routing policy and DNS behavior
- [Platform Integration](PLATFORMS.md) — desktop, Android, and iOS boundaries
- [PROXY_ONLY_MODE_PLAN.md](../archive/plans/PROXY_ONLY_MODE_PLAN.md) — implementation and test plan
- [PROXY_MODE_TEST_PLAN.md](../archive/plans/PROXY_MODE_TEST_PLAN.md) — test matrix
- [TESTING.md](../development/TESTING.md) — unit tests and coverage
