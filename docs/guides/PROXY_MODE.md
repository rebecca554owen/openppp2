# Proxy-only mode

> **Status:** Current; desktop behavior is source-backed, Android behavior is platform-specific
> **Type:** Guide
> **Last verified:** Application mode, client bootstrap, configuration, and Android VPN-service sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [Proxy-only 模式](PROXY_MODE_CN.md)

## Use the right switch

For desktop use, choose the process mode explicitly:

```bash
./ppp --mode=proxy --config=./client.json
```

`--mode=proxy` is not just shorthand for `client.proxy-only=true`:

| Choice | What the application does |
|---|---|
| `--mode=proxy` | Selects the client proxy runtime, uses `TapStub` on non-mobile builds, skips ordinary TUN route/DNS-rule/bypass/geo-rule setup, and follows the proxy-mode elevation path. |
| `--mode=client` plus `client.proxy-only: true` | Enables proxy-only behavior inside a client configuration, but does not itself select client mode or set the application `proxy_mode_` flag. |

Prefer `--mode=proxy` when the operator intent is a desktop local-proxy session.

## Local listeners

Proxy-only mode exposes local HTTP and SOCKS5 forwarding listeners after it connects to the configured VPN server.

| Listener | Configuration fields | Proxy-mode default |
|---|---|---|
| HTTP | `client.http-proxy.bind`, `client.http-proxy.port` | `127.0.0.1:8080` |
| SOCKS5 | `client.socks-proxy.bind`, `client.socks-proxy.port` | `127.0.0.1:1080` |
| SOCKS5 credentials | `client.socks-proxy.username`, `client.socks-proxy.password` | Optional configuration fields |

For desktop CLI proxy mode, the runtime forces both listener addresses to loopback and normalizes missing/invalid ports to `8080` and `1080`. Do not treat this mode as a LAN-facing proxy service or try to expose it through a public bind address.

`client.server-proxy` is different: it configures an upstream proxy for reaching the VPN server; it does not configure either local listener.

## Safe configuration shape

Keep endpoint and credentials out of version control. This example uses a documentation-only endpoint:

```json
{
  "client": {
    "server": "ppp://vpn.example.invalid:20000/",
    "proxy-only": true,
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
```

The JSON field can be useful for a client configuration, but it does not replace the recommended desktop `--mode=proxy` invocation.

## Static transport boundary

For an ordinary client, explicitly passing `--tun-ip` implicitly requests static mode even when `--tun-static=no`. Proxy-only startup normalizes the final setting back to disabled because it must not use the static transport. Consequently, proxy-only startup does not initiate the `STATIC`/`STATICACK` exchange that this mode would otherwise trigger. When server-side IPv4 allocation is configured, the same normalized setting requests automatic IPv4 allocation instead of submitting the local TUN address as a manual request.

## Verify locally

After the client reaches its connected state, test only loopback endpoints:

```bash
curl -x http://127.0.0.1:8080 https://example.com
curl -x socks5h://127.0.0.1:1080 https://example.com
```

A listener being open does not prove that the tunnel, upstream server, credentials, or remote routing are healthy. Use runtime diagnostics if a request fails.

## Android boundary

Android uses `vpnOptions.proxyOnly` in its bundled VPN application. It still establishes a `VpnService` interface and applies platform-specific narrow-route/DNS handling. Do not copy the desktop claim of “no route or DNS work” to Android.

## Related pages

- [Routing and DNS](ROUTING_AND_DNS.md)
- [Configuration reference](../reference/CONFIGURATION.md)
- [CLI reference](../reference/CLI_REFERENCE.md)
- [Operations and troubleshooting](../operations/OPERATIONS.md)