# Proxy-only mode

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-18.
> **Parent index:** [Back to index](README.md)


Proxy-only mode connects to an OpenPPP2 server and exposes **local HTTP and SOCKS5 forward proxies** without changing OS routes or requiring root on desktop platforms.

## Quick start

```bash
./ppp --mode=proxy --config=./appsettings.json
curl -x socks5h://127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:8080 https://example.com
```

## Configuration

Set `client.proxy-only` to `true`, or pass `--mode=proxy` on the command line:

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://your-server:20000/",
    "proxy-only": true,
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
```

When ports or bind addresses are omitted, defaults are applied automatically:

| Listener | Default bind | Default port |
|----------|--------------|--------------|
| HTTP     | 127.0.0.1    | 8080         |
| SOCKS5   | 127.0.0.1    | 1080         |

## Platform behavior

| Platform | TUN / routes | Root / admin |
|----------|--------------|--------------|
| Linux / macOS / Windows | Uses `TapStub` (no kernel interface) | Not required |
| Android | Minimal VPN route for socket protect | VpnService permission |

On Android, enable **仅代理模式** in profile options (`vpnOptions.proxyOnly=true`). The app still creates a minimal TUN for `protect()`, but skips full routing, DNS hijack, and geo bypass.

## CLI flags

| Flag | Description |
|------|-------------|
| `--mode=proxy` | Select proxy-only runtime |
| `--proxy-http-port=N` | Override HTTP listen port |
| `--proxy-socks-port=N` | Override SOCKS listen port |

See [CLI_REFERENCE.md](../reference/CLI_REFERENCE.md) and [CONFIGURATION.md](../reference/CONFIGURATION.md) for full details.

## Related docs

- [PROXY_ONLY_MODE_PLAN.md](../archive/plans/PROXY_ONLY_MODE_PLAN.md) — implementation and test plan
- [PROXY_MODE_TEST_PLAN.md](../archive/plans/PROXY_MODE_TEST_PLAN.md) — test matrix
- [TESTING.md](../development/TESTING.md) — unit tests and coverage
