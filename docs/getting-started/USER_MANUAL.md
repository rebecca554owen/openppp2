# User Manual
> Status: Active
> Type: Guide
> Last verified: 7bba7e4
>
> **Purpose:** Start the native `ppp` runtime without relying on stale configuration examples.
> **Audience:** Operators and developers running this repository's native executable.
> **Parent index:** [Getting Started](README.md) · **Chinese:** [用户手册](USER_MANUAL_CN.md)

## Scope

This guide covers the native `ppp` executable built from this tree or supplied alongside its configuration. It is not a complete field reference: use [Configuration](../reference/CONFIGURATION.md) and [CLI reference](../reference/CLI_REFERENCE.md) before exposing a service or changing network policy.

The runtime has three documented command roles:

| Role | Invocation | Important boundary |
|---|---|---|
| Server | `--mode=server` (or omit `--mode`) | A non-proxy run requires administrator/root privilege. |
| Client | `--mode=client` | A non-proxy run requires administrator/root privilege. |
| Proxy | `--mode=proxy` | The native privilege check is skipped, but listener exposure and configuration remain the operator's responsibility. |

Use the exact role names above. The parser accepts broader input than this table; that permissiveness is not a configuration contract.

## 1. Prepare a private configuration

`ppp` loads a JSON object. Create a private configuration for the intended role and give it a deliberate filename, such as `config.json`.

- `appsettings-server-minimal.json` is a compact structural example in this tree. It is **not** production-ready; replace its shared key material and choose your own listener, address-pool, and network policy values.
- `appsettings.json` is a broader repository example, not a deployment template. Do not publish or reuse its endpoints, keys, certificates, passwords, or local addresses.
- Client and server peers need compatible shared protocol/transport settings. Set role-specific values, including the client target or server listeners, from the canonical configuration reference.

Keep the configuration and any certificate/key files readable only by the account that must run the process. Do not place credentials in shell history or issue trackers.

## 2. Control configuration selection

Prefer an explicit, readable configuration path and run from a controlled working directory:

```bash
./ppp --mode=server --config=./config.json
./ppp --mode=client --config=./config.json
./ppp --mode=proxy --config=./config.json
```

The loader tries candidates in this order:

1. a readable path supplied by `--config` (also accepted as `-c`, `--c`, or `-config`),
2. `./config.json`,
3. `./appsettings.json`.

If an earlier candidate cannot be read or loaded, loading can continue to a later candidate. Therefore, do not assume an invalid explicit path prevents a working-directory configuration from being selected.

On Windows, start client/server mode from an elevated administrator session. On Unix-like hosts, start those modes with the required root privilege. Proxy mode is the exception to this specific privilege check, not a reason to treat its listeners as safe by default.

## 3. Add observability deliberately

`--stats-json` accepts a writable file path and emits runtime statistics as NDJSON. For example:

```bash
./ppp --mode=client --config=./config.json --stats-json=./stats.ndjson
```

Treat the output as local operational data. Choose a writable, non-secret location and arrange rotation or collection outside the process. The literal value `stdout` is also recognized by the current implementation.

## 4. Supply route and DNS rule files locally

The native options use local rule-file inputs by default:

| Purpose | Option | Default filename |
|---|---|---|
| Bypass IP list | `--bypass=./ip.txt` | `./ip.txt` |
| DNS rules | `--dns-rules=./dns-rules.txt` | `./dns-rules.txt` |
| Firewall rules | `--firewall-rules=./firewall-rules.txt` | `./firewall-rules.txt` |

Pass reviewed local files rather than treating these inputs as general remote URLs. Routing and DNS policy can change connectivity; validate it in a test environment first. See [Routing and DNS](../guides/ROUTING_AND_DNS.md) for the operational model.

## 5. Expect host-impacting behavior

A non-proxy client run initializes a platform network interface and may apply routing or DNS behavior selected by its configuration and arguments. Use a disposable or well-understood host for first runs, preserve a recovery path, and do not terminate the process forcibly when a graceful stop is available.

### Android system-proxy boundary

The bundled Android `PppVpnService` deliberately does **not** publish the native HTTP proxy through `VpnService.Builder`. The native listener can own its port only after `Builder.establish()` supplies the TUN descriptor and native `run()` begins. Publishing a system proxy earlier would allow another local application to win that bind race and intercept proxy traffic.

This restriction also applies when Android launch options request proxy-only or automatic app handling. Use full-tunnel mode, or configure trusted clients to use a local HTTP/SOCKS endpoint only after the native listener is known to be available.

Server, client, proxy, and platform behavior are intentionally split across the codebase. Before production deployment, review:

- [Platforms](../guides/PLATFORMS.md)
- [Proxy mode](../guides/PROXY_MODE.md)
- [Deployment](../operations/DEPLOYMENT.md)
- [Operations](../operations/OPERATIONS.md)
- [Security](../operations/SECURITY.md)

## Troubleshooting first checks

| Symptom | Check |
|---|---|
| The wrong settings appear active | Confirm the working directory and all three configuration candidates; make the desired `--config` file readable and valid JSON. |
| Client or server exits before networking starts | Confirm the required administrator/root privilege and inspect the diagnostic triplet written by the facade for a nonzero result. |
| A second instance refuses to start | The process holds a role/configuration instance lock; stop the existing instance cleanly or choose the intended configuration. |
| Automation treats help as a failure | `--help` prints help, but the current startup path returns a nonzero result and emits a diagnostic. Handle that behavior explicitly in scripts. |
| Routing or DNS changes are unexpected | Remove unreviewed local rule files, review the active options, and follow the routing/DNS and platform guides before retrying. |
| Android proxy traffic is intercepted locally | Do not publish the native listener as an Android system proxy before it owns the port; use the Android boundary above. |

## Next reading

- [Configuration](../reference/CONFIGURATION.md)
- [CLI reference](../reference/CLI_REFERENCE.md)
- [Startup and lifecycle](../architecture/STARTUP_AND_LIFECYCLE.md)
- [Routing and DNS](../guides/ROUTING_AND_DNS.md)
- [Deployment](../operations/DEPLOYMENT.md)
