# Deployment Model

> **Status:** Current implementation boundary
> **Type:** Operations guide
> **Last verified:** Application mode/config bootstrap, server/client bootstrap, CMake, and manager sources, 2026-07-22
> **Parent index:** [Operations](README.md) · **Chinese:** [部署模型](DEPLOYMENT_CN.md)

## Choose a role first

The `ppp` executable selects its role through CLI mode, not a JSON `mode` field:

```bash
./ppp --mode=server --config=./server.json
./ppp --mode=client --config=./client.json
./ppp --mode=proxy  --config=./client.json
```

| Role | Deployment effect |
|---|---|
| `server` | Opens configured server runtime/listener surfaces and optional managed/IPv6 features. |
| `client` | Uses normal client networking behavior, including host route/DNS integration when enabled by the runtime/configuration. |
| `proxy` | Selects the desktop proxy runtime; it uses `TapStub` on non-mobile builds and skips normal client TUN route/DNS-rule/bypass setup. |

Configuration lookup accepts `-c`, `--c`, `-config`, and `--config`. Without one of those, it searches `./config.json` then `./appsettings.json` in the current working directory.

## Host prerequisites

Normal client/server operation can create/use virtual interfaces and change host routes or DNS. Plan the required privileges and host capabilities for the target OS before starting the process. Desktop proxy mode intentionally follows a different application path, but it still requires a working network, a valid client configuration, and access to the remote server.

This tree builds `ppp`; it does not provide one universal service installer, unit file, or network-policy setup. Keep the following under operator control:

- service supervision and restart policy;
- port/firewall policy;
- DNS service interaction and route persistence;
- configuration-file ownership and secret storage;
- TLS termination for management/subscription publishing where required.

## Server deployment checklist

1. Select an explicit configuration file and `--mode=server`.
2. Enable and expose only the listener surfaces described by the current configuration reference; validate bind address/port ownership at the host level.
3. If using native Go managed authentication, configure `server.node >= 1`, `server.backend`, and `server.backend-key`, then run the native manager in managed mode with matching values.
4. Supply firewall rules through the implemented CLI surface `--firewall-rules=<file>` when that feature is required. `server.firewall` is not a current parsed JSON key.
5. Treat server IPv6 as Linux-only (excluding Android) and validate it separately before production. See [IPv6 transit plane](../guides/IPV6_TRANSIT_PLANE.md).
6. Bind management/subscription services to an intended network boundary; direct Go serving is not TLS termination.

## Client deployment checklist

1. Start `--mode=client` with a validated configuration path.
2. Confirm virtual-interface and route/DNS permissions for the selected host.
3. Confirm the server endpoint remains reachable during route-policy changes.
4. Keep route/DNS rule inputs local and review them before startup.
5. After connection, inspect host state and test traffic rather than treating process startup as proof of policy success.

For desktop local proxy use, start `--mode=proxy`; do not assume `client.proxy-only` alone selects that process path. See [Proxy-only mode](../guides/PROXY_MODE.md).

## Minimal validation sequence

1. Confirm the process selected the intended role and configuration file.
2. Confirm the server listener or local proxy listener is bound only where expected.
3. Confirm a client reaches `connected` using its runtime snapshot/diagnostics.
4. Confirm traffic and host route/DNS state match the intended deployment.
5. Confirm secrets, manager endpoints, and public subscription URLs are not exposed beyond the planned boundary.

## Related pages

- [Operations and troubleshooting](OPERATIONS.md)
- [Security model](SECURITY.md)
- [Platform integration](../guides/PLATFORMS.md)
- [Management backend](../guides/MANAGEMENT_BACKEND.md)
- [Configuration reference](../reference/CONFIGURATION.md)