# Routing and DNS

> **Status:** Current
> **Type:** Guide
> **Last verified:** Client configuration, bootstrap, route, and DNS sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [路由与 DNS](ROUTING_AND_DNS_CN.md)

## Scope

Normal client mode builds a route/DNS plan from CLI inputs, parsed configuration, negotiated session state, and host-network facts. This is host integration, not a firewall or leak-prevention guarantee: route/DNS changes can fail or differ by platform and privilege.

`--mode=proxy` follows a different path and skips normal TUN route, bypass-list, DNS-rule, and geo-rule setup. See [Proxy-only mode](PROXY_MODE.md).

## Select an input surface

| Need | Supported surface | Notes |
|---|---|---|
| Load a local bypass list | `--bypass=<path>` | The default CLI path is `./ip.txt`. |
| Load a local DNS rule file | `--dns-rules=<path>` | The default CLI path is `./dns-rules.txt`; startup checks a local file. |
| Set a DNS address at launch | `--dns=<address>` | Use the CLI reference for accepted forms. |
| Define route-list inputs in configuration | `client.routes` | Each usable route source has `ngw` and `path`; Linux also accepts `nic`. |
| Refresh a route list remotely | `client.routes[].vbgp` | `vbgp` is the per-route remote URL; it is not a top-level `vbgp.url` field. |
| Enable the VIRR path | `--virr=...` | This is the built-in country-list workflow, not an arbitrary URL setting. |
| Enable vBGP refresh behavior | `--vbgp=yes|no` | Refresh timing is configured through `vbgp.update-interval`. |

Do not use JSON keys such as `client.bypass`, `client.dns-rules`, `virr.url`, or `vbgp.url`: they are not the current parsed interface.

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