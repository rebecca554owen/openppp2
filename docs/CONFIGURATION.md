# Configuration Model

[中文版本](CONFIGURATION_CN.md)

## Position

This is the canonical guide to `AppConfiguration` and the launch-time shaping around it. OPENPPP2 does not treat configuration as plain JSON. It uses a staged admission flow:

1. `Clear()` builds safe defaults.
2. `Load(...)` merges JSON.
3. `Loaded()` repairs, clamps, clears, and derives runtime values.
4. `main.cpp` applies per-run CLI overrides for host-specific behavior.

Anchors:

- `ppp/configurations/AppConfiguration.h`
- `ppp/configurations/AppConfiguration.cpp`
- `main.cpp::LoadConfiguration(...)`
- `main.cpp::GetNetworkInterface(...)`
- `main.cpp::PreparedArgumentEnvironment(...)`

## Core Idea

Missing fields usually mean fallback, not missing behavior. Invalid fields are often normalized. Some values are cleared entirely when the surrounding subsystem is disabled.

## Configuration Shape

`AppConfiguration` is organized around these blocks:

- `concurrent`
- `cdn`
- `ip`
- `udp`
- `tcp`
- `mux`
- `websocket`
- `key`
- `vmem`
- `server`
- `client`

## Defaults From `Clear()`

Important defaults from `Clear()` include:

- `concurrent = Thread::GetProcessorCount()`
- `cdn[*] = IPEndPoint::MinPort`
- UDP DNS timeout, TTL, cache, and redirect defaults
- TCP and MUX timeout defaults
- WebSocket listeners off by default
- key material defaults such as `kf`, `kh`, `kl`, `kx`, `sb`
- `server.subnet = true`
- `server.mapping = true`
- server IPv6 disabled by default
- client GUID sentinel value
- client bandwidth limit `0`
- Windows-only `paper_airplane.tcp = true`

## Normalization Rules From `Loaded()`

`Loaded()` does the real shaping work. Notable rules:

- `concurrent < 1` resets to CPU count
- `server.node` is clamped to `>= 0`
- `server.ipv6.prefix_length` is clamped to the IPv6 prefix range
- non-positive timeouts fall back to defaults
- invalid ports become `IPEndPoint::MinPort`
- negative keepalive counts become `0`
- string fields are trimmed before use
- empty client GUID falls back to the sentinel GUID
- invalid IP strings are cleared
- unsupported key protocol or transport names fall back to defaults
- WebSocket serving is disabled when host/path or certificates are invalid
- `vmem` is cleared if path is empty or size is below `1`
- `server.ipv6.static_addresses` is filtered to valid, unique, in-prefix IPv6 entries

## IPv6 Server Behavior

IPv6 server mode is not just a boolean. `Loaded()` validates mode, CIDR, prefix length, gateway, and static address map.

If server IPv6 support is unavailable, the IPv6 server settings are disabled and related fields are cleared. If the configured prefix is invalid, the IPv6 server feature is disabled.

## WebSocket Behavior

WebSocket serving depends on a valid host name and path. If those are not valid, both listeners are disabled. If `wss` is disabled, certificate-related fields are cleared.

## Client Routing Data

`client.mappings` is rebuilt from validated mapping entries. The loader accepts either one mapping object or an array of mappings. Invalid endpoints, invalid IPs, and multicast addresses are rejected.

## CLI and JSON

JSON config is durable node intent. CLI values are launch-local overrides.

- `--mode` chooses client or server
- `--dns` populates local DNS input for the current run
- `--nic`, `--ngw`, `--tun-*`, `--bypass*`, and `--dns-rules` shape the current host environment

## Practical Rule

Use JSON for persistent node shape. Use CLI for host-specific startup shape. Do not expect CLI to replace the configuration model.

## Related Documents

- `README.md`
- `CLI_REFERENCE.md`
- `TRANSMISSION.md`
- `ARCHITECTURE.md`
