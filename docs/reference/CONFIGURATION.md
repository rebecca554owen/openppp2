# Configuration Reference
> Status: Active
> Type: Reference
> Last verified: 82643dc
> Parent index: [Reference index](README.md)
> Peer link: [中文](CONFIGURATION_CN.md)

## Scope and source of truth

`AppConfiguration` uses **JsonCpp** (`Json::Value`), not a generic JSON-object merger. This is current implementation documentation, not a published JSON Schema, migration policy, or compatibility promise. The implementation is the authority:

- `ppp/configurations/AppConfiguration.cpp` — defaults, load/normalization, and JSON emission
- `ppp/configurations/AppConfiguration.h` — configuration model
- `ppp/app/ApplicationConfig.cpp` — file selection and launch-time overrides

For the complete current JSON shape, use `AppConfiguration::ToJson()` (or `ToString()`) from `AppConfiguration.cpp`. Hand-maintained examples are intentionally not the schema authority.

## Load lifecycle

For `Load(Json::Value&)`, the sequence is:

1. `Clear()` resets serialized configuration fields to their defaults.
2. The input must be a JSON object; loader code deserializes its known fields.
3. `Loaded()` validates and normalizes the result.

This is **not** a merge or sparse-patch operation. A subsequent `Load()` reconstructs serialized configuration fields rather than preserving prior loaded values. Runtime-only state, such as the buffer allocator and remote MUX runtime override, is not part of that serialized reset. Some fields are assigned directly from JSON conversion while selected booleans and values use presence-aware helpers, so absent-field behavior is not uniform across the model. Start from the current `ToJson()` output or supply a complete, source-verified configuration, then check the load result.

## Canonical emitted shape

`ToJson()` emits these top-level sections:

```text
concurrent, cdn, ip, vmem, udp, tcp, mux, websocket, key, server,
client, virr, vbgp, telemetry, p2p, dns, geo-rules
```

Selected canonical structures:

| Section | Canonical fields / notes |
|---|---|
| `websocket` | `listen.ws` and `listen.wss` are integer ports, not `{ "port": ... }` objects. |
| `websocket.ssl` | `certificate-file`, `certificate-key-file`, `certificate-chain-file`, `certificate-key-password`, `ciphersuites`, `verify-peer`. |
| `mux` | `mode`, `turbo`, `flow`, `tx`, and optional `debug.key`; nested field spelling follows `ToJson()`. |
| `server.ipv6` | `mode`, `cidr`, `gateway`, `dns1`, `dns2`, `lease-time`, `static-addresses`; the CIDR carries its prefix length. |
| `server.session_resume` | `enabled` and `grace_ms`; server master switch and suspended-session grace period. |
| `client.session_resume` | `enabled`; client master switch for authenticated L3 roaming. |
| `key` | `kf`, `kh`, `kl`, `kx`, `sb`, cipher names/keys, and transform flags. |
| `client` | mappings, routes, proxy settings, reconnect timeout, identity, server, and bandwidth. |

For compatibility, `ToJson()` also emits `websocket.verify-peer` alongside the canonical nested `websocket.ssl.verify-peer`, and emits both `udp.static.servers` and the legacy `udp.static.server`. Author new configuration with `websocket.ssl.verify-peer`.

### MUX configuration versus launch overrides

`mux.mode` normalizes to one of `compat`, `flow`, `balance`, or `stripe`; empty or unrecognized input becomes `compat`. `mux.turbo` is a durable JSON field. `mux.debug.key` is read from JSON and emitted only when non-empty. `mux.debug.set_mode` is an in-memory launch request set by `--mux-mode-set`; it is neither loaded from nor emitted to this JSON shape. See [VMUX validation](VMUX_VALIDATION.md) for negotiation and evidence boundaries.

## Important defaults

`Clear()` establishes the following defaults before loading:

| Field | Default |
|---|---:|
| `mux.mode` / `mux.turbo` | `compat` / `false` |
| `websocket.listen.ws` / `websocket.listen.wss` | `0` / `0` (disabled) |
| `websocket.ssl.verify-peer` | `true` |
| `websocket.ssl.ciphersuites` | `GetDefaultCipherSuites()` |
| `client.session_resume.enabled` / `server.session_resume.enabled` | `false` / `false` |
| `server.session_resume.grace_ms` | `60000` milliseconds |
| `key.kf` | `154543927` |
| `key.kh` | `12` |
| `key.kl` | `10` |
| `key.kx` | `128` |
| `key.sb` | `0` |
| `key.masked` / `key.delta-encode` / `key.shuffle-data` | `true` / `true` / `true` |
| `key.plaintext` | **`true`** |
| `server.ipv6.mode` | disabled (`none` internally; emitted as an empty string) |
| `virr.update-interval` / `virr.retry-interval` | `86400` / `300` seconds |
| `vbgp.update-interval` | `3600` seconds |

`plaintext=true` keeps the base94 envelope active after handshake, and the startup security diagnostic explicitly reports packets transmitted without encryption. It is unsafe for untrusted networks. Set it to `false` and replace both default keys before any real deployment; both peers must also agree on the framing-related key flags.

## Authenticated L3 session roaming

`client.session_resume.enabled` and `server.session_resume.enabled` are independent master switches and both default to false. Roaming activates only when both peers enable and negotiate capability v1 over WSS and the concrete `ISslWebsocketTransmission` exposes an authenticated TLS session exporter. Plain TCP, plain WebSocket, CDN paths, WSS without the exporter, and mixed capability states fail closed to ordinary fresh-session behavior.

`server.session_resume.grace_ms` bounds how long the server retains only L3 session/IP/NAT/UDP-manager state after an eligible carrier failure. FRP mappings and VMUX are still closed. The retained authentication root is process-local and never serialized; a server restart therefore forces fresh authentication. When roaming is enabled, the WSS listener is pinned to the switcher's owner `io_context`, which avoids cross-executor handoff but may reduce accept/handshake parallelism. See [Authenticated L3 session roaming](../design/session-recovery/l3-roaming.md) for the protocol, threat model, and rollout limits.

## Security-sensitive example fragment

This is a **fragment**, not a complete runnable configuration. The values in angle brackets are non-secret placeholders and must be replaced; never deploy them as secrets.

```json
{
  "key": {
    "kf": 154543927,
    "kh": 12,
    "kl": 10,
    "kx": 128,
    "sb": 0,
    "protocol": "aes-256-cfb",
    "protocol-key": "<REPLACE_WITH_UNIQUE_PROTOCOL_SECRET>",
    "transport": "aes-256-cfb",
    "transport-key": "<REPLACE_WITH_UNIQUE_TRANSPORT_SECRET>",
    "masked": true,
    "plaintext": false,
    "delta-encode": true,
    "shuffle-data": true,
    "simd-auto": true
  },
  "websocket": {
    "host": "vpn.example.invalid",
    "path": "/openppp2",
    "listen": { "ws": 0, "wss": 443 },
    "ssl": {
      "certificate-file": "<PATH_TO_CERTIFICATE_PEM>",
      "certificate-key-file": "<PATH_TO_PRIVATE_KEY_PEM>",
      "certificate-chain-file": "<PATH_TO_CHAIN_PEM>",
      "certificate-key-password": "<REPLACE_ONLY_IF_KEY_IS_ENCRYPTED>",
      "ciphersuites": "",
      "verify-peer": true
    }
  }
}
```

Keep private-key files and real passphrases out of source control. `verify-peer` controls peer-certificate verification; choose it deliberately for the deployment's authentication model.

## WebSocket validation

- `ws` and `wss` are integer ports; `0` disables the respective listener.
- Invalid ports are normalized to `0`.
- An invalid host, an empty path, or a path not beginning with `/` disables both WebSocket listeners during normalization.
- Invalid WSS certificate material disables WSS.

Use the exact TLS field names shown above. Earlier names such as `certificate`, `certificate-key`, or `ca-certificate` are not the current emitted schema.

## Server IPv6

The only supported enabled modes are:

| `server.ipv6.mode` | Meaning |
|---|---|
| `nat66` | NAT66 with an IPv6 prefix pool |
| `gua` | Global-unicast address delegation |

Any other input normalizes to disabled. `ToJson()` represents disabled mode as `""`; do not add a separate `prefix-length` JSON field—`Load()` derives the internal prefix length from `server.ipv6.cidr`, for example `2001:db8:1234::/64`.

Enabled server IPv6 has platform validation: the current loader accepts its data plane only in native Linux builds (`_LINUX` and not `_ANDROID`), so Android, Windows, and macOS builds reject enabled `nat66` or `gua` during loading. Verify it on the intended Linux target rather than assuming equivalent behavior elsewhere. With `nat66`, an empty CIDR is given the internal ULA default. `gua` requires a valid global-unicast (`2000::/3`) prefix. Invalid enabled IPv6 settings are cleared or cause loading to fail, depending on the validation failure.

## JSON versus CLI

JSON is the durable configuration source. The CLI applies launch-specific behavior after configuration loading; it does not rewrite the configuration file. See [CLI Reference](CLI_REFERENCE.md) for startup order, mode selection, TUN overrides, statistics output, and route-list utilities.

## Source anchors

- `AppConfiguration::Clear()` — `ppp/configurations/AppConfiguration.cpp`
- `AppConfiguration::Load(Json::Value&)` — `ppp/configurations/AppConfiguration.cpp`
- `AppConfiguration::Loaded()` — `ppp/configurations/AppConfiguration.cpp`
- `AppConfiguration::ToJson()` — `ppp/configurations/AppConfiguration.cpp`
- Post-handshake plaintext framing — `ppp/transmissions/ITransmission.cpp`
