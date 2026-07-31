# Project Interface Map
> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Peer link: [中文](PROJECT_INTERFACE_MAP_CN.md)

> **Purpose:** Inventory discoverable interfaces in this repository and identify current user-facing behavior, experiments, internal implementation details, and known gaps.
> **Audience:** Users, operators, client authors, integrators, and maintainers.
> **Scope:** Current source and in-tree test evidence only. This discovery map is not a public SDK, ABI, release, support, or compatibility promise.

## How To Read This Map

This is a source inventory, not an external interface specification. Detailed field semantics remain in the linked specialist references; source paths win if documentation and code disagree.

| Label | Meaning |
|---|---|
| **Current** | Present in the current tree and used by a user-facing path or bundled companion. It is not a compatibility, release, or support commitment. |
| **Experimental** | Present today, with deliberately limited evidence or an unsettled behavior boundary. |
| **Internal** | A boundary between repository components or bundled companions; documented for maintenance, not offered as a third-party SDK. |
| **Deprecated** | A retained compatibility path whose replacement is named in source or the specialist reference. |
| **Gap** | A missing contract, unsafe ambiguity, implementation defect, or untested boundary. |

`public` in a C++ class means accessible to repository code. It does **not** make that class an external API. Root CMake has no `install()` rule or exported C++ target; the repository declares no installed header set, ABI version, or native SDK.

## Surface Summary

| Domain | Provider | Primary consumer | Input / output | Boundary / evidence | Canonical detail |
|---|---|---|---|---|---|
| `ppp` process and CLI | C++ executable | Users, service managers, scripts | Arguments and files / exit status, logs, TUI | **Current** executable behavior; no formal exit-code table | [CLI reference](CLI_REFERENCE.md) |
| `appsettings.json` | C++ configuration loader | Users and bundled profile producers | JSON / normalized runtime policy | **Current**, implementation-coupled serialized input | [Configuration](CONFIGURATION.md) |
| Connection URI | C++ client | Users and profile/subscription producers | `ppp://`, `ppp://ws/`, `ppp://wss/` | **Current** peer input; implementation-coupled | [Configuration](CONFIGURATION.md) |
| Tunnel wire protocol | C++ client/server | OPENPPP2 peers | Frames, handshake, opcodes, INFO JSON | **Internal** peer behavior; no version negotiation | [Packet formats](PACKET_FORMATS.md), [link layer](LINKLAYER_PROTOCOL.md) |
| Runtime snapshot v1 | C++ runtime | In-process TUI and bundled Android/iOS readers; partial desktop stats reader | C++ object, JSON, and embedded stats fields | **Internal** serialized contract with cross-language fixtures; not a native SDK | [UI runtime contract](UI_RUNTIME_CONTRACT.md) |
| Go manager admin API | `go/ppp` | Embedded `/admin/`, operators | HTTP JSON and subscription JSON | **Current** in-tree service surface; legacy routes remain internal | [Management backend](../guides/MANAGEMENT_BACKEND.md) |
| C++–Go control link | C++ server and `go/ppp` | Repository server components | Length-prefixed JSON over WebSocket | **Internal** | [Management backend](../guides/MANAGEMENT_BACKEND.md) |
| Guardian API | `go/guardian` | Guardian WebUI and operators | HTTP JSON, SSE | **Experimental** | `go/guardian/api/router.go` |
| Desktop Client (Tauri) | `desktop/client` | Windows/macOS end users | Tauri commands/events, local files, spawned `ppp` process | **Experimental** companion; not an SDK | [Client design](../design/SUB_CLIENT_DESIGN_CN.md), `desktop/client/src-tauri/src/desktop.rs` |
| Android Flutter bridge | Flutter/Kotlin/JNI | Bundled Android app | MethodChannel, Intent, JNI, private snapshot files | **Internal** bundled companion | `android/lib/vpn_service.dart`, `android/libopenppp2.cpp` |
| iOS Packet Tunnel bridge | Swift/C ABI | Bundled iOS app and extension | Provider messages, C callbacks, App Group files | **Internal** bundled companion | `ios/OpenPPP2PacketTunnelBridge.h` |
| TUI commands | `ConsoleUI` | Interactive operators | Line commands / rendered terminal state | **Experimental**, local-process-only | `ppp/app/ConsoleUI.cpp` |
| Platform adapters | Windows, Linux, Darwin, mobile code | C++ runtime | TAP/TUN, routes, DNS, socket protection | **Internal** | platform directories and [platform guide](../guides/PLATFORMS.md) |

## 1. Process Entrypoints And Modes

| Entrypoint | Contract | Lifecycle / privilege | Boundary / evidence | Source truth | Known gaps |
|---|---|---|---|---|---|
| `ppp` executable | `--mode=server` (default), `client`, or `proxy`; loads configuration and starts `PppApplication` | Full tunnel normally needs root/Administrator; proxy mode avoids desktop TUN/routes | **Current** executable behavior | `main.cpp`, `ppp/app/ApplicationConfig.cpp`, `ppp/app/PppApplication.*` | No formal exit-code table |
| Go manager executable | Optional configuration-file argument (default `appsettings.json`); runs managed mode only with complete `database.master` and Redis configuration, otherwise runs the local standalone subscription manager | Long-running HTTP/WebSocket service; standalone state persists locally | **Current** in-tree service | `go/main.go`, `go/ppp/Configuration.go`, `go/ppp/ManagedServer.go` | Operational shutdown and data migration contracts are not centrally specified |
| Guardian executable/service | Supervises binaries, profiles, instances, logs, and service installation | Host administration privileges may be required | **Experimental** | `go/guardian/main.go`, `go/guardian/api/router.go` | Host-path access and most handlers lack direct API coverage |
| Desktop Client app | Tauri shell runs local UI, manages subscription/manual nodes, spawns `ppp --mode=client` | Full tunnel needs Administrator/root for the child `ppp` process; UI itself is user-session | **Experimental** bundled companion | `desktop/client/`, `desktop/client/src-tauri/src/desktop.rs` | Not a third-party SDK; IPC surface may change without notice |
| Android `VpnService` | Bundled Flutter UI starts/stops native tunnel in `:vpn` process | Requires user VPN approval and foreground service; service is not exported | **Internal** bundled companion | `android/android/app/src/main/.../PppVpnService.kt` | Release-layout cross-process device coverage remains a gap; see register |
| iOS Packet Tunnel extension | App saves a `NETunnelProviderManager` profile and starts the extension | Requires Network Extension entitlement and user approval | **Internal** bundled companion | `ios/App/OpenPPP2/VPNController.swift`, `PacketTunnelProvider.swift` | No real extension/native-library integration build in Actions |

### Native and companion build evidence

CMake and CI describe build paths, not release support:

| Surface | Current evidence | Boundary / gap |
|---|---|---|
| Native `ppp` | Root `CMakeLists.txt` builds static `openppp2_lib` plus the `ppp` executable; Linux, Windows, and macOS workflows build native artifacts. | No install/export target or C++ ABI contract. |
| Android companion | `android/CMakeLists.txt` builds shared `libopenppp2.so`; `build-android.yml` builds ABIs and runs a debug emulator test. | Debug removes the service's separate process, so it does not test the release cross-process layout. |
| iOS companion | `ios/CMakeLists.txt` defines static `libopenppp2_ios.a`; `test.yml` typechecks Packet Tunnel code and runs Swift logic tests. | Actions do not invoke the native iOS CMake build or a real Packet Tunnel/native-library integration test. |
| Desktop Client and Go tools | Their source and local test/build entrypoints are present; Guardian has a dedicated build workflow and manager checks run in the unit workflow. | Source presence and CI build evidence do not establish an SDK, packaging, signing, or support commitment. |

## 2. Command-Line Interface

The current parsed command surface is grouped below. Exact aliases, defaults, parsing rules, examples, and platform restrictions are in [CLI Reference](CLI_REFERENCE.md).

| Group | Accepted switches | Current boundary / notes |
|---|---|---|
| Role and configuration | `--mode`, `--config`, `--proxy-http-port`, `--proxy-socks-port` | **Current** parser behavior |
| Runtime policy | `--rt`, `--dns`, `--tun-flash`, `--auto-restart`, `--link-restart`, `--block-quic`, `--firewall-rules`, `--lwip`, `--vbgp` | **Current** parser behavior |
| Adapter and address | `--nic`, `--ngw`, `--tun`, `--tun-ip`, `--tun-ipv6`, `--tun-gw`, `--tun-mask` | **Current** parser behavior |
| Tunnel behavior | `--tun-vnet`, `--tun-host`, `--tun-static`, `--tun-promisc`, `--tun-ssmt`, `--tun-route`, `--tun-protect`, `--tun-lease-time-in-seconds` | Platform-conditional parser behavior |
| MUX | `--tun-mux`, `--tun-mux-acceleration`, `--mux-mode`, `--mux-mode-turbo` | `compat`, `flow`, `balance`, and `stripe` are current mode tokens; `stripe` remains **Experimental** in companion presentation. |
| Live MUX debug control | `--debug-key`, `--mux-mode-set` | **Experimental**; no separately versioned control/auth interface |
| Routing and DNS inputs | `--bypass`, `--bypass-nic`, `--bypass-ngw`, `--virr`, `--dns-rules` | Current parser behavior; file formats lack complete schemas |
| Utilities | `--help`, `--pull-iplist` | Current parser behavior |
| Windows helper actions | Driver, route, DNS, proxy, and network-reset helpers, including parser-accepted `--set-http-proxy` | Windows-only parser behavior; many actions exit after the helper |

**Gap:** the generated help banner is not the complete parser contract. It omits parser-accepted `--mux-mode-turbo` and Windows `--set-http-proxy`; the detailed [CLI Reference](CLI_REFERENCE.md) records that drift, but automation still needs parser source until a machine-readable option registry exists.

## 3. JSON Configuration

`appsettings.json` is loaded into `AppConfiguration`; `Load(Json::Value&)` resets fields and calls `Loaded()` before returning. CLI overrides are then applied during application preparation. Unknown-key handling, migration behavior, and a schema version are not formally defined.

| Top-level block | Responsibility | Consumer | Stability | Source truth |
|---|---|---|---|---|
| `concurrent`, `vmem` | Execution concurrency and memory policy | Core runtime | **Current** | `ppp/configurations/AppConfiguration.*` |
| `key` | Cipher names, key material, masking, shuffle, delta, and plaintext mode | Both peers | **Current**, security-sensitive | same |
| `tcp`, `udp`, `websocket`, `cdn` | Carrier listeners, connect policy, TLS/WS, and port modes | Transport layer | **Current** | same |
| `mux` | Multiplexing mode and limits | Transport/runtime | `compat`/`flow`/`balance` **Current** de facto; `stripe` and live control **Experimental** | same |
| `server` | Pools, mappings, backend, policies, IPv6, accounting identity | Server runtime | **Current** | same |
| `client` | Server URI, reconnection, bandwidth, proxy, route behavior | Client runtime | **Current** | same |
| `ip`, `virr`, `vbgp` | Address, route/rule, and route propagation inputs | Network switcher | **Current** de facto | same |
| `dns` | Resolver, interception, fallback, cache, and policy | Client/server DNS runtime | **Current** de facto | same |
| `telemetry` | Enablement, level, count/span switches, endpoint, log file, and console filters | Diagnostics/platform bridges | **Experimental** | same |
| `p2p` | Direct-channel discovery, signaling, transport, and fallback | Client/server P2P runtime | **Experimental** | same |
| `geo-rules` | Geographical routing/rule sources and behavior | Route/DNS policy | **Experimental** | same |

Use [Configuration](CONFIGURATION.md) for source-backed fields and safe examples. Platform profile stores wrap this JSON but do not replace its contract.

**Gaps:** no published JSON Schema for the whole configuration, no `schema_version`, no migration/unknown-key policy, and no automated compatibility fixture spanning desktop, Android, and iOS profile producers.

## 4. Connection And File URIs

| Form | Meaning | Authentication / security | Stability |
|---|---|---|---|
| `ppp://host:port/` | Native tunnel over TCP | Tunnel key configuration; no carrier TLS | **Current** |
| `ppp://ws/host:port/` | Tunnel over WebSocket | Tunnel key configuration; no carrier TLS | **Current** |
| `ppp://wss/host:port/` | Tunnel over TLS WebSocket | TLS plus tunnel key configuration | **Current** |
| `ws://.../ppp/webhook`, `wss://...` | C++ server to Go manager control link | Shared backend key | **Internal** |
| `https://.../sub/{token}` | Android/iOS subscription document; HTTP is loopback-development-only there | Capability-bearing token in path | **Current** |
| `http(s)://...` subscription URL | Desktop Client subscription document | Capability-bearing token in path | **Experimental** desktop-client behavior |
| Local profile import/export file | iOS profile bundle JSON | User-selected file; contains secrets | **Current** for bundled iOS app |

## 5. Transport, Handshake, Link-Layer, And Packet Protocols

| Boundary | Input / output | Compatibility status | Source truth | Verification |
|---|---|---|---|---|
| Protected frame | First/subsequent headers, encrypted payload, masking and delta state | **Current** de facto; both peers must match | `ppp/transmissions/ITransmission.*` | [Packet reference](PACKET_FORMATS.md) and native builds; no direct frame compatibility test |
| Handshake | NOP exchange, session ID, `ivv`, `nmux`, cipher rebuild | **Current** de facto | same | [Session/control model](TRANSMISSION_PACK_SESSIONID.md) |
| Carrier | TCP, WS, WSS streams | **Current** | `ITcpipTransmission.*`, `IWebsocketTransmission.*` | native build/tests |
| Link-layer opcode | One-byte action plus opcode-specific payload | **Current** de facto | `ppp/app/protocol/VirtualEthernetLinklayer.h` | [Link-layer protocol](LINKLAYER_PROTOCOL.md) |
| INFO envelope | JSON session/capability information and extensions | Base fields **Current**; newer extensions **Experimental** | `VirtualEthernetInformation.*` | protocol tests where present |
| Runtime snapshot | Required `schema_version`, `generation`, `monotonic_ms`, and `phase`; standalone JSON for Android/iOS, in-process C++ object for TUI, selected embedded fields for desktop stats | **Current** | `RuntimeSnapshot*.h`, schema, and `RuntimeStatsJson.h` | Shared C++/Dart/Swift JSON fixtures; desktop reader is partial |

**Gaps:** the tunnel has no explicit protocol-version negotiation, reserved-opcode registry, formal extension negotiation, direct protected-frame/handshake golden tests, or compatibility matrix across released versions. Wire compatibility is therefore implementation-coupled even where behavior is stable in practice.

## 6. C++–Go Control Protocol

The optional manager control link uses WebSocket path `/ppp/webhook`. Each message is an 8-character hexadecimal body length followed by JSON:

```text
[8 hex characters][{"Id":1,"Node":7,"Guid":"...","Cmd":1002,"Data":"..."}]
```

| Command | Direction | Purpose | Stability |
|---|---|---|---|
| `1000` ECHO | Bidirectional | Keepalive / latency | **Internal** |
| `1001` CONNECT | C++ → Go and reply | Establish backend control session | **Internal** |
| `1002` AUTHENTICATION | C++ → Go and reply | Authorize a VPN user | **Internal** |
| `1003` TRAFFIC | C++ → Go and reply | Report traffic accounting | **Internal** |

Authentication uses the configured manager `key` matched by C++ `server.backend-key`. Source truth: `go/ppp/Packet.go`, `Handler.go`, `ManagedServer.go`, and `ppp/app/server/VirtualEthernetManagedServer.*`.

**Gaps:** no envelope version, capability negotiation, maximum-frame contract, formal error object, or cross-language golden frame suite. WebSocket origin checks currently allow all origins.

## 7. Go Manager HTTP API

### Current JSON API

All `/api/v1/*` routes require the admin bearer token. `/sub/{token}` is a separate public capability URL. The embedded UI is normally served from `/admin/`; `OPENPPP2_ADMIN_TOKEN` can override the configured token. Standalone mode persists its generated token in `manager-data.json`; managed mode generates only a process-lifetime token when none is configured.

| Method and path | Purpose | Stability |
|---|---|---|
| `GET /api/v1/status` | Counts and manager status | **Current** |
| `GET, POST /api/v1/users` | Managed mode lists/creates VPN users; standalone returns an empty list and rejects writes | **Current**, mode-dependent |
| `PUT, DELETE /api/v1/users/{guid}` | Managed mode updates/deletes a user; standalone returns 404 | **Current**, managed only |
| `GET, POST /api/v1/servers` | List/create server records | **Current** |
| `PUT, DELETE /api/v1/servers/{id}` | Update/delete a server record | **Current** |
| `GET, POST /api/v1/subscriptions` | List/create subscriptions | **Current** |
| `PUT, DELETE /api/v1/subscriptions/{id}` | Update/delete a subscription | **Current** |
| `POST /api/v1/subscriptions/{id}/rotate-token` | Invalidate and replace public token | **Current** |
| `GET /api/v1/subscriptions/{id}/preview` | Preview generated document | **Current** |
| `GET /sub/{token}` | Publish subscription JSON | **Current** capability URL |

The authoritative route table is `go/ppp/Admin.go`; persistence is `go/ppp/LocalStore.go` and `Subscription.go`.

### Legacy Internal API

| Routes | Status | Preferred surface / risk |
|---|---|---|
| `/ppp/consumer/set`, `/new`, `/reload`, `/load` | **Internal**, legacy compatibility | Prefer `/api/v1/users`; handlers accept arbitrary methods and encode business errors in HTTP 200 responses |
| `/ppp/server/all`, `/get`, `/load` | **Internal**, legacy compatibility | Prefer `/api/v1/servers`; the shared `key` query parameter is required, as it is for the consumer routes |

The control WebSocket and all `/ppp/*` routes exist only in managed mode. No source-level removal schedule or formal deprecation policy currently exists.

**Gaps:** origin policy is permissive; server secrets can be returned to the admin UI; a formal OpenAPI document and complete response/error schema are missing.

## 8. Subscription And Admin UI Contracts

The public subscription payload consumed by Android, iOS, and the desktop Client is:

```json
{
  "type": "openppp2-subscription",
  "version": 1,
  "nodes": []
}
```

The `type` and `version` pair is **Current**. Node entries are translated into complete native configuration profiles. Android parser tests exist in `android/test/remote_subscription_test.dart`; the iOS parser is in `ios/App/OpenPPP2/AppModels.swift` but lacks equivalent fixture tests.

The `/admin/` WebUI is a consumer of the manager API, not a separate supported API. Its storage, route, and authentication behavior must follow the backend contract.

The manager, Android, iOS, and desktop implementations currently cap subscription documents at 2 MiB. Android and iOS accept HTTPS sources (HTTP only for loopback development); the desktop Client accepts HTTP and HTTPS. **Gaps:** a published shared policy, aligned redirect/trust behavior, duplicate-node policy, and a shared Android/iOS fixture suite remain missing. Tokens in subscription URLs may leak through logs and referrers.

## 9. Desktop Client Tauri Bridge

The Windows/macOS Client Manager lives under `desktop/client/`. The Svelte UI talks only to the local Tauri shell; it does not call Guardian or the Sub admin API. The shell fetches subscription documents, stores preferences, merges manual nodes, and spawns the existing `ppp` binary.

| Command | Purpose | Stability |
|---|---|---|
| `client_bootstrap` | Load subscription cache, merged nodes, config, launch options, settings | **Experimental** |
| `subscription_refresh` | Fetch HTTP(S) subscription URL, cache, persist URL | **Experimental** |
| `client_probe_latency` | TCP probe selected nodes; also emits `client://latency` | **Experimental** |
| `client_connect` / `client_disconnect` | Build config, start/stop local `ppp --mode=client` | **Experimental** |
| `client_update_config` / `client_update_client_config` | Persist raw appsettings / client-side config edits | **Experimental** |
| `client_upsert_manual_node` / `client_delete_manual_node` | CRUD local `manual:` nodes | **Experimental** |
| `client_update_launch_options` / `client_update_setting` | Persist launch options and app settings | **Experimental** |
| `client_toggle_favorite` | Toggle favorite node id list | **Experimental** |

Events: `client://process` (process lifecycle/log lines), `client://latency`, `client://tray-error`. Persistence: `preferences.json` (manual nodes, launch options, settings, raw config, favorites) and `subscription-cache.json` under the app data directory; runtime writes `runtime/appsettings.json` and `runtime/stats.ndjson` for the child process. Source: `desktop/client/src-tauri/src/desktop.rs`, `preferences.rs`, `manual_nodes.rs`, `launch_options.rs`. Design: [manual profiles](../design/CLIENT_MANUAL_PROFILES_DESIGN_CN.md), [UI/UX](../design/CLIENT_UIUX_DESIGN_CN.md).

**Gaps:** no published IPC schema or version field; bundle/install/signing flow is incomplete (`bundle.active` is false). `autostart` is currently only a persisted preference—no OS startup registration is implemented. The shell launches `ppp` directly, so elevation remains platform/manifest-dependent and unvalidated.

## 10. Guardian HTTP And SSE API

Guardian routes are **Experimental**. When authentication is enabled, normal `/api/*` routes require `Authorization: Bearer <token>`. Auth routes and `GET /api/v1/status` bypass the common middleware. SSE also bypasses that middleware but performs its own TokenStore/JWT validation using a query token or Bearer token; it is public only when authentication is disabled. CORS currently allows `*`.

| Group | Routes |
|---|---|
| Authentication | `POST /api/v1/auth/login`, `POST /api/v1/auth/refresh`, `PUT /api/v1/auth/password` |
| Instances | `GET, POST /api/v1/instances`; `GET, PUT, DELETE /api/v1/instances/{name}`; `POST .../{name}/start|stop|restart`; `GET .../{name}/logs` |
| Profiles | `GET /api/v1/profiles`; `GET, PUT, DELETE /api/v1/profiles/{name}`; `POST .../{name}/validate`; `GET .../{name}/backups`; `POST .../{name}/restore/{backupId}` |
| Binaries | `GET /api/v1/binaries`, `GET /api/v1/binaries/discover`, `POST /api/v1/binaries`, `DELETE /api/v1/binaries/{id}` |
| Guardian/service | `GET /api/v1/status`, `PUT /api/v1/guardian/config`, `GET /api/v1/service/status`, `POST /api/v1/service/install`, `POST /api/v1/service/uninstall` |
| Streaming | `GET /api/v1/sse/logs/{name}`, `GET /api/v1/sse/events` |
| UI | `GET /` catch-all static file server; no SPA history fallback |

Source truth is `go/guardian/api/router.go`, `go/guardian/api/middleware.go`, handler files, and `go/guardian/webui/src/lib/api.js`.

Guardian config and instance state are written as JSON with mode `0600`; profiles and backups are ordinary files with mode `0644`; the registered-binary map is in memory and is rebuilt through discovery after restart.

**Gaps:** discover/register can access arbitrary host paths; `PUT /api/v1/guardian/config` currently ignores its request body; most handlers have no direct API tests; SSE credentials can appear in URLs; WebUI tokens use `localStorage`; profile save/restore is not atomic; binary registrations are not persistent. Password change is also the unauthenticated bootstrap path while auth is disabled, so first-time setup must remain on loopback or a trusted network.

## 11. Android Bridge

All Android entries below are **Internal** to the bundled Flutter application. Channel names are an internal ABI, not a third-party integration promise.

| Boundary | Operations / payload | Lifecycle | Source truth |
|---|---|---|---|
| Flutter MethodChannel `supersocksr.ppp/vpn` | `connect`, `disconnect`, `getRuntimeSnapshot`, `getLastError`, `readLog`, `getLogPath`, `clearLog`, `getVpnHeartbeatAgeMs`, `getInstalledApps`, `getAppIcon`, `getTelemetryIdentity`, `requestPermission` | UI process; asynchronous calls | `android/lib/vpn_service.dart`, `MainActivity.kt` |
| Activity → service Intent | connect/disconnect actions with `config_json`, `vpn_options_json` extras | Starts foreground non-exported `:vpn` service | `MainActivity.kt`, `PppVpnService.kt` |
| Kotlin → JNI | Native configuration/run/stop, link-state/error/runtime-snapshot queries, socket protection, telemetry HTTP callback; traffic is carried by runtime snapshots | `run()` blocks a background thread; callbacks require live service | `android/android/app/src/main/kotlin/supersocksr/ppp/android/c/libopenppp2.kt`, `android/libopenppp2.cpp` |
| JNI → Kotlin | `runtime_snapshot`, `protect`, `start_exec`, `post_exec`, telemetry HTTP | Static callbacks on `libopenppp2`; invoked from arbitrary runtime threads, so each attaches the JVM and never caches `JNIEnv*` | same |
| Profile storage | `profiles_v2`, active ID, options, bounded history | App-private SharedPreferences | `android/lib/services/profile_store.dart` |
| Cross-process state | `openppp2-heartbeat.txt`, `openppp2-linkstate.txt`, `openppp2-runtime-snapshot.json`, `openppp2-lasterror.txt` | Snapshot, link-state, and error values use temporary-file replacement; heartbeat freshness uses file mtime with a 30-second stale threshold | `PppStateStore.kt`, `MainActivity.kt` |

`PppVpnService` runs in `:vpn`. The removed EventChannel path was replaced by snapshot/error file mirroring and visible-UI polling. Native publishes reach the service through the `runtime_snapshot` JNI callback and are ordered by the snapshot's own `generation` and `monotonic_ms`.

**Gap:** debug builds strip `android:process` from the service (`app/src/debug/AndroidManifest.xml`), so instrumentation runs single-process and cannot exercise the release cross-process layout. That layout is currently covered by source-level checks in `tests/tooling/test_runtime_ui_wiring.py`, not by a device test.

Other gaps: no centralized channel/JNI ABI version, no complete method/error schema, no service kill/recreate coverage, no full JNI signature test, and profile storage has no explicit migration version.

## 12. iOS Bridge

All iOS entries below are **Internal** to the bundled app and Packet Tunnel extension unless explicitly stated.

| Boundary | Operations / payload | Lifecycle | Source truth |
|---|---|---|---|
| App → Network Extension | Save/load manager, start/stop tunnel, provider configuration | System authorization and `NETunnelProviderManager` lifecycle | `VPNController.swift` |
| Provider messages | `linkState`, `lastError`, `diagnostics`, `crashReports`, `deleteCrashReports`, JSON `uploadCrashReports` | Only a connected `NETunnelProviderSession` can exchange messages | `VPNController.swift`, `PacketTunnelProvider.swift` |
| Swift → C ABI | `openppp2_ios_version`; tap create/destroy/start/stop/input; link/snapshot/stage queries; last error; telemetry; P2P datagram callbacks | Tap and callback ownership is explicit; provider close must stop callbacks synchronously | `ios/OpenPPP2PacketTunnelBridge.h` |
| App Group state | Link heartbeat, runtime snapshot, diagnostics, defaults | App and extension share entitled container; atomic file writes | `TunnelSharedState.swift` |
| Profile bundle | `type=openppp2-profile-export`, `version=1`, active ID and profiles | User-selected security-scoped file; 2 MiB limit; secrets included | `ProfileImportExport.swift` |

Profile export v1 is **Current** for the bundled iOS app. The C ABI and provider-message commands remain **Internal**.

**Gaps:** provider messages use unversioned bare strings and `nil` for multiple failures; C structs have no ABI version or `struct_size`; no complete buffer truncation convention; Actions do not build the native iOS static library or execute a real Packet Tunnel integration test.

## 13. Runtime Snapshot And TUI

Runtime snapshot v1 has required `schema_version`, `generation`, `monotonic_ms`, and `phase` fields. Ordering uses `generation` and then `monotonic_ms`; the parser rejects unsupported schemas and the publisher rejects stale ordered updates. `capabilities` is an array of strings. The TUI consumes an in-process C++ `RuntimeSnapshot`; Android and iOS decode standalone JSON; the desktop Client consumes selected `runtime` fields embedded in `ppp-stats` records and does not validate the embedded snapshot version. Shared JSON fixtures cover C++, Dart, and Swift. TUI built-ins use the `openppp2` namespace; bare `openppp2` is a help alias.

| TUI command | Effect | Stability |
|---|---|---|
| `openppp2 [help]`, `openppp2 info`, `openppp2 clear` | Inspect or clear console state | **Experimental** |
| `openppp2 restart|reload|exit` | Restart/reload/shutdown application | **Experimental**; `reload` currently behaves like restart |
| `openppp2 telemetry [status|help]` | Inspect current console telemetry settings | **Experimental** |
| `openppp2 telemetry log|metric|span on|off|toggle` | Change in-process console filters | **Experimental** |
| `openppp2 telemetry level 0|1|2|3`, `all`, `quiet`, `clear` | Change in-process minimum telemetry level, filters, or event buffer | **Experimental** |

TUI availability depends on a TTY and `PPP_NO_TUI`. Commands execute on ConsoleUI lifecycle threads and are not a remote-control API; unknown input is shown as an unknown command and is never executed by a shell. Source: `ppp/app/ConsoleUI.cpp`, `ppp/app/tui/TuiRuntimeAdapter.h`.

**Gaps:** dedicated ConsoleUI command-parser, lifecycle, and concurrent-shutdown coverage is still limited; the schema omits some optional fields emitted by serializers.

## 14. C/C++ Headers And Extension Points

| Interface | Role | Classification | Why it is not an external SDK |
|---|---|---|---|
| `AppConfiguration` | Parsed and normalized runtime policy | **Internal** | Layout and fields can change with source |
| `ITransmission` | Protected carrier and handshake base | **Internal** | No installed headers or ABI contract |
| `VirtualEthernetLinklayer` / information types | Tunnel opcode and INFO implementation | **Internal**; base INFO/wire fields are stable de facto, newer extension JSON is **Experimental** | C++ object layout is not the wire contract |
| `PppApplication`, lifecycle/snapshot types | Composition root and state publication | **Internal** | Repository-owned lifecycle |
| DNS, route, MUX, TAP abstractions | Subsystem extension points | **Internal** | Platform/build-specific and not exported |
| Error handler and telemetry facade | Repository callbacks | **Internal**; numeric diagnostics are externally observable | No SDK target or callback ABI guarantee |
| `OpenPPP2PacketTunnelBridge.h` | iOS extension C boundary | **Internal** | Bundled bridge only; no install/export package |

Creating a supported native SDK would require a deliberately small installed header set, export visibility, ownership rules, ABI version and feature query, semantic version policy, packaging, examples, and cross-version binary tests. None currently exist.

## 15. Platform Adapters

| Platform | Internal boundary | Privilege / ownership | Main sources | Major gap |
|---|---|---|---|---|
| Windows | Wintun/TAP, route/DNS/proxy helpers, service/process helpers | Administrator for adapter and network changes | `windows/`, `TapWindows.*` | Helper exit/error behavior lacks one contract table |
| Linux | TUN, route/rule/DNS operations, optional io_uring/SYSNAT | root/CAP_NET_ADMIN | `linux/`, `TapLinux.*` | Distribution-specific command/rollback behavior needs integration coverage |
| macOS | utun, route/DNS operations | root for desktop tunnel | `darwin/`, `TapDarwin.*` | macOS build is not iOS extension validation |
| Android | `VpnService`, protected sockets, JNI callbacks | user VPN approval; service owns TUN fd | `android/` | Cross-process runtime snapshot defect and sparse device tests |
| iOS | Packet Tunnel, C callback bridge, App Group | entitlement and provider-owned packet flow | `ios/` | Native library and provider IPC not built end-to-end in CI |

## 16. Errors, Diagnostics, Telemetry, And Persistence

| Boundary | Format / behavior | Stability | Source truth | Gap |
|---|---|---|---|---|
| Diagnostic error code | Numeric enum plus text and thread-local/atomic last-error snapshot | **Current** de facto | `ppp/diagnostics/ErrorCodes.def`, [error codes](ERROR_CODES.md) | Append-only policy and removal rules are not enforced |
| Error callback | In-process handler dispatch | **Internal** | `ErrorHandler.*` | No external callback ABI |
| Runtime statistics/link state | JSON/text/file/channel depending on platform | **Experimental** except snapshot v1 | platform bridges | Multiple lifetime/freshness rules are inconsistent |
| Telemetry facade | Logs, metrics, spans, OTLP HTTP callbacks | **Experimental** | `ppp/diagnostics/Telemetry.h`, platform bridges | Documentation and builds disagree on default enablement |
| Manager state | `manager-data.json` with `version: 1` | **Current persisted format** for standalone manager | `go/ppp/LocalStore.go` | No published JSON Schema, migration policy, or corruption-recovery contract |
| Desktop Client preferences | `preferences.json`, `subscription-cache.json` | **Internal persisted format** | `desktop/client/src-tauri/src/preferences.rs` | No schema version or migration policy |
| Guardian config/instances | JSON written with mode `0600` | **Internal persisted format** | `go/guardian/config.go`, `guardian.go` | No published schema or migration contract |
| Guardian profiles/backups | Files written with mode `0644` | **Internal persisted format** | `go/guardian/profile/manager.go` | Save/restore is not atomic |
| Guardian binary registry | In-memory registration plus rediscovery | **Internal runtime state** | `go/guardian/binary/manager.go` | Explicit registrations do not survive restart |
| Android profiles | SharedPreferences JSON | **Internal** | `profile_store.dart` | No explicit storage schema/migration |
| iOS profile export | Versioned JSON bundle | **Current** | `ProfileImportExport.swift` | No standalone JSON Schema |
| Runtime fixtures | JSON plus hash manifest | **Stable test contract** | `tests/contracts/runtime-snapshot/`, `tools/check_runtime_fixture_hashes.py` | Schema does not enumerate all optional producer fields |

## 17. Build, Test, Tooling, And CI Interfaces

| Entrypoint | Output / purpose | Stability | Coverage gap |
|---|---|---|---|
| Root CMake; `build-openppp2-by-builds.sh` | Root CMake builds native `ppp`; the variant script packages Linux variants | **Developer interface** | The variant script temporarily rewrites root `CMakeLists.txt` and removes `build/`; use only in a clean, disposable worktree |
| `build_windows.bat` | Windows x86/x64/ARM64 Ninja builds | **Stable developer interface** | Environment/toolchain discovery is machine-dependent |
| `android/CMakeLists.txt`, build scripts | Four Android `libopenppp2.so` ABIs | **Internal build interface** | Hard-coded third-party defaults; no JNI export check |
| `ios/CMakeLists.txt` | `libopenppp2_ios.a` | **Experimental build interface** | Not built by current Actions |
| `cd go && go test ./ppp/... && go build .`; `cd go/guardian && go test ./... && go build .` | Separate manager and Guardian module checks | **Stable developer interface** | Guardian handler coverage is sparse; build `go/guardian/cmd/tui` separately when needed |
| `flutter test`; `cd ios/App && swift test` | Android Flutter/Dart tests; separate iOS Swift logic tests | **Stable developer interface** | No PR device test for Android VPN lifecycle |
| `cd desktop/client && npm test && npm run build` | Desktop Client frontend tests/build | **Experimental developer interface** | Tauri shell packaging/signing not gated |
| `scripts/run-cpp-tests.sh` | Standalone C++ CTest suite | **Stable developer interface** | Full platform networking still needs integration tests |
| `scripts/test-runtime-contract.sh` | `hashes`, `cpp`, `dart`, `swift` contract checks | **Stable test interface** | Hash check is repeated indirectly rather than one explicit CI gate |
| `tools/check_docs.py` | Metadata, relative links, bilingual map checks | **Stable governance interface** | Does not validate anchors or external URLs |
| Wave-B regression/bench scripts | Correctness and host-bound performance baselines | **Experimental** | Baselines are not portable across hosts/toolchains |

## Compatibility Rules For New Work

1. Update both language versions of every stable document.
2. Treat serialized bytes, JSON fields, route/method pairs, channel method names, and persisted files as contracts even when their implementation is internal.
3. Add a version or capability field before making incompatible serialized changes.
4. Preserve unknown fields where practical and define rejection behavior where not.
5. Never infer SDK support from C++ access modifiers.
6. Add producer/consumer fixtures for cross-language contracts.
7. Document authentication, secret exposure, lifecycle/thread ownership, error behavior, source truth, and tests for every new interface.

## Consolidated Gap Register

| Priority | Gap | Affected surface | Completion evidence |
|---|---|---|---|
| P1 | Android cross-process runtime delivery has no device test because debug builds collapse `:vpn` into the app process | Android runtime UI | An instrumentation variant that keeps `android:process`, or an equivalent multi-process harness |
| P1 | No tunnel protocol version/opcode registry/cross-release matrix | Wire protocol | Version negotiation, registry, and compatibility fixtures |
| P1 | Guardian binary paths can expose arbitrary host paths; config PUT ignores body | Guardian | Path policy, correct update behavior, and API tests |
| P1 | iOS native bridge/Packet Tunnel is not built end-to-end in CI | iOS | Static library build plus provider-message integration test |
| P1 | Whole configuration has no schema/version/migration policy | Configuration/profile stores | Published schema, version field, fixtures, migration tests |
| P1 | Go APIs lack OpenAPI and complete error/response schemas | Manager and Guardian | Generated/validated OpenAPI with auth and error models |
| P2 | CLI parser and help text can drift | CLI | Single option registry generating parser/help/tests |
| P2 | JNI/provider-message/C ABI boundaries lack consistent version and error contracts | Mobile bridges | ABI query/envelope versions and integration tests |
| P2 | Error numbers and telemetry defaults lack enforced compatibility policy | Diagnostics/telemetry | Automated enum policy and one verified default |
| P2 | Persistence formats lack atomic migration and schema contracts | Go/Android/iOS/Desktop Client | Versioned formats, atomic replacement, corruption recovery tests |
| P2 | Desktop Client IPC has no versioned schema or packaging gate; `autostart` is only a stored preference | Desktop Client Tauri bridge | Command/event schema, bundle signing, elevated-launch validation, and OS startup registration |

This register describes current evidence; it does not by itself authorize exposing unauthenticated or host-level operations to untrusted networks.
