# OpenPPP2 Telemetry and Observability Design

[中文版本](OTEL_DESIGN_CN.md)

## 1. Positioning

OPENPPP2 already has a **zero-cost error-code diagnostics system** (`ppp::diagnostics::ErrorCode`, thread-local snapshots, atomic propagation). This is the primary observability mechanism. It works on all machines, including low-end hardware, with no runtime overhead.

Telemetry (structured logging / OTel) is an **optional supplementary layer**, not a replacement for error codes.

| Capability | Error-Codes | Telemetry (Logs/Metrics/Traces) |
|------------|-------------|--------------------------------|
| Runtime cost | Near-zero | Non-zero (must be switchable) |
| Default state | Always on | **Off by default** |
| Low-end hardware | Fully usable | Disabled by default |
| Granularity | Error path coverage | Event-level detail |
| Use case | Production fault detection | Debugging / profiling / managed deployments |

> **Upstream principle**: "Don't use logs, use error codes instead. Logs are expensive; low-end machines suffer. If you must add logs, add a switch so they can be turned off." ([source](https://github.com/liulilittle/openppp2/issues/1#issuecomment-...))

---

## Implementation Status

The telemetry system described in this document has been fully implemented:

- **`ppp/diagnostics/Telemetry.h`** — Zero-cost facade. Provides inline no-op stubs when `PPP_TELEMETRY=0`, ensuring no runtime overhead when telemetry is disabled. Exposes `SetEnabled(bool)`, `SetMinLevel(int)`, `SetCountEnabled(bool)`, `SetSpanEnabled(bool)`, `Configure(const char* endpoint)`, `SetLogFile(const char* path)`, `Flush(int timeout_ms)`, `Histogram(...)`, and RAII `SpanScope` for runtime control and tracing.
- **`ppp/diagnostics/Telemetry.cpp`** — Async backend with bounded queue (4096 entries), drop-on-full semantics, and a background worker thread. Supports three output targets: built-in stderr backend (default), HTTP OTLP exporter (`HttpOtlpExporter`), and optional file output. The OTLP exporter batches up to 256 events and sends them as OTLP/JSON HTTP POST requests to a configured collector endpoint, supporting Logs, Counters, Gauges, Histograms, and completed Spans. OTLP output now includes resource/service metadata and per-event attributes such as `service.name`, `thread.id`, `log.level`, `component`, and non-empty `session.id` on spans. Uses raw POSIX sockets (WinSock2 on Windows) with no external dependencies.
- **CMake option `PPP_TELEMETRY`** — Compile-time switch, default `OFF`.
- **Instrumentation** — 13 modules instrumented: transmission, protocol, server switcher, server exchanger, client switcher, client exchanger, mux, tap, vnetstack, ITap, tcpip, websocket, managed.
- **Runtime config** — Loaded from `appsettings.json` via `AppConfiguration::telemetry.*` → `telemetry::SetEnabled/SetMinLevel/SetCountEnabled/SetSpanEnabled/Configure/SetLogFile()`.
- **Level filtering** — `Log` events are filtered by level both at the call site (fast path) and in the backend thread (defensive), ensuring no TRACE events slip through when level is lowered at runtime.
- **Count/Span switches** — `telemetry.count` and `telemetry.span` in `appsettings.json` independently control whether metric and trace events are emitted.
- **File output** — New `telemetry.log-file` field in `appsettings.json`. When set (e.g. `"./telemetry.log"`), all telemetry output is written to both stderr and the file simultaneously.
- **Graceful shutdown** — `Flush(int timeout_ms)` API waits for queued events to be drained before process exit. Hooked into `PppApplication::Dispose()`.
- **Tracing model** — `SpanScope` now generates real `traceId`/`spanId` pairs with parent-child propagation through a thread-local trace stack. One-shot `TraceSpan(...)` also emits spans with generated IDs.
- **Attribute enrichment** — OTLP export now includes global `service.name=openppp2`, per-event `thread.id`, `log.level` for logs, `component` for logs, and `session.id` for spans when present.

> **Note:** The backend supports multiple output targets (stderr, OTLP HTTP, and file), controlled at runtime via `Configure()` and `SetLogFile()`. Changing the backend or adding exporters required no changes to any instrumented modules.

---

## 2. Design Principles

### 2.1 Error Codes Are the Foundation

The existing error-code system is the ground truth:

- `SetLastErrorCode()` — thread-local, no allocation, no string formatting.
- `ErrorHandler::Dispatch()` — atomic snapshot with truncated timestamp.
- Coverage spans all subsystems: transmission, tunnel, protocol, client, server, platform.

Telemetry must **not** duplicate error-code semantics. It records **events** that error codes do not capture: timing, rates, queue state, session lifecycle.

### 2.2 Telemetry Must Be Switchable

This is non-negotiable.

- **Compile-time**: `#ifdef PPP_TELEMETRY` or CMake option.
- **Run-time**: configuration flag `telemetry.enabled = false` by default.
- **Per-module**: each subsystem can be enabled independently.
- **Hot-disable**: when disabled, the telemetry facade compiles to no-ops.

Low-end machines run with telemetry completely compiled out or runtime-disabled.

### 2.3 Telemetry Must Not Interfere with Packet Processing

When enabled:

- No blocking exporter calls on the hot path.
- No string formatting inside packet forwarding loops.
- No locks that contend with `syncobj_`, queue dispatch, or fd affinity.
- Telemetry observes; it never drives queue selection, routing, or protocol decisions.

---

## 3. When to Use Error Codes vs. Telemetry

### Use Error Codes

- Any abnormal branch (failure, timeout, validation reject).
- Resource exhaustion (fd limit, memory limit, queue full).
- Protocol violations (unexpected opcode, checksum failure).
- Security events (replay, auth failure, firewall block).

### Use Telemetry (Optional)

- Session establishment duration (not failure, but latency).
- Queue hit rate, fd affinity hit rate.
- Connection count, throughput rate (Metrics).
- Rare event sequences that need cross-module correlation (Traces).

---

## 4. Recommended Log Levels (When Telemetry Is Enabled)

If telemetry is compiled in and runtime-enabled, the following levels are recommended:

| Level | Default | Purpose |
|-------|---------|---------|
| INFO | On | Startup, configuration summary, listen success, major state changes |
| VERB | Off | Branch decisions, policy hits, management interactions |
| DEBUG | Off | Handshake, mux state, transit tun, queue/fd affinity, NAT/IPv6 allocation |
| TRACE | Off | Per-packet details; strictly module-scoped, rate-limited |

All levels above INFO must be explicitly enabled per module.

---

## 5. TRACE Constraints

TRACE is the highest-risk level. When enabled it must support:

1. Per-module enablement
2. Per-session / per-connection filtering
3. Sampling (e.g., 1%)
4. Rate limiting (events/second)
5. Queue-full drop (never block)
6. Async exporter

---

## 6. Structured Fields (Telemetry Only)

When telemetry exports events, the following fields are recommended:

**Base**
- `service.name`, `service.version`, `host.name`, `process.pid`
- `thread.id`, `log.level`, `component`, `mode`, `platform`

**Network**
- `session.id`, `node.id`, `user.id`, `connection.id`
- `remote.address`, `local.address`, `protocol`
- `tap.name`, `tun.fd`, `queue.id`, `preferred_tun_fd`
- `ipv6.address`, `ipv6.gateway`
- `packet.direction`, `packet.family`, `packet.proto`, `packet.length`

Error codes already carry `error_code` and `timestamp`; telemetry adds context, not replacement.

---

## 7. Implementation Facade

Do not scatter OTel SDK calls inside protocol code.

Use the project-internal facade in `ppp/diagnostics/Telemetry.h` (with the async backend in `ppp/diagnostics/Telemetry.cpp`) that compiles to no-ops when disabled:

```cpp
namespace ppp::telemetry {
    void Log(Level level, const char* component, const char* fmt, ...) noexcept;
    void Count(const char* metric, int64_t delta) noexcept;
    void Gauge(const char* metric, int64_t value) noexcept;
    void Histogram(const char* metric, int64_t value) noexcept;
    void TraceSpan(const char* name, const char* session_id) noexcept;
    void SetEnabled(bool enabled) noexcept;
    void SetMinLevel(int level) noexcept;
    void SetCountEnabled(bool enabled) noexcept;
    void SetSpanEnabled(bool enabled) noexcept;
    void Configure(const char* endpoint) noexcept;
    void SetLogFile(const char* path) noexcept;
    void Flush(int timeout_ms = 3000) noexcept;
    class SpanScope;
}
```

When `PPP_TELEMETRY` is undefined, these are inline empty functions — zero cost.

---

## 8. Relationship to Queue / FD Affinity

Telemetry may record:

- `queue.id`
- `tun.fd`
- `preferred_tun_fd`

It must **never**:

- Influence queue selection.
- Break fd affinity.
- Change packet flow.

---

## 9. Phased Rollout

### Phase 1 — Facade + Instrumentation ✅

- Compile-time telemetry flag `PPP_TELEMETRY` added (default OFF).
- Zero-cost facade implemented in `ppp/diagnostics/Telemetry.h`.
- Async backend implemented in `ppp/diagnostics/Telemetry.cpp` (bounded queue 4096, drop-on-full, stderr output, background worker thread).
- Instrumentation added to 13 modules: transmission, protocol, server switcher, server exchanger, client switcher, client exchanger, mux, tap, vnetstack, ITap, tcpip, websocket, managed.

### Phase 2 — Optional OTel Logs ✅ (Complete)

- ✅ Async OTel exporter implemented with stderr, OTLP HTTP, and file output backends.
- ✅ Runtime config `telemetry.enabled`, `telemetry.level`, `telemetry.count`, `telemetry.span`, `telemetry.endpoint`, `telemetry.log-file` loaded from `appsettings.json`.
- ✅ `HttpOtlpExporter` with batch POST to OTLP collector, supporting Logs, Counters, Gauges, Histograms, and Spans.
- ✅ Runtime API: `SetEnabled(bool)`, `SetMinLevel(int)`, `SetCountEnabled(bool)`, `SetSpanEnabled(bool)`, `Configure(const char* endpoint)`, `SetLogFile(const char* path)`.
- ✅ Independent Count/Span switches and defensive backend level filtering.

> **Note:** Because all instrumentation goes through the `Telemetry.h` facade, changing the backend or adding exporters required no changes to any instrumented modules.

### Phase 3 — Optional Metrics ✅

- `Gauge()` API added to `Telemetry.h` (zero-cost no-op when disabled).
- OTLP `BuildGaugeJson()` implements the OTel gauge data model (instantaneous value per data point).
- Gauges instrumented: `server.active_sessions`, `server.exchanger_count`, `tap.active_fds`, `tap.ipv6_routes`, `tap.neighbor_proxies`.
- `Histogram()` API added to `Telemetry.h` and OTLP `BuildHistogramJson()` now exports histogram samples.
- Histogram instrumentation added for `websocket.handshake.us`, `websocket.wss.handshake.us`, and `managed.auth.us`.
- Histogram instrumentation also covers `server.session.establish.us`, `server.ipv6.assign.us`, `server.route.add.us`, `server.route.delete.us`, `client.connect.us`, `client.proxy.setup.us`, `client.route.apply.us`, `client.dns.apply.us`, `managed.sync.us`, `mux.link.setup.us`, `tap.ipv6.route.add.us`, `tap.ipv6.neighbor.add.us`, `tap.ipv6.neighbor.delete.us`, `tap.interface.state.us`, `vnetstack.connect.us`, and `transmission.handshake.us`.
- Full bucket aggregation is still minimal; current implementation exports one-sample histogram points with fixed explicit bounds.

### Phase 4 — Optional Traces ✅

- `SpanScope` RAII tracing is implemented in `Telemetry.h` / `Telemetry.cpp`.
- OTLP span export now includes generated `traceId`, `spanId`, `parentSpanId`, `startTimeUnixNano`, and `endTimeUnixNano`.
- Scoped spans are instrumented in websocket handshake paths, managed authentication paths, and protocol authentication handling.
- Scoped spans are also instrumented in server session establishment, server IPv6 withdrawal, server route add / delete, client connect, client route apply, client DNS apply, client proxy setup, managed sync, mux link setup, tap IPv6 route add / neighbor add / neighbor delete, vnetstack connect, transmission lifecycle close, and exchanger static echo allocation paths.
- Remaining work is higher-level trace coverage and richer attribute propagation, not the core tracing pipeline.

---

## 10. Summary

1. **Error codes are primary.** They are always on, zero-cost, and the upstream-preferred mechanism.
2. **Telemetry is optional.** It must be switchable at compile time and runtime, default OFF.
3. **Low-end machines use error codes only.** Telemetry is for debugging, profiling, or managed deployments with spare capacity.
4. **Never interfere.** Telemetry is a passive observer; it never drives protocol, routing, or queue behavior.
5. **Facade with no-op fallback.** All telemetry calls compile away when disabled.
