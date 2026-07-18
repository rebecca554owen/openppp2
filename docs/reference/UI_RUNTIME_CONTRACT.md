# UI Runtime Contract

> **Purpose:** Specify the current runtime state contract consumed by user interfaces.
> **Audience:** Runtime, Android, iOS, and TUI developers.
> **Status:** Current.
> **Last verified against:** Latest main runtime and platform wiring, 2026-07-18.
> **Parent index:** [Reference](README.md) · **Chinese:** [UI Runtime 契约](UI_RUNTIME_CONTRACT_CN.md)

> Status: Stable
> Type: Reference
> Last verified: d8ddd71

This document defines the version 1 state boundary between the native OpenPPP2
runtime and the desktop, Android, and iOS user interfaces.

## Snapshot fields

| Field | Requirement |
|---|---|
| `schema_version` | Must equal `1`; other versions fail explicitly. |
| `generation` | Increases for every start attempt. Lower generations are ignored. |
| `monotonic_ms` | Increases within a generation. Duplicate or older events are ignored. |
| `phase` | Authoritative lifecycle phase. |
| `role`, `server`, `transport` | Runtime identity and selected transport. |
| `requested_mux_mode`, `effective_mux_mode` | Requested and negotiated MUX behavior. |
| `mux_fallback_reason` | Reason the effective MUX mode differs. |
| `p2p_state`, `effective_path` | Typed P2P state and effective path; the path is always `relay` or `direct`, and only the `direct` state maps to `direct`. |
| `last_error` | Code, severity, retryability, message key, and diagnostic detail. |

Consumers ignore unknown optional fields. Missing required ordering or phase
fields, unknown phase strings, and unsupported schema versions are errors.

## Phase sequence

`starting` → `preparing_host` → `connecting` → `handshaking` →
`applying_policy` → `connected`.

Link recovery uses `reconnecting`. Stop uses `stopping` and finishes at `idle`
or `failed`. `unknown` is a consumer presentation when the runtime snapshot is
invalid or unavailable; it is not a successful native teardown state.

## Connected gate

All five readiness facts must be true:

1. The session is established.
2. The TAP/TUN adapter exists and is open.
3. Route policy is applied, or routing is explicitly not required.
4. DNS policy is configured with an active session, or DNS interception is
   explicitly not required.
5. The negotiated policy information is present.

Until then, a request for `connected` is published as `applying_policy`. Losing
a readiness fact moves the presentation back to `applying_policy`.

For server mode, readiness is derived from the active listener runtime. A
constructed, non-disposed server object alone is insufficient.

## Subscription and UI rules

`PppApplication` exposes snapshot get, JSON get, subscribe, and unsubscribe
operations. Publisher callbacks receive an immutable copy and run outside the
publisher mutex.

All surfaces use the phase-to-controls mapping in
[ADR 0001](../adr/0001-runtime-ui-contract.md). Start/stop callbacks and legacy
link-state signals may carry commands or diagnostics, but cannot update the
lifecycle label. A decode failure with valid generation/timestamp metadata is
ordered as `unknown`. A payload without ordering metadata is reported and cannot
mutate newer state.

## Fixtures

Canonical examples live in `tests/contracts/runtime-snapshot/`. C++, Dart, and
Swift consume the same fixtures, and `tools/check_runtime_fixture_hashes.py`
guards their hashes.
