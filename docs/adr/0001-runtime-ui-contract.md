# ADR 0001: Runtime Snapshot Is the UI State Authority

> Status: Accepted
> Type: ADR
> Last verified: pending-runtime-ui-stage

## Decision

`PppApplication` owns one `RuntimeLifecycle`, which publishes immutable versioned
`RuntimeSnapshot` values. The desktop TUI, Android UI, and iOS UI render those
snapshots and send commands; they do not derive lifecycle state from exchanger
enums, VPN service callbacks, logs, or optimistic widget mutations.

The v1 phases are `idle`, `starting`, `preparing_host`, `connecting`,
`handshaking`, `applying_policy`, `connected`, `reconnecting`, `stopping`,
`failed`, and the UI-only fallback `unknown`.

## Readiness rule

The runtime may publish `connected` only when session, adapter, route, DNS, and
negotiated policy are ready. A client adapter must be open, not merely allocated.
Route and DNS may be marked ready only after successful application, or when the
current mode explicitly does not require them. Server readiness is derived from
active accept loops, not constant flags.

## Ordering and compatibility

- `schema_version` is mandatory. Consumers reject unsupported versions.
- `generation` prevents events from an older session replacing current state.
- `monotonic_ms` orders events within a generation.
- Unknown optional fields are ignored for forward compatibility.
- Listeners receive copies and execute outside publisher locks.
- Existing tunnel wire format and configuration remain unchanged.

## UI command behavior

| Phase | Primary action | Configuration |
|---|---|---|
| Idle | Start | Editable |
| Starting through ApplyingPolicy | Cancel | Locked |
| Connected, Reconnecting | Stop | Locked |
| Stopping | Disabled | Locked |
| Failed | Retry | Editable |
| Unknown | Force stop / diagnostics | Locked |

Starting and stopping commands wait for a matching runtime snapshot. A UI timeout
may report slow progress, but cannot publish `idle` itself. An invalid payload
with valid ordering metadata is presented as `unknown`; an unorderable payload
reports an error without mutating newer state.

## Consequences

The runtime contract adds one stable boundary shared by all surfaces. Transport
state remains available for data-plane decisions and diagnostics, but cannot be
used as a second lifecycle authority.

See the [runtime UI contract](../reference/UI_RUNTIME_CONTRACT.md) and its
[Chinese translation](../reference/UI_RUNTIME_CONTRACT_CN.md).
