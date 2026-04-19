# Error Handling API

[中文版本](ERROR_HANDLING_API_CN.md)

## Scope

This document defines the diagnostics error API contract used by startup/runtime paths and operational surfaces.

## Core API Surface

Anchors:

- `ppp/diagnostics/Error.h`
- `ppp/diagnostics/ErrorHandler.h`

Primary calls:

- `SetLastErrorCode(ErrorCode code)`
- `SetLastError(...)` typed helpers for `bool`, integral, pointer, and caller-provided return values
- `GetLastErrorCode()` for current thread-local value
- `GetLastErrorCodeSnapshot()` and `GetLastErrorTimestamp()` for process-wide latest observed snapshot
- `FormatErrorString(ErrorCode code)`

## Handler Registration Contract

`RegisterErrorHandler(const ppp::string& key, const ppp::function<void(int err)>& handler)` is key-based.

Behavior:

- key identifies one registration slot;
- calling with an existing key replaces the previous handler;
- passing a null handler removes the key;
- handlers receive integer form of the current `ErrorCode`.

## Registration-Time Thread-Safety Boundary

Registration changes are intended for initialization/teardown phases:

- supported: register/replace/remove handlers before multi-thread runtime starts;
- supported: remove handlers during controlled shutdown when worker activity is quiesced;
- not supported as a contract: frequent registration churn while worker threads are actively dispatching errors.

Dispatch paths copy current handlers under lock and invoke callbacks outside the lock. This protects dispatch continuity, but registration mutation should still be treated as lifecycle-managed, not hot-path control flow.

## Diagnostics Coverage Policy

Failure paths should set diagnostics before returning failure sentinels (`false`, `-1`, `NULLPTR`).

Coverage expectations:

- startup and environment preparation failures must set diagnostics;
- open/reconnect/release failures must set diagnostics;
- rollback failures must set diagnostics, even if best-effort rollback continues;
- newly added failure branches should not rely on generic fallback-only messages.

## Error Propagation Expectations

Diagnostics flow should remain single-source:

- backend sets `ErrorCode`;
- Console UI and other presentation layers read snapshots and format text;
- bridge layers (including Android JNI) preserve semantic mapping instead of introducing unrelated parallel enums where avoidable.

This keeps operational troubleshooting consistent across CLI, logs, and platform integrations.
