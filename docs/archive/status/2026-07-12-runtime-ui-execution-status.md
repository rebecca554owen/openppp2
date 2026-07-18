# Runtime/UI Execution Status

> **Purpose:** Preserve design rationale, decisions, or historical verification evidence.
> **Audience:** Maintainers investigating historical context.
> **Status:** Archived; not a source of current configuration truth.
> **Last verified against:** Document lifecycle and Git history, 2026-07-18.
> **Parent index:** [Back to index](README.md)

> **Archive notice:** This page is historical context only and must not be used as current installation, configuration, or runtime guidance.


> Branch: `codex/runtime-ui-lifecycle-foundation`
> Integration branch: `codex/runtime-ui-lifecycle-integration`
> Pull request: #39
> Head: `c4e1820`
> Status: Draft; native matrix green on latest head; awaiting explicit Ready conversion

## Completed in the foundation batch

- Runtime Contract v1 C++ DTOs and JSON schema.
- Shared runtime fixtures for C++, Dart, and Swift.
- Android and iOS generation-aware runtime stores.
- Generation-scoped stop coordinator.
- Desktop teardown DNS-cache recursive-lock fix.
- P2P replay-window sequence-zero regression fix.
- PeerPrefix incomplete-type include fix.
- Switcher non-movable type made explicit (`= delete`).
- RouteHost `get_dns_interceptor` returns a non-owning `shared_ptr` view over `unique_ptr` ownership.
- Windows proxy TUs include `AppConfiguration.h` after exchanger header slim.
- Unit-test switcher stub provides `GetProtectorNetwork()` on Linux.
- `BuildRouteHostPorts` platform-guards desktop-only and desktop-Linux-only members (Android defines `_LINUX` too).
- Restored `.github/workflows/test.yml` to normal build steps.
- Build/Unit workflows trigger for PRs targeting the integration branch.

## Validation state (head `c4e1820`)

- focused C++: pass
- full C++ unit suite: pass
- Flutter: pass
- Swift/iOS logic: pass
- Go: pass
- include-boundary / vcxproj parity: pass
- Linux amd64: pass
- Linux Cross (aarch64): pass
- Android arm64-v8a: pass
- macOS arm64: pass
- Windows x64 Release: pass
- Runtime UI PR Diagnostics focused-cpp + full-linux: pass

## Remaining process notes

- PR body could not be updated by this agent token (HTTP 403). Paste `/opt/cursor/artifacts/pr39-body.md` manually if needed.
- `Runtime UI PR Diagnostics` still lives on the **integration base** branch; remove it there in a follow-up. It is not part of long-term delivery.
- Keep Draft until the user explicitly asks to mark Ready for Review.
- Do not merge to `main` from this PR.

## Deferred to later batches

- Runtime snapshot publisher integration with `PppApplication`.
- TUI rendering from snapshots.
- Android/iOS presentation wiring.
- Immutable shared DNS host-port snapshots and weak callback ownership.
- Lifecycle stress and sanitizer gates.
- VMUX effective-mode presentation and P2P direct-path UI.
