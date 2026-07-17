# Runtime/UI Execution Status

> Type: Status report
> Last verified: cfd4571

> Branch: `main`
> Head: `cfd4571`
> Status: Implemented and merged; runtime, lifecycle, Route/DNS, VMUX state, and guarded P2P integration are on main

## Completion accounting

- 7.12-7.14 implementation plans: 234/237 tracked checkboxes complete (98.7%).
- The three open checkboxes are release-evidence gates: two VMUX network
  benchmark gates and physical-device P2P socket-protection evidence.
- This count measures repository plan execution. It does not authorize changing
  the VMUX default or enabling the production P2P capability gate.

## Completed scope

- Runtime Contract v1 DTOs, JSON schema, shared C++/Dart/Swift fixtures, ordered publisher, and readiness gate.
- TUI, Android, and iOS generation-aware stores and phase-driven controls.
- Generation-scoped stop ownership, ordered teardown, 100-cycle lifecycle stress, and sanitizer coverage.
- RouteCoordinator-owned state, platform route adapters, DnsController-owned policy/session state, and namespace rollback evidence.
- Repository layout, include boundary, documentation metadata/link, and cross-language fixture gates.
- VMUX requested/effective state, fallback diagnostics, transport boundary, benchmark harness, and carrier churn sanitizer test.
- P2P ADR, authenticated exporter/offer/data wiring, fail-closed capability gate, and Android emulator socket-protection evidence.
- Client Exchanger ownership split for keepalive timing policy, FRP mapping storage, StaticEcho session/socket state, and VMUX sessions.

## Validation state (head `cfd4571`)

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
- Android API 34 P2P socket-protection instrumentation: pass
- Main branch workflows: 9/9 pass

## Remaining release evidence

- Fixed Linux x86-64 UDP micro/E2E performance baseline with readable PMU cycles.
- VMUX fixed Linux plus real Android/iOS netem and throughput/p99 artifacts.
- P2P physical-device NAT, UDP-blocked, backgrounding, roaming, restart, and forced-relay scenarios.
- `ProductionAuthenticatedControlV1Ready` remains `false` until the P2P evidence gate passes.
