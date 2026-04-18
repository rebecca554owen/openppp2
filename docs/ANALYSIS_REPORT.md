# Stage-1 Analysis Report

## Scope and Method
- This report aggregates Stage-1 findings for diagnostics coverage, IPv6 managed path parity, TCPLink/VNetstack locking, protected memory regions, Android sync, style policy drift, and unused-code candidates.
- Evidence is based on direct source inspection with representative line references (not exhaustive callgraph output).
- References use the current workspace state and are intended to drive Stage-2/3/4 implementation planning.

## 1) Missing `SetLastErrorCode` Coverage by Module Groups

### Current Coverage Snapshot
- Central diagnostics API exists in `ppp/diagnostics/Error.h:34`, with implementation in `ppp/diagnostics/Error.cpp:24` and code catalog in `ppp/diagnostics/ErrorCodes.def:1`.
- Startup/config paths have explicit coverage, for example:
  - `ppp/app/ApplicationInitialize.cpp:289`
  - `ppp/app/ApplicationInitialize.cpp:319`
  - `ppp/app/ApplicationConfig.cpp:40`
  - `ppp/app/ApplicationNetwork.cpp:209`
- Linux IPv6 server prepare/finalize includes detailed error mapping, for example:
  - `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:606`
  - `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:659`
  - `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:742`

### Missing-Coverage Module Groups
- `ppp/ethernet/*` return-failure paths are mostly silent (no `SetLastErrorCode`), including core TCP path entry points:
  - `ppp/ethernet/VNetstack.cpp:260`
  - `ppp/ethernet/VNetstack.cpp:358`
  - `ppp/ethernet/VNetstack.cpp:721`
- Most `ppp/net/*` socket/protocol failures are returned as bool/null without diagnostic code propagation.
- Android bridge layer (`android/libopenppp2.cpp`) uses independent numeric error enum and does not map into `ppp::diagnostics::ErrorCode`.
- Client exchanger path has only one explicit deadlock signal set:
  - `ppp/app/client/VEthernetExchanger.cpp:403`

### Additional API Drift Found
- `GetLastErrorCodeSnapshot()` is defined in `ppp/diagnostics/Error.cpp:11` and used by UI in `ppp/app/ConsoleUI.cpp:290`, but no declaration exists in `ppp/diagnostics/Error.h:1`.
- `RegisterErrorHandler()` stores handlers but no dispatch site is visible:
  - write path: `ppp/diagnostics/ErrorHandler.cpp:40`
  - storage: `ppp/diagnostics/ErrorHandler.h:29`

## 2) IPv6 Six-Rule Gaps and Per-Platform Fixes

### Six Rules (Managed Client Path)
- Rule-1: capture original state (`CaptureClientOriginalState`).
- Rule-2: apply address (`ApplyClientAddress`).
- Rule-3: apply default route (`ApplyClientDefaultRoute`).
- Rule-4: apply subnet route (`ApplyClientSubnetRoute`, NAT66 path).
- Rule-5: apply DNS (`ApplyClientDns`).
- Rule-6: rollback (`RestoreClientConfiguration`) on any partial failure.

### Cross-Platform Dispatcher Evidence
- Shared dispatch API in `ppp/ipv6/IPv6Auxiliary.cpp:56`, `ppp/ipv6/IPv6Auxiliary.cpp:71`, `ppp/ipv6/IPv6Auxiliary.cpp:87`, `ppp/ipv6/IPv6Auxiliary.cpp:103`, `ppp/ipv6/IPv6Auxiliary.cpp:119`, `ppp/ipv6/IPv6Auxiliary.cpp:134`.
- Client application entrypoint applies all six rules in sequence at `ppp/app/client/VEthernetNetworkSwitcher.cpp:749` through `ppp/app/client/VEthernetNetworkSwitcher.cpp:795`.

### Gaps
- Gap-A (diagnostics): platform apply/restore helpers return `false` but generally do not set `SetLastErrorCode`.
  - Windows examples: `windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:165`, `windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:250`, `windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:253`
  - Darwin examples: `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:269`, `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:309`, `darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:349`
  - Linux examples: `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:760`, `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:802`, `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:842`
- Gap-B (rollback verification): Linux restore replays default routes without result checks at `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:897`.
- Gap-C (platform support signaling): shared `ClientSupportsManaged()` exists in `ppp/ipv6/IPv6Auxiliary.cpp:45`, but client side uses duplicated local helper `ClientSupportsManagedIPv6()` in `ppp/app/client/VEthernetNetworkSwitcher.cpp:54`.
- Gap-D (Android managed IPv6): Android build path uses mobile/Linux integration (`android/libopenppp2.cpp:32`), while client managed gating is desktop-only in `ppp/app/client/VEthernetNetworkSwitcher.cpp:54`.

### Per-Platform Fix Direction
- Windows:
  - Keep multi-route snapshot/restore logic as base (`windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:148`, `windows/ppp/ipv6/WIN32_IPv6Auxiliary.cpp:287`).
  - Add per-step `SetLastErrorCode` mapping for address/route/dns/restore failures.
- Darwin:
  - Keep route shell token hardening (`darwin/ppp/ipv6/DARWIN_IPv6Auxiliary.cpp:10`).
  - Add diagnostics mapping around `SetRoute`/`DeleteRoute` and ifconfig failures.
- Linux:
  - Keep server-side rich diagnostics already present (`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:606` onward).
  - Add client-side diagnostics + restore verification checks around route replay (`linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:897`).

## 3) TCPLink/VNetstack Deadlock Analysis and Lock-Order Graph

### Lock Objects and Regions
- L1: VNetstack flow-table mutex `syncobj_` (`ppp/ethernet/VNetstack.h:257`).
- L2: per-client SYSNAT mutex `sysnat_synbobj_` (`ppp/ethernet/VNetstack.h:177`).
- L3: process-global SYSNAT mutex `openppp2_sysnat_syncobj()` (`ppp/ethernet/VNetstack.cpp:54`).

### Observed Acquisition Order
- `VNetstack::Update()` acquires L1, then conditionally L2 in SYSNAT branch:
  - L1 at `ppp/ethernet/VNetstack.cpp:545`
  - L2 at `ppp/ethernet/VNetstack.cpp:584`
- `TapTcpClient::AckAccept()` acquires L2, then L3:
  - L2 at `ppp/ethernet/VNetstack.cpp:1197`
  - L3 at `ppp/ethernet/VNetstack.cpp:1238`
- `TapTcpClient::Finalize()` acquires L2, then L3:
  - L2 at `ppp/ethernet/VNetstack.cpp:1071`
  - L3 at `ppp/ethernet/VNetstack.cpp:1074`

### Lock-Order Graph (Current)
```text
L1 (syncobj_) -> L2 (sysnat_synbobj_) -> L3 (openppp2_sysnat_syncobj)
```

### Risk Assessment
- No confirmed L3->L1 path was identified in Stage-1, so no proven hard cycle yet.
- Risk remains high for future regressions because multi-level ordering is implicit and undocumented.
- Separate re-entrancy guard exists in exchanger update path (not VNetstack lock graph):
  - guard and deadlock signal at `ppp/app/client/VEthernetExchanger.cpp:401` and `ppp/app/client/VEthernetExchanger.cpp:403`.

## 4) Protected Regions: UDP Shared 64KB Buffer and `nullof` Usages

### UDP Shared 64KB Buffer
- Global size constant is `PPP_BUFFER_SIZE = 65536` in `ppp/stdafx.h:336`.
- Per-io_context cached buffer allocation in executors:
  - `ppp/threading/Executors.cpp:173`
  - `ppp/threading/Executors.cpp:198`
- Shared async receive examples using this buffer:
  - client static echo receive: `ppp/app/client/VEthernetExchanger.cpp:1935`
  - server static echo receive: `ppp/app/server/VirtualEthernetSwitcher.cpp:2229`
- Protection requirement: one outstanding receive operation per shared buffer owner/context, or switch to dedicated per-socket buffer/strand ownership.

### `nullof` Protected Region
- Primitive definition uses null-reference dereference pattern: `ppp/stdafx.h:1049`.
- Representative callsites in synchronous facade paths:
  - `ppp/app/client/VEthernetExchanger.cpp:1137`
  - `ppp/app/server/VirtualEthernetDatagramPort.cpp:62`
  - `ppp/app/protocol/VirtualEthernetLinklayer.cpp:830`
  - `android/libopenppp2.cpp:1531`
- Risk: undefined behavior contract hidden behind utility abstraction; Stage-2 should fence and replace in hot paths.

## 5) Android Sync Checklist

- Align Android error reporting with diagnostics pipeline (bridge enum -> `ErrorCode`) so JNI-visible failures and core logs are consistent:
  - Android enum block: `android/libopenppp2.cpp:125`
  - Diagnostics API: `ppp/diagnostics/Error.h:34`
- Decide managed IPv6 behavior explicitly for Android builds and remove duplicated support gating:
  - local helper gate: `ppp/app/client/VEthernetNetworkSwitcher.cpp:54`
  - shared gate function: `ppp/ipv6/IPv6Auxiliary.cpp:45`
- Ensure mobile build keeps source parity with Linux IPv6 helpers where intended:
  - Android CMake source glob includes linux tree: `android/CMakeLists.txt:124`
- Validate JNI main-thread callbacks and lifecycle sequencing against switcher disposal:
  - JNI post path: `android/libopenppp2.cpp:351`
  - stop/release path: `android/libopenppp2.cpp:1264`

## 6) Style Violations (`nullptr`->`NULLPTR`, Constant-Side Policy, Formatting)

### Policy Baseline
- Project macro baseline is `#define NULLPTR nullptr` in `ppp/stdafx.h:17`.
- Existing style predominantly uses constant-side comparisons like `NULLPTR == x`.

### Violations and Drift
- Non-constant-side null checks exist, e.g.:
  - `ppp/stdafx.cpp:167` (`s == NULLPTR`)
  - `ppp/DateTime.cpp:104` (`s == NULLPTR`)
  - `ppp/DateTime.cpp:109` (`s != NULLPTR`)
  - `ppp/net/Ipep.cpp:204` (`p != NULLPTR`)
- Residual `nullptr` wording appears in project comments/docs (policy target requires normalization where policy applies):
  - `ppp/transmissions/ITransmissionQoS.h:74`
  - `ppp/net/native/tcp.h:136`
- Minor formatting inconsistency in utility definition:
  - `ppp/stdafx.h:1049` (brace spacing in `nullof`).

## 7) Unused Code Candidates (Functions/Globals/Files)

### Functions
- `ppp::ipv6::auxiliary::ClientSupportsManaged()` appears unused by callsites:
  - declaration: `ppp/ipv6/IPv6Auxiliary.h:91`
  - definition: `ppp/ipv6/IPv6Auxiliary.cpp:45`
  - active caller side uses local duplicate helper: `ppp/app/client/VEthernetNetworkSwitcher.cpp:54`
- Linux helper `ReadDefaultRoute()` appears unused:
  - declaration: `linux/ppp/ipv6/IPv6Auxiliary.h:14`
  - definition: `linux/ppp/ipv6/LINUX_IPv6Auxiliary.cpp:521`

### Globals / Stored State
- Error handler list is write-only in current Stage-1 view (registered, not dispatched):
  - storage: `ppp/diagnostics/ErrorHandler.h:29`
  - append path: `ppp/diagnostics/ErrorHandler.cpp:46`

### File-Level Candidate for Follow-Up Validation
- Diagnostics API/header drift suggests dead or incomplete interface surface:
  - undeclared exported use pair: `ppp/diagnostics/Error.cpp:11` and `ppp/app/ConsoleUI.cpp:290`
  - missing declaration in header: `ppp/diagnostics/Error.h:1`

## Stage-2/3/4 Implementation Plan

## Stage-2 (Safety and Observability Baseline)
- Add deterministic `SetLastErrorCode` mapping for all six IPv6 managed-rule steps on Windows/Darwin/Linux client paths.
- Add diagnostics coverage in `ppp/ethernet/*` critical failure exits (`Open`, `Input`, `CloseTcpLink`, accept path).
- Define and document lock-order contract `L1->L2->L3`; add lightweight debug assertions around violations.
- Fence `nullof` usage: introduce safe optional-yield wrapper in high-frequency callsites and mark remaining legacy use.

## Stage-3 (Behavioral Parity and Refactor)
- Unify managed IPv6 support probe by removing duplicated local helper and adopting one shared capability API.
- Complete Android diagnostics bridge so JNI error codes and `ErrorCode` remain synchronized.
- Harden Linux/Darwin restore verification (default-route replay success checks, actionable error codes).
- Resolve diagnostics API/header drift (`GetLastErrorCodeSnapshot` declaration + tests, or remove usage).

## Stage-4 (Cleanup and Enforcement)
- Remove or retire confirmed unused helpers/globals after callgraph validation.
- Enforce null-check policy and `nullptr` wording policy in project-owned files; exclude third-party trees.
- Add CI checks for lock-order annotation, diagnostics coverage in new failure branches, and style policy regression.
- Publish updated docs in EN/CN and add checklist to release gate.
