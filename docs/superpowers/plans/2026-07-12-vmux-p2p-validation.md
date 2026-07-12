# VMUX and P2P Validation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Validate VMUX modes with observable requested/effective state, then prepare a secure and testable P2P direct-path implementation without weakening relay connectivity.

**Architecture:** VMUX publishes negotiated capabilities, effective mode, receiver ordering, link count, and fallback reason through `RuntimeSnapshot`. Benchmarks and fault injection determine rollout. P2P begins with protocol, state, crypto, and replay tests before any direct data path is enabled.

**Tech Stack:** C++17, Boost.Asio, Boost.Test, iperf3, tc netem, Linux namespaces, Flutter, Swift, GitHub Actions.

## Global Constraints

- Keep `compat` as default until benchmark gates pass.
- Requested mode and effective mode are separate fields.
- Unsupported peers fail safe to compatible ordering.
- `stripe` remains experimental and hidden from normal UI.
- P2P failure never tears down the base relay tunnel.
- Direct is displayed only after authenticated channel establishment.
- Never expose keys, tokens, or replay material in UI/telemetry.

---

### Task 1: Publish VMUX Negotiation State

**Files:**
- Modify: `ppp/app/mux/vmux_net.h`
- Modify: `ppp/app/mux/vmux_net.cpp`
- Modify: client/server exchanger negotiation paths
- Modify: `ppp/app/runtime/RuntimeSnapshot.h`
- Test: `tests/cpp/vmux_runtime_state_test.cpp`

**Interfaces:**

```cpp
struct MuxRuntimeState {
    ppp::string requested_mode;
    ppp::string effective_mode;
    ppp::string receiver_ordering;
    uint16_t active_links = 0;
    ppp::string fallback_reason;
};
```

- [ ] **Step 1: Test compatible negotiation**

Request `flow`, advertise FLOW_V2 on both peers, and assert effective mode/order are reported correctly.

- [ ] **Step 2: Test fallback**

Request `balance`, simulate a peer without FLOW_V2, and assert:

```text
effective_mode = compat
receiver_ordering = compat
fallback_reason = peer_missing_flow_v2
```

- [ ] **Step 3: Publish state after handshake and link changes**

Update active link count on add, retire, and reap. Do not emit one snapshot per packet.

- [ ] **Step 4: Run and commit**

```bash
ctest --test-dir build/test -R vmux_runtime_state_test --output-on-failure
git add ppp/app/mux ppp/app/runtime ppp/app/client ppp/app/server tests/cpp
 git commit -m "feat(vmux): publish negotiated runtime state"
```

### Task 2: Render Requested and Effective VMUX State in UI

**Files:**
- Modify: Android advanced settings and diagnostics views
- Modify: iOS advanced settings and diagnostics views
- Modify: TUI runtime adapter
- Test: Dart widget, Swift view-model, and C++ renderer tests

- [ ] **Step 1: Add capability-driven selector tests**

Modes unavailable in `snapshot.capabilities` are disabled or hidden. `stripe` is visible only in developer/experimental mode.

- [ ] **Step 2: Add fallback presentation**

The normal UI shows `Compatibility mode` while diagnostics show requested mode and fallback reason.

- [ ] **Step 3: Mark restart-required changes**

Changing negotiated mode updates configuration but displays `Takes effect on next connection`; do not hot-switch production sessions.

- [ ] **Step 4: Run and commit**

```bash
cd android && flutter test
cd ../ios/App && ./run-tests.sh
cd ../..
ctest --test-dir build/test -R tui_runtime_adapter_test --output-on-failure
git add android ios ppp/app/tui
 git commit -m "feat(ui): expose effective VMUX mode and fallback"
```

### Task 3: Build Repeatable VMUX Benchmark Harness

**Files:**
- Create: `benchmarks/vmux/run.sh`
- Create: `benchmarks/vmux/netem.sh`
- Create: `benchmarks/vmux/README.md`
- Create: `benchmarks/vmux/result.schema.json`
- Create: `benchmarks/vmux/parse_results.py`

- [ ] **Step 1: Define benchmark matrix**

Required scenarios:

```text
mux off, one flow
compat, one flow
flow, one flow
compat, eight flows
flow, eight flows
balance, eight flows
one carrier with added delay
one carrier with packet loss
runtime carrier removal
turbo grow/shrink churn
```

- [ ] **Step 2: Capture metrics**

Write JSON containing throughput, p50/p99 latency, reorder depth, buffered bytes, active links, disconnects, and fallback state.

- [ ] **Step 3: Add deterministic netem profiles**

Profiles must include exact delay/loss/rate parameters and clean themselves up on exit.

- [ ] **Step 4: Run local smoke benchmark**

```bash
sudo benchmarks/vmux/run.sh --scenario one-flow --duration 10
python3 benchmarks/vmux/parse_results.py build/benchmarks/vmux/*.json
```

- [ ] **Step 5: Commit**

```bash
git add benchmarks
 git commit -m "bench(vmux): add repeatable scheduler benchmark harness"
```

### Task 4: Add VMUX Fault and Compatibility Tests

**Files:**
- Create: `tests/cpp/vmux_negotiation_test.cpp`
- Create: `tests/cpp/vmux_link_churn_test.cpp`
- Create: `tests/cpp/vmux_flow_reorder_test.cpp`
- Modify: `tests/cpp/CMakeLists.txt`

- [ ] **Step 1: Test old peer fallback**
- [ ] **Step 2: Test reordered per-flow frames remain isolated**
- [ ] **Step 3: Test bounded reorder memory**
- [ ] **Step 4: Test retiring link with in-flight writes**
- [ ] **Step 5: Test repeated grow/shrink under ASan**
- [ ] **Step 6: Commit**

```bash
ctest --test-dir build/test -R "vmux_(negotiation|link_churn|flow_reorder)_test" --output-on-failure
git add tests/cpp
 git commit -m "test(vmux): cover negotiation reorder and link churn"
```

### Task 5: Define VMUX Rollout Gate

**Files:**
- Create: `docs/reference/VMUX_VALIDATION.md`
- Modify: `docs/MUX_PERFLOW_DELIVERY_DESIGN_CN.md`
- Modify: configuration docs

- [ ] **Step 1: Record exact acceptance thresholds**

Initial thresholds:

```text
flow single-stream throughput >= 95% of mux-off baseline
flow p99 latency regression <= 10% on equal links
reorder memory never exceeds configured bound
old peer always falls back to compat
no sanitizer failure during 100 grow/shrink cycles
```

- [ ] **Step 2: Require two-platform evidence before default change**

At minimum Linux desktop and one mobile platform.

- [ ] **Step 3: Keep compat default until evidence is attached**

A default change requires a separate PR containing benchmark artifacts and compatibility results.

- [ ] **Step 4: Commit**

```bash
git add docs
 git commit -m "docs(vmux): define scheduler rollout gates"
```

### Task 6: Correct P2P Replay Window Edge Cases

**Files:**
- Modify: `ppp/p2p/P2PReplayWindow.h`
- Modify: `tests/cpp/p2p_replay_window_test.cpp`
- Modify: `tests/red-manifest/p2p_replay_window.md`

- [ ] **Step 1: Add failing zero-sequence test**

```cpp
BOOST_AUTO_TEST_CASE(replay_rejects_duplicate_zero) {
    P2PReplayWindow window;
    BOOST_REQUIRE(window.Accept(0));
    BOOST_TEST(!window.Accept(0));
}
```

- [ ] **Step 2: Add wrap and boundary tests**

Cover `UINT32_MAX`, reset followed by zero, exactly `REPLAY_WINDOW_SIZE - 1`, and exactly `REPLAY_WINDOW_SIZE` behind base.

- [ ] **Step 3: Add explicit initialized state**

```cpp
bool initialized_ = false;
uint64_t base_ = 0;
```

Reset clears `initialized_`; first accepted sequence sets it.

- [ ] **Step 4: Run and commit**

```bash
ctest --test-dir build/test -R p2p_replay_window_test --output-on-failure
git add ppp/p2p tests/cpp tests/red-manifest
 git commit -m "fix(p2p): handle zero sequence in replay window"
```

### Task 7: Write and Accept P2P Protocol ADR Before Data Path

**Files:**
- Create: `docs/adr/0002-p2p-direct-channel-security.md`
- Create: `docs/design/p2p-direct-channel/protocol.md`
- Create: `docs/design/p2p-direct-channel/state-machine.md`
- Create: `docs/design/p2p-direct-channel/threat-model.md`

- [ ] **Step 1: Define transport-independent session exporter or TLS-only restriction**

The ADR must explicitly choose one. It must not assume a TLS master secret exists for raw TCP sessions.

- [ ] **Step 2: Define wire version and downgrade behavior**
- [ ] **Step 3: Define directional keys, nonce construction, replay window, token lifetime, and restart rules**
- [ ] **Step 4: Define NAT candidate authentication and migration grace**
- [ ] **Step 5: Define reflection/amplification and probe rate limits**
- [ ] **Step 6: Define relay fallback as mandatory invariant**
- [ ] **Step 7: Review and commit design only**

```bash
git add docs/adr docs/design/p2p-direct-channel
 git commit -m "docs(p2p): specify direct-channel security and lifecycle"
```

Do not implement the direct data path in this task.

### Task 8: Add P2P State Contract and UI Before Networking

**Files:**
- Create: `ppp/p2p/P2PState.h`
- Modify: `ppp/app/runtime/RuntimeSnapshot.h`
- Modify: Android, iOS, and TUI runtime models
- Test: C++, Dart, Swift state mapping tests

**Interfaces:**

```cpp
enum class P2PState {
    Disabled,
    Unavailable,
    Relay,
    Eligible,
    Probing,
    Direct,
    Suspect,
    FallingBack,
    Failed,
};
```

- [ ] **Step 1: Add phase mapping tests**
- [ ] **Step 2: Add effective path field: `relay` or `direct`**
- [ ] **Step 3: Ensure Probing still reports relay as effective path**
- [ ] **Step 4: Ensure P2P Failed leaves base RuntimePhase Connected when relay works**
- [ ] **Step 5: Render user-facing path status and diagnostic detail**
- [ ] **Step 6: Commit**

```bash
git add ppp/p2p ppp/app/runtime android ios ppp/app/tui tests
 git commit -m "feat(p2p): define observable direct-path state"
```

### Task 9: Implement P2P Control Plane and Authentication Tests

**Files:**
- Create focused files under `ppp/p2p/` for token validation, packet header parsing, key derivation, and state transitions
- Create corresponding `tests/cpp/p2p_*_test.cpp`

- [ ] **Step 1: Implement packet parser from test vectors only**
- [ ] **Step 2: Implement key derivation from the accepted ADR**
- [ ] **Step 3: Implement token expiry and peer binding tests**
- [ ] **Step 4: Implement replay and endpoint spoof rejection tests**
- [ ] **Step 5: Implement `Relay -> Probing -> Direct -> Suspect -> FallingBack -> Relay` as a pure state machine**
- [ ] **Step 6: Run under ASan/UBSan and commit**

No socket forwarding is enabled yet.

### Task 10: Add Protected UDP Channel Behind Experimental Capability

**Files:**
- Create platform socket protection adapters for Linux/Android/iOS
- Create `ppp/p2p/P2PChannel.*`
- Modify exchangers only through an explicit P2P coordinator interface
- Add integration and adversarial tests

- [ ] **Step 1: Add disabled-by-default capability flag**
- [ ] **Step 2: Protect socket before first probe**
- [ ] **Step 3: Authenticate probe/ack before Direct transition**
- [ ] **Step 4: Forward data only while state is Direct**
- [ ] **Step 5: Fall back to relay on timeout, auth failure, socket error, or migration failure**
- [ ] **Step 6: Test UDP blocked, symmetric NAT, stale token, spoofed endpoint, and process restart**
- [ ] **Step 7: Verify UI never reports Direct before authentication**
- [ ] **Step 8: Commit in platform-separated PRs**

P2P must remain experimental until the release gate in the roadmap is satisfied.