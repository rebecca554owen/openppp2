# upstream-reference

The record of which inherited test files are built, which are not, and why.

## Why this directory exists

Keeping an unwired test file in `tests/cpp/` is worse than not having it: the
directory is scanned by the build and by anyone looking for coverage, so a
reader who finds `session_roaming_switcher_e2e_test.cpp` would assume it ran
in CI. This directory says plainly: this is the inherited copy, it does not
run here, and here is why.

On the upstream baseline every vmux test file IS wired into the build. The
table below is the audit that keeps it that way.

## The vmux files

Every vmux test file under `tests/cpp/` is registered in
`tests/cpp/CMakeLists.txt` and runs in the normal CTest pass, with two
exceptions that need the whole library and are therefore registered in the
root `CMakeLists.txt` instead.

| File | Registered in | Runs |
|---|---|---|
| `vmux_runtime_state_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_negotiation_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_reliability_negotiation_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_ack_tracker_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_backlog_watchdog_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_retransmit_buffer_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_fec_codec_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_flow_reorder_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_rx_backpressure_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_tx_backpressure_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_flow_context_admission_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_rx_queue_limit_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `mux_transport_adapter_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_link_churn_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_wave0_rtx_release_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_wave2_flow_isolation_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_wave3_per_link_rtt_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_wave4_pto_rtx_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_wave5_control_plane_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_wave6_property_wrap_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_wave6_long_stability_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_qa001_write_failure_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_qa001_fec_race_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_qa001_ack_malicious_test.cpp` | `tests/cpp/CMakeLists.txt` | yes |
| `vmux_receive_semantics_test.cpp` | root `CMakeLists.txt` (`ENABLE_VMUX_RECEIVE_SEMANTICS_TEST`) | opt-in |
| `vmux_net_churn_integration_test.cpp` | root `CMakeLists.txt` (`ENABLE_VMUX_CHURN_TEST`) | opt-in |

The two root-linked files need the whole `openppp2_lib`: they drive a real
`vmux_net` session with a live carrier, so they cannot be built from a
header-only fixture the way the other vmux tests are. They are off by
default because they build the entire library.

## The contract tests that were added on top

These are not inherited from upstream. They pin invariants that upstream
expresses in comments rather than in code, so they are source contract
assertions against `ppp/app/mux/`:

| File | Pins |
|---|---|
| `mux_invariants_contract_test.cpp` | connection id lifetime; the three lock domains never nest; strand affinity |
| `mux_flow_refusal_contract_test.cpp` | a dead flow is never swallowed in silence |
| `mux_connect_yield_lifetime_contract_test.cpp` | the posted lambda of `connect_yield` captures no bare `this` |
| `mux_carrier_clean_close_test.cpp` | a carrier drains its receive queue before it is disposed |
| `mux_runtime_counters_test.cpp` | the mux counters and the published JSON keys stay in lockstep |

## The unwired file in `tests/cpp/`

| File | Lines | Why it does not run |
|---|---|---|
| `session_roaming_switcher_e2e_test.cpp` | 1158 | Not registered in `tests/cpp/CMakeLists.txt` nor in the root `CMakeLists.txt`. It drives the production `VirtualEthernetSwitcher`/`VirtualEthernetExchanger` graph with a real WSS/TLS carrier and the authenticated resume transcript, so it needs the whole library and a TLS fixture. Wiring it in is a separate piece of work: it has to be checked against this repository's interfaces the same way the vmux files were. |

The XTCP files (`xtcp_dependency_contract_test.cpp`,
`xtcp_ndi_ownership_test.cpp`, `xtcp_listener_gate_test.cpp`,
`xtcp_ooo_backpressure_probe.cpp`, `xtcp_ooo_resume_contract_test.cpp`) are
registered, but only inside the `ENABLE_XTCP_TESTS` block, because they link
the pinned `third-party/xtcp` tree. They run whenever that option is on.
