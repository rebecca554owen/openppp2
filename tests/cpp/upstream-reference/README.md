# upstream-reference

Test files that came in with the upstream tree and are kept here for the
record. They are NOT built and NOT run.

## Why this directory exists

Upstream builds all ten of its vmux test files. This repository inherited
the files but never added them to the test build, so they sat in the tree as
dead code: a reader checking what covers the FEC recovery path would find a
test file and assume it ran. Nine of them are now wired into the build and
run (see the table below); the one that is not, is here.

Keeping an unwired file in `tests/cpp/` is worse than deleting it, because
the directory is scanned by the build and by anyone looking for coverage.
Keeping it here says plainly: this is the upstream copy, it does not run
here, and here is why.

## The vmux files

| File | Lines | Disposition |
|---|---|---|
| `vmux_qa001_fec_race_test.cpp` | 646 | **runs** — compiled as it was, asserts hold |
| `vmux_qa001_write_failure_test.cpp` | 664 | **runs** — compiled as it was, asserts hold |
| `vmux_wave5_control_plane_test.cpp` | 309 | **runs** — compiled as it was, asserts hold |
| `vmux_wave2_flow_isolation_test.cpp` | 610 | **runs** — ported to this repository's interfaces |
| `vmux_wave6_property_wrap_test.cpp` | 422 | **runs** — ported to this repository's interfaces |
| `vmux_wave0_rtx_release_test.cpp` | 477 | **runs** — ported to this repository's interfaces |
| `vmux_wave6_long_stability_test.cpp` | 322 | **runs** — ported to this repository's interfaces |
| `vmux_qa001_ack_malicious_test.cpp` | 941 | **runs** — ported to this repository's interfaces |
| `vmux_wave4_pto_rtx_test.cpp` | 309 | **runs** — ported to this repository's interfaces |
| `vmux_wave3_per_link_rtt_test.cpp` | 454 | **here** — not ported, see below |

## Why the wave 3 file is not ported

It tests upstream's per-link round-trip time: a frame remembers the carrier
it was sent on, the acknowledgement hands back a sample together with that
carrier, and the per-link state is then used to derive a per-link probe
timeout.

This repository has the measurement and not the decision, on purpose. The
probe timeout is derived from the session estimate, the loss detection is
the probe timeout alone, and the per-link minimum is not read by anything.
Upstream is in the same state: its per-link probe timeout function has no
caller.

The port would have been a decision, not a port: porting the cases would
have meant implementing the per-link probe timeout they assert, which is
the part the audit report (P1-1, P2-11) records as a deliberate decision
not to take. The reasoning and the conditions under which it should be
revisited are in `docs/vmux/VMUX_AUDIT_REPORT.md`.

The measurement was implemented, run on all four production endpoints, and
then removed again: it answered the question (the carriers of a production
session are not heterogeneous) and the answer is recorded in the audit
report. The file is kept here so the upstream design stays readable.

## Other unwired files in `tests/cpp/`

These are also inherited from the upstream tree and are not built. They are
outside the vmux area and were not touched by this work:

| File | Lines |
|---|---|
| `datapath_acceptance_boundary_test.cpp` | 583 |
| `session_roaming_switcher_e2e_test.cpp` | 1158 |
| `tun_gso_coalescer_test.cpp` | 520 |
| `tun_gso_mergeability_test.cpp` | 313 |
| `mta_handoff_telemetry_test.cpp` | 133 |
| `tcp_stack_mode_test.cpp` | 133 |
| `tap_vnet_codec_test.cpp` | 175 |
| `xtcp_ooo_backpressure_probe.cpp` | 175 |
| `xtcp_ooo_resume_contract_test.cpp` | 173 |
| `xtcp_listener_gate_test.cpp` | 142 |
| `xtcp_ndi_ownership_test.cpp` | 127 |
| `tun_gso_ledger_test.cpp` | 110 |
| `xtcp_dependency_contract_test.cpp` | 72 |
| `random_test.cpp` | 51 |

They are listed here so the gap is visible. Wiring them in is a separate
piece of work: each one has to be checked against this repository's
interfaces the same way the vmux files were.
