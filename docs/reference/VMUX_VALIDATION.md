# VMUX Validation and Rollout Gate

> Status: Stable
> Type: Reference
> Last verified: 2566750

[中文版本](VMUX_VALIDATION_CN.md)

This reference defines the evidence required to change the production VMUX
scheduler default. It does not claim that the performance gates have passed.
`compat` remains the default, and `stripe` remains experimental.

## Acceptance gates

All gates are mandatory and must be evaluated from artifacts produced by the
repeatable harness in [`../../benchmarks/vmux/`](../../benchmarks/vmux/README.md).

| Gate | Required result |
|---|---|
| Single-flow throughput | `flow-one-flow` throughput is at least 95% of the matching `off-one-flow` baseline. |
| Equal-link tail latency | `flow-one-flow` p99 latency is no more than 110% of the matching `off-one-flow` p99 on equal links. |
| Bounded reorder memory | Buffered bytes never exceed `mux.flow.reorder.bytes`, and the derived reorder-entry cap is never exceeded. |
| Old-peer compatibility | Against a peer without FLOW_V2, `balance` / `stripe` negotiate `effective_mode=compat`, `receiver_ordering=compat`, and `fallback_reason=peer_missing_flow_v2`; `flow` keeps `effective_mode=flow` but uses `receiver_ordering=compat`. |
| Link churn safety | 100 grow/shrink cycles complete under ASan/UBSan without an error, leak, underflow, disconnect, or premature in-flight link retirement. |

Comparisons must use the same environment fingerprint, configuration except
for the mode under test, duration, flow count, and netem profile. A harness
smoke run proves only that evidence can be collected; it is not performance
evidence.

## Required platforms and artifacts

Before changing the default, attach real results from both:

1. Linux desktop on the fixed Linux x86-64 benchmark host; and
2. at least one real mobile platform, Android or iOS.

The evidence bundle must contain the raw result JSON, environment and
configuration fingerprints, parser output, sanitizer logs, old-peer
compatibility results, and the tested commits for both endpoints. Shared CI,
WSL, virtual machines, dry-runs, and synthetic telemetry may be used for
correctness diagnostics but do not satisfy this gate.

## Default-change rule

`compat` stays the production default until every gate above has qualifying
two-platform evidence. Changing the default requires a separate pull request
that attaches the benchmark artifacts and compatibility results and explains
any exclusions. It must not be bundled with scheduler implementation work.
`stripe` is excluded from the default gate and remains experimental.

## Current evidence boundary

The implementation baseline provides:

- negotiated requested/effective state and old-peer fallback (`7719c5f`);
- UI presentation of effective mode and fallback diagnostics (`b991cd1`);
- the benchmark harness, schema, parser, and tooling tests (`62c7441`); and
- negotiation, bounded reorder, in-flight retirement, and a 100-cycle drain-state
  regression tests (`2566750`).

The 100-cycle drain-state unit test was also run locally with
`-fsanitize=address,undefined` on 2026-07-15 (4 test cases, no ASan/UBSan
error). It does not drive real `vmux_net` grow/shrink or asynchronous carrier
I/O, so the actual churn sanitizer gate remains open.

These commits establish the measurement and compatibility mechanisms. No real
Linux-plus-mobile baseline demonstrating the throughput or p99 thresholds is
stored yet, so the production default must not change.
