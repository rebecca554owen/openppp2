# VMUX Validation and Rollout Gate

> Status: Stable
> Type: Reference
> Last verified: ded25d6

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

Each real result must carry the `--endpoint-manifest` attestation described by
the benchmark README. Before promotion, validate the complete physical Linux
and Android/iOS result bundle with:

```bash
python3 benchmarks/vmux/parse_results.py --rollout-gate <results...>
```

This executable gate checks endpoint class and commits, paired environments and
durations, throughput/p99 thresholds, zero disconnects, and configured reorder
byte/entry bounds. Linux client evidence must be x86-64, non-WSL, and use the
same commit as the runner checkout. The gate does not replace the sanitizer and
old-peer artifacts.

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
- negotiation, bounded reorder, and in-flight retirement tests (`2566750`); and
- a 100-cycle production `vmux_net` carrier-container churn test (`ded25d6`).

The `ded25d6` integration test drives the production attach helper, live RX/TX
containers, in-flight retirement gate, reap, exactly-once transport disposal,
and runtime active-link count for 100 grow/shrink cycles. It passed both the
normal jemalloc build and the ASan/UBSan build with leak detection on
2026-07-15. This closes the carrier-container lifecycle sanitizer gate, but it
does not drive real network carrier I/O or satisfy the Linux-plus-mobile
performance artifact gates.

These commits establish the measurement and compatibility mechanisms. No real
Linux-plus-mobile baseline demonstrating the throughput or p99 thresholds is
stored yet, so the production default must not change.
