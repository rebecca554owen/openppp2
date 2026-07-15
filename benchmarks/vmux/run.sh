#!/bin/bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"

usage() {
    cat <<'EOF'
Usage: run.sh [OPTIONS]

Defaults to a non-mutating dry-run. Pass --execute to run iperf3 and write a
result. Real runs require --server and --telemetry; fault scenarios also
require root, ip, tc, and an explicit --interface.

Options:
  --scenario NAME       Scenario or one-flow alias (default: one-flow)
  --duration SECONDS    Positive integer (default: 10)
  --output DIRECTORY    Result directory (default: build/benchmarks/vmux)
  --server HOST         iperf3 server for --execute
  --telemetry FILE      Real VMUX telemetry captured during the run
  --prepare-hook FILE   Required executable that configures/verifies the tunnel
  --interface NAME      Interface used only by fault scenarios
  --hook FILE           Executable carrier control hook for churn scenarios
  --execute             Run the benchmark; otherwise print the validated plan
  --list-scenarios      Print the scenario matrix
EOF
}

list_scenarios() {
    cat <<'EOF'
off-one-flow           mux off, one flow
compat-one-flow        compat, one flow
flow-one-flow          flow, one flow
compat-eight-flows     compat, eight flows
flow-eight-flows       flow, eight flows
balance-eight-flows    balance, eight flows
carrier-delay          one carrier with added delay
carrier-loss           one carrier with packet loss
carrier-removal        runtime carrier removal
turbo-churn            turbo grow/shrink churn
EOF
}

SCENARIO=one-flow
DURATION=10
OUTPUT="$ROOT/build/benchmarks/vmux"
SERVER=
TELEMETRY=
PREPARE_HOOK=
INTERFACE=
HOOK=
EXECUTE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scenario) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; SCENARIO="$2"; shift 2 ;;
        --duration) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; DURATION="$2"; shift 2 ;;
        --output) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; OUTPUT="$2"; shift 2 ;;
        --server) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; SERVER="$2"; shift 2 ;;
        --telemetry) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; TELEMETRY="$2"; shift 2 ;;
        --prepare-hook) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; PREPARE_HOOK="$2"; shift 2 ;;
        --interface) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; INTERFACE="$2"; shift 2 ;;
        --hook) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; HOOK="$2"; shift 2 ;;
        --execute) EXECUTE=1; shift ;;
        --list-scenarios) list_scenarios; exit 0 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: '$1'" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || { echo "duration must be a positive integer" >&2; exit 2; }
[ "$DURATION" -le 3600 ] || { echo "duration must not exceed 3600 seconds" >&2; exit 2; }

[[ "$SCENARIO" == one-flow ]] && SCENARIO=compat-one-flow
case "$SCENARIO" in
    off-one-flow) MODE=off; FLOWS=1; PROFILE=none; ACTION=none ;;
    compat-one-flow) MODE=compat; FLOWS=1; PROFILE=none; ACTION=none ;;
    flow-one-flow) MODE=flow; FLOWS=1; PROFILE=none; ACTION=none ;;
    compat-eight-flows) MODE=compat; FLOWS=8; PROFILE=none; ACTION=none ;;
    flow-eight-flows) MODE=flow; FLOWS=8; PROFILE=none; ACTION=none ;;
    balance-eight-flows) MODE=balance; FLOWS=8; PROFILE=none; ACTION=none ;;
    carrier-delay) MODE=balance; FLOWS=8; PROFILE=carrier-delay; ACTION=none ;;
    carrier-loss) MODE=balance; FLOWS=8; PROFILE=carrier-loss; ACTION=none ;;
    carrier-removal) MODE=balance; FLOWS=8; PROFILE=none; ACTION=carrier-removal ;;
    turbo-churn) MODE=flow; FLOWS=8; PROFILE=none; ACTION=turbo-churn ;;
    *) echo "unknown scenario: '$SCENARIO'" >&2; list_scenarios >&2; exit 2 ;;
esac

printf 'VMUX benchmark dry-run: scenario=%s mode=%s flows=%s duration=%ss netem=%s action=%s\n' \
    "$SCENARIO" "$MODE" "$FLOWS" "$DURATION" "$PROFILE" "$ACTION"
if [ "$EXECUTE" -eq 0 ]; then
    echo "dry-run only; no network state changed and no result was written"
    exit 0
fi

[[ -n "$SERVER" ]] || { echo "--execute requires --server" >&2; exit 2; }
[[ -n "$TELEMETRY" && -f "$TELEMETRY" ]] || {
    echo "--execute requires an existing --telemetry file; latency/reorder metrics are not fabricated" >&2
    exit 2
}
[[ -n "$PREPARE_HOOK" && -x "$PREPARE_HOOK" ]] || {
    echo "--execute requires an executable --prepare-hook" >&2
    exit 2
}
if [[ "$ACTION" != none ]]; then
    [[ -n "$HOOK" && -x "$HOOK" ]] || { echo "$SCENARIO requires an executable --hook" >&2; exit 2; }
fi
command -v iperf3 >/dev/null || { echo "--execute requires iperf3" >&2; exit 1; }
command -v python3 >/dev/null || { echo "--execute requires python3" >&2; exit 1; }

"$PREPARE_HOOK" "$SCENARIO" "$MODE" "$FLOWS" || {
    echo "prepare hook rejected scenario; no result written" >&2
    exit 1
}

NETEM_APPLIED=0
HOOK_PID=
RAW=
RESULT_TMP=
cleanup() {
    local status="${1:-$?}"
    trap - EXIT INT TERM HUP
    if [[ -n "$HOOK_PID" ]]; then
        kill "$HOOK_PID" 2>/dev/null || true
        wait "$HOOK_PID" 2>/dev/null || true
    fi
    if [ "$NETEM_APPLIED" -eq 1 ]; then
        "$HERE/netem.sh" clear "$INTERFACE" || true
    fi
    [[ -z "$RAW" ]] || rm -f "$RAW"
    [[ -z "$RESULT_TMP" ]] || rm -f "$RESULT_TMP"
    exit "$status"
}
trap 'cleanup $?' EXIT
trap 'exit 130' INT TERM HUP

if [[ "$PROFILE" != none ]]; then
    [[ -n "$INTERFACE" ]] || { echo "$SCENARIO requires --interface" >&2; exit 2; }
    [ "${EUID:-$(id -u)}" -eq 0 ] || { echo "$SCENARIO --execute requires root" >&2; exit 1; }
    command -v ip >/dev/null || { echo "$SCENARIO requires ip" >&2; exit 1; }
    command -v tc >/dev/null || { echo "$SCENARIO requires tc" >&2; exit 1; }
    "$HERE/netem.sh" apply "$INTERFACE" "$PROFILE"
    NETEM_APPLIED=1
fi

mkdir -p "$OUTPUT"
RAW="$(mktemp "$OUTPUT/.iperf.XXXXXX.json")"
RESULT_TMP="$(mktemp "$OUTPUT/.result.$SCENARIO.XXXXXX.json")"
RESULT="$OUTPUT/$SCENARIO-$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}.json"

if [[ "$ACTION" != none ]]; then
    (sleep "$(( DURATION / 2 ))"; "$HOOK" "$ACTION") &
    HOOK_PID=$!
fi

if ! iperf3 -c "$SERVER" -J -t "$DURATION" -P "$FLOWS" >"$RAW"; then
    echo "iperf3 failed; no result written" >&2
    exit 1
fi
if [[ -n "$HOOK_PID" ]]; then
    wait "$HOOK_PID" || { echo "carrier control hook failed; no result written" >&2; exit 1; }
    HOOK_PID=
fi

GIT_COMMIT="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || printf unknown)"
python3 - "$RAW" "$TELEMETRY" "$RESULT_TMP" "$SCENARIO" "$DURATION" "$MODE" "$FLOWS" "$PROFILE" "$GIT_COMMIT" <<'PY'
import hashlib
import json
import math
from pathlib import Path
import platform
import sys

raw_path, telemetry_path, output_path = map(Path, sys.argv[1:4])
scenario, duration, mode, flows, profile, commit = sys.argv[4:10]
def reject_constant(value):
    raise ValueError(f"invalid number {value}")


with raw_path.open(encoding="utf-8") as stream:
    iperf = json.load(stream, parse_constant=reject_constant)
if not isinstance(iperf, dict):
    raise SystemExit("iperf result must be an object")
if iperf.get("error"):
    raise SystemExit(f"iperf error: {iperf['error']}")
with telemetry_path.open(encoding="utf-8") as stream:
    telemetry = json.load(stream, parse_constant=reject_constant)
if not isinstance(telemetry, dict):
    raise SystemExit("telemetry must be an object")
metrics = telemetry.get("metrics", {})
runtime_state = telemetry.get("runtime_state", {})
required_metrics = {
    "p50_latency_ms", "p99_latency_ms", "reorder_depth", "buffered_bytes",
    "active_links", "disconnects",
}
if not isinstance(metrics, dict) or metrics.keys() != required_metrics:
    raise SystemExit("telemetry metrics must contain exactly: " + ", ".join(sorted(required_metrics)))
runtime_fields = {"requested_mode", "effective_mode", "fallback_reason"}
if not isinstance(runtime_state, dict) or runtime_state.keys() != runtime_fields:
    raise SystemExit("telemetry runtime_state must contain exactly: " + ", ".join(sorted(runtime_fields)))
for name in ("p50_latency_ms", "p99_latency_ms"):
    value = metrics[name]
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise SystemExit(f"telemetry {name} must be a finite non-negative number")
for name in ("reorder_depth", "buffered_bytes", "active_links", "disconnects"):
    value = metrics[name]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SystemExit(f"telemetry {name} must be a non-negative integer")
for name in runtime_fields:
    if not isinstance(runtime_state[name], str):
        raise SystemExit(f"telemetry {name} must be a string")
if mode == "off":
    if metrics["active_links"] != 0:
        raise SystemExit("off scenario requires active_links == 0")
    if runtime_state["fallback_reason"] not in ("", "mux_inactive"):
        raise SystemExit("off scenario fallback must be empty or mux_inactive")
else:
    if runtime_state["requested_mode"] != mode or runtime_state["effective_mode"] != mode:
        raise SystemExit("telemetry requested/effective mode does not match scenario")
    if runtime_state["fallback_reason"]:
        raise SystemExit("fallback telemetry cannot be used as requested mode evidence")
end = iperf.get("end", {})
summary = end.get("sum_received") or end.get("sum") or end.get("sum_sent") or {}
bps = summary.get("bits_per_second")
if isinstance(bps, bool) or not isinstance(bps, (int, float)) or not math.isfinite(bps) or bps < 0:
    raise SystemExit("iperf result missing end throughput")
config = {"mux_mode": mode, "flows": int(flows), "netem_profile": profile}
fingerprint_input = {**config, "scenario": scenario, "duration_seconds": int(duration)}
config["fingerprint"] = "sha256:" + hashlib.sha256(
    json.dumps(fingerprint_input, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
cpu = platform.processor()
if not cpu:
    try:
        cpu = next(
            line.split(":", 1)[1].strip()
            for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines()
            if line.lower().startswith("model name")
        )
    except (OSError, StopIteration):
        cpu = "unknown"
environment = {
    "architecture": platform.machine() or "unknown",
    "kernel": f"{platform.system()} {platform.release()}",
    "cpu": cpu,
    "git_commit": commit,
}
environment["fingerprint"] = "sha256:" + hashlib.sha256(
    json.dumps(environment, sort_keys=True, separators=(",", ":")).encode()
).hexdigest()
result = {
    "schema_version": 1,
    "scenario": scenario,
    "duration_seconds": int(duration),
    "environment": environment,
    "config": config,
    "metrics": {"throughput_mbps": bps / 1_000_000, **{name: metrics[name] for name in required_metrics}},
    "runtime_state": {name: runtime_state[name] for name in ("requested_mode", "effective_mode", "fallback_reason")},
    "iperf": iperf,
}
with output_path.open("w", encoding="utf-8") as stream:
    json.dump(result, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

python3 "$HERE/parse_results.py" "$RESULT_TMP" >/dev/null || {
    echo "generated result failed validation" >&2
    exit 1
}
mv "$RESULT_TMP" "$RESULT"
RESULT_TMP=
echo "result: $RESULT"
