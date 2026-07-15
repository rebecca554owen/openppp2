#!/usr/bin/env python3
"""Validate VMUX result files and print a scenario summary as JSON."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys


TOP_LEVEL = {
    "schema_version",
    "scenario",
    "duration_seconds",
    "environment",
    "config",
    "metrics",
    "runtime_state",
}
TOP_ALLOWED = TOP_LEVEL | {"iperf"}
ENVIRONMENT_FIELDS = {"architecture", "kernel", "cpu", "git_commit", "fingerprint"}
CONFIG_FIELDS = {"mux_mode", "flows", "netem_profile", "fingerprint"}
RUNTIME_FIELDS = {"requested_mode", "effective_mode", "fallback_reason"}
METRICS = {
    "throughput_mbps": (float, int),
    "p50_latency_ms": (float, int),
    "p99_latency_ms": (float, int),
    "reorder_depth": (int,),
    "buffered_bytes": (int,),
    "active_links": (int,),
    "disconnects": (int,),
}
SCENARIOS = {
    "off-one-flow": ("off", 1),
    "compat-one-flow": ("compat", 1),
    "flow-one-flow": ("flow", 1),
    "compat-eight-flows": ("compat", 8),
    "flow-eight-flows": ("flow", 8),
    "balance-eight-flows": ("balance", 8),
    "carrier-delay": ("balance", 8),
    "carrier-loss": ("balance", 8),
    "carrier-removal": ("balance", 8),
    "turbo-churn": ("flow", 8),
}


def fail(path, message):
    raise ValueError(f"{path}: {message}")


def require_object(path, value, fields, allowed=None):
    if not isinstance(value, dict):
        fail(path, "must be an object")
    missing = fields - value.keys()
    if missing:
        fail(path, "missing " + ", ".join(sorted(missing)))
    unexpected = value.keys() - (allowed if allowed is not None else fields)
    if unexpected:
        fail(path, "additional properties: " + ", ".join(sorted(unexpected)))


def require_string(path, value):
    if not isinstance(value, str):
        fail(path, "must be a string")


def validate(path, result):
    require_object(path, result, TOP_LEVEL, TOP_ALLOWED)
    if type(result["schema_version"]) is not int or result["schema_version"] != 1:
        fail(path, "unsupported schema_version")
    require_string(path, result["scenario"])
    if not result["scenario"]:
        fail(path, "scenario must not be empty")
    duration = result["duration_seconds"]
    if (
        isinstance(duration, bool)
        or not isinstance(duration, (int, float))
        or not math.isfinite(duration)
        or duration <= 0
    ):
        fail(path, "duration_seconds must be positive")

    environment_base_fields = {"architecture", "kernel", "cpu", "git_commit"}
    require_object(path, result["environment"], ENVIRONMENT_FIELDS)
    for name in ENVIRONMENT_FIELDS:
        require_string(path, result["environment"][name])
        if not result["environment"][name]:
            fail(path, f"environment.{name} must not be empty")
    fingerprint_source = {
        name: result["environment"][name] for name in environment_base_fields
    }
    expected_fingerprint = "sha256:" + hashlib.sha256(
        json.dumps(fingerprint_source, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    if result["environment"]["fingerprint"] != expected_fingerprint:
        fail(path, "environment.fingerprint mismatch")

    require_object(path, result["config"], CONFIG_FIELDS)
    if result["config"]["mux_mode"] not in {"off", "compat", "flow", "balance", "turbo"}:
        fail(path, "unknown config.mux_mode")
    flows = result["config"]["flows"]
    if isinstance(flows, bool) or not isinstance(flows, int) or flows < 1:
        fail(path, "config.flows must be a positive integer")
    if result["config"]["netem_profile"] not in {"none", "carrier-delay", "carrier-loss"}:
        fail(path, "unknown config.netem_profile")
    require_string(path, result["config"]["fingerprint"])
    if not result["config"]["fingerprint"]:
        fail(path, "config.fingerprint must not be empty")
    expected_config = SCENARIOS.get(result["scenario"])
    if expected_config is None:
        fail(path, "unknown scenario")
    if expected_config != (result["config"]["mux_mode"], flows):
        fail(path, "scenario does not match mux_mode/flows")

    require_object(path, result["metrics"], set(METRICS))
    for name, types in METRICS.items():
        value = result["metrics"][name]
        if (
            isinstance(value, bool)
            or not isinstance(value, types)
            or not math.isfinite(value)
            or value < 0
        ):
            fail(path, f"metrics.{name} must be a non-negative number")

    require_object(path, result["runtime_state"], RUNTIME_FIELDS)
    for name in RUNTIME_FIELDS:
        require_string(path, result["runtime_state"][name])
    expected_mode = result["config"]["mux_mode"]
    if expected_mode == "off":
        if result["metrics"]["active_links"] != 0:
            fail(path, "off scenario requires active_links == 0")
        if result["runtime_state"]["fallback_reason"] not in {"", "mux_inactive"}:
            fail(path, "off scenario fallback must be empty or mux_inactive")
    else:
        if result["runtime_state"]["requested_mode"] != expected_mode:
            fail(path, "runtime requested_mode does not match scenario")
        if result["runtime_state"]["effective_mode"] != expected_mode:
            fail(path, "runtime effective_mode does not match scenario")
        if result["runtime_state"]["fallback_reason"]:
            fail(path, "fallback result cannot be used as requested mode evidence")

    if "iperf" in result:
        if not isinstance(result["iperf"], dict):
            fail(path, "iperf must be an object")
        if result["iperf"].get("error"):
            fail(path, f"iperf error: {result['iperf']['error']}")


def metric_summary(values):
    return {
        "min": min(values),
        "mean": statistics.fmean(values),
        "max": max(values),
    }


def summarize(results):
    scenarios = {}
    for result in results:
        scenarios.setdefault(result["scenario"], []).append(result)
    return {
        "schema_version": 1,
        "result_count": len(results),
        "scenarios": {
            scenario: {
                name: metric_summary([item["metrics"][name] for item in items])
                for name in METRICS
            }
            for scenario, items in sorted(scenarios.items())
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("results", nargs="+", type=Path)
    args = parser.parse_args(argv)
    results = []
    try:
        for path in args.results:
            with path.open(encoding="utf-8") as stream:
                result = json.load(
                    stream,
                    parse_constant=lambda value: fail(path, f"invalid number {value}"),
                )
            validate(path, result)
            results.append(result)
    except (OSError, json.JSONDecodeError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    json.dump(summarize(results), sys.stdout, indent=2, sort_keys=True)
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
