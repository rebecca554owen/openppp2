import json
import hashlib
import math
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VMUX = ROOT / "benchmarks" / "vmux"


def run_wsl(command):
    if os.name != "nt":
        return subprocess.run(
            ["bash", "-lc", command],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    converted = subprocess.run(
        ["wsl", "-d", "Debian", "--", "pwd"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return subprocess.run(
        ["wsl", "-d", "Debian", "--", "bash", "-lc", f"cd {shlex.quote(converted)} && {command}"],
        capture_output=True,
        text=True,
    )


def valid_result(scenario="compat-one-flow", throughput=100.0):
    environment = {
        "architecture": "x86_64",
        "kernel": "Linux 6.8",
        "cpu": "test cpu",
        "git_commit": "0123456789abcdef",
    }
    environment["fingerprint"] = "sha256:" + hashlib.sha256(
        json.dumps(environment, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": 1,
        "scenario": scenario,
        "duration_seconds": 10,
        "environment": environment,
        "config": {
            "mux_mode": "compat",
            "flows": 1,
            "netem_profile": "none",
            "fingerprint": "sha256:test",
        },
        "metrics": {
            "throughput_mbps": throughput,
            "p50_latency_ms": 1.25,
            "p99_latency_ms": 2.5,
            "reorder_depth": 0,
            "buffered_bytes": 0,
            "active_links": 1,
            "disconnects": 0,
        },
        "runtime_state": {
            "requested_mode": "compat",
            "effective_mode": "compat",
            "fallback_reason": "",
        },
    }


class VmuxBenchmarkContractTests(unittest.TestCase):
    def test_matrix_and_metrics_are_declared(self):
        runner = (VMUX / "run.sh").read_text(encoding="utf-8")
        readme = (VMUX / "README.md").read_text(encoding="utf-8")
        schema = json.loads((VMUX / "result.schema.json").read_text(encoding="utf-8"))

        scenarios = (
            "off-one-flow",
            "compat-one-flow",
            "flow-one-flow",
            "compat-eight-flows",
            "flow-eight-flows",
            "balance-eight-flows",
            "carrier-delay",
            "carrier-loss",
            "carrier-removal",
            "turbo-churn",
        )
        for scenario in scenarios:
            self.assertIn(scenario, runner)
            self.assertIn(scenario, readme)

        required_metrics = schema["properties"]["metrics"]["required"]
        self.assertEqual(
            {
                "throughput_mbps",
                "p50_latency_ms",
                "p99_latency_ms",
                "reorder_depth",
                "buffered_bytes",
                "active_links",
                "disconnects",
            },
            set(required_metrics),
        )
        self.assertIn("environment", schema["required"])
        self.assertIn("fingerprint", schema["properties"]["environment"]["required"])
        self.assertIn("config", schema["required"])
        self.assertIn("runtime_state", schema["required"])
        self.assertIn("allOf", schema)

    def test_default_smoke_is_dry_run_and_rejects_bad_arguments(self):
        runner = VMUX / "run.sh"
        result = subprocess.run(
            ["bash", "benchmarks/vmux/run.sh", "--scenario", "one-flow", "--duration", "10"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("dry-run", result.stdout)
        self.assertNotIn('"throughput_mbps"', result.stdout)

        invalid = subprocess.run(
            ["bash", "benchmarks/vmux/run.sh", "--scenario", "not-a-scenario"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(0, invalid.returncode)

    def test_failed_embedded_validation_is_nonzero_and_leaves_no_result(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            directory = Path(directory)
            fakebin = directory / "bin"
            output = directory / "output"
            fakebin.mkdir()
            output.mkdir()
            iperf = fakebin / "iperf3"
            iperf.write_text(
                '#!/bin/sh\nprintf \'%s\\n\' \'{"end":{"sum_received":{"bits_per_second":1000000}}}\'\n',
                encoding="utf-8",
            )
            telemetry = directory / "telemetry.json"
            telemetry.write_text(
                json.dumps({
                    "metrics": {
                        "p50_latency_ms": 1.0,
                        "p99_latency_ms": 2.0,
                        "reorder_depth": 0,
                        "buffered_bytes": 0,
                        "active_links": 1,
                        "disconnects": 0,
                    },
                    "runtime_state": {
                        "requested_mode": "compat",
                        "effective_mode": "compat",
                        "fallback_reason": "",
                    },
                }),
                encoding="utf-8",
            )
            rel_bin = fakebin.relative_to(ROOT).as_posix()
            rel_output = output.relative_to(ROOT).as_posix()
            rel_telemetry = telemetry.relative_to(ROOT).as_posix()
            command = (
                f"chmod +x {shlex.quote(rel_bin + '/iperf3')} && "
                f"PATH={shlex.quote(rel_bin)}:$PATH benchmarks/vmux/run.sh --execute "
                f"--scenario flow-one-flow --duration 1 --server 127.0.0.1 "
                f"--telemetry {shlex.quote(rel_telemetry)} --prepare-hook /bin/true "
                f"--output {shlex.quote(rel_output)}"
            )
            result = run_wsl(command)
            leftovers = list(output.iterdir())

        self.assertNotEqual(0, result.returncode, result.stdout)
        self.assertEqual([], leftovers)

    def test_execute_requires_prepare_hook_before_tools_or_network(self):
        runner = VMUX / "run.sh"
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            telemetry = Path(directory) / "telemetry.json"
            telemetry.write_text("{}", encoding="utf-8")
            relative = telemetry.relative_to(ROOT).as_posix()
            result = subprocess.run(
                [
                    "bash", "benchmarks/vmux/run.sh", "--execute",
                    "--server", "127.0.0.1", "--telemetry", relative,
                ],
                cwd=ROOT, capture_output=True, text=True,
            )
        self.assertNotEqual(0, result.returncode)
        self.assertIn("--prepare-hook", result.stderr)

    def test_parser_rejects_mode_mismatch_fallback_and_off_links(self):
        parser = VMUX / "parse_results.py"
        mismatch = valid_result()
        mismatch["runtime_state"]["effective_mode"] = "flow"
        mismatch["runtime_state"]["fallback_reason"] = "peer_missing_flow_v2"
        off = valid_result("off-one-flow")
        off["config"]["mux_mode"] = "off"
        off["runtime_state"].update(requested_mode="off", effective_mode="off")
        off["metrics"]["active_links"] = 1
        with tempfile.TemporaryDirectory() as directory:
            for index, payload in enumerate((mismatch, off)):
                path = Path(directory) / f"bad-{index}.json"
                path.write_text(json.dumps(payload), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, parser, path], capture_output=True, text=True
                )
                self.assertNotEqual(0, result.returncode, payload)

    def test_parser_accepts_inactive_off_runtime_state(self):
        parser = VMUX / "parse_results.py"
        off = valid_result("off-one-flow")
        off["config"]["mux_mode"] = "off"
        off["runtime_state"].update(
            requested_mode="compat",
            effective_mode="compat",
            fallback_reason="mux_inactive",
        )
        off["metrics"]["active_links"] = 0
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "off.json"
            path.write_text(json.dumps(off), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, parser, path], capture_output=True, text=True
            )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_netem_profiles_are_exact_and_interface_is_guarded(self):
        netem = VMUX / "netem.sh"
        profiles = subprocess.run(
            ["bash", "benchmarks/vmux/netem.sh", "profiles"], cwd=ROOT, capture_output=True, text=True
        )
        self.assertEqual(0, profiles.returncode, profiles.stderr)
        self.assertIn("delay 40ms 0ms rate 100mbit", profiles.stdout)
        self.assertIn("loss random 2% 0% rate 100mbit seed 71214", profiles.stdout)

        for interface in ("", "lo", "--help", "eth0;true"):
            rejected = subprocess.run(
                ["bash", "benchmarks/vmux/netem.sh", "validate-interface", interface],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, rejected.returncode, interface)

        accepted = subprocess.run(
            ["bash", "benchmarks/vmux/netem.sh", "validate-interface", "vmux-test0"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, accepted.returncode, accepted.stderr)

    def test_parser_validates_and_aggregates_results(self):
        parser = VMUX / "parse_results.py"
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            first.write_text(json.dumps(valid_result(throughput=100)), encoding="utf-8")
            second.write_text(json.dumps(valid_result(throughput=120)), encoding="utf-8")

            result = subprocess.run(
                [sys.executable, parser, first, second], capture_output=True, text=True
            )
            self.assertEqual(0, result.returncode, result.stderr)
            summary = json.loads(result.stdout)
            self.assertEqual(2, summary["result_count"])
            self.assertEqual(110, summary["scenarios"]["compat-one-flow"]["throughput_mbps"]["mean"])

    def test_parser_rejects_bad_json_missing_fields_and_iperf_errors(self):
        parser = VMUX / "parse_results.py"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            cases = ("{", json.dumps({"schema_version": 1}), json.dumps({**valid_result(), "iperf": {"error": "connection failed"}}))
            for content in cases:
                path.write_text(content, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, parser, path], capture_output=True, text=True
                )
                self.assertNotEqual(0, result.returncode, content)

            missing_fingerprint = valid_result()
            del missing_fingerprint["environment"]["fingerprint"]
            path.write_text(json.dumps(missing_fingerprint), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, parser, path], capture_output=True, text=True
            )
            self.assertNotEqual(0, result.returncode)

    def test_parser_rejects_nonfinite_bool_and_additional_properties(self):
        parser = VMUX / "parse_results.py"
        payloads = []
        nonfinite = valid_result()
        nonfinite["metrics"]["throughput_mbps"] = math.nan
        payloads.append(nonfinite)
        boolean_integer = valid_result()
        boolean_integer["metrics"]["active_links"] = True
        payloads.append(boolean_integer)
        boolean_version = valid_result()
        boolean_version["schema_version"] = True
        payloads.append(boolean_version)
        empty_config_fingerprint = valid_result()
        empty_config_fingerprint["config"]["fingerprint"] = ""
        payloads.append(empty_config_fingerprint)
        for section in (None, "environment", "config", "metrics", "runtime_state"):
            extra = valid_result()
            target = extra if section is None else extra[section]
            target["unexpected"] = 1
            payloads.append(extra)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            for payload in payloads:
                path.write_text(json.dumps(payload), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, parser, path], capture_output=True, text=True
                )
                self.assertNotEqual(0, result.returncode, payload)

    def test_readme_keeps_compat_default_and_limits_ci_thresholds(self):
        readme = (VMUX / "README.md").read_text(encoding="utf-8")
        reference = (ROOT / "docs" / "reference" / "VMUX_VALIDATION.md").read_text(
            encoding="utf-8"
        )
        reference_cn = (
            ROOT / "docs" / "reference" / "VMUX_VALIDATION_CN.md"
        ).read_text(encoding="utf-8")
        self.assertIn("compat", readme)
        self.assertIn("Linux x86-64", readme)
        self.assertIn("correctness/smoke", readme)
        self.assertIn("environment fingerprint", readme)
        self.assertIn("configuration fingerprint", readme)
        self.assertIn("active_links == 0", readme)
        for document in (reference, reference_cn):
            self.assertIn("ded25d6", document)
        self.assertNotIn("actual churn sanitizer gate remains open", reference)


if __name__ == "__main__":
    unittest.main()
