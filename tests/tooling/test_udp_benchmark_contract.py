from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class UdpBenchmarkContractTests(unittest.TestCase):
    def _validate_fixed_host(self, environment, expected_host_id="bench-01"):
        validator = ROOT / "tools" / "bench" / "validate_fixed_host.py"
        with tempfile.TemporaryDirectory() as directory:
            fingerprint = Path(directory) / "env.json"
            fingerprint.write_text(json.dumps(environment), encoding="utf-8")
            return subprocess.run(
                [sys.executable, validator, fingerprint, expected_host_id],
                capture_output=True,
                text=True,
            )

    def test_fixed_host_validator_rejects_wsl(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "bench-01",
                "virt": "wsl",
                "governor": "performance",
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("WSL", result.stderr)

    def test_fixed_host_validator_requires_x86_64(self):
        result = self._validate_fixed_host(
            {
                "arch": "aarch64",
                "host_id": "bench-01",
                "virt": "none",
                "governor": "performance",
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("x86-64", result.stderr)

    def test_fixed_host_validator_requires_performance_governor(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "bench-01",
                "virt": "none",
                "governor": "unknown",
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("performance governor", result.stderr)

    def test_fixed_host_validator_requires_perf_cycles(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "bench-01",
                "virt": "none",
                "governor": "performance",
                "perf_cycles": False,
            }
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("cycles", result.stderr)

    def test_fixed_host_validator_requires_nonempty_host_id(self):
        result = self._validate_fixed_host(
            {
                "arch": "x86_64",
                "host_id": "",
                "virt": "none",
                "governor": "performance",
                "perf_cycles": True,
            },
            expected_host_id="",
        )

        self.assertNotEqual(0, result.returncode)
        self.assertIn("host_id", result.stderr)

    def test_all_microbenchmarks_are_built_and_smoke_tested(self):
        cmake = (ROOT / "bench" / "CMakeLists.txt").read_text(encoding="utf-8")

        for target in ("bm_crypto_chain", "bm_endpoint_serialize", "bm_packet_codec"):
            self.assertIn(f"ppp_add_bench({target}", cmake)
            self.assertIn(f"COMMAND {target} --benchmark_min_time=0.001", cmake)

    def test_linux_smoke_uses_the_built_boost_headers(self):
        cmake = (ROOT / "bench" / "CMakeLists.txt").read_text(encoding="utf-8")
        workflow = (ROOT / ".github" / "workflows" / "build-linux-amd64.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("OPENPPP2_BOOST_INCLUDE_DIR", cmake)
        self.assertIn(
            '-DOPENPPP2_BOOST_INCLUDE_DIR="$TP/boost"',
            workflow,
        )

    def test_micro_runner_records_every_required_metric(self):
        runner = (ROOT / "tools" / "bench" / "run_micro.sh").read_text(encoding="utf-8")

        for target in (
            "bm_crypto",
            "bm_crypto_chain",
            "bm_allocator",
            "bm_endpoint_serialize",
            "bm_packet_codec",
        ):
            self.assertIn(target, runner)
        self.assertIn("perf stat", runner)
        self.assertIn("cycles", runner)

        for source in (
            "bm_crypto.cpp",
            "bm_crypto_chain.cpp",
            "bm_allocator.cpp",
            "bm_endpoint_serialize.cpp",
            "bm_packet_codec.cpp",
        ):
            text = (ROOT / "bench" / "udp" / source).read_text(encoding="utf-8")
            self.assertIn('counters["allocations"]', text)

    def test_environment_fingerprint_records_fixed_host_eligibility(self):
        fingerprint = (ROOT / "tools" / "bench" / "env_fingerprint.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("BENCH_HOST_ID", fingerprint)
        self.assertIn('"arch"', fingerprint)
        self.assertIn('"host_id"', fingerprint)
        self.assertIn('"perf_cycles"', fingerprint)
        self.assertIn("perf stat -e cycles", fingerprint)

    def test_e2e_harness_uses_frozen_config_and_json_output(self):
        runner = ROOT / "tools" / "bench" / "run_e2e.sh"
        config = ROOT / "tools" / "bench" / "appsettings.bench.json"

        self.assertTrue(runner.is_file())
        self.assertTrue(config.is_file())
        script = runner.read_text(encoding="utf-8")
        self.assertIn("appsettings.bench.json", script)
        self.assertIn("iperf3", script)
        self.assertIn("64 1400", script)
        self.assertIn("env_fingerprint.sh", script)
        self.assertIn("kill -0", script)
        self.assertIn("--connect-timeout", script)
        self.assertIn("BENCH_SERVER_WAIT", script)
        self.assertIn('timeout "$((DURATION + 15))" iperf3 -s', script)
        self.assertIn("validate_e2e.py", script)
        self.assertIn('BITRATE="${BENCH_BITRATE:-10M}"', script)
        self.assertIn('--bitrate "$BITRATE"', script)
        self.assertNotIn("--bitrate 0", script)
        self.assertIn('"$BITRATE" > "$OUT/e2e-$size.summary.json"', script)
        self.assertIn("BENCH_BITRATE must be a positive integer", script)

    def test_e2e_validator_rejects_iperf_errors_and_reports_pps(self):
        validator = ROOT / "tools" / "bench" / "validate_e2e.py"
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.json"
            result.write_text(json.dumps({"error": "mapping failed"}), encoding="utf-8")
            failed = subprocess.run(
                [sys.executable, validator, result, "100M"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, failed.returncode)

            result.write_text(
                json.dumps({"end": {"sum": {"seconds": 2, "packets": 100, "lost_packets": 1}}}),
                encoding="utf-8",
            )
            passed = subprocess.run(
                [sys.executable, validator, result, "100M"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, passed.returncode, passed.stderr)
            summary = json.loads(passed.stdout)
            self.assertEqual(50, summary["pps"])
            self.assertEqual("100M", summary["offered_bitrate"])

            invalid_bitrate = subprocess.run(
                [sys.executable, validator, result, "0"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, invalid_bitrate.returncode)


if __name__ == "__main__":
    unittest.main()
