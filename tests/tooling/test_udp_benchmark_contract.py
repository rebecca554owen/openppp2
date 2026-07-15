from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class UdpBenchmarkContractTests(unittest.TestCase):
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

    def test_e2e_validator_rejects_iperf_errors_and_reports_pps(self):
        validator = ROOT / "tools" / "bench" / "validate_e2e.py"
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory) / "result.json"
            result.write_text(json.dumps({"error": "mapping failed"}), encoding="utf-8")
            failed = subprocess.run([sys.executable, validator, result], capture_output=True, text=True)
            self.assertNotEqual(0, failed.returncode)

            result.write_text(
                json.dumps({"end": {"sum": {"seconds": 2, "packets": 100, "lost_packets": 1}}}),
                encoding="utf-8",
            )
            passed = subprocess.run([sys.executable, validator, result], capture_output=True, text=True)
            self.assertEqual(0, passed.returncode, passed.stderr)
            self.assertEqual(50, json.loads(passed.stdout)["pps"])


if __name__ == "__main__":
    unittest.main()
