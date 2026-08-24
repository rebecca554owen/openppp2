import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class VmuxReceiveSemanticsCiTests(unittest.TestCase):
    def test_vmux_context_outlives_strand(self) -> None:
        header = (ROOT / "ppp/app/mux/vmux_net.h").read_text(encoding="utf-8")
        ownership_start = header.rindex("vmux_skt_map")
        ownership = header[
            ownership_start : header.index("vmux_tx_flow_map", ownership_start)
        ]

        self.assertLess(ownership.index("ContextPtr"), ownership.index("StrandPtr"))

    def test_linux_asan_builds_and_runs_receive_semantics(self) -> None:
        # The dedicated build-asan job was trimmed from CI; the
        # receive-semantics test now ships as an opt-in CMake target.
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("OPTION(ENABLE_VMUX_RECEIVE_SEMANTICS_TEST", cmake)
        self.assertIn("ADD_EXECUTABLE(vmux_receive_semantics_test", cmake)

        unit_workflow = (ROOT / ".github/workflows/test.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "python3 -m unittest tests.tooling.test_vmux_receive_semantics_ci -v",
            unit_workflow,
        )


if __name__ == "__main__":
    unittest.main()
