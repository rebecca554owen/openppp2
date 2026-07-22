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


if __name__ == "__main__":
    unittest.main()
