import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ExchangerSubsystemBoundaryTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_frp_registry_owns_mapping_table(self) -> None:
        header = self.source("ppp/app/client/ClientFrpRegistry.h")
        self.assertIn("class ClientFrpRegistry final", header)
        self.assertIn("MappingTable mappings_", header)
        self.assertIn("std::mutex mutex_", header)
        for method in ("Add(", "Get(", "Remove(", "Tick(", "ReleaseAll("):
            self.assertIn(method, header)
        self.assertNotIn("VEthernetExchanger", header)
        self.assertNotIn("owner_", header)

    def test_exchanger_delegates_frp_storage_and_keepalive_state(self) -> None:
        header = self.source("ppp/app/client/VEthernetExchanger.h")
        source = self.source("ppp/app/client/VEthernetExchanger.cpp")
        self.assertNotIn("VirtualEthernetMappingPortTable mappings_", header)
        self.assertIn("std::unique_ptr<ClientFrpRegistry>", header)
        self.assertIn("frp_registry_->Tick(now)", source)
        self.assertIn("frp_registry_->ReleaseAll()", source)
        self.assertIn("ClientKeepAlivePolicy", header)
        self.assertNotIn("sekap_last_", header)
        self.assertNotIn("sekap_next_", header)


if __name__ == "__main__":
    unittest.main()
