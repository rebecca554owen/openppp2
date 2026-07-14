import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RuntimeUIWiringTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_client_readiness_uses_live_adapter_and_committed_route(self) -> None:
        source = self.source("ppp/app/client/VEthernetNetworkSwitcher.cpp")
        self.assertIn("tap->IsOpen()", source)
        self.assertIn("tap->IsHostedNetwork()", source)
        self.assertIn("facts.route_applied = route_snapshot.applied", source)
        self.assertIn("BuildClientRuntimeReadiness(facts)", source)

        mobile = self.source("ppp/app/client/route/RouteCoordinator_mobile.cpp")
        self.assertIn("state_.MarkApplied(true)", mobile)

    def test_server_exposes_actual_running_state(self) -> None:
        header = self.source("ppp/app/server/VirtualEthernetSwitcher.h")
        source = self.source("ppp/app/server/VirtualEthernetSwitcher.cpp")
        self.assertIn("IsRunning()", header)
        self.assertIn("running_.store(bany", source)
        self.assertIn("running_.store(false", source)

    def test_application_server_readiness_is_not_hardcoded(self) -> None:
        source = self.source("ppp/app/ApplicationMainLoop.cpp")
        self.assertIn("BuildServerRuntimeReadiness(server_->IsRunning())", source)
        self.assertNotIn("readiness.session = true", source)

    def test_application_explicitly_enters_applying_policy(self) -> None:
        source = self.source("ppp/app/ApplicationMainLoop.cpp")
        established = source.index("NetworkState::NetworkState_Established")
        readiness = source.index("client->GetRuntimeReadiness()", established)
        path = source[established:readiness]
        self.assertIn("RuntimePhase::ApplyingPolicy", path)

    def test_tui_lifecycle_status_is_rendered_from_snapshot(self) -> None:
        source = self.source("ppp/app/ApplicationMainLoop.cpp")
        self.assertIn("#include <ppp/app/tui/TuiRuntimeAdapter.h>", source)
        self.assertIn("BuildStatusLines(runtime)", source)

        status_path = source[
            source.index("if (!GetTransmissionStatistics"):
            source.index("ConsoleUI::GetInstance().UpdateStatus")
        ]
        self.assertNotIn("GetNetworkState()", status_path)
        self.assertNotIn("vpn_state", status_path)

    def test_android_home_does_not_subscribe_to_legacy_link_state(self) -> None:
        source = self.source("android/lib/pages/home_page.dart")
        self.assertNotIn("linkStateStream", source)
        self.assertNotIn("getLinkState()", source)
        self.assertNotIn("_linkState", source)
        self.assertIn("_pendingStartGeneration", source)
        self.assertNotIn("_connectInFlight", source)
        self.assertIn("controls.buttonEnabled && !commandPending", source)

    def test_mobile_decode_failure_does_not_retain_stale_connected_state(self) -> None:
        android = self.source("android/lib/vpn_service.dart")
        ios = self.source("ios/App/OpenPPP2/HomeViewController.swift")
        self.assertIn("decodeRuntimeOrdering", android)
        self.assertIn("runtimeStore.applyUnknown", android)
        self.assertIn("_markRuntimeUnavailable", android)
        self.assertIn("onError:", android)
        self.assertIn("onDone:", android)
        self.assertIn("decodeOrdering", ios)
        self.assertIn("runtimeStore.applyUnknown", ios)
        self.assertIn("runtimeStore.markUnknown()", ios)
        self.assertIn("runtimeDecodeError", ios)

    def test_ios_start_waits_for_runtime_snapshot(self) -> None:
        source = self.source("ios/App/OpenPPP2/HomeViewController.swift")
        start = source.index("@objc private func toggleConnection()")
        end = source.index("@objc private func openProfiles()", start)
        self.assertNotIn("statusCard.apply", source[start:end])
        self.assertIn("pendingStartGeneration", source[start:end])
        self.assertIn("guard pendingStartGeneration == nil", source[start:end])
        self.assertIn("runtimeStore.state.generation", source[start:end])
        self.assertIn("controls.buttonEnabled = false", source)
        self.assertIn("controls.configEditable = false", source)

    def test_runtime_contract_docs_are_governed_and_indexed(self) -> None:
        paths = (
            "docs/adr/0001-runtime-ui-contract.md",
            "docs/reference/UI_RUNTIME_CONTRACT.md",
            "docs/reference/UI_RUNTIME_CONTRACT_CN.md",
        )
        for relative in paths:
            self.assertTrue((ROOT / relative).is_file(), relative)

        index = self.source("docs/README.md")
        self.assertIn("reference/UI_RUNTIME_CONTRACT.md", index)
        self.assertIn("reference/UI_RUNTIME_CONTRACT_CN.md", index)


if __name__ == "__main__":
    unittest.main()
