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

    def test_android_state_is_not_derived_from_log_text(self) -> None:
        activity = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/MainActivity.kt"
        )
        # The old getState scanned the log with lastIndexOf("failed") and friends,
        # so any benign log line containing "failed" reported a disconnect.
        self.assertNotIn("lastIndexOf", activity)
        self.assertNotIn("vpnThread started", activity)
        self.assertIn("legacyStateFromSnapshot()", activity)
        self.assertIn("getRuntimeSnapshotIfAlive", activity)
        # Statics of a service running in `:vpn` are always zero here.
        self.assertNotIn("PppVpnService.isRunning", activity)
        self.assertNotIn("PppVpnService.currentState", activity)

        home = self.source("android/lib/pages/home_page.dart")
        self.assertNotIn("vpnThread started", home)

        settings = self.source("android/lib/pages/settings_page.dart")
        self.assertNotIn("VpnState", settings)
        self.assertIn("controlsFor(_runtimeStore.state.phase)", settings)

    def test_android_service_mirrors_runtime_state_across_processes(self) -> None:
        service = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/PppVpnService.kt"
        )
        # MainActivity.sendEvent touches a process-local sink, so every event
        # published from `:vpn` needs a file mirror to reach the UI process.
        self.assertIn("PppStateStore.setRuntimeSnapshot(this, value)", service)
        self.assertIn("PppStateStore.setLastError(this, message)", service)
        self.assertIn("updateNotificationForSnapshot(value)", service)
        self.assertNotIn('updateNotification("已连接")', service)

        store = self.source(
            "android/android/app/src/main/kotlin/supersocksr/ppp/android/PppStateStore.kt"
        )
        self.assertIn("createTempFile", store)
        self.assertIn("renameTo", store)
        self.assertNotIn("writeText(value.toString())", store)

        dart = self.source("android/lib/vpn_service.dart")
        self.assertIn("applyRuntimeSnapshotPoll", dart)
        self.assertIn("runtimeStore.beginSession()", dart)
        self.assertIn("runtimeStore.endSession()", dart)
        self.assertIn("getRuntimeSnapshot", dart)
        self.assertIn("getLastError", dart)

        store_dart = self.source("android/lib/runtime/runtime_store.dart")
        self.assertIn("resetForNewSession", store_dart)

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

    def test_vmux_ui_uses_snapshot_capabilities_and_next_connection_config(self) -> None:
        android_model = self.source("android/lib/runtime/runtime_snapshot.dart")
        android_view = self.source("android/lib/pages/options_advanced_page.dart")
        android_selector = self.source("android/lib/widgets/vmux_mode_selector.dart")
        android_config = self.source("android/lib/services/profile_store.dart")
        ios_model = self.source("ios/App/OpenPPP2/Runtime/RuntimeSnapshot.swift")
        ios_view = self.source("ios/App/OpenPPP2/OptionsViewController.swift")
        ios_config = self.source("ios/App/OpenPPP2/ProfileStore.swift")

        for source in (android_model, ios_model):
            self.assertIn("capabilities", source)
            self.assertIn("stripe", source)
            self.assertIn("Compatibility mode", source)
        self.assertIn("capabilities.contains('mux.$mode')", android_model)
        self.assertIn('capabilities.contains("mux.\\($0)")', ios_model)

        self.assertIn("Takes effect on next connection", android_view)
        self.assertIn("Takes effect on next connection", ios_view)
        self.assertIn("VmuxModeSelector", android_view)
        self.assertIn("availableMuxModes", android_selector)
        self.assertIn("availableMuxModes", ios_view)
        self.assertIn("muxMode", android_config)
        self.assertIn('mux["mode"]', ios_config)
        self.assertNotIn("setMuxMode", android_view)
        self.assertNotIn("setMuxMode", ios_view)

    def test_mobile_native_runtime_publishes_vmux_state(self) -> None:
        for relative in ("android/libopenppp2.cpp", "ios/OpenPPP2PacketTunnelBridge.cpp"):
            source = self.source(relative)
            self.assertIn('"mux.compat", "mux.flow", "mux.balance", "mux.stripe"', source)
            self.assertIn("GetMuxRuntimeState()", source)
            self.assertIn("UpdateMuxState(", source)
        ios = self.source("ios/OpenPPP2PacketTunnelBridge.cpp")
        missing_exchanger = ios[ios.index("if (exchanger == nullptr)"):ios.index("UpdateMuxState(")]
        self.assertIn("return;", missing_exchanger)

    def test_vmux_selector_and_home_are_wired_for_normal_ui(self) -> None:
        selector = self.source("android/lib/widgets/vmux_mode_selector.dart")
        android_home = self.source("android/lib/pages/home_page.dart")
        android_model = self.source("android/lib/runtime/runtime_snapshot.dart")
        android_store = self.source("android/lib/runtime/runtime_store.dart")
        ios_home = self.source("ios/App/OpenPPP2/HomeViewController.swift")
        ios_model = self.source("ios/App/OpenPPP2/Runtime/RuntimeSnapshot.swift")
        ios_store = self.source("ios/App/OpenPPP2/Runtime/RuntimeStore.swift")

        self.assertIn("availableMuxModes", selector)
        self.assertIn("Takes effect on next connection", selector)
        self.assertIn("effectiveMuxDisplayName", selector)
        self.assertIn("effectiveMuxDisplayName", android_home)
        self.assertIn("effectiveMuxDisplayName", ios_home)
        self.assertIn("bundledCapabilities", self.source("ios/App/OpenPPP2/OptionsViewController.swift"))
        self.assertIn("bundledCapabilities", android_store)
        self.assertIn("bundledCapabilities", ios_store)
        self.assertIn("json.containsKey('capabilities')", android_model)
        self.assertIn("container.contains(.capabilities)", ios_model)

        swift_test = ROOT / "ios/App/Tests/OpenPPP2LogicTests/VMuxPresentationTests.swift"
        self.assertTrue(swift_test.is_file())
        self.assertIn("import OpenPPP2Logic", swift_test.read_text(encoding="utf-8"))
        self.assertFalse((ROOT / "ios/App/OpenPPP2Tests").exists())


if __name__ == "__main__":
    unittest.main()
