import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class P2PCapabilityWiringTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_client_register_is_guarded_by_authenticated_capabilities(self) -> None:
        source = self.source("ppp/app/client/VEthernetExchanger.cpp")
        register = source[source.index("const auto p2p_capability") :]
        self.assertIn("P2PCapabilityGate::Evaluate", register)
        self.assertIn("transmission->HasAuthenticatedSessionExporter()", register)
        self.assertIn("protector->IsReady()", register)
        self.assertIn("ProductionAuthenticatedControlV1Ready", register)
        self.assertIn("if (p2p_capability.allowed)", register)

    def test_server_registration_and_offers_are_guarded(self) -> None:
        source = self.source("ppp/app/server/VirtualEthernetSwitcher.cpp")
        registration = source[
            source.index("bool VirtualEthernetSwitcher::UpdateP2PPeer") :
            source.index("bool VirtualEthernetSwitcher::DeleteP2PPeer")
        ]
        offers = source[
            source.index("bool VirtualEthernetSwitcher::OfferP2PPeerHints") :
            source.index("bool VirtualEthernetSwitcher::DeleteNatInformation", source.index("bool VirtualEthernetSwitcher::OfferP2PPeerHints"))
        ]
        self.assertIn("P2PCapabilityGate::Evaluate", registration)
        self.assertIn("HasAuthenticatedSessionExporter()", registration)
        self.assertIn("response.P2P.enabled = p2p_capability.allowed", registration)
        self.assertNotIn("CreateSocketProtector", registration)
        self.assertIn("P2PCapabilityGate::Evaluate", offers)
        self.assertGreaterEqual(offers.count("HasAuthenticatedSessionExporter()"), 2)
        self.assertNotIn("CreateSocketProtector", offers)
        self.assertGreaterEqual(
            offers.count("ProductionAuthenticatedControlV1Ready"), 2
        )

    def test_channel_protects_before_receive_and_probe(self) -> None:
        channel = self.source("ppp/p2p/P2PChannel.cpp")
        transport = self.source("ppp/p2p/P2PDatagramTransport.cpp")
        start = transport[
            transport.index("bool Start(const P2PDatagramReceiveCallback") :
            transport.index("boost::asio::ip::udp::endpoint LocalEndpoint")
        ]
        protection = start.index("ProtectP2PSocket")
        self.assertLess(protection, start.index("StartReceive()"))
        probing = channel[
            channel.index("void P2PChannel::StartProbing") :
            channel.index("bool P2PChannel::SendProbe")
        ]
        self.assertLess(probing.index("transport_->Start("), probing.index("SendProbe("))
        self.assertNotIn("boost::asio::ip::udp::socket", channel)

    def test_channel_forwards_data_only_while_direct(self) -> None:
        source = self.source("ppp/p2p/P2PChannel.cpp")
        receive = source[
            source.index("void P2PChannel::HandleTier2") :
            source.index("bool P2PChannel::SendFrame")
        ]
        receive_gate = receive[: receive.index("if (sender != peer_endpoint_)")]
        self.assertIn("CanProcessAuthenticatedP2PTier2(current_state)", receive_gate)

        payload_gate = receive[
            receive.index("if (IsHeartbeatAck(header.flags))") :
            receive.index("if (IsCoalesced(header.flags))")
        ]
        self.assertIn("if (!CanForwardP2PPayload(current_state))", payload_gate)

        send = source[
            source.index("bool P2PChannel::SendFrame") :
            source.index("void P2PChannel::OnHeartbeatTimer")
        ]
        self.assertGreaterEqual(
            send.count("state_.load(std::memory_order_acquire) != P2PChannelState::Direct"),
            2,
        )

    def test_channel_errors_use_one_fallback_cleanup_path(self) -> None:
        header = self.source("ppp/p2p/P2PChannel.h")
        source = self.source("ppp/p2p/P2PChannel.cpp")
        self.assertIn("void FallbackToRelay(P2PFallbackReason reason)", header)
        self.assertIn("void ResetAttemptState()", header)
        self.assertIn("bool SendProbe(const boost::asio::ip::udp::endpoint& ep)", header)

        cleanup = source[
            source.index("void P2PChannel::ResetAttemptState") :
            source.index("bool P2PChannel::BuildTier1TokenInput")
        ]
        for required in (
            "OPENSSL_cleanse(base_session_key_",
            "OPENSSL_cleanse(tx_session_key_",
            "OPENSSL_cleanse(rx_session_key_",
            "OPENSSL_cleanse(token_key_",
            "offer_token_.clear()",
            "replay_window_.Reset()",
            "candidates_.clear()",
            "transport_.reset()",
        ):
            self.assertIn(required, cleanup)

        probe_timeout = source[
            source.index("void P2PChannel::OnProbeTimeout") :
            source.index("void P2PChannel::OnProbeAck")
        ]
        suspect_timeout = source[
            source.index("void P2PChannel::OnSuspectTimeout") :
            source.index("uint64_t P2PChannel::NextChannelNonce")
        ]
        self.assertIn("FallbackToRelay(P2PFallbackReason::Timeout)", probe_timeout)
        self.assertIn("FallbackToRelay(P2PFallbackReason::Timeout)", suspect_timeout)

        probing = source[
            source.index("void P2PChannel::StartProbing") :
            source.index("void P2PChannel::SendProbe")
        ]
        after_initial_probes = probing[
            probing.index("for (const auto& cand : candidates)") :
            probing.index("probe_timer_ =")
        ]
        self.assertIn("closed_.load(std::memory_order_acquire)", after_initial_probes)
        self.assertIn("if (!SendProbe(cand.endpoint)) return", after_initial_probes)

        retry_probes = probe_timeout[
            probe_timeout.index("for (const auto& cand : candidates_)") :
            probe_timeout.index("if (probe_timer_)")
        ]
        self.assertIn("closed_.load(std::memory_order_acquire)", retry_probes)
        self.assertIn("if (!SendProbe(cand.endpoint)) return", retry_probes)

        probing_receive = probing[
            probing.index("transport_->Start(") : probing.index("TransitionTo(")
        ]
        self.assertIn(
            "FallbackToRelay(P2PFallbackReason::SocketError)", probing_receive
        )

        tier1 = source[
            source.index("void P2PChannel::HandleTier1") :
            source.index("void P2PChannel::HandleTier2")
        ]
        invalid_token = tier1[
            tier1.index("if (!VerifyTier1Token(header))") :
            tier1.index("P2PChannelState current_state")
        ]
        self.assertNotIn("FallbackToRelay", invalid_token)

        encrypt = source[
            source.index("bool P2PChannel::EncryptAndSendTier2") :
            source.index("void P2PChannel::OnHeartbeatTimer")
        ]
        missing_transport = encrypt[: encrypt.index("bool is_heartbeat")]
        self.assertIn(
            "FallbackToRelay(P2PFallbackReason::SocketError)", missing_transport
        )

        send_probe = source[
            source.index("bool P2PChannel::SendProbe(") :
            source.index("void P2PChannel::SendProbeAck(")
        ]
        send_ack = source[
            source.index("void P2PChannel::SendProbeAck(") :
            source.index("bool P2PChannel::VerifyTier1Token")
        ]
        for control_send in (send_probe, send_ack):
            self.assertIn("if (!TokenGenerate", control_send)
            self.assertGreaterEqual(
                control_send.count(
                    "FallbackToRelay(P2PFallbackReason::AuthenticationFailure)"
                ),
                3,
            )

        verify_token = source[
            source.index("bool P2PChannel::VerifyTier1Token") :
            source.index("void P2PChannel::OnProbeTimeout")
        ]
        self.assertIn("OPENSSL_cleanse(token_input, sizeof(token_input))", verify_token)

    def test_android_protector_reuses_the_vpn_service_bridge(self) -> None:
        bridge_header = self.source("android/OpenPPP2VpnProtectBridge.h")
        bridge_source = self.source("android/OpenPPP2VpnProtectBridge.cpp")
        kotlin = self.source(
            "android/android/app/src/main/kotlin/"
            "supersocksr/ppp/android/c/libopenppp2.kt"
        )
        protector_header = self.source("ppp/p2p/P2PSocketProtector.h")
        protector_source = self.source("ppp/p2p/P2PSocketProtector.cpp")

        self.assertIn("IsProtectBridgeReady()", bridge_header)
        self.assertIn('GetStaticMethodID(local_clazz, "isProtectReady", "()Z")', bridge_source)
        self.assertIn("fun isProtectReady(): Boolean", kotlin)
        self.assertIn("PppVpnService.instance != null", kotlin)
        service = self.source(
            "android/android/app/src/main/kotlin/"
            "supersocksr/ppp/android/PppVpnService.kt"
        )
        self.assertIn("@Volatile\n        var instance: PppVpnService?", service)
        self.assertIn("bool IsReady() const noexcept override", protector_header)
        self.assertNotIn("void Initialize(void* env, void* vpn_service)", protector_header)
        self.assertIn("<android/OpenPPP2VpnProtectBridge.h>", protector_source)
        self.assertIn("ppp::android::IsProtectBridgeReady()", protector_source)
        self.assertIn("ppp::android::ProtectSocketFd(fd)", protector_source)
        protect_call = bridge_source[bridge_source.index("bool ProtectSocketFd(int fd)") :]
        self.assertIn("NewLocalRef(state.clazz)", protect_call)
        self.assertIn("DeleteLocalRef(clazz)", protect_call)

    def test_ios_uses_provider_owned_udp_transport(self) -> None:
        header = self.source("ios/OpenPPP2PacketTunnelBridge.h")
        bridge = self.source("ios/OpenPPP2PacketTunnelBridge.cpp")
        adapter = self.source(
            "ios/App/OpenPPP2PacketTunnel/OpenPPP2PacketTunnelAdapter.swift"
        )
        provider_transport = self.source(
            "ios/App/OpenPPP2PacketTunnel/ProviderOwnedP2PDatagramTransport.swift"
        )
        native_transport = self.source("ppp/p2p/P2PDatagramTransport.cpp")

        self.assertIn("openppp2_ios_tap_set_p2p_datagram_provider", header)
        self.assertIn("CreateIosProviderP2PDatagramTransportFactory", bridge)
        self.assertIn("install(on: createdTap)", adapter)
        self.assertIn("uninstall(from: tap)", adapter)
        self.assertLess(
            adapter.index("install(on: createdTap)"),
            adapter.index("startNativeTap(createdTap"),
        )
        self.assertLess(
            adapter.index("uninstall(from: tap)"),
            adapter.index("openppp2_ios_tap_destroy(tap)"),
        )
        self.assertIn("createUDPSession", provider_transport)
        self.assertIn("setReadHandler", provider_transport)
        self.assertIn("writeDatagram", provider_transport)
        iphone_factory = native_transport[native_transport.index("#if defined(_IPHONE)") :]
        self.assertIn("return nullptr", iphone_factory)

        workflow = self.source(".github/workflows/test.yml")
        self.assertIn("Typecheck PacketTunnel P2P provider transport", workflow)
        self.assertIn("ProviderOwnedP2PDatagramTransport.swift", workflow)
        self.assertIn("swiftc -typecheck", workflow)


if __name__ == "__main__":
    unittest.main()
