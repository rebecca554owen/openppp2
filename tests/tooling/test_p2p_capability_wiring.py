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
        source = self.source("ppp/p2p/P2PChannel.cpp")
        probing = source[
            source.index("void P2PChannel::StartProbing") :
            source.index("void P2PChannel::SendProbe")
        ]
        protection = probing.index("ProtectP2PSocket")
        self.assertLess(protection, probing.index("StartReceive()"))
        self.assertLess(protection, probing.index("SendProbe("))

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


if __name__ == "__main__":
    unittest.main()
