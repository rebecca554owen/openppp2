#define BOOST_TEST_MODULE p2p_client_offer_session_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PClientOfferSession.h>
#include <ppp/p2p/P2PControlDatagram.h>
#include <ppp/p2p/P2PControlStateMachine.h>
#include <ppp/p2p/P2POfferToken.h>
#include <ppp/p2p/P2PRelayOfferCoordinator.h>

#include <algorithm>

namespace {

using namespace ppp::p2p;

template <std::size_t N>
std::array<std::uint8_t, N> Bytes(std::uint8_t first) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < value.size(); ++i) {
        value[i] = static_cast<std::uint8_t>(first + i);
    }
    return value;
}

struct Fixture {
    P2PRelayOfferInput input;
    P2PRelayOfferBundle bundle;
    P2PRelayOfferRecipientContext context;
    P2PPairSeed pair_seed{};
    std::string encoded;
};

Fixture MakeFixture(std::uint8_t seed = 1, bool responder = false) {
    Fixture fixture;
    fixture.input.initiator_session_id = Bytes<16>(seed);
    fixture.input.responder_session_id = Bytes<16>(seed + 20);
    fixture.input.initiator_peer_id = Bytes<16>(seed + 40);
    fixture.input.responder_peer_id = Bytes<16>(seed + 60);
    fixture.input.ttl_seconds = 10;
    fixture.input.candidate_set_hash = Bytes<32>(seed + 80);

    P2PRelayOfferSecrets secrets;
    secrets.offer_id = Bytes<16>(seed + 100);
    secrets.connection_epoch = Bytes<16>(seed + 120);
    fixture.pair_seed = Bytes<32>(seed + 140);
    secrets.pair_seed = fixture.pair_seed;
    secrets.initiator_wrap_nonce = Bytes<12>(seed + 180);
    secrets.responder_wrap_nonce = Bytes<12>(seed + 200);
    BOOST_REQUIRE(BuildP2PRelayOfferBundle(
        fixture.input, Bytes<32>(7), Bytes<32>(47),
        secrets, fixture.bundle));
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(
        fixture.bundle.offer,
        responder ? fixture.bundle.responder_envelope
                  : fixture.bundle.initiator_envelope,
        fixture.encoded));
    fixture.context.local_session_id = responder
        ? fixture.input.responder_session_id
        : fixture.input.initiator_session_id;
    fixture.context.local_peer_id = responder
        ? fixture.input.responder_peer_id
        : fixture.input.initiator_peer_id;
    fixture.context.candidate_set_hash = fixture.input.candidate_set_hash;
    return fixture;
}

P2PRelayOfferExporter Exporter(const P2PExporterKey& key = Bytes<32>(7)) {
    return [key](const char*, const std::uint8_t*, std::size_t,
                 std::uint8_t* output, std::size_t output_length) {
        if (output_length != key.size()) return false;
        std::copy(key.begin(), key.end(), output);
        return true;
    };
}

P2PCandidateEndpoint Endpoint(std::uint8_t seed, std::uint16_t port) {
    P2PCandidateEndpoint endpoint;
    endpoint.address_family = 6;
    endpoint.address = Bytes<16>(seed);
    endpoint.port = port;
    return endpoint;
}

P2POfferBinding BindingFromPacket(
    const Fixture& fixture,
    const P2PControlPacket& packet) {
    P2POfferBinding binding;
    binding.version = packet.version;
    binding.offer_id = fixture.bundle.offer.offer_id;
    binding.initiator_session_id = fixture.bundle.offer.initiator_session_id;
    binding.responder_session_id = fixture.bundle.offer.responder_session_id;
    binding.initiator_peer_id = fixture.bundle.offer.initiator_peer_id;
    binding.responder_peer_id = fixture.bundle.offer.responder_peer_id;
    binding.connection_epoch = packet.connection_epoch;
    binding.message_type = packet.type;
    binding.offer_hash = packet.offer_hash;
    binding.sender_role = packet.sender_role;
    binding.receiver_role = packet.receiver_role;
    binding.direction = packet.direction;
    binding.source = packet.source;
    binding.destination = packet.destination;
    binding.sequence = packet.sequence;
    binding.nonce = packet.nonce;
    binding.ttl_seconds = packet.ttl_seconds;
    binding.probe_transcript_hash = packet.probe_transcript_hash;
    return binding;
}

P2PControlPacket SignedProbeAck(
    const Fixture& fixture,
    const P2PControlPacket& probe,
    std::uint32_t sequence = 1) {
    P2POfferHash offer_hash{};
    P2PV1KeyMaterial keys{};
    BOOST_REQUIRE(HashP2PRelayOffer(fixture.bundle.offer, offer_hash));
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(fixture.pair_seed, offer_hash, keys));

    P2PControlPacket ack;
    ack.version = 1;
    ack.type = P2PControlType::ProbeAck;
    ack.offer_hash = offer_hash;
    ack.sender_role = probe.receiver_role;
    ack.receiver_role = probe.sender_role;
    ack.direction = ack.sender_role;
    ack.connection_epoch = probe.connection_epoch;
    ack.source = probe.destination;
    ack.destination = probe.source;
    ack.sequence = sequence;
    const auto& ack_nonce_prefix = ack.sender_role == 0
        ? keys.initiator_to_responder_nonce
        : keys.responder_to_initiator_nonce;
    ack.nonce = BuildP2PV1Nonce(ack_nonce_prefix, sequence);
    ack.ttl_seconds = probe.ttl_seconds;
    BOOST_REQUIRE(CreateP2PProbeTranscriptHash(
        BindingFromPacket(fixture, probe), ack.probe_transcript_hash));
    BOOST_REQUIRE(CreateP2POfferToken(
        keys.offer_token_key, BindingFromPacket(fixture, ack), ack.token));
    return ack;
}

}

BOOST_AUTO_TEST_CASE(valid_offer_becomes_eligible_but_keeps_relay_effective) {
    const auto fixture = MakeFixture();
    P2PClientOfferSession session;

    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000));
    const auto snapshot = session.Snapshot();
    BOOST_TEST(snapshot.active);
    BOOST_TEST(static_cast<int>(snapshot.state) == static_cast<int>(P2PState::Eligible));
    BOOST_TEST(std::string(snapshot.effective_path) == "relay");
    BOOST_TEST(snapshot.offer_id == fixture.bundle.offer.offer_id);
    BOOST_TEST(snapshot.peer_session_id == fixture.bundle.offer.responder_session_id);
    BOOST_TEST(snapshot.received_at_ms == 1000);
    BOOST_TEST(snapshot.deadline_ms == 11000);
}

BOOST_AUTO_TEST_CASE(duplicate_offer_cannot_extend_steady_clock_deadline) {
    const auto fixture = MakeFixture();
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000));

    BOOST_TEST(!session.Accept(
        fixture.encoded, fixture.context, Exporter(), 9000));
    BOOST_TEST(session.Snapshot().deadline_ms == 11000);
    BOOST_TEST(!session.Expire(10999));
    BOOST_TEST(session.Expire(11000));
    const auto expired = session.Snapshot();
    BOOST_TEST(!expired.active);
    BOOST_TEST(static_cast<int>(expired.state) == static_cast<int>(P2PState::Relay));
}

BOOST_AUTO_TEST_CASE(replayed_previous_offer_is_rejected_after_replacement) {
    const auto first = MakeFixture(1);
    const auto second = MakeFixture(2);
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(first.encoded, first.context, Exporter(), 1000));
    BOOST_REQUIRE(session.Accept(second.encoded, second.context, Exporter(), 2000));

    BOOST_TEST(!session.Accept(first.encoded, first.context, Exporter(), 3000));
    BOOST_TEST(session.Snapshot().offer_id == second.bundle.offer.offer_id);
}

BOOST_AUTO_TEST_CASE(invalid_offer_leaves_existing_session_unchanged) {
    const auto fixture = MakeFixture();
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000));
    const auto baseline = session.Snapshot();

    BOOST_TEST(!session.Accept(
        fixture.encoded, fixture.context, Exporter(Bytes<32>(47)), 2000));
    const auto after = session.Snapshot();
    BOOST_TEST(after.offer_id == baseline.offer_id);
    BOOST_TEST(after.deadline_ms == baseline.deadline_ms);
}

BOOST_AUTO_TEST_CASE(stale_generation_cleanup_preserves_newer_offer) {
    const auto first = MakeFixture(1);
    const auto second = MakeFixture(2);
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        first.encoded, first.context, Exporter(), 1000, 10));
    BOOST_REQUIRE(session.Accept(
        second.encoded, second.context, Exporter(), 2000, 11));

    BOOST_TEST(!session.ResetGeneration(10));
    BOOST_TEST(session.Snapshot().offer_id == second.bundle.offer.offer_id);
    BOOST_TEST(session.ResetGeneration(11));
    BOOST_TEST(!session.Snapshot().active);
}

BOOST_AUTO_TEST_CASE(late_older_generation_cannot_replace_newer_offer) {
    const auto newer = MakeFixture(3);
    const auto older = MakeFixture(4);
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        newer.encoded, newer.context, Exporter(), 2000, 11));

    BOOST_TEST(!session.Accept(
        older.encoded, older.context, Exporter(), 3000, 10));
    const auto snapshot = session.Snapshot();
    BOOST_TEST(snapshot.offer_id == newer.bundle.offer.offer_id);
    BOOST_TEST(snapshot.generation == 11);
}

BOOST_AUTO_TEST_CASE(session_creates_a_fully_bound_probe_without_exposing_keys) {
    const auto fixture = MakeFixture();
    const auto source = Endpoint(10, 4000);
    const auto destination = Endpoint(40, 5000);
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000, 7));

    P2PControlPacket probe;
    BOOST_REQUIRE(session.CreateAuthenticatedProbe(
        source, destination, 1001, 7, probe));
    BOOST_TEST(probe.version == 1u);
    BOOST_TEST(static_cast<int>(probe.type) ==
        static_cast<int>(P2PControlType::Probe));
    BOOST_TEST(probe.sender_role == 0u);
    BOOST_TEST(probe.receiver_role == 1u);
    BOOST_TEST(probe.direction == 0u);
    BOOST_TEST(probe.connection_epoch == fixture.bundle.offer.connection_epoch);
    BOOST_TEST(static_cast<bool>(probe.source == source));
    BOOST_TEST(static_cast<bool>(probe.destination == destination));
    BOOST_TEST(probe.sequence == 0u);
    BOOST_TEST(probe.ttl_seconds == fixture.bundle.offer.ttl_seconds);

    P2POfferHash offer_hash{};
    P2PV1KeyMaterial keys{};
    BOOST_REQUIRE(HashP2PRelayOffer(fixture.bundle.offer, offer_hash));
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(fixture.pair_seed, offer_hash, keys));
    BOOST_TEST(probe.offer_hash == offer_hash);
    BOOST_TEST(probe.nonce == BuildP2PV1Nonce(
        keys.initiator_to_responder_nonce, 0));
    P2PReplayWindow replay;
    BOOST_TEST(ValidateP2POfferToken(
        keys.offer_token_key, BindingFromPacket(fixture, probe),
        BindingFromPacket(fixture, probe), source, destination, 1,
        probe.token, keys.initiator_to_responder_nonce, replay));
}

BOOST_AUTO_TEST_CASE(probe_creation_is_generation_and_deadline_fenced) {
    const auto fixture = MakeFixture();
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000, 7));

    P2PControlPacket output;
    output.version = 99;
    const auto source = Endpoint(10, 4000);
    const auto destination = Endpoint(40, 5000);
    BOOST_TEST(!session.CreateAuthenticatedProbe(
        source, destination, 1001, 6, output));
    BOOST_TEST(output.version == 99u);
    BOOST_TEST(!session.CreateAuthenticatedProbe(
        source, destination, 11000, 7, output));
    BOOST_TEST(output.version == 99u);
}

BOOST_AUTO_TEST_CASE(probe_creation_is_limited_to_two_rounds_per_offer) {
    const auto fixture = MakeFixture();
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000, 7));
    const auto source = Endpoint(10, 4000);
    const auto destination = Endpoint(40, 5000);

    P2PControlPacket first;
    P2PControlPacket second;
    P2PControlPacket rejected;
    rejected.version = 99;
    BOOST_REQUIRE(session.CreateAuthenticatedProbe(
        source, destination, 1001, 7, first));
    BOOST_TEST(!session.CreateAuthenticatedProbe(
        source, destination, 1002, 7, rejected));
    BOOST_TEST(rejected.version == 99u);

    const auto first_ack = SignedProbeAck(fixture, first, 1);
    BOOST_REQUIRE(session.AuthenticateProbeAck(
        first_ack, first_ack.source, first_ack.destination, 1002, 7).has_value());
    BOOST_REQUIRE(session.CreateAuthenticatedProbe(
        source, destination, 1003, 7, second));
    BOOST_TEST(first.sequence == 0u);
    BOOST_TEST(second.sequence == 1u);

    const auto second_ack = SignedProbeAck(fixture, second, 2);
    BOOST_REQUIRE(session.AuthenticateProbeAck(
        second_ack, second_ack.source, second_ack.destination, 1004, 7).has_value());
    BOOST_TEST(!session.CreateAuthenticatedProbe(
        source, destination, 1005, 7, rejected));
    BOOST_TEST(rejected.version == 99u);
}

BOOST_AUTO_TEST_CASE(responder_uses_reverse_tx_and_rx_nonce_directions) {
    const auto fixture = MakeFixture(1, true);
    const auto source = Endpoint(40, 5000);
    const auto destination = Endpoint(10, 4000);
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(Bytes<32>(47)), 1000, 7));

    P2PControlPacket probe;
    BOOST_REQUIRE(session.CreateAuthenticatedProbe(
        source, destination, 1001, 7, probe));
    BOOST_TEST(probe.sender_role == 1u);
    BOOST_TEST(probe.receiver_role == 0u);

    P2POfferHash offer_hash{};
    P2PV1KeyMaterial keys{};
    BOOST_REQUIRE(HashP2PRelayOffer(fixture.bundle.offer, offer_hash));
    BOOST_REQUIRE(DeriveP2PV1KeyMaterial(fixture.pair_seed, offer_hash, keys));
    BOOST_TEST(probe.nonce == BuildP2PV1Nonce(
        keys.responder_to_initiator_nonce, 0));

    const auto ack = SignedProbeAck(fixture, probe);
    BOOST_TEST(ack.nonce == BuildP2PV1Nonce(
        keys.initiator_to_responder_nonce, 1));
    BOOST_TEST(session.AuthenticateProbeAck(
        ack, ack.source, ack.destination, 1002, 7).has_value());
}

BOOST_AUTO_TEST_CASE(session_authenticates_one_ack_without_entering_direct) {
    const auto fixture = MakeFixture();
    const auto source = Endpoint(10, 4000);
    const auto destination = Endpoint(40, 5000);
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000, 7));
    P2PControlPacket probe;
    BOOST_REQUIRE(session.CreateAuthenticatedProbe(
        source, destination, 1001, 7, probe));
    const auto ack = SignedProbeAck(fixture, probe);

    auto wrong_offer_hash = ack;
    wrong_offer_hash.offer_hash[0] ^= 1;
    BOOST_TEST(!session.AuthenticateProbeAck(
        wrong_offer_hash, ack.source, ack.destination, 1002, 7).has_value());

    auto tampered = ack;
    tampered.token[0] ^= 1;
    BOOST_TEST(!session.AuthenticateProbeAck(
        tampered, ack.source, ack.destination, 1002, 7).has_value());

    auto proof = session.AuthenticateProbeAck(
        ack, ack.source, ack.destination, 1002, 7);
    BOOST_REQUIRE(proof.has_value());
    BOOST_TEST(!session.AuthenticateProbeAck(
        ack, ack.source, ack.destination, 1002, 7).has_value());
    BOOST_TEST(static_cast<int>(session.Snapshot().state) ==
        static_cast<int>(P2PState::Eligible));
    BOOST_TEST(std::string(session.Snapshot().effective_path) == "relay");

    P2PControlStateMachine machine;
    BOOST_REQUIRE(machine.MarkEligible());
    BOOST_REQUIRE(machine.AcceptOffer());
    BOOST_TEST(machine.AcceptProbeAck(std::move(*proof)));
}

BOOST_AUTO_TEST_CASE(stale_generation_ack_cannot_consume_current_probe) {
    const auto fixture = MakeFixture();
    const auto source = Endpoint(10, 4000);
    const auto destination = Endpoint(40, 5000);
    P2PClientOfferSession session;
    BOOST_REQUIRE(session.Accept(
        fixture.encoded, fixture.context, Exporter(), 1000, 7));
    P2PControlPacket probe;
    BOOST_REQUIRE(session.CreateAuthenticatedProbe(
        source, destination, 1001, 7, probe));
    const auto ack = SignedProbeAck(fixture, probe);

    BOOST_TEST(!session.AuthenticateProbeAck(
        ack, ack.source, ack.destination, 1002, 6).has_value());
    BOOST_TEST(session.AuthenticateProbeAck(
        ack, ack.source, ack.destination, 1002, 7).has_value());
}

BOOST_AUTO_TEST_CASE(peer_sessions_complete_an_authenticated_probe_round_trip) {
    const auto initiator_fixture = MakeFixture(1, false);
    const auto responder_fixture = MakeFixture(1, true);
    P2PClientOfferSession initiator;
    P2PClientOfferSession responder;
    BOOST_REQUIRE(initiator.Accept(
        initiator_fixture.encoded, initiator_fixture.context,
        Exporter(Bytes<32>(7)), 1000, 7));
    BOOST_REQUIRE(responder.Accept(
        responder_fixture.encoded, responder_fixture.context,
        Exporter(Bytes<32>(47)), 1000, 7));

    const auto initiator_endpoint = Endpoint(10, 4000);
    const auto responder_endpoint = Endpoint(40, 5000);
    P2PControlPacket probe;
    BOOST_REQUIRE(initiator.CreateAuthenticatedProbe(
        initiator_endpoint, responder_endpoint, 1001, 7, probe));

    P2PControlPacket ack;
    BOOST_REQUIRE(responder.CreateAuthenticatedProbeAck(
        probe, probe.source, probe.destination, 1002, 7, ack));
    BOOST_TEST(static_cast<int>(ack.type) ==
        static_cast<int>(P2PControlType::ProbeAck));
    BOOST_TEST(ack.sender_role == 1u);
    BOOST_TEST(ack.receiver_role == 0u);
    BOOST_TEST(static_cast<bool>(ack.source == probe.destination));
    BOOST_TEST(static_cast<bool>(ack.destination == probe.source));
    BOOST_TEST(ack.sequence == 0u);

    auto proof = initiator.AuthenticateProbeAck(
        ack, ack.source, ack.destination, 1003, 7);
    BOOST_REQUIRE(proof.has_value());
    BOOST_TEST(std::string(initiator.Snapshot().effective_path) == "relay");
    BOOST_TEST(std::string(responder.Snapshot().effective_path) == "relay");
}

BOOST_AUTO_TEST_CASE(invalid_probe_does_not_consume_replay_or_mutate_ack_output) {
    const auto initiator_fixture = MakeFixture(1, false);
    const auto responder_fixture = MakeFixture(1, true);
    P2PClientOfferSession initiator;
    P2PClientOfferSession responder;
    BOOST_REQUIRE(initiator.Accept(
        initiator_fixture.encoded, initiator_fixture.context,
        Exporter(Bytes<32>(7)), 1000, 7));
    BOOST_REQUIRE(responder.Accept(
        responder_fixture.encoded, responder_fixture.context,
        Exporter(Bytes<32>(47)), 1000, 7));

    P2PControlPacket probe;
    BOOST_REQUIRE(initiator.CreateAuthenticatedProbe(
        Endpoint(10, 4000), Endpoint(40, 5000), 1001, 7, probe));
    auto tampered = probe;
    tampered.token[0] ^= 1;
    P2PControlPacket output;
    output.version = 99;
    BOOST_TEST(!responder.CreateAuthenticatedProbeAck(
        tampered, probe.source, probe.destination, 1002, 7, output));
    BOOST_TEST(output.version == 99u);

    auto spoofed_source = probe.source;
    ++spoofed_source.port;
    BOOST_TEST(!responder.CreateAuthenticatedProbeAck(
        probe, spoofed_source, probe.destination, 1002, 7, output));
    BOOST_TEST(output.version == 99u);

    BOOST_REQUIRE(responder.CreateAuthenticatedProbeAck(
        probe, probe.source, probe.destination, 1002, 7, output));
    const auto baseline = output;
    BOOST_REQUIRE(responder.CreateAuthenticatedProbeAck(
        probe, probe.source, probe.destination, 1003, 7, output));
    BOOST_TEST(output.version == baseline.version);
    BOOST_TEST(output.token == baseline.token);
    BOOST_TEST(output.nonce == baseline.nonce);
    BOOST_TEST(output.sequence == baseline.sequence);
}

BOOST_AUTO_TEST_CASE(probe_ack_creation_is_generation_and_deadline_fenced) {
    const auto initiator_fixture = MakeFixture(1, false);
    const auto responder_fixture = MakeFixture(1, true);
    P2PClientOfferSession initiator;
    P2PClientOfferSession responder;
    BOOST_REQUIRE(initiator.Accept(
        initiator_fixture.encoded, initiator_fixture.context,
        Exporter(Bytes<32>(7)), 1000, 7));
    BOOST_REQUIRE(responder.Accept(
        responder_fixture.encoded, responder_fixture.context,
        Exporter(Bytes<32>(47)), 1000, 7));
    P2PControlPacket probe;
    BOOST_REQUIRE(initiator.CreateAuthenticatedProbe(
        Endpoint(10, 4000), Endpoint(40, 5000), 1001, 7, probe));

    P2PControlPacket output;
    output.version = 99;
    BOOST_TEST(!responder.CreateAuthenticatedProbeAck(
        probe, probe.source, probe.destination, 1002, 6, output));
    BOOST_TEST(!responder.CreateAuthenticatedProbeAck(
        probe, probe.source, probe.destination, 11000, 7, output));
    BOOST_TEST(output.version == 99u);
}

BOOST_AUTO_TEST_CASE(rx_replay_is_shared_across_probe_and_probe_ack_types) {
    const auto initiator_fixture = MakeFixture(1, false);
    const auto responder_fixture = MakeFixture(1, true);
    P2PClientOfferSession initiator;
    P2PClientOfferSession responder;
    BOOST_REQUIRE(initiator.Accept(
        initiator_fixture.encoded, initiator_fixture.context,
        Exporter(Bytes<32>(7)), 1000, 7));
    BOOST_REQUIRE(responder.Accept(
        responder_fixture.encoded, responder_fixture.context,
        Exporter(Bytes<32>(47)), 1000, 7));

    P2PControlPacket initiator_probe;
    BOOST_REQUIRE(initiator.CreateAuthenticatedProbe(
        Endpoint(10, 4000), Endpoint(40, 5000), 1001, 7,
        initiator_probe));
    P2PControlPacket responder_ack;
    BOOST_REQUIRE(responder.CreateAuthenticatedProbeAck(
        initiator_probe, initiator_probe.source, initiator_probe.destination,
        1002, 7, responder_ack));

    P2PControlPacket responder_probe;
    BOOST_REQUIRE(responder.CreateAuthenticatedProbe(
        Endpoint(40, 5000), Endpoint(10, 4000), 1003, 7,
        responder_probe));
    BOOST_TEST(responder_probe.sequence == 1u);

    const auto reused_sequence_ack = SignedProbeAck(
        responder_fixture, responder_probe, 0);
    BOOST_TEST(!responder.AuthenticateProbeAck(
        reused_sequence_ack, reused_sequence_ack.source,
        reused_sequence_ack.destination, 1004, 7).has_value());

    const auto fresh_sequence_ack = SignedProbeAck(
        responder_fixture, responder_probe, 1);
    BOOST_TEST(responder.AuthenticateProbeAck(
        fresh_sequence_ack, fresh_sequence_ack.source,
        fresh_sequence_ack.destination, 1004, 7).has_value());
}

BOOST_AUTO_TEST_CASE(control_datagram_boundary_completes_authenticated_round_trip) {
    const auto initiator_fixture = MakeFixture(1, false);
    const auto responder_fixture = MakeFixture(1, true);
    P2PClientOfferSession initiator;
    P2PClientOfferSession responder;
    BOOST_REQUIRE(initiator.Accept(
        initiator_fixture.encoded, initiator_fixture.context,
        Exporter(Bytes<32>(7)), 1000, 7));
    BOOST_REQUIRE(responder.Accept(
        responder_fixture.encoded, responder_fixture.context,
        Exporter(Bytes<32>(47)), 1000, 7));

    const auto initiator_endpoint = Endpoint(10, 4000);
    const auto responder_endpoint = Endpoint(40, 5000);
    std::vector<std::uint8_t> probe_bytes;
    BOOST_REQUIRE(CreateAuthenticatedProbeDatagram(
        initiator, initiator_endpoint, responder_endpoint,
        1001, 7, probe_bytes));
    BOOST_TEST(probe_bytes.size() == P2PControlPacket::WireSize);

    P2PControlDatagramResult responder_result;
    BOOST_REQUIRE(HandleAuthenticatedControlDatagram(
        responder, probe_bytes, initiator_endpoint, responder_endpoint,
        1002, 7, responder_result));
    BOOST_TEST(static_cast<int>(responder_result.action) ==
        static_cast<int>(P2PControlDatagramAction::Reply));
    BOOST_TEST(responder_result.reply.size() ==
        P2PControlPacket::ProbeAckWireSize);

    P2PControlDatagramResult initiator_result;
    BOOST_REQUIRE(HandleAuthenticatedControlDatagram(
        initiator, responder_result.reply,
        responder_endpoint, initiator_endpoint,
        1003, 7, initiator_result));
    BOOST_TEST(static_cast<int>(initiator_result.action) ==
        static_cast<int>(P2PControlDatagramAction::AuthenticatedAck));
    BOOST_TEST(initiator_result.authenticated_ack.has_value());
    BOOST_TEST(std::string(initiator.Snapshot().effective_path) == "relay");
}

BOOST_AUTO_TEST_CASE(control_datagram_boundary_rejects_malformed_input_atomically) {
    P2PClientOfferSession session;
    P2PControlDatagramResult result;
    result.action = P2PControlDatagramAction::Reply;
    result.reply = {9, 8, 7};
    const std::vector<std::uint8_t> truncated(
        P2PControlPacket::WireSize - 1, 0);

    BOOST_TEST(!HandleAuthenticatedControlDatagram(
        session, truncated, Endpoint(10, 4000), Endpoint(40, 5000),
        1000, 7, result));
    BOOST_TEST(static_cast<int>(result.action) ==
        static_cast<int>(P2PControlDatagramAction::Reply));
    BOOST_TEST(result.reply == std::vector<std::uint8_t>({9, 8, 7}));
}
