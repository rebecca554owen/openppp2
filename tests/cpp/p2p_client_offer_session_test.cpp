#define BOOST_TEST_MODULE p2p_client_offer_session_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PClientOfferSession.h>
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
    std::string encoded;
};

Fixture MakeFixture(std::uint8_t seed = 1) {
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
    secrets.pair_seed = Bytes<32>(seed + 140);
    secrets.initiator_wrap_nonce = Bytes<12>(seed + 180);
    secrets.responder_wrap_nonce = Bytes<12>(seed + 200);
    BOOST_REQUIRE(BuildP2PRelayOfferBundle(
        fixture.input, Bytes<32>(7), Bytes<32>(47),
        secrets, fixture.bundle));
    BOOST_REQUIRE(EncodeP2PRelayOfferRecipientHex(
        fixture.bundle.offer, fixture.bundle.initiator_envelope,
        fixture.encoded));
    fixture.context.local_session_id = fixture.input.initiator_session_id;
    fixture.context.local_peer_id = fixture.input.initiator_peer_id;
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
