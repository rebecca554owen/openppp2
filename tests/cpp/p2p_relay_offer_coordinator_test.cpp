#define BOOST_TEST_MODULE p2p_relay_offer_coordinator_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PRelayOfferCoordinator.h>

#include <algorithm>
#include <cstdint>
#include <cstring>

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

P2PRelayOfferInput Input() {
    P2PRelayOfferInput input;
    input.initiator_session_id = Bytes<16>(1);
    input.responder_session_id = Bytes<16>(21);
    input.initiator_peer_id = Bytes<16>(41);
    input.responder_peer_id = Bytes<16>(61);
    input.ttl_seconds = 10;
    input.candidate_set_hash = Bytes<32>(81);
    return input;
}

P2PRelayOfferSecrets Secrets() {
    P2PRelayOfferSecrets secrets;
    secrets.offer_id = Bytes<16>(101);
    secrets.connection_epoch = Bytes<16>(121);
    secrets.pair_seed = Bytes<32>(141);
    secrets.initiator_wrap_nonce = Bytes<12>(181);
    secrets.responder_wrap_nonce = Bytes<12>(201);
    return secrets;
}

}

BOOST_AUTO_TEST_CASE(wraps_one_pair_seed_for_two_session_exporters) {
    const auto input = Input();
    const auto secrets = Secrets();
    const auto initiator_exporter = Bytes<32>(7);
    const auto responder_exporter = Bytes<32>(47);
    P2PRelayOfferBundle bundle;

    BOOST_REQUIRE(BuildP2PRelayOfferBundle(
        input, initiator_exporter, responder_exporter, secrets, bundle));
    BOOST_TEST(bundle.initiator_envelope.recipient_peer_id == input.initiator_peer_id);
    BOOST_TEST(bundle.responder_envelope.recipient_peer_id == input.responder_peer_id);
    BOOST_TEST(bundle.initiator_envelope.ciphertext != bundle.responder_envelope.ciphertext);

    P2POfferHash offer_hash{};
    BOOST_REQUIRE(HashP2PRelayOffer(bundle.offer, offer_hash));
    P2PWrapKey initiator_key{};
    P2PWrapKey responder_key{};
    BOOST_REQUIRE(DeriveP2PWrapKey(
        initiator_exporter, offer_hash, P2PPeerRole::Initiator, initiator_key));
    BOOST_REQUIRE(DeriveP2PWrapKey(
        responder_exporter, offer_hash, P2PPeerRole::Responder, responder_key));

    P2PPairSeed initiator_seed{};
    P2PPairSeed responder_seed{};
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        initiator_key, offer_hash, input.initiator_peer_id,
        P2PPeerRole::Initiator, bundle.initiator_envelope, initiator_seed));
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        responder_key, offer_hash, input.responder_peer_id,
        P2PPeerRole::Responder, bundle.responder_envelope, responder_seed));
    BOOST_TEST(initiator_seed == secrets.pair_seed);
    BOOST_TEST(responder_seed == secrets.pair_seed);

    P2PPairSeed unchanged = Bytes<32>(3);
    const auto baseline = unchanged;
    BOOST_TEST(!UnwrapP2PPairSeed(
        initiator_key, offer_hash, input.responder_peer_id,
        P2PPeerRole::Responder, bundle.responder_envelope, unchanged));
    BOOST_TEST(unchanged == baseline);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_input_without_modifying_output) {
    auto input = Input();
    const auto secrets = Secrets();
    auto initiator_exporter = Bytes<32>(7);
    const auto responder_exporter = Bytes<32>(47);
    P2PRelayOfferBundle output;
    output.offer.offer_id = Bytes<16>(233);
    const auto baseline = output.offer.offer_id;

    initiator_exporter.fill(0);
    BOOST_TEST(!BuildP2PRelayOfferBundle(
        input, initiator_exporter, responder_exporter, secrets, output));
    BOOST_TEST(output.offer.offer_id == baseline);

    initiator_exporter = Bytes<32>(7);
    input.responder_peer_id = input.initiator_peer_id;
    BOOST_TEST(!BuildP2PRelayOfferBundle(
        input, initiator_exporter, responder_exporter, secrets, output));
    BOOST_TEST(output.offer.offer_id == baseline);
}

BOOST_AUTO_TEST_CASE(creates_fresh_session_bound_bundles) {
    const auto input = Input();
    const auto initiator_exporter = Bytes<32>(7);
    const auto responder_exporter = Bytes<32>(47);
    P2PRelayOfferBundle first;
    P2PRelayOfferBundle second;
    P2PExporterContext initiator_context{};
    P2PExporterContext responder_context{};
    int initiator_calls = 0;
    int responder_calls = 0;

    const auto export_initiator = [&](const char* label,
                                      const std::uint8_t* context,
                                      std::size_t context_length,
                                      std::uint8_t* output,
                                      std::size_t output_length) {
        BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
        BOOST_REQUIRE_EQUAL(context_length, initiator_context.size());
        BOOST_REQUIRE_EQUAL(output_length, initiator_exporter.size());
        std::memcpy(initiator_context.data(), context, context_length);
        std::memcpy(output, initiator_exporter.data(), output_length);
        ++initiator_calls;
        return true;
    };
    const auto export_responder = [&](const char* label,
                                      const std::uint8_t* context,
                                      std::size_t context_length,
                                      std::uint8_t* output,
                                      std::size_t output_length) {
        BOOST_TEST(std::string(label) == P2PWrapExporterLabel);
        BOOST_REQUIRE_EQUAL(context_length, responder_context.size());
        BOOST_REQUIRE_EQUAL(output_length, responder_exporter.size());
        std::memcpy(responder_context.data(), context, context_length);
        std::memcpy(output, responder_exporter.data(), output_length);
        ++responder_calls;
        return true;
    };

    BOOST_REQUIRE(CreateP2PRelayOfferBundle(
        input, export_initiator, export_responder, first));
    BOOST_REQUIRE(CreateP2PRelayOfferBundle(
        input, export_initiator, export_responder, second));
    BOOST_TEST(initiator_calls == 2);
    BOOST_TEST(responder_calls == 2);
    BOOST_TEST(first.offer.offer_id != second.offer.offer_id);
    BOOST_TEST(first.offer.connection_epoch != second.offer.connection_epoch);
    BOOST_TEST(first.initiator_envelope.wrap_nonce !=
        second.initiator_envelope.wrap_nonce);

    P2POfferHash offer_hash{};
    BOOST_REQUIRE(HashP2PRelayOffer(first.offer, offer_hash));
    P2PWrapKey initiator_key{};
    P2PWrapKey responder_key{};
    BOOST_REQUIRE(DeriveP2PWrapKey(
        initiator_exporter, offer_hash, P2PPeerRole::Initiator, initiator_key));
    BOOST_REQUIRE(DeriveP2PWrapKey(
        responder_exporter, offer_hash, P2PPeerRole::Responder, responder_key));
    P2PPairSeed initiator_seed{};
    P2PPairSeed responder_seed{};
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        initiator_key, offer_hash, input.initiator_peer_id,
        P2PPeerRole::Initiator, first.initiator_envelope, initiator_seed));
    BOOST_REQUIRE(UnwrapP2PPairSeed(
        responder_key, offer_hash, input.responder_peer_id,
        P2PPeerRole::Responder, first.responder_envelope, responder_seed));
    BOOST_TEST(initiator_seed == responder_seed);
    BOOST_TEST(std::any_of(
        initiator_seed.begin(), initiator_seed.end(),
        [](std::uint8_t value) { return value != 0; }));

    P2PExporterContext expected_initiator_context{};
    P2PExporterContext expected_responder_context{};
    BOOST_REQUIRE(BuildP2PExporterContext(
        second.offer, P2PPeerRole::Initiator, expected_initiator_context));
    BOOST_REQUIRE(BuildP2PExporterContext(
        second.offer, P2PPeerRole::Responder, expected_responder_context));
    BOOST_TEST(initiator_context == expected_initiator_context);
    BOOST_TEST(responder_context == expected_responder_context);
}

BOOST_AUTO_TEST_CASE(exporter_failure_is_fail_closed) {
    const auto input = Input();
    P2PRelayOfferBundle output;
    output.offer.offer_id = Bytes<16>(233);
    const auto baseline = output.offer.offer_id;
    int responder_calls = 0;

    const P2PSessionExporter throwing_exporter =
        [](const char*, const std::uint8_t*, std::size_t,
           std::uint8_t*, std::size_t) -> bool {
        throw 1;
    };
    const P2PSessionExporter responder_exporter =
        [&](const char*, const std::uint8_t*, std::size_t,
            std::uint8_t*, std::size_t) {
        ++responder_calls;
        return true;
    };

    BOOST_TEST(!CreateP2PRelayOfferBundle(
        input, throwing_exporter, responder_exporter, output));
    BOOST_TEST(responder_calls == 0);
    BOOST_TEST(output.offer.offer_id == baseline);
}
