#define BOOST_TEST_MODULE p2p_offer_token_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2POfferToken.h>
#include <ppp/p2p/P2PKeyDerivation.h>

#include <array>

using namespace ppp::p2p;

namespace {
template <std::size_t N>
std::array<std::uint8_t, N> Bytes(std::uint8_t seed) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) value[i] = seed + i;
    return value;
}

P2PCandidateEndpoint Endpoint(std::uint8_t seed, std::uint16_t port) {
    P2PCandidateEndpoint endpoint;
    endpoint.address_family = 6;
    endpoint.address = Bytes<16>(seed);
    endpoint.port = port;
    return endpoint;
}

P2POfferBinding Binding() {
    P2POfferBinding binding;
    binding.version = 1;
    binding.offer_id = Bytes<16>(1);
    binding.initiator_session_id = Bytes<16>(20);
    binding.responder_session_id = Bytes<16>(40);
    binding.initiator_peer_id = Bytes<16>(60);
    binding.responder_peer_id = Bytes<16>(80);
    binding.connection_epoch = Bytes<16>(100);
    binding.message_type = P2PControlType::Probe;
    binding.offer_hash = Bytes<32>(180);
    binding.sender_role = 0;
    binding.receiver_role = 1;
    binding.direction = 0;
    binding.sequence = 7;
    binding.nonce = BuildP2PV1Nonce(Bytes<8>(200), binding.sequence);
    binding.source = Endpoint(120, 4000);
    binding.destination = Endpoint(140, 5000);
    binding.ttl_seconds = 30;
    return binding;
}

bool ValidateOnce(const std::array<std::uint8_t, 32>& key,
                  const P2POfferBinding& received,
                  const P2POfferBinding& current,
                  const P2PCandidateEndpoint& source,
                  const P2PCandidateEndpoint& destination,
                  std::uint64_t elapsed,
                  const P2POfferToken& token) {
    P2PReplayWindow replay;
    return ValidateP2POfferToken(key, received, current, source, destination,
        elapsed, token, Bytes<8>(200), replay);
}
}

BOOST_AUTO_TEST_CASE(accepts_only_an_unexpired_fully_bound_token) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    BOOST_TEST(ValidateOnce(key, binding, binding,
        binding.source, binding.destination, 29'999, token));
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        binding.source, binding.destination, 30'000, token));
}

BOOST_AUTO_TEST_CASE(rejects_ttl_outside_one_through_thirty) {
    const auto key = Bytes<32>(9);
    auto binding = Binding();
    P2POfferToken token{};
    binding.ttl_seconds = 0;
    BOOST_TEST(!CreateP2POfferToken(key, binding, token));
    binding.ttl_seconds = 31;
    BOOST_TEST(!CreateP2POfferToken(key, binding, token));
}

BOOST_AUTO_TEST_CASE(token_api_rejects_noncanonical_ipv4_candidates) {
    const auto key = Bytes<32>(9);
    auto binding = Binding();
    binding.source.address_family = 4;
    binding.source.address = {};
    binding.source.address[12] = 192;
    binding.source.address[13] = 0;
    binding.source.address[14] = 2;
    binding.source.address[15] = 1;
    P2POfferToken token{};
    BOOST_TEST(!CreateP2POfferToken(key, binding, token));

    binding.source.address[10] = 0xff;
    binding.source.address[11] = 0xff;
    BOOST_TEST(CreateP2POfferToken(key, binding, token));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_peer_both_sessions_direction_and_candidate) {
    const auto key = Bytes<32>(9);
    const auto received = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, received, token));

    auto expected = received;
    expected.initiator_peer_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.initiator_session_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.responder_session_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.direction = 1;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
    expected = received;
    expected.destination.port++;
    BOOST_TEST(!ValidateOnce(key, received, expected,
        received.source, received.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(rejects_old_epoch_after_restart_and_wrong_offer) {
    const auto key = Bytes<32>(9);
    const auto received = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, received, token));
    auto current = received;
    current.connection_epoch[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, current,
        received.source, received.destination, 0, token));
    current = received;
    current.offer_id[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, received, current,
        received.source, received.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(rejects_spoofed_observed_endpoints) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    auto spoofed = binding.source;
    spoofed.port++;
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        spoofed, binding.destination, 0, token));
    spoofed = binding.destination;
    spoofed.address[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        binding.source, spoofed, 0, token));
}

BOOST_AUTO_TEST_CASE(rejects_tampered_token) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    token[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, binding, binding,
        binding.source, binding.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(control_hmac_covers_every_dynamic_control_field) {
    const auto key = Bytes<32>(9);
    const auto original = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, original, token));

    auto changed = original;
    changed.message_type = P2PControlType::ProbeAck;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    changed.offer_hash[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    std::swap(changed.sender_role, changed.receiver_role);
    changed.direction = changed.sender_role;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    changed.sequence++;
    changed.nonce = BuildP2PV1Nonce(Bytes<8>(200), changed.sequence);
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
    changed = original;
    changed.nonce[0] ^= 1;
    BOOST_TEST(!ValidateOnce(key, changed, changed, changed.source, changed.destination, 0, token));
}

BOOST_AUTO_TEST_CASE(control_hmac_uses_the_exact_protocol_transcript) {
    const auto key = Bytes<32>(9);
    const auto original = Binding();
    auto same_transcript = original;
    same_transcript.offer_id[0] ^= 1;
    same_transcript.initiator_session_id[0] ^= 1;
    same_transcript.responder_session_id[0] ^= 1;
    same_transcript.initiator_peer_id[0] ^= 1;
    same_transcript.responder_peer_id[0] ^= 1;

    P2POfferToken original_token{};
    P2POfferToken same_transcript_token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, original, original_token));
    BOOST_REQUIRE(CreateP2POfferToken(key, same_transcript, same_transcript_token));
    BOOST_TEST(original_token == same_transcript_token);
}

BOOST_AUTO_TEST_CASE(validates_nonce_and_hmac_before_consuming_replay_window) {
    const auto key = Bytes<32>(9);
    const auto binding = Binding();
    P2POfferToken token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, binding, token));
    P2PReplayWindow replay;
    auto tampered = token;
    tampered[0] ^= 1;
    BOOST_TEST(!ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, tampered, Bytes<8>(200), replay));
    BOOST_TEST(ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(200), replay));
    BOOST_TEST(!ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(200), replay));

    P2PReplayWindow nonce_replay;
    BOOST_TEST(!ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(201), nonce_replay));
    BOOST_TEST(ValidateP2POfferToken(key, binding, binding,
        binding.source, binding.destination, 0, token, Bytes<8>(200), nonce_replay));
}

BOOST_AUTO_TEST_CASE(stale_authenticated_sequence_is_rejected_by_validator) {
    const auto key = Bytes<32>(9);
    auto newest = Binding();
    newest.sequence = 2000;
    newest.nonce = BuildP2PV1Nonce(Bytes<8>(200), newest.sequence);
    P2POfferToken newest_token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, newest, newest_token));

    P2PReplayWindow replay;
    BOOST_REQUIRE(ValidateP2POfferToken(key, newest, newest,
        newest.source, newest.destination, 0, newest_token, Bytes<8>(200), replay));

    auto stale = newest;
    stale.sequence = newest.sequence - REPLAY_WINDOW_SIZE;
    stale.nonce = BuildP2PV1Nonce(Bytes<8>(200), stale.sequence);
    P2POfferToken stale_token{};
    BOOST_REQUIRE(CreateP2POfferToken(key, stale, stale_token));
    BOOST_TEST(!ValidateP2POfferToken(key, stale, stale,
        stale.source, stale.destination, 0, stale_token, Bytes<8>(200), replay));
}
