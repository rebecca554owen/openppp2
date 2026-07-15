#include <ppp/p2p/P2POfferToken.h>
#include <ppp/p2p/P2PCrypto.h>
#include <ppp/p2p/P2PKeyDerivation.h>

#include <array>

namespace ppp::p2p {
namespace {
constexpr std::size_t CanonicalSize = 107;

bool ValidEndpoint(const P2PCandidateEndpoint& endpoint) noexcept {
    return IsCanonicalP2PCandidate(endpoint);
}

bool ValidBinding(const P2POfferBinding& binding) noexcept {
    const auto type = static_cast<std::uint8_t>(binding.message_type);
    return binding.version == 1 &&
        type >= static_cast<std::uint8_t>(P2PControlType::Probe) &&
        type <= static_cast<std::uint8_t>(P2PControlType::MigrateAck) &&
        binding.sender_role <= 1 && binding.receiver_role <= 1 &&
        binding.sender_role != binding.receiver_role &&
        binding.direction == binding.sender_role &&
        binding.ttl_seconds >= 1 && binding.ttl_seconds <= 30 &&
        binding.initiator_peer_id != binding.responder_peer_id &&
        binding.initiator_session_id != binding.responder_session_id &&
        ValidEndpoint(binding.source) && ValidEndpoint(binding.destination);
}

bool SameStaticContext(const P2POfferBinding& a,
                       const P2POfferBinding& b) noexcept {
    return a.version == b.version && a.offer_id == b.offer_id &&
        a.offer_hash == b.offer_hash &&
        a.initiator_session_id == b.initiator_session_id &&
        a.responder_session_id == b.responder_session_id &&
        a.initiator_peer_id == b.initiator_peer_id &&
        a.responder_peer_id == b.responder_peer_id &&
        a.connection_epoch == b.connection_epoch &&
        a.sender_role == b.sender_role && a.receiver_role == b.receiver_role &&
        a.direction == b.direction && a.source == b.source &&
        a.destination == b.destination && a.ttl_seconds == b.ttl_seconds;
}

void AppendEndpoint(std::array<std::uint8_t, CanonicalSize>& bytes,
                    std::size_t& offset,
                    const P2PCandidateEndpoint& endpoint) noexcept {
    bytes[offset++] = endpoint.address_family;
    for (const auto byte : endpoint.address) bytes[offset++] = byte;
    bytes[offset++] = static_cast<std::uint8_t>(endpoint.port >> 8);
    bytes[offset++] = static_cast<std::uint8_t>(endpoint.port);
}

std::array<std::uint8_t, CanonicalSize> Canonicalize(
    const P2POfferBinding& binding) noexcept {
    std::array<std::uint8_t, CanonicalSize> bytes{};
    std::size_t offset = 0;
    bytes[offset++] = static_cast<std::uint8_t>(binding.message_type);
    const auto append = [&bytes, &offset](const auto& field) {
        for (const auto byte : field) bytes[offset++] = byte;
    };
    append(binding.offer_hash);
    bytes[offset++] = binding.sender_role;
    bytes[offset++] = binding.receiver_role;
    bytes[offset++] = binding.direction;
    append(binding.connection_epoch);
    AppendEndpoint(bytes, offset, binding.source);
    AppendEndpoint(bytes, offset, binding.destination);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence >> 24);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence >> 16);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence >> 8);
    bytes[offset++] = static_cast<std::uint8_t>(binding.sequence);
    append(binding.nonce);
    bytes[offset] = binding.ttl_seconds;
    return bytes;
}
}

bool CreateP2POfferToken(const std::array<std::uint8_t, 32>& token_key,
                         const P2POfferBinding& binding,
                         P2POfferToken& token) noexcept {
    if (!ValidBinding(binding)) return false;
    const auto canonical = Canonicalize(binding);
    return TokenGenerate(token_key.data(), canonical.data(), canonical.size(), token.data());
}

bool ValidateP2POfferToken(const std::array<std::uint8_t, 32>& token_key,
                           const P2POfferBinding& received,
                           const P2POfferBinding& current,
                           const P2PCandidateEndpoint& observed_source,
                           const P2PCandidateEndpoint& observed_destination,
                           std::uint64_t elapsed_milliseconds,
                           const P2POfferToken& token,
                           const std::array<std::uint8_t, 8>& expected_nonce_prefix,
                           P2PReplayWindow& replay_window) noexcept {
    if (!ValidBinding(received) || !ValidBinding(current) ||
        !SameStaticContext(received, current) ||
        !(received.source == observed_source) ||
        !(received.destination == observed_destination) ||
        elapsed_milliseconds >= static_cast<std::uint64_t>(received.ttl_seconds) * 1000) {
        return false;
    }
    if (received.nonce != BuildP2PV1Nonce(expected_nonce_prefix, received.sequence)) {
        return false;
    }
    const auto canonical = Canonicalize(received);
    if (!TokenVerify(token_key.data(), canonical.data(), canonical.size(), token.data())) {
        return false;
    }
    return replay_window.Accept(received.sequence);
}

}
