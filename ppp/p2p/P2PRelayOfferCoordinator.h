#pragma once

#include <ppp/p2p/P2PRelayOffer.h>

#include <cstddef>
#include <functional>

namespace ppp::p2p {

struct P2PRelayOfferInput {
    P2PId initiator_session_id{};
    P2PId responder_session_id{};
    P2PId initiator_peer_id{};
    P2PId responder_peer_id{};
    std::uint8_t ttl_seconds = 0;
    P2POfferHash candidate_set_hash{};
};

struct P2PRelayOfferSecrets {
    P2PId offer_id{};
    P2PId connection_epoch{};
    P2PPairSeed pair_seed{};
    P2PWrapNonce initiator_wrap_nonce{};
    P2PWrapNonce responder_wrap_nonce{};
};

struct P2PRelayOfferBundle {
    P2PRelayOfferV1 offer;
    P2PWrappedPairSeed initiator_envelope;
    P2PWrappedPairSeed responder_envelope;
};

using P2PSessionExporter = std::function<bool(
    const char* label,
    const std::uint8_t* context,
    std::size_t context_length,
    std::uint8_t* output,
    std::size_t output_length)>;

bool BuildP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PExporterKey& initiator_exporter,
    const P2PExporterKey& responder_exporter,
    const P2PRelayOfferSecrets& secrets,
    P2PRelayOfferBundle& output) noexcept;

bool CreateP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PSessionExporter& initiator_exporter,
    const P2PSessionExporter& responder_exporter,
    P2PRelayOfferBundle& output) noexcept;

}
