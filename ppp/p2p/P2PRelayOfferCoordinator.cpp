#include <ppp/p2p/P2PRelayOfferCoordinator.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

namespace ppp::p2p {
namespace {

template <std::size_t N>
bool Random(std::array<std::uint8_t, N>& output) noexcept {
    return RAND_bytes(output.data(), static_cast<int>(output.size())) == 1;
}

void Cleanse(P2PRelayOfferSecrets& secrets) noexcept {
    OPENSSL_cleanse(secrets.offer_id.data(), secrets.offer_id.size());
    OPENSSL_cleanse(
        secrets.connection_epoch.data(), secrets.connection_epoch.size());
    OPENSSL_cleanse(secrets.pair_seed.data(), secrets.pair_seed.size());
    OPENSSL_cleanse(
        secrets.initiator_wrap_nonce.data(),
        secrets.initiator_wrap_nonce.size());
    OPENSSL_cleanse(
        secrets.responder_wrap_nonce.data(),
        secrets.responder_wrap_nonce.size());
}

P2PRelayOfferV1 MakeOffer(
    const P2PRelayOfferInput& input,
    const P2PRelayOfferSecrets& secrets) noexcept {
    P2PRelayOfferV1 offer;
    offer.offer_id = secrets.offer_id;
    offer.initiator_session_id = input.initiator_session_id;
    offer.responder_session_id = input.responder_session_id;
    offer.initiator_peer_id = input.initiator_peer_id;
    offer.responder_peer_id = input.responder_peer_id;
    offer.connection_epoch = secrets.connection_epoch;
    offer.ttl_seconds = input.ttl_seconds;
    offer.candidate_set_hash = input.candidate_set_hash;
    return offer;
}

bool Export(
    const P2PSessionExporter& exporter,
    const P2PExporterContext& context,
    P2PExporterKey& output) noexcept {
    if (!exporter) {
        return false;
    }
    try {
        return exporter(
            P2PWrapExporterLabel,
            context.data(), context.size(),
            output.data(), output.size());
    }
    catch (...) {
        return false;
    }
}

}

bool BuildP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PExporterKey& initiator_exporter,
    const P2PExporterKey& responder_exporter,
    const P2PRelayOfferSecrets& secrets,
    P2PRelayOfferBundle& output) noexcept {
    P2PRelayOfferBundle bundle;
    bundle.offer = MakeOffer(input, secrets);

    P2POfferHash offer_hash{};
    P2PWrapKey initiator_key{};
    P2PWrapKey responder_key{};
    const bool ok = HashP2PRelayOffer(bundle.offer, offer_hash) &&
        DeriveP2PWrapKey(
            initiator_exporter, offer_hash,
            P2PPeerRole::Initiator, initiator_key) &&
        DeriveP2PWrapKey(
            responder_exporter, offer_hash,
            P2PPeerRole::Responder, responder_key) &&
        WrapP2PPairSeed(
            initiator_key, offer_hash, input.initiator_peer_id,
            P2PPeerRole::Initiator, secrets.initiator_wrap_nonce,
            secrets.pair_seed, bundle.initiator_envelope) &&
        WrapP2PPairSeed(
            responder_key, offer_hash, input.responder_peer_id,
            P2PPeerRole::Responder, secrets.responder_wrap_nonce,
            secrets.pair_seed, bundle.responder_envelope);

    OPENSSL_cleanse(initiator_key.data(), initiator_key.size());
    OPENSSL_cleanse(responder_key.data(), responder_key.size());
    if (!ok) {
        return false;
    }
    output = bundle;
    return true;
}

bool CreateP2PRelayOfferBundle(
    const P2PRelayOfferInput& input,
    const P2PSessionExporter& initiator_exporter,
    const P2PSessionExporter& responder_exporter,
    P2PRelayOfferBundle& output) noexcept {
    P2PRelayOfferSecrets secrets;
    P2PExporterContext initiator_context{};
    P2PExporterContext responder_context{};
    P2PExporterKey initiator_key{};
    P2PExporterKey responder_key{};
    const bool random_ready = Random(secrets.offer_id) &&
        Random(secrets.connection_epoch) &&
        Random(secrets.pair_seed) &&
        Random(secrets.initiator_wrap_nonce) &&
        Random(secrets.responder_wrap_nonce);
    const auto offer = MakeOffer(input, secrets);
    const bool ok = random_ready &&
        BuildP2PExporterContext(
            offer, P2PPeerRole::Initiator, initiator_context) &&
        BuildP2PExporterContext(
            offer, P2PPeerRole::Responder, responder_context) &&
        Export(initiator_exporter, initiator_context, initiator_key) &&
        Export(responder_exporter, responder_context, responder_key) &&
        BuildP2PRelayOfferBundle(
            input, initiator_key, responder_key, secrets, output);
    OPENSSL_cleanse(initiator_key.data(), initiator_key.size());
    OPENSSL_cleanse(responder_key.data(), responder_key.size());
    Cleanse(secrets);
    return ok;
}

}
