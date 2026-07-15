#include <ppp/p2p/P2PRelayOffer.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <algorithm>
#include <cstring>

namespace ppp::p2p {
namespace {

template <std::size_t N>
bool IsZero(const std::array<std::uint8_t, N>& value) noexcept {
    std::uint8_t combined = 0;
    for (std::uint8_t byte : value) {
        combined |= byte;
    }
    return combined == 0;
}

bool ValidOffer(const P2PRelayOfferV1& offer) noexcept {
    return offer.version == 1 &&
        offer.ttl_seconds >= 1 && offer.ttl_seconds <= 30 &&
        offer.cipher == 1 &&
        !IsZero(offer.offer_id) &&
        !IsZero(offer.initiator_session_id) &&
        !IsZero(offer.responder_session_id) &&
        !IsZero(offer.initiator_peer_id) &&
        !IsZero(offer.responder_peer_id) &&
        !IsZero(offer.connection_epoch) &&
        offer.initiator_session_id != offer.responder_session_id &&
        offer.initiator_peer_id != offer.responder_peer_id;
}

bool ValidRole(P2PPeerRole role) noexcept {
    return role == P2PPeerRole::Initiator ||
        role == P2PPeerRole::Responder;
}

template <std::size_t N>
void Append(std::uint8_t*& cursor, const std::array<std::uint8_t, N>& value) noexcept {
    std::memcpy(cursor, value.data(), value.size());
    cursor += value.size();
}

std::array<std::uint8_t, 48> BuildWrapAad(
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id) noexcept {
    std::array<std::uint8_t, 48> aad{};
    std::memcpy(aad.data(), offer_hash.data(), offer_hash.size());
    std::memcpy(aad.data() + offer_hash.size(),
        recipient_peer_id.data(), recipient_peer_id.size());
    return aad;
}

bool CryptPairSeed(
    bool encrypt,
    const P2PWrapKey& wrap_key,
    const P2PWrapNonce& nonce,
    const std::array<std::uint8_t, 48>& aad,
    const P2PPairSeed& input,
    const P2PWrapTag* input_tag,
    P2PPairSeed& output,
    P2PWrapTag* output_tag) noexcept {
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (!context) {
        return false;
    }

    P2PPairSeed temporary{};
    int length = 0;
    int total = 0;
    bool ok = EVP_CipherInit_ex(
            context, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr,
            encrypt ? 1 : 0) == 1 &&
        EVP_CIPHER_CTX_ctrl(
            context, EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(nonce.size()), nullptr) == 1 &&
        EVP_CipherInit_ex(
            context, nullptr, nullptr, wrap_key.data(), nonce.data(),
            encrypt ? 1 : 0) == 1 &&
        EVP_CipherUpdate(
            context, nullptr, &length, aad.data(),
            static_cast<int>(aad.size())) == 1;

    if (ok && !encrypt) {
        ok = input_tag != nullptr &&
            EVP_CIPHER_CTX_ctrl(
                context, EVP_CTRL_AEAD_SET_TAG,
                static_cast<int>(input_tag->size()),
                const_cast<std::uint8_t*>(input_tag->data())) == 1;
    }
    if (ok) {
        ok = EVP_CipherUpdate(
            context, temporary.data(), &length, input.data(),
            static_cast<int>(input.size())) == 1;
        total = length;
    }
    if (ok) {
        ok = EVP_CipherFinal_ex(context, temporary.data() + total, &length) == 1;
        total += length;
    }

    P2PWrapTag tag{};
    if (ok && encrypt) {
        ok = output_tag != nullptr &&
            EVP_CIPHER_CTX_ctrl(
                context, EVP_CTRL_AEAD_GET_TAG,
                static_cast<int>(tag.size()), tag.data()) == 1;
    }
    ok = ok && total == static_cast<int>(temporary.size());
    EVP_CIPHER_CTX_free(context);

    if (ok) {
        output = temporary;
        if (encrypt) {
            *output_tag = tag;
        }
    }
    OPENSSL_cleanse(temporary.data(), temporary.size());
    OPENSSL_cleanse(tag.data(), tag.size());
    return ok;
}

}

bool SerializeP2PRelayOffer(
    const P2PRelayOfferV1& offer,
    P2PRelayOfferBytes& output) noexcept {
    if (!ValidOffer(offer)) {
        return false;
    }

    P2PRelayOfferBytes serialized{};
    std::uint8_t* cursor = serialized.data();
    *cursor++ = offer.version;
    Append(cursor, offer.offer_id);
    Append(cursor, offer.initiator_session_id);
    Append(cursor, offer.responder_session_id);
    Append(cursor, offer.initiator_peer_id);
    Append(cursor, offer.responder_peer_id);
    Append(cursor, offer.connection_epoch);
    *cursor++ = offer.ttl_seconds;
    *cursor++ = offer.cipher;
    Append(cursor, offer.candidate_set_hash);
    if (cursor != serialized.data() + serialized.size()) {
        return false;
    }
    output = serialized;
    return true;
}

bool HashP2PRelayOffer(
    const P2PRelayOfferV1& offer,
    P2POfferHash& output) noexcept {
    P2PRelayOfferBytes serialized{};
    if (!SerializeP2PRelayOffer(offer, serialized)) {
        return false;
    }

    P2POfferHash digest{};
    unsigned int digest_size = 0;
    const bool ok = EVP_Digest(
        serialized.data(), serialized.size(),
        digest.data(), &digest_size, EVP_sha256(), nullptr) == 1 &&
        digest_size == digest.size();
    if (ok) {
        output = digest;
    }
    OPENSSL_cleanse(digest.data(), digest.size());
    return ok;
}

bool BuildP2PExporterContext(
    const P2PRelayOfferV1& offer,
    P2PPeerRole recipient_role,
    P2PExporterContext& output) noexcept {
    if (!ValidOffer(offer) || !ValidRole(recipient_role)) {
        return false;
    }

    P2PExporterContext context{};
    std::uint8_t* cursor = context.data();
    Append(cursor, recipient_role == P2PPeerRole::Initiator
        ? offer.initiator_session_id
        : offer.responder_session_id);
    Append(cursor, offer.initiator_peer_id);
    Append(cursor, offer.responder_peer_id);
    Append(cursor, offer.initiator_session_id);
    Append(cursor, offer.responder_session_id);
    Append(cursor, offer.connection_epoch);
    Append(cursor, offer.offer_id);
    *cursor++ = offer.version;
    if (cursor != context.data() + context.size()) {
        return false;
    }
    output = context;
    return true;
}

bool DeriveP2PWrapKey(
    const P2PExporterKey& exporter_key,
    const P2POfferHash& offer_hash,
    P2PPeerRole recipient_role,
    P2PWrapKey& output) noexcept {
    if (IsZero(exporter_key) || IsZero(offer_hash) ||
        !ValidRole(recipient_role)) {
        return false;
    }

    static constexpr char info[] = "openppp2 p2p v1 wrap key";
    // OpenSSL 3.0.13 replaces provider HKDF info on repeated add calls.
    std::array<std::uint8_t, sizeof(info)> info_with_role{};
    std::memcpy(info_with_role.data(), info, sizeof(info) - 1);
    info_with_role.back() = static_cast<std::uint8_t>(recipient_role);
    P2PWrapKey derived{};
    std::size_t derived_size = derived.size();
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!context) {
        return false;
    }

    const bool ok = EVP_PKEY_derive_init(context) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(
            context, offer_hash.data(), offer_hash.size()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(
            context, exporter_key.data(), exporter_key.size()) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            context, info_with_role.data(), info_with_role.size()) > 0 &&
        EVP_PKEY_derive(context, derived.data(), &derived_size) > 0 &&
        derived_size == derived.size();
    EVP_PKEY_CTX_free(context);
    if (ok) {
        output = derived;
    }
    OPENSSL_cleanse(derived.data(), derived.size());
    return ok;
}

bool WrapP2PPairSeed(
    const P2PWrapKey& wrap_key,
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id,
    P2PPeerRole recipient_role,
    const P2PWrapNonce& nonce,
    const P2PPairSeed& pair_seed,
    P2PWrappedPairSeed& output) noexcept {
    if (IsZero(wrap_key) || IsZero(offer_hash) || IsZero(recipient_peer_id) ||
        IsZero(nonce) || IsZero(pair_seed) || !ValidRole(recipient_role)) {
        return false;
    }

    P2PWrappedPairSeed envelope;
    envelope.recipient_peer_id = recipient_peer_id;
    envelope.recipient_role = recipient_role;
    envelope.wrap_nonce = nonce;
    const auto aad = BuildWrapAad(offer_hash, recipient_peer_id);
    if (!CryptPairSeed(
            true, wrap_key, nonce, aad, pair_seed, nullptr,
            envelope.ciphertext, &envelope.auth_tag)) {
        return false;
    }
    output = envelope;
    return true;
}

bool UnwrapP2PPairSeed(
    const P2PWrapKey& wrap_key,
    const P2POfferHash& offer_hash,
    const P2PId& recipient_peer_id,
    P2PPeerRole recipient_role,
    const P2PWrappedPairSeed& envelope,
    P2PPairSeed& output) noexcept {
    if (IsZero(wrap_key) || IsZero(offer_hash) || IsZero(recipient_peer_id) ||
        !ValidRole(recipient_role) ||
        envelope.recipient_peer_id != recipient_peer_id ||
        envelope.recipient_role != recipient_role ||
        IsZero(envelope.wrap_nonce)) {
        return false;
    }

    P2PPairSeed pair_seed{};
    const auto aad = BuildWrapAad(offer_hash, recipient_peer_id);
    const bool ok = CryptPairSeed(
        false, wrap_key, envelope.wrap_nonce, aad, envelope.ciphertext,
        &envelope.auth_tag, pair_seed, nullptr);
    if (ok) {
        output = pair_seed;
    }
    OPENSSL_cleanse(pair_seed.data(), pair_seed.size());
    return ok;
}

}
