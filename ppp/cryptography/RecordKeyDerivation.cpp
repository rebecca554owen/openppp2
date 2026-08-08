/**
 * @file RecordKeyDerivation.cpp
 * @brief v2.2.0 record key derivation (HKDF-SHA256 with domain separation).
 */

#include <ppp/cryptography/RecordKeyDerivation.h>

#include <array>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <ppp/diagnostics/Error.h>

namespace ppp {
namespace cryptography {

namespace {

bool DeriveOne(const RecordKeyContext& context,
               const char* label,
               std::uint8_t* output,
               std::size_t output_size) noexcept {
    if (NULLPTR == context.exporter_secret || NULLPTR == output) {
        return false;
    }

    // Salt: handshake hash (optional; HKDF accepts empty salt).  The Noise
    // exporter already binds the full handshake transcript, so the salt may be
    // left empty here.
    // IKM:  exporter secret (v2.2.2: Noise record-protector root, PFS).
    // Info: domain-separated label + session binding context so identical
    //       exporter material never derives the same keys twice.
    EVP_PKEY_CTX* hkdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULLPTR);
    if (NULLPTR == hkdf) {
        return false;
    }

    std::size_t derived_size = output_size;
    const std::uint8_t* session_id = context.session_id;
    std::size_t session_id_len = context.session_id_len;
    std::uint8_t zero_session[16]{};
    if (session_id == NULLPTR || session_id_len == 0) {
        // Fixed 16-byte slot keeps the info encoding length-stable.
        session_id = zero_session;
        session_id_len = sizeof(zero_session);
    }
    const std::uint32_t key_id = context.transport_auth_key_id;
    const std::uint8_t key_id_be[4] = {
        static_cast<std::uint8_t>((key_id >> 24) & 0xFF),
        static_cast<std::uint8_t>((key_id >> 16) & 0xFF),
        static_cast<std::uint8_t>((key_id >> 8) & 0xFF),
        static_cast<std::uint8_t>(key_id & 0xFF),
    };

    // Build the HKDF info as ONE contiguous buffer and add it with a single
    // EVP_PKEY_CTX_add1_hkdf_info call.  Multiple add1 calls rely on the
    // OpenSSL implementation appending subsequent chunks; on OpenSSL 3.0.x
    // only the last chunk is retained, which would drop the direction label
    // and produce identical keys for both record directions.
    std::array<std::uint8_t, 160> info{};
    std::size_t info_len = 0;
    const std::size_t label_len = std::strlen(label);
    if (info.size() - info_len < label_len + session_id_len + 1 + sizeof(key_id_be)) {
        EVP_PKEY_CTX_free(hkdf);
        return false;
    }
    std::memcpy(info.data() + info_len, label, label_len);
    info_len += label_len;
    std::memcpy(info.data() + info_len, session_id, session_id_len);
    info_len += session_id_len;
    info[info_len++] = context.carrier_kind;
    std::memcpy(info.data() + info_len, key_id_be, sizeof(key_id_be));
    info_len += sizeof(key_id_be);

    const bool ok =
        EVP_PKEY_derive_init(hkdf) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(hkdf, EVP_sha256()) > 0 &&
        (context.handshake_hash_len == 0 ||
         EVP_PKEY_CTX_set1_hkdf_salt(hkdf, context.handshake_hash,
                                     static_cast<int>(context.handshake_hash_len)) > 0) &&
        EVP_PKEY_CTX_set1_hkdf_key(hkdf, context.exporter_secret,
                                   static_cast<int>(context.exporter_secret_len)) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(hkdf, info.data(),
                                    static_cast<int>(info_len)) > 0 &&
        EVP_PKEY_derive(hkdf, output, &derived_size) > 0 &&
        derived_size == output_size;
    EVP_PKEY_CTX_free(hkdf);
    OPENSSL_cleanse(info.data(), info.size());
    OPENSSL_cleanse(zero_session, sizeof(zero_session));
    return ok;
}

} // namespace

bool DeriveRecordKeyMaterial(const RecordKeyContext& context,
                             RecordKeyMaterial& output) noexcept {
    RecordKeyMaterial derived;
    if (!DeriveOne(context, "openppp2/v2.2/record/client-to-server/key",
                   derived.client_to_server_key.data(),
                   derived.client_to_server_key.size()) ||
        !DeriveOne(context, "openppp2/v2.2/record/client-to-server/nonce",
                   derived.client_to_server_nonce_prefix.data(),
                   derived.client_to_server_nonce_prefix.size()) ||
        !DeriveOne(context, "openppp2/v2.2/record/server-to-client/key",
                   derived.server_to_client_key.data(),
                   derived.server_to_client_key.size()) ||
        !DeriveOne(context, "openppp2/v2.2/record/server-to-client/nonce",
                   derived.server_to_client_nonce_prefix.data(),
                   derived.server_to_client_nonce_prefix.size())) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpInitKeyDerivationFailed);
        OPENSSL_cleanse(derived.client_to_server_key.data(), derived.client_to_server_key.size());
        OPENSSL_cleanse(derived.client_to_server_nonce_prefix.data(), derived.client_to_server_nonce_prefix.size());
        OPENSSL_cleanse(derived.server_to_client_key.data(), derived.server_to_client_key.size());
        OPENSSL_cleanse(derived.server_to_client_nonce_prefix.data(), derived.server_to_client_nonce_prefix.size());
        return false;
    }
    output = derived;
    OPENSSL_cleanse(derived.client_to_server_key.data(), derived.client_to_server_key.size());
    OPENSSL_cleanse(derived.client_to_server_nonce_prefix.data(), derived.client_to_server_nonce_prefix.size());
    OPENSSL_cleanse(derived.server_to_client_key.data(), derived.server_to_client_key.size());
    OPENSSL_cleanse(derived.server_to_client_nonce_prefix.data(), derived.server_to_client_nonce_prefix.size());
    return true;
}

} // namespace cryptography
} // namespace ppp
