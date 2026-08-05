/**
 * @file RecordKeyDerivation.cpp
 * @brief v2.2.0 record key derivation (HKDF-SHA256 with domain separation).
 */

#include <ppp/cryptography/RecordKeyDerivation.h>

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

    // Salt: handshake hash (optional; HKDF accepts empty salt).
    // IKM:  exporter secret.
    // Info: domain-separated label + binding context.
    EVP_PKEY_CTX* hkdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULLPTR);
    if (NULLPTR == hkdf) {
        return false;
    }

    std::size_t derived_size = output_size;
    const bool ok =
        EVP_PKEY_derive_init(hkdf) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(hkdf, EVP_sha256()) > 0 &&
        (context.handshake_hash_len == 0 ||
         EVP_PKEY_CTX_set1_hkdf_salt(hkdf, context.handshake_hash,
                                     static_cast<int>(context.handshake_hash_len)) > 0) &&
        EVP_PKEY_CTX_set1_hkdf_key(hkdf, context.exporter_secret,
                                   static_cast<int>(context.exporter_secret_len)) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            hkdf,
            reinterpret_cast<const std::uint8_t*>(label),
            static_cast<int>(std::strlen(label))) > 0 &&
        EVP_PKEY_derive(hkdf, output, &derived_size) > 0 &&
        derived_size == output_size;
    EVP_PKEY_CTX_free(hkdf);
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
        return false;
    }
    output = derived;
    return true;
}

} // namespace cryptography
} // namespace ppp
