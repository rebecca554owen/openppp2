/**
 * @file RecordKeyDerivation.cpp
 * @brief v2.2.0 record key derivation (HKDF-SHA256 with domain separation).
 *
 * The Noise RecordProtector exporter binds the whole session-level context
 * (AUTH key, canonical transport-auth key id, handshake transcript, ivv and
 * carrier) into the 32-byte record root.  This layer performs the final
 * purpose/direction separation only: HKDF-SHA256 with an empty salt, the root
 * as IKM, and a single direction/purpose label as info.
 */

#include <ppp/cryptography/RecordKeyDerivation.h>

#include <climits>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <ppp/diagnostics/Error.h>

namespace ppp {
namespace cryptography {

namespace {

bool DeriveOne(const std::uint8_t* record_root,
               std::size_t record_root_len,
               const char* label,
               std::uint8_t* output,
               std::size_t output_size) noexcept {
    if (NULLPTR == record_root || record_root_len == 0 || NULLPTR == output) {
        return false;
    }
    const std::size_t label_len = std::strlen(label);
    if (record_root_len > static_cast<std::size_t>(INT_MAX) ||
        label_len > static_cast<std::size_t>(INT_MAX)) {
        return false;
    }

    // Salt:  empty.  The Noise exporter already bound the handshake
    //        transcript, ivv, carrier and canonical key id into the root.
    // IKM:   record root (RecordProtector exporter output).
    // Info:  one direction/purpose label only.
    EVP_PKEY_CTX* hkdf = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULLPTR);
    if (NULLPTR == hkdf) {
        return false;
    }

    std::size_t derived_size = output_size;
    const bool ok =
        EVP_PKEY_derive_init(hkdf) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(hkdf, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(
            hkdf, reinterpret_cast<const unsigned char*>(record_root),
            static_cast<int>(record_root_len)) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(
            hkdf, reinterpret_cast<const unsigned char*>(label),
            static_cast<int>(label_len)) > 0 &&
        EVP_PKEY_derive(hkdf, output, &derived_size) > 0 &&
        derived_size == output_size;
    EVP_PKEY_CTX_free(hkdf);
    return ok;
}

} // namespace

bool DeriveRecordKeyMaterial(const std::uint8_t* record_root,
                             std::size_t record_root_len,
                             RecordKeyMaterial& output) noexcept {
    RecordKeyMaterial derived;
    if (!DeriveOne(record_root, record_root_len,
                   "openppp2/v2.2/record/client-to-server/key",
                   derived.client_to_server_key.data(),
                   derived.client_to_server_key.size()) ||
        !DeriveOne(record_root, record_root_len,
                   "openppp2/v2.2/record/client-to-server/nonce",
                   derived.client_to_server_nonce_prefix.data(),
                   derived.client_to_server_nonce_prefix.size()) ||
        !DeriveOne(record_root, record_root_len,
                   "openppp2/v2.2/record/server-to-client/key",
                   derived.server_to_client_key.data(),
                   derived.server_to_client_key.size()) ||
        !DeriveOne(record_root, record_root_len,
                   "openppp2/v2.2/record/server-to-client/nonce",
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
