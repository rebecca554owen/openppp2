/**
 * @file P2PCrypto.cpp
 * @brief P2P cryptographic operations implementation using OpenSSL EVP.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PCrypto.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <cstring>

// Suppress OpenSSL 3.0 deprecation warnings for HMAC_* functions.
// The project still targets OpenSSL 1.1.1+ compatibility; migrating
// to EVP_MAC is deferred until the minimum OpenSSL version is raised.
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable: 4996)  // deprecated in OpenSSL 3.0
#endif

namespace ppp {
    namespace p2p {

        // ---------------------------------------------------------------------------
        // HKDF-SHA256 key derivation
        // ---------------------------------------------------------------------------

        bool HKDFDeriveSessionKey(const uint8_t* tls_master_secret, int tls_secret_len,
                                  const uint8_t session_id[SESSION_ID_SIZE],
                                  uint8_t derived_key[SESSION_KEY_SIZE]) noexcept {
            if (!tls_master_secret || tls_secret_len <= 0 || !session_id || !derived_key) {
                return false;
            }

            static constexpr const char* SALT_SUFFIX = "p2p-v1";
            const size_t salt_len = SESSION_ID_SIZE + std::strlen(SALT_SUFFIX);
            uint8_t salt[SESSION_ID_SIZE + 16];
            std::memcpy(salt, session_id, SESSION_ID_SIZE);
            std::memcpy(salt + SESSION_ID_SIZE, SALT_SUFFIX, std::strlen(SALT_SUFFIX));

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
            if (!ctx) {
                return false;
            }

            bool ok = false;
            if (EVP_PKEY_derive_init(ctx) > 0 &&
                EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, static_cast<int>(salt_len)) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_key(ctx, tls_master_secret, tls_secret_len) > 0 &&
                EVP_PKEY_CTX_add1_hkdf_info(ctx,
                    reinterpret_cast<const uint8_t*>("direct-channel-key"), 18) > 0) {
                size_t out_len = SESSION_KEY_SIZE;
                ok = EVP_PKEY_derive(ctx, derived_key, &out_len) > 0 && out_len == SESSION_KEY_SIZE;
            }

            EVP_PKEY_CTX_free(ctx);
            return ok;
        }

        bool HKDFDeriveTokenKey(const uint8_t session_key[SESSION_KEY_SIZE],
                                uint8_t token_key[SESSION_KEY_SIZE]) noexcept {
            if (!session_key || !token_key) {
                return false;
            }

            static constexpr const char* SALT_STR = "token-generation";
            static constexpr const char* INFO_STR = "p2p-token";

            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
            if (!ctx) {
                return false;
            }

            bool ok = false;
            if (EVP_PKEY_derive_init(ctx) > 0 &&
                EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_salt(ctx,
                    reinterpret_cast<const uint8_t*>(SALT_STR),
                    static_cast<int>(std::strlen(SALT_STR))) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_key(ctx, session_key, SESSION_KEY_SIZE) > 0 &&
                EVP_PKEY_CTX_add1_hkdf_info(ctx,
                    reinterpret_cast<const uint8_t*>(INFO_STR),
                    static_cast<int>(std::strlen(INFO_STR))) > 0) {
                size_t out_len = SESSION_KEY_SIZE;
                ok = EVP_PKEY_derive(ctx, token_key, &out_len) > 0 && out_len == SESSION_KEY_SIZE;
            }

            EVP_PKEY_CTX_free(ctx);
            return ok;
        }

        // ---------------------------------------------------------------------------
        // H1: Directional key derivation
        // ---------------------------------------------------------------------------

        /**
         * @brief Internal HKDF helper with caller-specified info string.
         */
        static bool HKDFDeriveWithInfo(const uint8_t ikm[SESSION_KEY_SIZE],
                                       const uint8_t* salt, int salt_len,
                                       const char* info,
                                       uint8_t out[SESSION_KEY_SIZE]) noexcept {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
            if (!ctx) {
                return false;
            }
            bool ok = false;
            if (EVP_PKEY_derive_init(ctx) > 0 &&
                EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, salt_len) > 0 &&
                EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, SESSION_KEY_SIZE) > 0 &&
                EVP_PKEY_CTX_add1_hkdf_info(ctx,
                    reinterpret_cast<const uint8_t*>(info),
                    static_cast<int>(std::strlen(info))) > 0) {
                size_t out_len = SESSION_KEY_SIZE;
                ok = EVP_PKEY_derive(ctx, out, &out_len) > 0 && out_len == SESSION_KEY_SIZE;
            }
            EVP_PKEY_CTX_free(ctx);
            return ok;
        }

        bool HKDFDeriveDirectionalKeys(const uint8_t session_key[SESSION_KEY_SIZE],
                                       const uint8_t local_session_id[SESSION_ID_SIZE],
                                       const uint8_t remote_session_id[SESSION_ID_SIZE],
                                       uint8_t tx_key[SESSION_KEY_SIZE],
                                       uint8_t rx_key[SESSION_KEY_SIZE]) noexcept {
            if (!session_key || !local_session_id || !remote_session_id || !tx_key || !rx_key) {
                return false;
            }

            // Fail closed if session IDs are identical (cannot determine direction).
            if (SessionIdEqual(local_session_id, remote_session_id)) {
                return false;
            }

            // Determine direction by lexicographic comparison of session IDs.
            // "A" = lower ID, "B" = higher ID.
            // A's TX = "p2p-direct-a-to-b", A's RX = "p2p-direct-b-to-a".
            // B's TX = "p2p-direct-b-to-a", B's RX = "p2p-direct-a-to-b".
            // Note: This ordering comparison is not timing-sensitive (session IDs
            // are not secret), so memcmp is acceptable here.
            int cmp = std::memcmp(local_session_id, remote_session_id, SESSION_ID_SIZE);
            bool local_is_a = (cmp < 0);

            // Salt must be identical for both peers so that HKDF produces the
            // same intermediate key material.  Use canonical ordering:
            //   min(local_id, remote_id) || max(local_id, remote_id) || suffix
            // The direction differentiation comes solely from the info string,
            // not the salt.
            static constexpr const char* SALT_SUFFIX = "p2p-directional";
            const size_t suffix_len = std::strlen(SALT_SUFFIX);
            const size_t salt_len = SESSION_ID_SIZE * 2 + suffix_len;
            uint8_t salt[SESSION_ID_SIZE * 2 + 32];

            const uint8_t* lower_id = local_is_a ? local_session_id : remote_session_id;
            const uint8_t* upper_id = local_is_a ? remote_session_id : local_session_id;
            std::memcpy(salt, lower_id, SESSION_ID_SIZE);
            std::memcpy(salt + SESSION_ID_SIZE, upper_id, SESSION_ID_SIZE);
            std::memcpy(salt + SESSION_ID_SIZE * 2, SALT_SUFFIX, suffix_len);

            static constexpr const char* INFO_A_TO_B = "p2p-direct-a-to-b";
            static constexpr const char* INFO_B_TO_A = "p2p-direct-b-to-a";

            const char* tx_info = local_is_a ? INFO_A_TO_B : INFO_B_TO_A;
            const char* rx_info = local_is_a ? INFO_B_TO_A : INFO_A_TO_B;

            if (!HKDFDeriveWithInfo(session_key, salt, static_cast<int>(salt_len),
                                    tx_info, tx_key)) {
                return false;
            }
            if (!HKDFDeriveWithInfo(session_key, salt, static_cast<int>(salt_len),
                                    rx_info, rx_key)) {
                return false;
            }

            return true;
        }

        // ---------------------------------------------------------------------------
        // Token generation and verification
        // ---------------------------------------------------------------------------

        bool TokenGenerate(const uint8_t token_key[SESSION_KEY_SIZE],
                           const uint8_t* data, int data_len,
                           uint8_t token_out[TOKEN_SIZE]) noexcept {
            if (!token_key || !data || data_len <= 0 || !token_out) {
                return false;
            }

            unsigned int hmac_len = 0;
            uint8_t full_mac[EVP_MAX_MD_SIZE];

            HMAC_CTX* ctx = HMAC_CTX_new();
            if (!ctx) {
                return false;
            }

            bool ok = false;
            if (HMAC_Init_ex(ctx, token_key, SESSION_KEY_SIZE, EVP_sha256(), nullptr) > 0 &&
                HMAC_Update(ctx, data, static_cast<size_t>(data_len)) > 0 &&
                HMAC_Final(ctx, full_mac, &hmac_len) > 0 &&
                hmac_len >= TOKEN_SIZE) {
                std::memcpy(token_out, full_mac, TOKEN_SIZE);
                ok = true;
            }

            HMAC_CTX_free(ctx);
            OPENSSL_cleanse(full_mac, sizeof(full_mac));
            return ok;
        }

        bool TokenVerify(const uint8_t token_key[SESSION_KEY_SIZE],
                         const uint8_t* data, int data_len,
                         const uint8_t token_in[TOKEN_SIZE]) noexcept {
            uint8_t computed[TOKEN_SIZE];
            if (!TokenGenerate(token_key, data, data_len, computed)) {
                return false;
            }
            return SecureCompare(computed, token_in, TOKEN_SIZE);
        }

        // ---------------------------------------------------------------------------
        // Secure comparison
        // ---------------------------------------------------------------------------

        bool SecureCompare(const void* a, const void* b, size_t len) noexcept {
            if (!a || !b || len == 0) {
                return false;
            }
            return CRYPTO_memcmp(a, b, len) == 0;
        }

        // ---------------------------------------------------------------------------
        // AEAD encrypt/decrypt
        // ---------------------------------------------------------------------------

        static void ExpandNonce(const uint8_t nonce[NONCE_SIZE], uint8_t out[12]) noexcept {
            out[0] = 0; out[1] = 0; out[2] = 0; out[3] = 0;
            std::memcpy(out + 4, nonce, NONCE_SIZE);
        }

        P2PCryptoResult AEADEncrypt(P2PCipher cipher,
                                    const uint8_t key[SESSION_KEY_SIZE],
                                    const uint8_t nonce[NONCE_SIZE],
                                    const uint8_t* plaintext, int plaintext_len,
                                    const uint8_t* aad, int aad_len,
                                    uint8_t* ciphertext,
                                    uint8_t auth_tag[AUTH_TAG_SIZE]) noexcept {
            P2PCryptoResult result;
            // C3: Permit nullptr only when length is exactly 0.
            if (!key || !nonce || plaintext_len < 0 || !ciphertext || !auth_tag) {
                return result;
            }
            if (plaintext_len > 0 && !plaintext) {
                return result;
            }
            // L1: AAD pointer must be valid when aad_len > 0.
            if (aad_len > 0 && !aad) {
                return result;
            }

            const EVP_CIPHER* evp_cipher = nullptr;
            switch (cipher) {
                case P2PCipher::AES256GCM:
                    evp_cipher = EVP_aes_256_gcm();
                    break;
                case P2PCipher::ChaCha20Poly1305:
                default:
                    evp_cipher = EVP_chacha20_poly1305();
                    break;
            }

            uint8_t expanded_nonce[12];
            ExpandNonce(nonce, expanded_nonce);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                return result;
            }

            do {
                if (EVP_EncryptInit_ex(ctx, evp_cipher, nullptr, nullptr, nullptr) != 1) break;
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
                if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, expanded_nonce) != 1) break;

                int out_len = 0;
                if (aad && aad_len > 0) {
                    if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad, aad_len) != 1) break;
                }
                // C3: Skip EVP_EncryptUpdate for zero-length plaintext.
                int total_len = 0;
                if (plaintext_len > 0) {
                    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len) != 1) break;
                    total_len = out_len;
                }
                if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &out_len) != 1) break;
                total_len += out_len;

                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AUTH_TAG_SIZE, auth_tag) != 1) break;

                result.output_length = total_len;
                result.success = true;
            } while (false);

            EVP_CIPHER_CTX_free(ctx);
            return result;
        }

        P2PCryptoResult AEADDecrypt(P2PCipher cipher,
                                    const uint8_t key[SESSION_KEY_SIZE],
                                    const uint8_t nonce[NONCE_SIZE],
                                    const uint8_t* ciphertext, int ciphertext_len,
                                    const uint8_t* aad, int aad_len,
                                    const uint8_t auth_tag[AUTH_TAG_SIZE],
                                    uint8_t* plaintext) noexcept {
            P2PCryptoResult result;
            // C3: Permit nullptr only when length is exactly 0.
            if (!key || !nonce || ciphertext_len < 0 || !auth_tag || !plaintext) {
                return result;
            }
            if (ciphertext_len > 0 && !ciphertext) {
                return result;
            }
            // L1: AAD pointer must be valid when aad_len > 0.
            if (aad_len > 0 && !aad) {
                return result;
            }

            const EVP_CIPHER* evp_cipher = nullptr;
            switch (cipher) {
                case P2PCipher::AES256GCM:
                    evp_cipher = EVP_aes_256_gcm();
                    break;
                case P2PCipher::ChaCha20Poly1305:
                default:
                    evp_cipher = EVP_chacha20_poly1305();
                    break;
            }

            uint8_t expanded_nonce[12];
            ExpandNonce(nonce, expanded_nonce);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) {
                return result;
            }

            do {
                if (EVP_DecryptInit_ex(ctx, evp_cipher, nullptr, nullptr, nullptr) != 1) break;
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) break;
                if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, expanded_nonce) != 1) break;

                int out_len = 0;
                if (aad && aad_len > 0) {
                    if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, aad_len) != 1) break;
                }
                // C3: Skip EVP_DecryptUpdate for zero-length ciphertext.
                int total_len = 0;
                if (ciphertext_len > 0) {
                    if (EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, ciphertext_len) != 1) break;
                    total_len = out_len;
                }

                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AUTH_TAG_SIZE,
                                        const_cast<uint8_t*>(auth_tag)) != 1) break;

                if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &out_len) != 1) {
                    break;
                }
                total_len += out_len;

                result.output_length = total_len;
                result.success = true;
            } while (false);

            EVP_CIPHER_CTX_free(ctx);
            return result;
        }

    }
}

#if defined(_MSC_VER)
#pragma warning(pop)
#endif
