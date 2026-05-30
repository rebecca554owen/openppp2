#pragma once

/**
 * @file P2PCrypto.h
 * @brief P2P encryption, authentication, key derivation, and token verification.
 *
 * Provides:
 * - HKDF-SHA256 key derivation from TLS session material.
 * - Platform-adaptive cipher selection (ChaCha20-Poly1305 on ARM/mobile,
 *   AES-256-GCM on x86 with AES-NI).
 * - AEAD encrypt/decrypt with per-packet nonce.
 * - HMAC-SHA256 token generation and verification.
 * - Cipher detection at compile time.
 *
 * All operations use OpenSSL EVP and are guarded by fail-closed semantics:
 * any cryptographic failure rejects the packet.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/stdafx.h>
#include <cstdint>
#include <cstring>

// Forward declare OpenSSL types to avoid header pollution.
struct evp_cipher_ctx_st;
struct hmac_ctx_st;
struct evp_md_ctx_st;

namespace ppp {
    namespace p2p {

        /**
         * @brief Detects the best available cipher for this platform at compile time.
         *
         * On x86/x86_64 with AES-NI (__AES_NI__ macro set by the build system),
         * AES-256-GCM is preferred. On all other architectures (ARM, ARM64, etc.),
         * ChaCha20-Poly1305 is preferred.
         */
        inline P2PCipher DetectPreferredCipher() noexcept {
#if defined(__AES_NI__) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
            return P2PCipher::AES256GCM;
#else
            return P2PCipher::ChaCha20Poly1305;
#endif
        }

        /**
         * @brief AEAD encrypt/decrypt result.
         *
         * After AEADEncrypt: output_length = ciphertext byte count (excluding auth tag).
         * After AEADDecrypt: output_length = plaintext byte count.
         */
        struct P2PCryptoResult {
            int     output_length   = 0;    ///< Byte count of the output (ciphertext or plaintext).
            bool    success         = false;///< True if encryption/decryption succeeded.
        };

        /**
         * @brief Derives a P2P session key from TLS master secret via HKDF-SHA256.
         *
         * @param[in]  tls_master_secret  TLS handshake master secret (or placeholder).
         * @param[in]  tls_secret_len     Length of the master secret.
         * @param[in]  session_id         16-byte session identifier (UUID).
         * @param[out] derived_key        Output buffer (must be >= SESSION_KEY_SIZE).
         * @return true if derivation succeeds.
         */
        bool HKDFDeriveSessionKey(const uint8_t* tls_master_secret, int tls_secret_len,
                                  const uint8_t session_id[SESSION_ID_SIZE],
                                  uint8_t derived_key[SESSION_KEY_SIZE]) noexcept;

        /**
         * @brief Derives a token key from the session key via HKDF-SHA256.
         *
         * @param[in]  session_key   32-byte session key.
         * @param[out] token_key     Output 32-byte token key.
         * @return true if derivation succeeds.
         */
        bool HKDFDeriveTokenKey(const uint8_t session_key[SESSION_KEY_SIZE],
                                uint8_t token_key[SESSION_KEY_SIZE]) noexcept;

        /**
         * @brief Derives directional TX/RX AEAD keys to prevent nonce reuse (H1).
         *
         * Both peers derive complementary keys from the same session key:
         * - The peer with the lower session ID (lexicographic byte comparison)
         *   gets tx_key = "p2p-direct-a-to-b" and rx_key = "p2p-direct-b-to-a".
         * - The peer with the higher session ID gets the reversed labels.
         *
         * This ensures peer A's TX key == peer B's RX key and vice versa,
         * while preventing both directions from using the same AEAD key+nonce.
         *
         * @param[in]  session_key      32-byte shared session key.
         * @param[in]  local_session_id This peer's 16-byte session ID.
         * @param[in]  remote_session_id Remote peer's 16-byte session ID.
         * @param[out] tx_key           Output 32-byte transmit key.
         * @param[out] rx_key           Output 32-byte receive key.
         * @return true if derivation succeeds. Fails if local == remote.
         */
        bool HKDFDeriveDirectionalKeys(const uint8_t session_key[SESSION_KEY_SIZE],
                                       const uint8_t local_session_id[SESSION_ID_SIZE],
                                       const uint8_t remote_session_id[SESSION_ID_SIZE],
                                       uint8_t tx_key[SESSION_KEY_SIZE],
                                       uint8_t rx_key[SESSION_KEY_SIZE]) noexcept;

        /**
         * @brief Generates an HMAC-SHA256 token truncated to TOKEN_SIZE bytes.
         *
         * @param[in]  token_key    32-byte token key.
         * @param[in]  data         Data to authenticate.
         * @param[in]  data_len     Length of data.
         * @param[out] token_out    Output token (TOKEN_SIZE bytes).
         * @return true on success.
         */
        bool TokenGenerate(const uint8_t token_key[SESSION_KEY_SIZE],
                           const uint8_t* data, int data_len,
                           uint8_t token_out[TOKEN_SIZE]) noexcept;

        /**
         * @brief Verifies an HMAC-SHA256 token (constant-time comparison).
         *
         * @param[in]  token_key    32-byte token key.
         * @param[in]  data         Data that was authenticated.
         * @param[in]  data_len     Length of data.
         * @param[in]  token_in     Token to verify (TOKEN_SIZE bytes).
         * @return true if the token is valid.
         */
        bool TokenVerify(const uint8_t token_key[SESSION_KEY_SIZE],
                         const uint8_t* data, int data_len,
                         const uint8_t token_in[TOKEN_SIZE]) noexcept;

        /**
         * @brief AEAD encrypt using the selected cipher.
         *
         * @param[in]  cipher       Cipher algorithm to use.
         * @param[in]  key          32-byte encryption key.
         * @param[in]  nonce        8-byte per-packet nonce (expanded to cipher's nonce size).
         * @param[in]  plaintext    Plaintext buffer. May be nullptr only when plaintext_len == 0.
         * @param[in]  plaintext_len Plaintext length. 0 is valid for heartbeat-only packets.
         * @param[in]  aad          Additional authenticated data (header bytes).
         * @param[in]  aad_len      AAD length.
         * @param[out] ciphertext   Output buffer (plaintext_len + AUTH_TAG_SIZE capacity).
         * @param[out] auth_tag     Output auth tag (AUTH_TAG_SIZE bytes).
         * @return Result with output_length and success flag.
         */
        P2PCryptoResult AEADEncrypt(P2PCipher cipher,
                                    const uint8_t key[SESSION_KEY_SIZE],
                                    const uint8_t nonce[NONCE_SIZE],
                                    const uint8_t* plaintext, int plaintext_len,
                                    const uint8_t* aad, int aad_len,
                                    uint8_t* ciphertext,
                                    uint8_t auth_tag[AUTH_TAG_SIZE]) noexcept;

        /**
         * @brief AEAD decrypt using the selected cipher.
         *
         * @param[in]  cipher       Cipher algorithm to use.
         * @param[in]  key          32-byte decryption key.
         * @param[in]  nonce        8-byte per-packet nonce.
         * @param[in]  ciphertext   Ciphertext buffer. May be nullptr only when ciphertext_len == 0.
         * @param[in]  ciphertext_len Ciphertext length (excluding auth tag). 0 is valid.
         * @param[in]  aad          Additional authenticated data (header bytes).
         * @param[in]  aad_len      AAD length.
         * @param[in]  auth_tag     Auth tag to verify (AUTH_TAG_SIZE bytes).
         * @param[out] plaintext    Output buffer (ciphertext_len capacity).
         * @return Result with output_length and success flag.
         */
        P2PCryptoResult AEADDecrypt(P2PCipher cipher,
                                    const uint8_t key[SESSION_KEY_SIZE],
                                    const uint8_t nonce[NONCE_SIZE],
                                    const uint8_t* ciphertext, int ciphertext_len,
                                    const uint8_t* aad, int aad_len,
                                    const uint8_t auth_tag[AUTH_TAG_SIZE],
                                    uint8_t* plaintext) noexcept;

        /**
         * @brief Constant-time memory comparison (timing-safe).
         *
         * @param[in] a   First buffer.
         * @param[in] b   Second buffer.
         * @param[in] len Number of bytes to compare.
         * @return true if buffers are equal.
         */
        bool SecureCompare(const void* a, const void* b, size_t len) noexcept;

    }
}
