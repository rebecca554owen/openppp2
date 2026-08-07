#pragma once

/**
 * @file AuthenticatedRecordProtector.h
 * @brief v2.2.0 AEAD record protector: AES-256-GCM through OpenSSL EVP.
 *
 * Replaces the legacy double-CFB data path with a single authenticated record
 * layer (see docs/design/v2.2.0/CRYPTO_PROTOCOL_V2_2_0_CN.md).  Each record
 * carries a 64-bit sequence-derived nonce, a canonical AAD, and a 16-byte GCM
 * tag.  Sequence replay, reordering, truncation, length tampering and tag
 * tampering must fail and close the carrier.
 */

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

#include <ppp/stdafx.h>

#include <openssl/evp.h>

namespace ppp {
namespace cryptography {

/**
 * @brief Direction of a record stream (used inside the canonical AAD).
 */
enum class RecordDirection : std::uint8_t
{
    ClientToServer = 0,
    ServerToClient = 1,
};

/**
 * @brief AEAD record protector for one direction of a protected stream.
 *
 * Instances hold one direction's key, nonce prefix and sequence counter.
 * Seal() produces [ciphertext || tag] from a plaintext record; Open()
 * authenticates and reverses it.  Any authentication failure must be treated
 * as fatal by the caller (close the carrier).
 */
class AuthenticatedRecordProtector
{
public:
    static constexpr std::size_t TagLength = 16;
    static constexpr std::size_t NonceLength = 12;
    static constexpr std::size_t KeyLength = 32;             // AES-256
    static constexpr std::size_t NoncePrefixLength = 4;
    static constexpr std::size_t SequenceLength = 8;
    static constexpr std::size_t RecordHeaderLength = 12;    // 4B len + 8B seq
    static constexpr std::size_t MaxPlaintextLength = PPP_BUFFER_SIZE;

public:
    /**
     * @brief Constructs a protector for one direction.
     * @param key            32-byte record key.
     * @param nonce_prefix   4-byte nonce prefix.
     * @param direction      ClientToServer or ServerToClient.
     * @param carrier_kind   Carrier type byte (TCP=0, WS=1, WSS=2).
     */
    AuthenticatedRecordProtector(
        const std::array<std::uint8_t, KeyLength>& key,
        const std::array<std::uint8_t, NoncePrefixLength>& nonce_prefix,
        RecordDirection direction,
        std::uint8_t carrier_kind,
        const ppp::string& cipher_name) noexcept;

    /**
     * @brief Whether a cipher name resolves to a supported OpenSSL AEAD.
     * @param cipher_name OpenSSL cipher name (e.g. "aes-256-gcm").
     * @return True when the cipher exists and is GCM, CCM or CHACHA20-POLY1305.
     */
    static bool IsSupportedAeadCipher(const ppp::string& cipher_name) noexcept;

    ~AuthenticatedRecordProtector() noexcept;

    AuthenticatedRecordProtector(const AuthenticatedRecordProtector&) = delete;
    AuthenticatedRecordProtector& operator=(const AuthenticatedRecordProtector&) = delete;

public:
    /**
     * @brief Seals a plaintext record into [ciphertext_len|seq|ciphertext|tag].
     * @param plaintext   Plaintext record bytes.
     * @param plaintext_len Plaintext length in bytes (1..PPP_BUFFER_SIZE).
     * @param output      Output buffer of capacity plaintext_len + 28.
     * @param output_len  Receives the total sealed length (plaintext + 28).
     * @return True on success; false on failure (caller must close carrier).
     */
    bool Seal(const std::uint8_t* plaintext, std::size_t plaintext_len,
              std::uint8_t* output, std::size_t& output_len) noexcept;

    /**
     * @brief Opens a sealed record [ciphertext_len|seq|ciphertext|tag].
     * @param input        Sealed record bytes.
     * @param input_len    Total input length.
     * @param output       Output buffer of capacity input_len.
     * @param output_len   Receives the plaintext length on success.
     * @return True on success (tag verified); false on authentication failure.
     */
    bool Open(const std::uint8_t* input, std::size_t input_len,
              std::uint8_t* output, std::size_t& output_len) noexcept;

    /**
     * @brief Invalidates the key material (zeroizes keys).
     */
    void Invalidate() noexcept;

    /**
     * @brief Whether the protector is still usable.
     */
    bool IsValid() const noexcept { return valid_; }

    /**
     * @brief Current send sequence (for diagnostics/tests).
     */
    std::uint64_t SendSequence() const noexcept {
        return send_sequence_.load(std::memory_order_relaxed);
    }

    /**
     * @brief Current receive sequence (for diagnostics/tests).
     */
    std::uint64_t ReceiveSequence() const noexcept {
        return receive_sequence_.load(std::memory_order_relaxed);
    }

private:
    bool BuildAad(std::uint8_t* aad, std::size_t& aad_len,
                  std::uint32_t ciphertext_len, std::uint64_t sequence) const noexcept;

private:
    std::array<std::uint8_t, KeyLength>         key_{};
    std::array<std::uint8_t, NoncePrefixLength> nonce_prefix_{};
    RecordDirection                             direction_;
    std::uint8_t                                carrier_kind_;
    ppp::string                                 cipher_name_;
    const EVP_CIPHER*                           cipher_ = NULLPTR;
    bool                                        ccm_mode_ = false;
    std::atomic<std::uint64_t>                  send_sequence_{0};
    std::atomic<std::uint64_t>                  receive_sequence_{0};
    bool                                        valid_ = false;
};

} // namespace cryptography
} // namespace ppp
