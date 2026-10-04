/**
 * @file AuthenticatedRecordProtector.cpp
 * @brief v2.2.0 AEAD record protector implementation (AES-256-GCM via EVP).
 */

#include <ppp/cryptography/AuthenticatedRecordProtector.h>

#include <cstring>

#include <ppp/diagnostics/TelemetryFwd.h>

#include <openssl/evp.h>

#include <ppp/diagnostics/Error.h>

// OpenSSL 4.0 renamed the AEAD capability flag (3.x: EVP_CIPH_AEAD_CIPHER).
#if !defined(EVP_CIPH_AEAD_CIPHER) && defined(EVP_CIPH_FLAG_AEAD_CIPHER)
#define EVP_CIPH_AEAD_CIPHER EVP_CIPH_FLAG_AEAD_CIPHER
#endif

namespace ppp {
namespace cryptography {

AuthenticatedRecordProtector::AuthenticatedRecordProtector(
    const std::array<std::uint8_t, KeyLength>& key,
    const std::array<std::uint8_t, NoncePrefixLength>& nonce_prefix,
    RecordDirection direction,
    std::uint8_t carrier_kind,
    const ppp::string& cipher_name) noexcept
    : key_(key)
    , nonce_prefix_(nonce_prefix)
    , direction_(direction)
    , cipher_name_(cipher_name)
    , carrier_kind_(carrier_kind) {
    // The record protector accepts OpenSSL AEAD ciphers: GCM, CCM or
    // CHACHA20-POLY1305.  A stream cipher (CFB/CTR) or an unknown name is not
    // usable as an AEAD: fall back to the historical default AES-256-GCM so
    // deployments that keep a legacy non-AEAD key.transport (e.g.
    // simd-aes-256-cfb) keep working without reconfiguration.  The fallback
    // is logged so operators can migrate to an explicit AEAD name.
    cipher_ = EVP_get_cipherbyname(cipher_name_.data());
    if (NULLPTR != cipher_ && (EVP_CIPHER_flags(cipher_) & EVP_CIPH_AEAD_CIPHER) != 0) {
        // v2.2.0: verify the AEAD key length matches the derived 32-byte key.
        // aes-128/192-* would otherwise silently truncate the key material.
        if (EVP_CIPHER_key_length(cipher_) != static_cast<int>(KeyLength)) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "arp",
                "key.transport '%s' AEAD key length %d != %d; falling back to aes-256-gcm",
                cipher_name_.data(), EVP_CIPHER_key_length(cipher_),
                static_cast<int>(KeyLength));
            cipher_ = EVP_get_cipherbyname("aes-256-gcm");
        }
        if (NULLPTR != cipher_) {
            ccm_mode_ = (EVP_CIPHER_mode(cipher_) == EVP_CIPH_CCM_MODE);
            valid_ = true;
            return;
        }
    }

    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "arp",
        "key.transport '%s' is not an OpenSSL AEAD cipher; falling back to aes-256-gcm",
        cipher_name_.data());
    cipher_ = EVP_get_cipherbyname("aes-256-gcm");
    ccm_mode_ = false;
    if (NULLPTR == cipher_) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
        valid_ = false;
        return;
    }
    valid_ = true;
}

bool AuthenticatedRecordProtector::IsSupportedAeadCipher(const ppp::string& cipher_name) noexcept {
    if (cipher_name.empty()) {
        return false;
    }

    const EVP_CIPHER* cipher = EVP_get_cipherbyname(cipher_name.data());
    if (NULLPTR == cipher) {
        return false;
    }

    // v2.2.0: use the AEAD capability flag instead of a name substring match;
    // the bare stream cipher "chacha20" must not be mistaken for
    // "chacha20-poly1305" (GCM/CCM/ChaCha20-Poly1305 all set the flag).
    return (EVP_CIPHER_flags(cipher) & EVP_CIPH_AEAD_CIPHER) != 0;
}

AuthenticatedRecordProtector::~AuthenticatedRecordProtector() noexcept {
    Invalidate();
}

void AuthenticatedRecordProtector::Invalidate() noexcept {
    if (valid_) {
        OPENSSL_cleanse(key_.data(), key_.size());
        OPENSSL_cleanse(nonce_prefix_.data(), nonce_prefix_.size());
        valid_ = false;
    }
}

bool AuthenticatedRecordProtector::BuildAad(
    std::uint8_t* aad,
    std::size_t& aad_len,
    std::uint32_t ciphertext_len,
    std::uint64_t sequence) const noexcept {
    if (NULLPTR == aad) {
        return false;
    }

    std::size_t offset = 0;
    const std::uint8_t magic[4] = { 'O', 'P', 'P', '2' };
    std::memcpy(aad + offset, magic, 4);
    offset += 4;
    aad[offset++] = 2;   // major
    aad[offset++] = 2;   // minor
    aad[offset++] = carrier_kind_;
    aad[offset++] = static_cast<std::uint8_t>(direction_);
    aad[offset++] = static_cast<std::uint8_t>((ciphertext_len >> 24) & 0xFF);
    aad[offset++] = static_cast<std::uint8_t>((ciphertext_len >> 16) & 0xFF);
    aad[offset++] = static_cast<std::uint8_t>((ciphertext_len >> 8) & 0xFF);
    aad[offset++] = static_cast<std::uint8_t>(ciphertext_len & 0xFF);
    for (int i = 7; i >= 0; --i) {
        aad[offset++] = static_cast<std::uint8_t>((sequence >> (i * 8)) & 0xFF);
    }

    aad_len = offset;   // 20 bytes
    return true;
}

bool AuthenticatedRecordProtector::Seal(
    const std::uint8_t* plaintext,
    std::size_t plaintext_len,
    std::uint8_t* output,
    std::size_t& output_len) noexcept {
    output_len = 0;
    if (!valid_) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
        return false;
    }
    if (NULLPTR == plaintext || NULLPTR == output) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpEncryptInvalidArguments);
        return false;
    }
    if (plaintext_len < 1 || plaintext_len > MaxPlaintextLength) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpEncryptZeroLengthInput);
        return false;
    }
    // Reserve a unique sequence number with an atomic CAS so concurrent
    // writers (cross-strand paths today, any future path) can never share a
    // GCM nonce: exactly one Seal() call wins each value.  An EVP failure
    // after the reservation may leave a gap in the stream, but the reserved
    // sequence is never handed out twice and UINT64_MAX is never used.
    std::uint64_t sequence = send_sequence_.load(std::memory_order_relaxed);
    for (;;) {
        if (sequence == UINT64_MAX) {
            // Sequence wrap must never happen; close before nonce reuse.
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
            return false;
        }
        if (send_sequence_.compare_exchange_weak(sequence, sequence + 1,
                std::memory_order_relaxed, std::memory_order_relaxed)) {
            break;   // This thread owns the reserved sequence exclusively.
        }
        // Lost the race: 'sequence' now holds the current counter, retry.
    }

    // Header: ciphertext_len (4B BE) || sequence (8B BE)
    std::uint8_t* header = output;
    const std::uint32_t ciphertext_len = static_cast<std::uint32_t>(plaintext_len);
    header[0] = static_cast<std::uint8_t>((ciphertext_len >> 24) & 0xFF);
    header[1] = static_cast<std::uint8_t>((ciphertext_len >> 16) & 0xFF);
    header[2] = static_cast<std::uint8_t>((ciphertext_len >> 8) & 0xFF);
    header[3] = static_cast<std::uint8_t>(ciphertext_len & 0xFF);
    for (int i = 0; i < 8; ++i) {
        header[4 + i] = static_cast<std::uint8_t>((sequence >> ((7 - i) * 8)) & 0xFF);
    }

    // Nonce = nonce_prefix[4] || sequence_be64[8]
    std::uint8_t nonce[NonceLength];
    std::memcpy(nonce, nonce_prefix_.data(), NoncePrefixLength);
    for (int i = 0; i < 8; ++i) {
        nonce[NoncePrefixLength + i] = static_cast<std::uint8_t>((sequence >> ((7 - i) * 8)) & 0xFF);
    }

    std::uint8_t aad[20];
    std::size_t aad_len = 0;
    if (!BuildAad(aad, aad_len, ciphertext_len, sequence)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (NULLPTR == ctx) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        return false;
    }

    std::uint8_t* ciphertext = output + RecordHeaderLength;
    std::uint8_t* tag = ciphertext + plaintext_len;
    int len = 0;
    bool ok = false;

    do {
        if (EVP_EncryptInit_ex(ctx, cipher_, NULLPTR, NULLPTR, NULLPTR) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NonceLength, NULLPTR) != 1) {
            break;
        }
        if (EVP_EncryptInit_ex(ctx, NULLPTR, NULLPTR, key_.data(), nonce) != 1) {
            break;
        }
        if (ccm_mode_) {
            // CCM needs the tag length and the total message length (AAD +
            // plaintext) declared before any data is fed.
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TagLength, NULLPTR) != 1) {
                break;
            }
            if (EVP_EncryptUpdate(ctx, NULLPTR, &len, NULLPTR,
                                  static_cast<int>(aad_len + plaintext_len)) != 1) {
                break;
            }
        }
        if (EVP_EncryptUpdate(ctx, NULLPTR, &len, aad, static_cast<int>(aad_len)) != 1) {
            break;
        }
        int ciphertext_out = 0;
        if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_out,
                              plaintext, static_cast<int>(plaintext_len)) != 1) {
            break;
        }
        int final_out = 0;
        if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_out, &final_out) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TagLength, tag) != 1) {
            break;
        }
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
        OPENSSL_cleanse(output, RecordHeaderLength + plaintext_len);
        return false;
    }

    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(aad, sizeof(aad));
    output_len = RecordHeaderLength + plaintext_len + TagLength;
    // NOTE: the send counter was already advanced by the reservation CAS
    // above; a trailing store here would clobber concurrent reservations
    // (nonce reuse).  Sequence advancement happens exactly once, in the CAS.
    return true;
}

bool AuthenticatedRecordProtector::Open(
    const std::uint8_t* input,
    std::size_t input_len,
    std::uint8_t* output,
    std::size_t& output_len) noexcept {
    output_len = 0;
    if (!valid_) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
        return false;
    }
    if (NULLPTR == input || NULLPTR == output) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpDecryptInvalidArguments);
        return false;
    }
    if (input_len < RecordHeaderLength + TagLength + 1) {
        // Too short to hold header + 1 byte ciphertext + tag.
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
        return false;
    }
    if (input_len > RecordHeaderLength + MaxPlaintextLength + TagLength) {
        // Reject oversized records before allocating/processing.
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
        return false;
    }

    const std::uint32_t ciphertext_len =
        (static_cast<std::uint32_t>(input[0]) << 24) |
        (static_cast<std::uint32_t>(input[1]) << 16) |
        (static_cast<std::uint32_t>(input[2]) << 8) |
        static_cast<std::uint32_t>(input[3]);
    if (ciphertext_len < 1 || ciphertext_len > MaxPlaintextLength) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
        return false;
    }
    if (RecordHeaderLength + static_cast<std::size_t>(ciphertext_len) + TagLength != input_len) {
        // Length field must match the actual record size exactly.
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
        return false;
    }

    std::uint64_t sequence = 0;
    for (int i = 0; i < 8; ++i) {
        sequence = (sequence << 8) | input[4 + i];
    }
    const std::uint64_t expected = receive_sequence_.load(std::memory_order_relaxed);
    if (sequence != expected) {
        // Replay, reorder or jump: protocol error.
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
        return false;
    }

    const std::uint8_t* ciphertext = input + RecordHeaderLength;
    const std::uint8_t* tag = ciphertext + ciphertext_len;

    std::uint8_t nonce[NonceLength];
    std::memcpy(nonce, nonce_prefix_.data(), NoncePrefixLength);
    for (int i = 0; i < 8; ++i) {
        nonce[NoncePrefixLength + i] = static_cast<std::uint8_t>((sequence >> ((7 - i) * 8)) & 0xFF);
    }

    std::uint8_t aad[20];
    std::size_t aad_len = 0;
    if (!BuildAad(aad, aad_len, ciphertext_len, sequence)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (NULLPTR == ctx) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        return false;
    }

    int len = 0;
    bool ok = false;

    do {
        if (EVP_DecryptInit_ex(ctx, cipher_, NULLPTR, NULLPTR, NULLPTR) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NonceLength, NULLPTR) != 1) {
            break;
        }
        if (EVP_DecryptInit_ex(ctx, NULLPTR, NULLPTR, key_.data(), nonce) != 1) {
            break;
        }
        if (ccm_mode_) {
            // CCM: the expected tag must be set before any data, and the
            // total message length (AAD + ciphertext) must be declared first.
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TagLength,
                                    const_cast<std::uint8_t*>(tag)) != 1) {
                break;
            }
            if (EVP_DecryptUpdate(ctx, NULLPTR, &len, NULLPTR,
                                  static_cast<int>(aad_len + ciphertext_len)) != 1) {
                break;
            }
        }
        if (EVP_DecryptUpdate(ctx, NULLPTR, &len, aad, static_cast<int>(aad_len)) != 1) {
            break;
        }
        int plaintext_out = 0;
        if (EVP_DecryptUpdate(ctx, output, &plaintext_out,
                              ciphertext, static_cast<int>(ciphertext_len)) != 1) {
            break;
        }
        if (!ccm_mode_) {
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TagLength,
                                    const_cast<std::uint8_t*>(tag)) != 1) {
                break;
            }
        }
        int final_out = 0;
        if (EVP_DecryptFinal_ex(ctx, output + plaintext_out, &final_out) != 1) {
            // Tag verification failed.
            break;
        }
        output_len = static_cast<std::size_t>(plaintext_out + final_out);
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        // Authentication failure: do NOT advance receive_sequence_.  The
        // dedicated error code lets operators distinguish active tampering
        // from plain network corruption / frame decode errors.
        OPENSSL_cleanse(output, ciphertext_len);
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpDecryptAuthenticationFailed);
        return false;
    }

    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(aad, sizeof(aad));
    if (expected == UINT64_MAX) {
        // Sequence wrap-around would reuse nonces: reject like the send side.
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpDecryptAuthenticationFailed);
        return false;
    }
    // Strict sequencing under concurrency: the record was authenticated, but
    // the receive counter must only advance once per sequence.  When two
    // threads open the same record concurrently, exactly one CAS wins and
    // the loser is a duplicate delivery: reject it like any other replay.
    std::uint64_t current = expected;
    if (!receive_sequence_.compare_exchange_strong(current, expected + 1,
            std::memory_order_relaxed, std::memory_order_relaxed)) {
        OPENSSL_cleanse(output, ciphertext_len);
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
        return false;
    }
    return true;
}

} // namespace cryptography
} // namespace ppp
