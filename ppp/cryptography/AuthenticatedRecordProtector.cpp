/**
 * @file AuthenticatedRecordProtector.cpp
 * @brief v2.2.0 AEAD record protector implementation (AES-256-GCM via EVP).
 */

#include <ppp/cryptography/AuthenticatedRecordProtector.h>

#include <cstring>

#include <openssl/evp.h>

#include <ppp/diagnostics/Error.h>

namespace ppp {
namespace cryptography {

AuthenticatedRecordProtector::AuthenticatedRecordProtector(
    const std::array<std::uint8_t, KeyLength>& key,
    const std::array<std::uint8_t, NoncePrefixLength>& nonce_prefix,
    RecordDirection direction,
    std::uint8_t carrier_kind) noexcept
    : key_(key)
    , nonce_prefix_(nonce_prefix)
    , direction_(direction)
    , carrier_kind_(carrier_kind) {
    valid_ = true;
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
    if (send_sequence_ == UINT64_MAX) {
        // Sequence wrap must never happen; close before nonce reuse.
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
        return false;
    }

    const std::uint64_t sequence = send_sequence_;

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
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULLPTR, NULLPTR, NULLPTR) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NonceLength, NULLPTR) != 1) {
            break;
        }
        if (EVP_EncryptInit_ex(ctx, NULLPTR, NULLPTR, key_.data(), nonce) != 1) {
            break;
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
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TagLength, tag) != 1) {
            break;
        }
        ok = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
        return false;
    }

    output_len = RecordHeaderLength + plaintext_len + TagLength;
    ++send_sequence_;
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
    if (sequence != receive_sequence_) {
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
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULLPTR, NULLPTR, NULLPTR) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NonceLength, NULLPTR) != 1) {
            break;
        }
        if (EVP_DecryptInit_ex(ctx, NULLPTR, NULLPTR, key_.data(), nonce) != 1) {
            break;
        }
        if (EVP_DecryptUpdate(ctx, NULLPTR, &len, aad, static_cast<int>(aad_len)) != 1) {
            break;
        }
        int plaintext_out = 0;
        if (EVP_DecryptUpdate(ctx, output, &plaintext_out,
                              ciphertext, static_cast<int>(ciphertext_len)) != 1) {
            break;
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TagLength,
                                const_cast<std::uint8_t*>(tag)) != 1) {
            break;
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
        // Authentication failure: do NOT advance receive_sequence_.
        OPENSSL_cleanse(output, ciphertext_len);
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::EvpDecryptInvalidArguments);
        return false;
    }

    ++receive_sequence_;
    return true;
}

} // namespace cryptography
} // namespace ppp
