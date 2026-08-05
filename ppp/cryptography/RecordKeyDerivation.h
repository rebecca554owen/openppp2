#pragma once

/**
 * @file RecordKeyDerivation.h
 * @brief v2.2.0 record key derivation (HKDF-SHA256 with domain separation).
 *
 * Derives per-direction AES-256-GCM record keys and nonce prefixes from the
 * Noise handshake exporter secret plus binding context (see
 * docs/design/v2.2.0/CRYPTO_PROTOCOL_V2_2_0_CN.md section 6).
 */

#include <array>
#include <cstddef>
#include <cstdint>

#include <ppp/stdafx.h>

namespace ppp {
namespace cryptography {

/**
 * @brief Directional record key material for one protected stream.
 */
struct RecordKeyMaterial
{
    std::array<std::uint8_t, 32> client_to_server_key{};
    std::array<std::uint8_t, 4>  client_to_server_nonce_prefix{};
    std::array<std::uint8_t, 32> server_to_client_key{};
    std::array<std::uint8_t, 4>  server_to_client_nonce_prefix{};
};

/**
 * @brief Binding context for record key derivation.
 */
struct RecordKeyContext
{
    const std::uint8_t* exporter_secret = NULLPTR;  ///< 32-byte Noise exporter secret.
    std::size_t         exporter_secret_len = 0;
    const std::uint8_t* handshake_hash = NULLPTR;   ///< Noise handshake hash (32 bytes).
    std::size_t         handshake_hash_len = 0;
    const std::uint8_t* session_id = NULLPTR;       ///< Canonical session id.
    std::size_t         session_id_len = 0;
    std::uint8_t        carrier_kind = 0;           ///< TCP=0, WS=1, WSS=2.
    std::uint32_t       transport_auth_key_id = 0;  ///< transport-auth key id.
};

/**
 * @brief Derives the full v2.2.0 record key material.
 * @param context Binding context.
 * @param output  Receives the four derived values.
 * @return True on success.
 */
bool DeriveRecordKeyMaterial(const RecordKeyContext& context,
                             RecordKeyMaterial& output) noexcept;

} // namespace cryptography
} // namespace ppp
