#pragma once

/**
 * @file RecordKeyDerivation.h
 * @brief v2.2.0 record key derivation (HKDF-SHA256 with domain separation).
 *
 * Derives per-direction AES-256-GCM record keys and nonce prefixes from the
 * Noise RecordProtector exporter root (see
 * docs/design/v2.2.0/CRYPTO_PROTOCOL_V2_2_0_CN.md section 6).
 *
 * The Noise exporter is the single place that binds the session-level context
 * (AUTH key, canonical transport-auth key id, handshake transcript, ivv and
 * carrier) into the 32-byte record root.  This layer only separates record
 * direction and purpose: HKDF-SHA256 with an empty salt, the root as IKM and
 * one purpose label as info, so it never re-encodes session, carrier or key id.
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
 * @brief Derives the full v2.2.0 record key material from the record root.
 *
 * @param record_root     Noise RecordProtector exporter output (32 bytes);
 *                        it already binds ivv, carrier, canonical key id and
 *                        the handshake transcript, so identical roots must
 *                        only be produced from identical binding contexts.
 * @param record_root_len Root length in bytes.
 * @param output          Receives the four derived values.
 * @return True on success.
 */
bool DeriveRecordKeyMaterial(const std::uint8_t* record_root,
                             std::size_t record_root_len,
                             RecordKeyMaterial& output) noexcept;

} // namespace cryptography
} // namespace ppp
