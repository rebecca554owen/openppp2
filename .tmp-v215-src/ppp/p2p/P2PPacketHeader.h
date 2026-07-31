#pragma once

/**
 * @file P2PPacketHeader.h
 * @brief Two-tier P2P packet header serialization and parsing.
 *
 * Tier 1 (control): 48-byte full header for probes, heartbeats, token requests.
 * Tier 2 (data): 16-byte minimal header for steady-state encrypted data.
 *
 * All parsers validate bounds and return false on malformed input (fail closed).
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/Int128.h>
#include <cstring>

namespace ppp {
    namespace p2p {

        /**
         * @brief Tier 1 full control header (probes, heartbeats, token requests).
         *
         * Wire layout (48 bytes before auth tag):
         *   [0]     Flags (1B)
         *   [1..3]  Magic (3B, 0x503250 — first 3 bytes of P2P_MAGIC)
         *   [4..19] Session ID (16B, UUID)
         *   [20..27] Nonce (8B, big-endian)
         *   [28..31] Sequence (4B, big-endian)
         *   [32..47] Token (16B, HMAC-SHA256 truncated)
         *   [48..]  Payload (encrypted or plaintext for probes)
         *   [N-16..N-1] Auth Tag (16B)
         */
        struct P2PTier1Header {
            uint8_t     flags       = 0;
            uint8_t     session_id[SESSION_ID_SIZE] = {};
            uint64_t    nonce       = 0;
            uint32_t    sequence    = 0;
            uint8_t     token[TOKEN_SIZE] = {};

            /**
             * @brief Serializes this header into a buffer.
             * @param[out] buf   Destination buffer (must have >= TIER1_HEADER_SIZE bytes).
             * @param[in]  bufsz Buffer capacity in bytes.
             * @return Number of bytes written (TIER1_HEADER_SIZE) or 0 on error.
             */
            int Serialize(uint8_t* buf, int bufsz) const noexcept {
                if (bufsz < TIER1_HEADER_SIZE) {
                    return 0;
                }

                buf[0] = flags | P2P_FLAG_TIER;
                // Magic stored as 3 bytes in positions [1..3].
                buf[1] = 0x50;  // 'P'
                buf[2] = 0x32;  // '2'
                buf[3] = 0x50;  // 'P' — first 3 bytes of "P2P1"
                std::memcpy(buf + 4, session_id, SESSION_ID_SIZE);

                // nonce: big-endian 8 bytes using helper (no mutation).
                NonceToBytes(nonce, buf + 20);

                // sequence: big-endian 4 bytes
                buf[28] = static_cast<uint8_t>((sequence >> 24) & 0xFF);
                buf[29] = static_cast<uint8_t>((sequence >> 16) & 0xFF);
                buf[30] = static_cast<uint8_t>((sequence >> 8) & 0xFF);
                buf[31] = static_cast<uint8_t>(sequence & 0xFF);

                std::memcpy(buf + 32, token, TOKEN_SIZE);
                return TIER1_HEADER_SIZE;
            }

            /**
             * @brief Parses a Tier 1 header from a buffer.
             * @param[in]  buf   Source buffer.
             * @param[in]  bufsz Buffer length in bytes.
             * @return true if parsed successfully with valid magic and flags.
             */
            bool Parse(const uint8_t* buf, int bufsz) noexcept {
                if (bufsz < TIER1_HEADER_SIZE) {
                    return false;
                }

                flags = buf[0];
                if (!(flags & P2P_FLAG_TIER)) {
                    return false;  // Not a Tier 1 packet
                }

                // Validate magic bytes in positions [1..3].
                if (buf[1] != 0x50 || buf[2] != 0x32 || buf[3] != 0x50) {
                    return false;
                }

                std::memcpy(session_id, buf + 4, SESSION_ID_SIZE);
                nonce = BytesToNonce(buf + 20);

                sequence = (static_cast<uint32_t>(buf[28]) << 24) |
                           (static_cast<uint32_t>(buf[29]) << 16) |
                           (static_cast<uint32_t>(buf[30]) << 8) |
                            static_cast<uint32_t>(buf[31]);

                std::memcpy(token, buf + 32, TOKEN_SIZE);
                return true;
            }
        };

        /**
         * @brief Tier 2 minimal data header (steady-state after channel established).
         *
         * Wire layout (16 bytes before auth tag):
         *   [0]     Flags (1B) — TIER bit clear
         *   [1]     Channel ID (1B) — replaces full session ID for demux
         *   [2..3]  Reserved (2B, zero)
         *   [4..7]  Sequence (4B, big-endian)
         *   [8..15] Nonce (8B, big-endian, per-packet unique)
         *   [16..]  Payload (encrypted Ethernet frame)
         *   [N-16..N-1] Auth Tag (16B)
         */
        struct P2PTier2Header {
            uint8_t     flags       = 0;
            uint8_t     channel_id  = 0;
            uint32_t    sequence    = 0;
            uint64_t    nonce       = 0;

            /**
             * @brief Serializes this header into a buffer.
             * @param[out] buf   Destination buffer (>= TIER2_HEADER_SIZE).
             * @param[in]  bufsz Buffer capacity in bytes.
             * @return Bytes written (TIER2_HEADER_SIZE) or 0 on error.
             */
            int Serialize(uint8_t* buf, int bufsz) const noexcept {
                if (bufsz < TIER2_HEADER_SIZE) {
                    return 0;
                }

                buf[0] = flags & ~P2P_FLAG_TIER;  // Ensure TIER bit clear
                buf[1] = channel_id;
                buf[2] = 0;  // reserved
                buf[3] = 0;  // reserved

                buf[4] = static_cast<uint8_t>((sequence >> 24) & 0xFF);
                buf[5] = static_cast<uint8_t>((sequence >> 16) & 0xFF);
                buf[6] = static_cast<uint8_t>((sequence >> 8) & 0xFF);
                buf[7] = static_cast<uint8_t>(sequence & 0xFF);

                NonceToBytes(nonce, buf + 8);

                return TIER2_HEADER_SIZE;
            }

            /**
             * @brief Parses a Tier 2 header from a buffer.
             * @param[in]  buf   Source buffer.
             * @param[in]  bufsz Buffer length in bytes.
             * @return true if parsed successfully.
             */
            bool Parse(const uint8_t* buf, int bufsz) noexcept {
                if (bufsz < TIER2_HEADER_SIZE) {
                    return false;
                }

                flags = buf[0];
                if (flags & P2P_FLAG_TIER) {
                    return false;  // Not a Tier 2 packet
                }

                channel_id = buf[1];

                sequence = (static_cast<uint32_t>(buf[4]) << 24) |
                           (static_cast<uint32_t>(buf[5]) << 16) |
                           (static_cast<uint32_t>(buf[6]) << 8) |
                            static_cast<uint32_t>(buf[7]);

                nonce = BytesToNonce(buf + 8);

                return true;
            }
        };

        /**
         * @brief Determines packet tier from raw buffer without full parse.
         * @param[in] buf   First byte of the packet.
         * @param[in] bufsz Buffer length (must be >= 1).
         * @return 1 for Tier 1, 2 for Tier 2, 0 on insufficient data.
         */
        inline int DetectTier(const uint8_t* buf, int bufsz) noexcept {
            if (bufsz < 1) {
                return 0;
            }
            return (buf[0] & P2P_FLAG_TIER) ? 1 : 2;
        }

        /**
         * @brief Demuxes coalesced frames from a payload buffer.
         *
         * Each frame is prefixed with a 2-byte big-endian length.
         * Validates that each declared length fits within the remaining buffer.
         * Caps at MAX_COALESCED_FRAMES to prevent unbounded allocation.
         *
         * @param[in]  payload     Start of coalesced payload (after header).
         * @param[in]  payload_len Total payload length in bytes.
         * @param[out] frames      Fixed-size array of (offset, length) pairs.
         * @param[in]  max_frames  Maximum number of frames to accept.
         * @return Number of frames found, or -1 on parse error.
         */
        inline int DemuxCoalescedFrames(const uint8_t* payload, int payload_len,
                                         std::pair<int, int>* frames, int max_frames) noexcept {
            if (!payload || payload_len <= 0 || !frames || max_frames <= 0) {
                return -1;
            }
            int frame_count = 0;
            int offset = 0;
            while (offset + 2 <= payload_len) {
                if (frame_count >= max_frames) {
                    return -1;  // Too many frames — fail closed.
                }
                uint16_t frame_len = (static_cast<uint16_t>(payload[offset]) << 8) |
                                      static_cast<uint16_t>(payload[offset + 1]);
                offset += 2;
                if (frame_len == 0 || offset + frame_len > payload_len) {
                    return -1;  // Malformed — fail closed.
                }
                frames[frame_count] = std::make_pair(offset, static_cast<int>(frame_len));
                ++frame_count;
                offset += frame_len;
            }
            if (offset != payload_len) {
                return -1;  // Trailing bytes without a valid length prefix.
            }
            return frame_count;
        }

        /**
         * @brief Coalesces multiple Ethernet frames into a single payload buffer.
         *
         * Each frame is prefixed with a 2-byte big-endian length.
         *
         * @param[out] out         Destination buffer.
         * @param[in]  outsz       Destination buffer capacity.
         * @param[in]  frames      Array of (data, length) frame pointers.
         * @param[in]  frame_count Number of frames (must be <= MAX_COALESCED_FRAMES).
         * @return Total bytes written, or -1 on error.
         */
        inline int CoalesceFrames(uint8_t* out, int outsz,
                                  const std::pair<const uint8_t*, int>* frames,
                                  int frame_count) noexcept {
            if (!out || outsz <= 0 || !frames) {
                return -1;
            }
            if (frame_count <= 0 || frame_count > MAX_COALESCED_FRAMES) {
                return -1;
            }
            int offset = 0;
            for (int i = 0; i < frame_count; ++i) {
                if (!frames[i].first) {
                    return -1;  // Null frame pointer.
                }
                int flen = frames[i].second;
                if (flen <= 0 || flen > MAX_ETHERNET_FRAME_SIZE) {
                    return -1;
                }
                if (offset + 2 + flen > outsz) {
                    return -1;  // Overflow
                }
                out[offset]     = static_cast<uint8_t>((flen >> 8) & 0xFF);
                out[offset + 1] = static_cast<uint8_t>(flen & 0xFF);
                std::memcpy(out + offset + 2, frames[i].first, flen);
                offset += 2 + flen;
            }
            return offset;
        }

    }
}
