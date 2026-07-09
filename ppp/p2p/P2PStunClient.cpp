/**
 * @file P2PStunClient.cpp
 * @brief STUN Binding Request/Response implementation per RFC 5389.
 *
 * Uses a dedicated temporary socket for each query.  Validates
 * transaction ID and sender endpoint in responses.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PStunClient.h>
#include <ppp/Random.h>
#include <openssl/rand.h>
#include <cstring>

namespace ppp {
    namespace p2p {

        int P2PStunClient::BuildRequest(uint8_t* buf, int bufsz, uint8_t txn_id[12]) noexcept {
            if (bufsz < 20 || !buf || !txn_id) {
                return 0;
            }

            // H3: Use OpenSSL RAND_bytes for cryptographically strong transaction IDs.
            if (RAND_bytes(txn_id, 12) != 1) {
                return 0;  // Fail if secure random is unavailable.
            }

            buf[0] = (STUN_METHOD_BINDING >> 8) & 0xFF;
            buf[1] = STUN_METHOD_BINDING & 0xFF;
            buf[2] = 0;
            buf[3] = 0;

            buf[4] = (STUN_MAGIC_COOKIE >> 24) & 0xFF;
            buf[5] = (STUN_MAGIC_COOKIE >> 16) & 0xFF;
            buf[6] = (STUN_MAGIC_COOKIE >> 8) & 0xFF;
            buf[7] = STUN_MAGIC_COOKIE & 0xFF;

            std::memcpy(buf + 8, txn_id, 12);

            return 20;
        }

        bool P2PStunClient::ParseResponse(const uint8_t* response, int response_len,
                                           const uint8_t txn_id[12],
                                           boost::asio::ip::udp::endpoint& mapped_ep) noexcept {
            if (!response || response_len < 20 || !txn_id) {
                return false;
            }

            uint32_t cookie = (static_cast<uint32_t>(response[4]) << 24) |
                              (static_cast<uint32_t>(response[5]) << 16) |
                              (static_cast<uint32_t>(response[6]) << 8) |
                               static_cast<uint32_t>(response[7]);
            if (cookie != STUN_MAGIC_COOKIE) {
                return false;
            }

            // Validate transaction ID (#13).
            if (std::memcmp(response + 8, txn_id, 12) != 0) {
                return false;
            }

            uint16_t type = (static_cast<uint16_t>(response[0]) << 8) |
                             static_cast<uint16_t>(response[1]);
            // L2: Require exact Binding Success Response type (0x0101),
            // not merely the success class bits.
            if (type != STUN_TYPE_BINDING_SUCCESS_RESP) {
                return false;
            }

            uint16_t msg_len = (static_cast<uint16_t>(response[2]) << 8) |
                                static_cast<uint16_t>(response[3]);
            if (msg_len + 20 > response_len) {
                return false;
            }

            int offset = 20;
            while (offset + 4 <= 20 + msg_len) {
                uint16_t attr_type = (static_cast<uint16_t>(response[offset]) << 8) |
                                      static_cast<uint16_t>(response[offset + 1]);
                uint16_t attr_len  = (static_cast<uint16_t>(response[offset + 2]) << 8) |
                                      static_cast<uint16_t>(response[offset + 3]);
                int attr_offset = offset + 4;

                int padded_len = (attr_len + 3) & ~3;
                if (attr_offset + attr_len > 20 + msg_len) {
                    return false;
                }

                if (attr_type == STUN_ATTR_XOR_MAPPED_ADDR && attr_len >= 8) {
                    uint8_t family = response[attr_offset + 1];
                    uint16_t xport = (static_cast<uint16_t>(response[attr_offset + 2]) << 8) |
                                      static_cast<uint16_t>(response[attr_offset + 3]);
                    uint16_t port = xport ^ static_cast<uint16_t>(STUN_MAGIC_COOKIE >> 16);

                    if (family == 0x01 && attr_len >= 8) {
                        uint32_t xaddr = (static_cast<uint32_t>(response[attr_offset + 4]) << 24) |
                                         (static_cast<uint32_t>(response[attr_offset + 5]) << 16) |
                                         (static_cast<uint32_t>(response[attr_offset + 6]) << 8) |
                                          static_cast<uint32_t>(response[attr_offset + 7]);
                        uint32_t addr = xaddr ^ STUN_MAGIC_COOKIE;

                        boost::asio::ip::address_v4::bytes_type bytes = {
                            static_cast<uint8_t>((addr >> 24) & 0xFF),
                            static_cast<uint8_t>((addr >> 16) & 0xFF),
                            static_cast<uint8_t>((addr >> 8) & 0xFF),
                            static_cast<uint8_t>(addr & 0xFF)
                        };
                        mapped_ep = boost::asio::ip::udp::endpoint(
                            boost::asio::ip::address_v4(bytes), port);
                        return true;
                    }
                }

                offset = attr_offset + padded_len;
            }

            return false;
        }

        P2PStunClient::StunResult P2PStunClient::Query(
                boost::asio::io_context& io_ctx,
                const boost::asio::ip::udp::endpoint& stun_server,
                int timeout_ms) noexcept {
            StunResult result;

            // Create a dedicated temporary socket (#13).
            boost::system::error_code ec;
            boost::asio::ip::udp::socket tmp_socket(io_ctx, boost::asio::ip::udp::v4());
            if (!tmp_socket.is_open()) {
                return result;
            }
            tmp_socket.bind(boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0), ec);
            if (ec) {
                return result;
            }

            uint8_t request[28];
            uint8_t txn_id[12];
            int req_len = BuildRequest(request, sizeof(request), txn_id);
            if (req_len == 0) {
                return result;
            }

            tmp_socket.send_to(boost::asio::buffer(request, req_len), stun_server, 0, ec);
            if (ec) {
                return result;
            }

            // Non-blocking poll with timeout.
            uint8_t response[512];
            boost::asio::ip::udp::endpoint sender;

            tmp_socket.non_blocking(true, ec);
            uint64_t start = ppp::GetTickCount();

            for (;;) {
                ec.clear();
                size_t received = 0;
                try {
                    received = tmp_socket.receive_from(
                        boost::asio::buffer(response, sizeof(response)), sender, 0, ec);
                } catch (...) {
                    ec = boost::asio::error::eof;
                }

                if (!ec && received >= 20) {
                    // Validate sender is the STUN server we sent to (#13).
                    if (sender == stun_server) {
                        if (ParseResponse(response, static_cast<int>(received), txn_id, result.mapped_endpoint)) {
                            result.success = true;
                            break;
                        }
                    }
                }

                if (ppp::GetTickCount() - start >= static_cast<uint64_t>(timeout_ms)) {
                    break;
                }

                ppp::Sleep(10);
            }

            // Close temporary socket (does not affect P2P data socket).
            tmp_socket.close(ec);
            return result;
        }

    }
}
