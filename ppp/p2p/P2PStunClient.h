#pragma once

/**
 * @file P2PStunClient.h
 * @brief Lightweight STUN Binding Request/Response client for mapped-endpoint detection.
 *
 * Uses a dedicated temporary UDP socket for STUN queries.  MUST NOT be called
 * on the active P2P data socket to avoid consuming P2P datagrams.
 *
 * Call constraints: invoke only before the P2P channel enters Direct state,
 * or on a separate thread/strand from the data receive loop.
 *
 * Validates transaction ID and source endpoint in responses.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <boost/asio.hpp>

namespace ppp {
    namespace p2p {

        /**
         * @brief Minimal STUN Binding Request/Response implementation.
         *
         * Creates a temporary UDP socket for the query to avoid consuming
         * P2P data-path packets.
         */
        class P2PStunClient final {
        public:
            struct StunResult {
                boost::asio::ip::udp::endpoint mapped_endpoint;
                bool success = false;
            };

            /**
             * @brief Sends a STUN Binding Request on a dedicated temporary socket.
             *
             * Creates a fresh UDP socket, sends the request, waits for the
             * response (blocking with timeout), and closes the socket.
             * Does not touch the P2P data socket.
             *
             * @param[in]  io_ctx       io_context for socket creation.
             * @param[in]  stun_server  STUN server endpoint.
             * @param[in]  timeout_ms   Timeout in milliseconds.
             * @return StunResult with mapped endpoint on success.
             */
            static StunResult Query(boost::asio::io_context& io_ctx,
                                    const boost::asio::ip::udp::endpoint& stun_server,
                                    int timeout_ms = 3000) noexcept;

            /**
             * @brief Parses a STUN Binding Response and extracts XOR-MAPPED-ADDRESS.
             *
             * Validates transaction ID against the expected value.
             *
             * @param[in]  response     Raw response buffer.
             * @param[in]  response_len Response length in bytes.
             * @param[in]  txn_id       Expected 12-byte transaction ID.
             * @param[out] mapped_ep    Parsed XOR-MAPPED-ADDRESS endpoint.
             * @return true if parsing succeeds and transaction ID matches.
             */
            static bool ParseResponse(const uint8_t* response, int response_len,
                                      const uint8_t txn_id[12],
                                      boost::asio::ip::udp::endpoint& mapped_ep) noexcept;

            static int BuildRequest(uint8_t* buf, int bufsz, uint8_t txn_id[12]) noexcept;

        private:
            static constexpr uint16_t STUN_METHOD_BINDING             = 0x0001;
            static constexpr uint16_t STUN_TYPE_BINDING_SUCCESS_RESP  = 0x0101;  ///< L2: exact type.
            static constexpr uint32_t STUN_MAGIC_COOKIE               = 0x2112A442;
            static constexpr uint16_t STUN_ATTR_XOR_MAPPED_ADDR       = 0x0020;
        };

    }
}
