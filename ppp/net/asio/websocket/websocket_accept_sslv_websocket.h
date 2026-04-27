#pragma once 

/**
 * @file websocket_accept_sslv_websocket.h
 * @brief Declares the SSL-enabled accepted WebSocket wrapper.
 */

#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief WebSocket adapter used for accepted SSL WebSocket sessions.
             *
             * This type forwards lifecycle and decorator hooks to the owning
             * `sslwebsocket` instance while preserving the base template behavior
             * as fallback.
             */
            class AcceptSslvWebSocket final : public ppp::net::asio::templates::WebSocket<sslwebsocket::SslvWebSocket> {
            public:
                /**
                 * @brief Initializes an accepted SSL WebSocket session adapter.
                 * @param reference Owning SSL WebSocket controller.
                 * @param websocket Accepted Beast SSL WebSocket stream.
                 * @param binary Whether binary frame mode is enabled.
                 * @param host Handshake host value.
                 * @param path Handshake path value.
                 */
                AcceptSslvWebSocket(const std::shared_ptr<sslwebsocket>& reference, sslwebsocket::SslvWebSocket& websocket, bool binary, ppp::string& host, ppp::string& path) noexcept;

            public:
                /** @brief Disposes the associated SSL WebSocket owner. */
                virtual void                                                    Dispose() noexcept override;
                /**
                 * @brief Updates forwarded client address metadata.
                 * @param address Address string to expose via forwarding header semantics.
                 */
                virtual void                                                    SetAddressString(const ppp::string& address) noexcept override;
                /**
                 * @brief Applies request decoration before handshake processing.
                 * @param req Outgoing or inspected WebSocket request object.
                 */
                virtual void                                                    Decorator(boost::beast::websocket::request_type& req) noexcept override;
                /**
                 * @brief Applies response decoration before handshake reply.
                 * @param res Outgoing WebSocket response object.
                 */
                virtual void                                                    Decorator(boost::beast::websocket::response_type& res) noexcept override;

            private:
                /** @brief Strong reference to the owning SSL WebSocket object. */
                std::shared_ptr<sslwebsocket>                                   reference_;
            };
        }
    }
}
