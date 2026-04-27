#pragma once 

/**
 * @file websocket_accept_websocket.h
 * @brief Declares the accepted non-SSL WebSocket wrapper.
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
             * @brief WebSocket adapter used for accepted plain TCP WebSocket sessions.
             *
             * The adapter delegates lifecycle and decorator customization to the
             * owning `websocket` instance and falls back to base behavior when
             * custom hooks are not provided.
             */
            class AcceptWebSocket final : public ppp::net::asio::templates::WebSocket<websocket::AsioWebSocket> {
            public:
                /**
                 * @brief Initializes an accepted plain WebSocket session adapter.
                 * @param reference Owning WebSocket controller.
                 * @param websocket Accepted Beast WebSocket stream.
                 * @param binary Whether binary frame mode is enabled.
                 * @param host Handshake host value.
                 * @param path Handshake path value.
                 */
                AcceptWebSocket(const std::shared_ptr<websocket>& reference, websocket::AsioWebSocket& websocket, bool binary, const ppp::string& host, const ppp::string& path) noexcept;
            
            public:
                /** @brief Disposes the associated WebSocket owner. */
                virtual void                                        Dispose() noexcept override;
                /**
                 * @brief Updates forwarded client address metadata.
                 * @param address Address string to expose via forwarding header semantics.
                 */
                virtual void                                        SetAddressString(const ppp::string& address) noexcept override;
                /**
                 * @brief Applies request decoration before handshake processing.
                 * @param req Outgoing or inspected WebSocket request object.
                 */
                virtual void                                        Decorator(boost::beast::websocket::request_type& req) noexcept override;
                /**
                 * @brief Applies response decoration before handshake reply.
                 * @param res Outgoing WebSocket response object.
                 */
                virtual void                                        Decorator(boost::beast::websocket::response_type& res) noexcept override;

            private:
                /** @brief Strong reference to the owning WebSocket object. */
                std::shared_ptr<websocket>                          reference_;
            };
        }
    }
}
