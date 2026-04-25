/**
 * @file websocket_async_sslv_websocket_perform_websocket_handshake.cpp
 * @brief Implements WebSocket handshake for asynchronous SSLv transport.
 */

#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>
#include <ppp/diagnostics/Error.h>

namespace ppp {
    namespace net {
        namespace asio {
            typedef sslwebsocket::SslvTcpSocket                             SslvTcpSocket;
            typedef sslwebsocket::SslvWebSocket                             SslvWebSocket;
            typedef std::shared_ptr<SslvWebSocket>                          SslvWebSocketPtr;
            
            /**
             * @brief Performs the WebSocket handshake over an established SSL channel.
             * @param handshaked_client Indicates whether client-side handshake preconditions are already satisfied.
             * @param y Coroutine yield context used for asynchronous operations.
             * @return true if the handshake succeeds; otherwise false.
             */
            bool AsyncSslvWebSocket::PerformWebSocketHandshake(bool handshaked_client, YieldContext& y) noexcept {
                SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                if (NULLPTR == ssl_websocket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return false;
                }

                /**
                 * @brief Creates the handshake executor bound to current connection state.
                 */
                std::shared_ptr<AcceptSslvWebSocket> accept = make_shared_object<AcceptSslvWebSocket>(reference_, *ssl_websocket, binary_, host_, path_);
                if (NULLPTR == accept) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return false;
                }

                return accept->Run(handshaked_client, y);
            }
        }
    }
}
