#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

/**
 * @file websocket_async_sslv_websocket_perform_ssl_handshake.cpp
 * @brief Implements SSL handshake stage for async SSL WebSocket sessions.
 */

namespace ppp {
    namespace net {
        namespace asio {
            typedef sslwebsocket::SslvTcpSocket                             SslvTcpSocket;
            typedef sslwebsocket::SslvWebSocket                             SslvWebSocket;
            typedef std::shared_ptr<SslvWebSocket>                          SslvWebSocketPtr;

            /**
             * @brief Performs the SSL handshake and then the WebSocket handshake.
             * @param handshaked_client True for client mode, false for server mode.
             * @param y Coroutine yield context used to suspend and resume execution.
             * @return True if both handshakes succeed; otherwise false.
             */
            bool AsyncSslvWebSocket::PerformSslHandshake(bool handshaked_client, YieldContext& y) noexcept {
                /**
                 * Retrieve stable references required by the asynchronous callback.
                 * The captured shared reference keeps the owner alive while suspended.
                 */
                const std::shared_ptr<Reference> reference = GetReference();
                const SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                if (NULLPTR == ssl_websocket) {
                    return false;
                }

                bool ok = false;
                auto& ssl_socket = ssl_websocket->next_layer();
                /**
                 * Start asynchronous SSL negotiation and resume the coroutine from
                 * the completion handler by signaling the yield context.
                 */
                ssl_socket.async_handshake(handshaked_client ? boost::asio::ssl::stream_base::client : boost::asio::ssl::stream_base::server,
                    [reference, this, handshaked_client, &ok, &y](const boost::system::error_code& ec) noexcept {
                        ok = ec == boost::system::errc::success;
                        y.R();
                    });

                /**
                 * Suspend until the SSL callback runs; abort immediately on failure,
                 * otherwise continue with the HTTP/WebSocket upgrade handshake.
                 */
                y.Suspend();
                if (!ok) {
                    return false;
                }

                return PerformWebSocketHandshake(handshaked_client, y);
            }
        }
    }
}
