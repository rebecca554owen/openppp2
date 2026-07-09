#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

/**
 * @file websocket_accept_sslv_websocket.cpp
 * @brief Implements accepted SSL WebSocket adapter behavior.
 */

namespace ppp {
    namespace net {
        namespace asio {
            typedef sslwebsocket::SslvWebSocket                                 SslvWebSocket;
            typedef std::shared_ptr<SslvWebSocket>                              SslvWebSocketPtr;

            /**
             * @brief Constructs an accepted SSL WebSocket adapter.
             * @param reference Shared owner that handles session-level behavior.
             * @param websocket Accepted SSL WebSocket stream.
             * @param binary Whether binary frame mode is enabled.
             * @param host Handshake host value.
             * @param path Handshake target path.
             */
            AcceptSslvWebSocket::AcceptSslvWebSocket(const std::shared_ptr<sslwebsocket>& reference, SslvWebSocket& websocket, bool binary, ppp::string& host, ppp::string& path) noexcept
                : WebSocket(websocket, binary, host, path)
                , reference_(reference) {

            }

            /**
             * @brief Disposes the owning SSL WebSocket object once.
             */
            void AcceptSslvWebSocket::Dispose() noexcept {
                std::shared_ptr<sslwebsocket> reference = std::move(reference_);
                if (reference) {
                    reference->Dispose();
                }
            }

            /**
             * @brief Stores the forwarded client address on the owner.
             * @param address Client address string.
             */
            void AcceptSslvWebSocket::SetAddressString(const ppp::string& address) noexcept {
                std::shared_ptr<sslwebsocket> reference = reference_;
                if (reference) {
                    reference->XForwardedFor = address;
                }
            }

            /**
             * @brief Applies request decoration with base fallback.
             * @param req WebSocket request object.
             */
            void AcceptSslvWebSocket::Decorator(boost::beast::websocket::request_type& req) noexcept {
                /**
                 * Delegate to the owner first so user customization wins.
                 * If not handled, apply the default decorator from the base wrapper.
                 */
                bool ok = reference_->Decorator(req);
                if (!ok) {
                    WebSocket::Decorator(req);
                }
            }

            /**
             * @brief Applies response decoration with base fallback.
             * @param res WebSocket response object.
             */
            void AcceptSslvWebSocket::Decorator(boost::beast::websocket::response_type& res) noexcept {
                /**
                 * Delegate to the owner first so user customization wins.
                 * If not handled, apply the default decorator from the base wrapper.
                 */
                bool ok = reference_->Decorator(res);
                if (!ok) {
                    WebSocket::Decorator(res);
                }
            }
        }
    }
}
