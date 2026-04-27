#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/asio/websocket/websocket_accept_websocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>

/**
 * @file websocket_accept_websocket.cpp
 * @brief Implements accepted plain WebSocket adapter behavior.
 */

namespace ppp {
    namespace net {
        namespace asio {
            typedef websocket::AsioWebSocket AsioWebSocket;
            
            /**
             * @brief Constructs an accepted plain WebSocket adapter.
             * @param reference Shared owner that handles session-level behavior.
             * @param websocket Accepted WebSocket stream.
             * @param binary Whether binary frame mode is enabled.
             * @param host Handshake host value.
             * @param path Handshake target path.
             */
            AcceptWebSocket::AcceptWebSocket(const std::shared_ptr<websocket>& reference, AsioWebSocket& websocket, bool binary, const ppp::string& host, const ppp::string& path) noexcept
                : WebSocket(websocket, binary, host, path)
                , reference_(reference) {

            }

            /**
             * @brief Disposes the owning WebSocket object once.
             */
            void AcceptWebSocket::Dispose() noexcept {
                std::shared_ptr<websocket> reference = std::move(reference_);
                if (reference) {
                    reference->Dispose();
                }
            }

            /**
             * @brief Stores the forwarded client address on the owner.
             * @param address Client address string.
             */
            void AcceptWebSocket::SetAddressString(const ppp::string& address) noexcept {
                std::shared_ptr<websocket> reference = reference_;
                if (reference) {
                    reference->XForwardedFor = address;
                }
            }

            /**
             * @brief Applies request decoration with base fallback.
             * @param req WebSocket request object.
             */
            void AcceptWebSocket::Decorator(boost::beast::websocket::request_type& req) noexcept {
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
            void AcceptWebSocket::Decorator(boost::beast::websocket::response_type& res) noexcept {
                /**
                 * Delegate to the owner first so user customization wins.
                 * If not handled, apply the default decorator from the base wrapper.
                 */
                bool ok = reference_->Decorator(res);
                if (!ok) {
                    WebSocket::Decorator(res);
                }
            }

            /**
             * @brief Creates a WebSocket owner around an accepted TCP socket.
             * @param context Asio I/O context used for asynchronous operations.
             * @param strand Execution strand for serialized handlers.
             * @param socket Accepted TCP socket to be moved into the stream.
             * @param binary Whether binary frame mode is enabled.
             */
            websocket::websocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, bool binary) noexcept
                : disposed_(false)
                , binary_(binary)
                , context_(context)
                , strand_(strand)
                , websocket_(std::move(*socket)) {

                /**
                 * Capture the remote endpoint as early as possible, because
                 * higher-level lifecycle code may close or transfer the socket later.
                 */
                boost::system::error_code ec;
                remoteEP_ = IPEndPoint::ToEndPoint(websocket_.next_layer().remote_endpoint(ec));
            }
        }
    }
}
