/**
 * @file websocket_async_sslv_websocket.cpp
 * @brief Implements async SSLv WebSocket lifecycle and SSL handle access.
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
             * @brief Initializes an asynchronous SSLv WebSocket wrapper.
             * @param reference Owner reference used for coordinated disposal.
             * @param tcp_socket Underlying TCP socket shared pointer.
             * @param ssl_context SSL context used to configure TLS behavior.
             * @param ssl_websocket Wrapped SSL WebSocket stream storage.
             * @param verify_peer Whether to verify the remote peer certificate.
             * @param binary Whether WebSocket frames are handled as binary.
             * @param host Target host name used by upper-layer connection logic.
             * @param path WebSocket request path used during handshake.
             * @param certificate_file Certificate file path.
             * @param certificate_key_file Private key file path.
             * @param certificate_chain_file Certificate chain file path.
             * @param certificate_key_password Password for private key loading.
             * @param ciphersuites TLS cipher suite configuration string.
             */
            AsyncSslvWebSocket::AsyncSslvWebSocket(
                const std::shared_ptr<sslwebsocket>&                        reference,
                std::shared_ptr<boost::asio::ip::tcp::socket>&              tcp_socket,
                std::shared_ptr<boost::asio::ssl::context>&                 ssl_context,
                SslvWebSocketPtr&                                           ssl_websocket,
                bool                                                        verify_peer,
                bool                                                        binary,
                const ppp::string&                                          host,
                const ppp::string&                                          path,
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file,
                const std::string&                                          certificate_key_password,
                const std::string&                                          ciphersuites) noexcept
                : SslSocket(tcp_socket, ssl_context, ssl_websocket, verify_peer, host, certificate_file, certificate_key_file, certificate_chain_file, certificate_key_password, ciphersuites)
                , path_(path)
                , reference_(reference)
                , binary_(binary) {

            }

            /**
             * @brief Disposes the owner reference to terminate connection resources.
             */
            void AsyncSslvWebSocket::Dispose() noexcept {
                std::shared_ptr<sslwebsocket> reference = std::move(reference_);
                if (reference) {
                    reference->Dispose();
                }
            }

            /**
             * @brief Gets the native OpenSSL SSL handle from the wrapped stream.
             * @return Native SSL handle when available; otherwise nullptr.
             */
            SSL* AsyncSslvWebSocket::GetSslHandle() noexcept {
                SslvWebSocketPtr& ssl_websocket = GetSslSocket();
                if (NULLPTR == ssl_websocket) {
                    return ppp::diagnostics::SetLastError<SSL*>(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                }

                SslvTcpSocket& ssl_socket = ssl_websocket->next_layer();
                return ssl_socket.native_handle();
            }
        };
    }
}
