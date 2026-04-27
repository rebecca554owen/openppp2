/**
 * @file websocket_async_sslv_websocket.h
 * @brief Declares asynchronous SSLv WebSocket adapter utilities.
 */

#pragma once 

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
             * @brief Asynchronous SSL-enabled WebSocket adapter built on SslSocket template.
             */
            class AsyncSslvWebSocket final : public ppp::net::asio::templates::SslSocket<std::shared_ptr<sslwebsocket::SslvWebSocket>/**/> {
            public:
                /**
                 * @brief Constructs an asynchronous SSLv WebSocket adapter.
                 * @param reference Owner instance used to control object lifetime.
                 * @param tcp_socket Underlying TCP socket shared pointer.
                 * @param ssl_context SSL context used to initialize TLS stream.
                 * @param ssl_websocket Storage for SSL WebSocket stream object.
                 * @param verify_peer Whether certificate verification is enabled.
                 * @param binary Whether to use binary frame mode.
                 * @param host Host name associated with the remote endpoint.
                 * @param path WebSocket request path.
                 * @param certificate_file Certificate file path.
                 * @param certificate_key_file Private key file path.
                 * @param certificate_chain_file Certificate chain file path.
                 * @param certificate_key_password Private key password.
                 * @param ciphersuites TLS cipher suites configuration.
                 */
                AsyncSslvWebSocket(
                    const std::shared_ptr<sslwebsocket>&                        reference,
                    std::shared_ptr<boost::asio::ip::tcp::socket>&              tcp_socket,
                    std::shared_ptr<boost::asio::ssl::context>&                 ssl_context,
                    std::shared_ptr<sslwebsocket::SslvWebSocket>&               ssl_websocket,
                    bool                                                        verify_peer,
                    bool                                                        binary,
                    const ppp::string&                                          host,
                    const ppp::string&                                          path,
                    const std::string&                                          certificate_file,
                    const std::string&                                          certificate_key_file,
                    const std::string&                                          certificate_chain_file,
                    const std::string&                                          certificate_key_password,
                    const std::string&                                          ciphersuites) noexcept;

            public:
                /**
                 * @brief Performs the WebSocket protocol handshake over SSL.
                 * @param handshaked_client Indicates whether client side is already handshaked.
                 * @param y Coroutine yield context for asynchronous waiting.
                 * @return true on successful handshake; otherwise false.
                 */
                bool                                                            PerformWebSocketHandshake(bool handshaked_client, YieldContext& y) noexcept;
                /**
                 * @brief Releases owned resources and closes underlying connection state.
                 */
                virtual void                                                    Dispose() noexcept override;
                /**
                 * @brief Returns native OpenSSL handle for low-level SSL operations.
                 * @return Pointer to SSL handle, or nullptr when unavailable.
                 */
                virtual SSL*                                                    GetSslHandle() noexcept override;
                /**
                 * @brief Performs SSL/TLS handshake for this socket.
                 * @param handshaked_client Indicates whether client side handshake is done.
                 * @param y Coroutine yield context.
                 * @return true if SSL handshake succeeds; otherwise false.
                 */
                virtual bool                                                    PerformSslHandshake(bool handshaked_client, YieldContext& y) noexcept override;

            private:
                /** @brief WebSocket request path used during handshake. */
                ppp::string                                                     path_;
                /** @brief Strong owner reference for coordinated disposal. */
                std::shared_ptr<sslwebsocket>                                   reference_;
                /** @brief Indicates whether message frames are treated as binary. */
                bool                                                            binary_ = false;
            };
        }
    }
}
