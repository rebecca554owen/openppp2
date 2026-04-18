#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

/**
 * @file websocket_ssl_close_websocket.cpp
 * @brief Implements close and scheduler-shift operations for SSL WebSocket sessions.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Disposes the SSL WebSocket and closes underlying transport layers.
             * @return This function does not return a value.
             * @note Close and shutdown are dispatched onto the configured executor context.
             */
            void sslwebsocket::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                /**
                 * @brief Performs asynchronous websocket close and TLS shutdown in order.
                 */
                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        std::shared_ptr<SslvWebSocket> ssl_websocket = std::move(ssl_websocket_);
                        disposed_ = true;

                        if (NULLPTR != ssl_websocket) {
                            ssl_websocket->async_close(boost::beast::websocket::close_code::normal,
                                [self, this, ssl_websocket](const boost::system::error_code& ec_) noexcept {
                                    sslwebsocket::SslvTcpSocket& ssl_socket = ssl_websocket->next_layer();
                                    ssl_socket.async_shutdown(
                                        [self, this, ssl_websocket, &ssl_socket](const boost::system::error_code& ec_) noexcept {
                                            Socket::Closesocket(ssl_socket.next_layer());
                                        });
                                    return true;
                                });
                        }
                    });
            }

            /**
             * @brief Moves the underlying TCP socket to a scheduler-managed context.
             * @return true if the socket is successfully moved; otherwise false.
             */
            bool sslwebsocket::ShiftToScheduler() noexcept {
                std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULLPTR == ssl_websocket) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket_new;
                ppp::threading::Executors::ContextPtr scheduler;
                ppp::threading::Executors::StrandPtr strand;

                auto& socket = ssl_websocket->next_layer().next_layer();
                bool ok = ppp::threading::Executors::ShiftToScheduler(socket, socket_new, scheduler, strand);
                if (ok) {
                    socket = std::move(*socket_new);
                    strand_ = strand;
                    context_ = scheduler;
                }

                return ok;
            }
        }
    }
}
