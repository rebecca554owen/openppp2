#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

/**
 * @file websocket_ssl_write_websocket.cpp
 * @brief Implements asynchronous write dispatch for SSL WebSocket sessions.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Queues an asynchronous write operation on the SSL WebSocket.
             * @param buffer Source buffer that contains bytes to send.
             * @param offset Zero-based byte offset into @p buffer where sending starts.
             * @param length Number of bytes to send.
             * @param cb Completion callback that receives whether sending succeeded.
             * @return true if the operation is posted to the executor; otherwise false.
             */
            bool sslwebsocket::Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept {
                if (NULLPTR == buffer || offset < 0 || length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return false;
                }

                if (NULLPTR == cb) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return false;
                }

                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return false;
                }

                const std::shared_ptr<SslvWebSocket> ssl_websocket = ssl_websocket_;
                if (NULLPTR == ssl_websocket || !ssl_websocket->is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return false;
                }

                const std::shared_ptr<sslwebsocket> self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                /**
                 * @brief Executes websocket async_write on the serialized executor strand.
                 */
                auto complete_do_async_write_callback = [self, this, cb, buffer, offset, length, ssl_websocket, context, strand]() noexcept {
                    ssl_websocket->async_write(boost::asio::buffer((Byte*)buffer + offset, length),
                        [self, this, cb](const boost::system::error_code& ec, size_t sz) noexcept {
                            bool ok = ec == boost::system::errc::success;
                            if (cb) {
                                cb(ok); /* b is boost::system::errc::success. */
                            }
                        });
                };

                return ppp::threading::Executors::Post(context, strand, complete_do_async_write_callback);
            }
        }
    }
}
