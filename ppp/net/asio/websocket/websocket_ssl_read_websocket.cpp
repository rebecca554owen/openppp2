#include <ppp/net/asio/websocket/websocket_async_sslv_websocket.h>
#include <ppp/net/asio/websocket/websocket_accept_sslv_websocket.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file websocket_ssl_read_websocket.cpp
 * @brief Implements synchronous-style read operation wrappers for SSL WebSocket sessions.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Reads a fixed number of bytes from the SSL WebSocket stream.
             * @param buffer Destination buffer that receives incoming bytes.
             * @param offset Zero-based byte offset into @p buffer where writing starts.
             * @param length Number of bytes to read.
             * @param y Coroutine yield context used to suspend and resume the operation.
             * @return true if read succeeds; otherwise false.
             */
            bool sslwebsocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (NULLPTR == buffer || offset < 0 || length < 1) {
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

                return ppp::coroutines::asio::async_read(*ssl_websocket, boost::asio::buffer((Byte*)buffer + offset, length), y);
            }
        }
    }
}
