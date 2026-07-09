/**
 * @file websocket_read_websocket.cpp
 * @brief Implements buffered read operations for WebSocket transport.
 */

#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/diagnostics/Error.h>

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Reads exactly length bytes from WebSocket stream into caller buffer.
             * @param buffer Destination memory buffer.
             * @param offset Byte offset inside destination buffer.
             * @param length Number of bytes to read.
             * @param y Coroutine yield context for asynchronous read.
             * @return true if the read completes successfully; otherwise false.
             */
            bool websocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (NULLPTR == buffer || offset < 0 || length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketReadInvalidArguments);
                    return false;
                }

                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!websocket_.is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                bool ok = ppp::coroutines::asio::async_read(websocket_, boost::asio::buffer((Byte*)buffer + offset, length), y);
                if (!ok && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketReadFailed);
                }
                return ok;
            }
        }
    }
}
