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
                    return false;
                }

                if (IsDisposed() || !websocket_.is_open()) {
                    return false;
                }

                return ppp::coroutines::asio::async_read(websocket_, boost::asio::buffer((Byte*)buffer + offset, length), y);
            }
        }
    }
}
