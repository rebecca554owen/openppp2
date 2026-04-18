#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>

/**
 * @file websocket_write_websocket.cpp
 * @brief Implements asynchronous write dispatch for non-SSL WebSocket sessions.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Queues an asynchronous write operation on the websocket stream.
             * @param buffer Source buffer that contains bytes to send.
             * @param offset Zero-based byte offset into @p buffer where sending starts.
             * @param length Number of bytes to send.
             * @param cb Completion callback that receives whether sending succeeded.
             * @return true if the operation is posted to the executor; otherwise false.
             */
            bool websocket::Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept {
                if (NULLPTR == buffer || offset < 0 || length < 1) {
                    return false;
                }

                if (NULLPTR == cb) {
                    return false;
                }

                if (IsDisposed() || !websocket_.is_open()) {
                    return false;
                }

                const std::shared_ptr<websocket> self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                /**
                 * @brief Executes websocket async_write on the serialized executor strand.
                 */
                auto complete_do_write_async_callback = [self, this, cb, buffer, offset, length, context, strand]() noexcept {
                    websocket_.async_write(boost::asio::buffer(((Byte*)buffer) + (offset), length),
                        [self, this, cb](const boost::system::error_code& ec, size_t sz) noexcept {
                            bool ok = ec == boost::system::errc::success;
                            if (cb) {
                                cb(ok); /* b is boost::system::errc::success. */
                            }
                        });
                    };

                return ppp::threading::Executors::Post(context, strand, complete_do_write_async_callback);
            }
        }
    }
}
