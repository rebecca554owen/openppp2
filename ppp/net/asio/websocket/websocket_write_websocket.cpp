#include <ppp/net/asio/websocket.h>
#include <ppp/net/asio/templates/SslSocket.h>
#include <ppp/net/asio/templates/WebSocket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/diagnostics/Error.h>

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
                if (NULLPTR == buffer || 0 > offset || 1 > length) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketWriteInvalidArguments);
                    return false;
                }

                if (NULLPTR == cb) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketWriteNullCallback);
                    return false;
                }

                if (true == IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (false == websocket_.is_open()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    return false;
                }

                /**
                 * @brief Takes ownership of the payload before dispatching; the caller is
                 *        free to release or overwrite @p buffer as soon as this call returns.
                 */
                std::shared_ptr<Byte> payload = ppp::make_shared_alloc<Byte>(length);
                if (NULLPTR == payload) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }
                memcpy(payload.get(), (const Byte*)buffer + offset, length);

                const std::shared_ptr<websocket> self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                /**
                 * @brief Enqueues the write on the serialized executor strand; the Beast
                 *        async_write chain itself is driven by DoWriteAsync() so that at
                 *        most one write is ever in flight on the stream.
                 */
                auto complete_do_write_async_callback = [self, this, cb, payload, length, context, strand]() noexcept {
                    bool saturated = false;
                    bool saturation_post_failed = false;
                    {
                        std::lock_guard<std::mutex> scope(write_mutex_);

                        constexpr size_t MAX_QUEUE_SIZE = 1024;
                        if (write_queue_.size() >= MAX_QUEUE_SIZE) {
                            // Queue saturation is backpressure: deliver the
                            // failure callback OUTSIDE the lock so a re-entrant
                            // callback cannot deadlock on write_mutex_.  The
                            // posted lambda never runs inline, so posting while
                            // holding write_mutex_ is safe; the synchronous
                            // fallback below runs after the lock is released.
                            saturated = true;
                            if (cb) {
                                saturation_post_failed = !ppp::threading::Executors::Post(
                                    context, strand, [cb]() noexcept { cb(false); });
                            }
                        }
                        else {
                            AsynchronousWriteContext message;
                            message.buffer = payload;
                            message.length = length;
                            message.cb     = cb;
                            write_queue_.emplace_back(std::move(message));
                            if (write_in_progress_) {
                                return;
                            }

                            write_in_progress_ = true;
                        }
                    }

                    if (saturated) {
                        // The Post rejected the callback delivery (e.g. the
                        // context is stopped): this lambda already runs on the
                        // strand, so deliver the failure synchronously, outside
                        // write_mutex_, to avoid losing the completion and
                        // stalling the IAsynchronousWriteIoQueue in-flight slot.
                        if (saturation_post_failed && cb) {
                            cb(false);
                        }
                        return;
                    }

                    DoWriteAsync();
                };

                bool ok = ppp::threading::Executors::Post(context, strand, complete_do_write_async_callback);
                if (false == ok && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                }
                return ok;
            }

            /**
             * @brief Starts the next queued asynchronous write, if any.
             *
             * Pops one message from the write queue and issues Beast async_write for it;
             * the completion handler re-enters this method, so queued writes are emitted
             * strictly one at a time as required by Boost.Beast.
             */
            void websocket::DoWriteAsync() noexcept {
                AsynchronousWriteContext message;
                {
                    std::lock_guard<std::mutex> scope(write_mutex_);
                    if (write_queue_.empty()) {
                        write_in_progress_ = false;
                        return;
                    }

                    message = std::move(write_queue_.front());
                    write_queue_.pop_front();
                }

                const std::shared_ptr<websocket> self = shared_from_this();
                const std::shared_ptr<Byte> payload = message.buffer;
                const AsynchronousWriteCallback cb = message.cb;
                websocket_.async_write(boost::asio::buffer(payload.get(), message.length),
                    [self, this, payload, cb](const boost::system::error_code& ec, size_t sz) noexcept {
                        bool ok = boost::system::errc::success == ec;
                        if (false == ok) {
                            if (boost::asio::error::operation_aborted != ec &&
                                boost::beast::websocket::error::closed != ec &&
                                boost::asio::error::eof != ec)
                            {
                                if (boost::asio::error::timed_out == ec) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketTimeout);
                                }
                                elif (boost::asio::error::connection_reset == ec ||
                                      boost::asio::error::connection_aborted == ec ||
                                      boost::asio::error::not_connected == ec)
                                {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                                }
                                elif (boost::asio::error::invalid_argument == ec) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                                }
                                elif (boost::beast::websocket::make_error_code(boost::beast::websocket::error::closed).category() == ec.category()) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketWriteFailed);
                                }
                                else {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                                }
                            }
                        }

                        if (NULLPTR != cb) {
                            cb(ok); /* b is boost::system::errc::success. */
                        }

                        /* Drains the next queued write; keeps at most one async_write in flight. */
                        DoWriteAsync();
                    });
            }
        }
    }
}
