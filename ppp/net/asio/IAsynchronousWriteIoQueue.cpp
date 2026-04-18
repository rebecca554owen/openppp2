#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/collections/Dictionary.h>

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @file IAsynchronousWriteIoQueue.cpp
             * @brief Implements serialized asynchronous write queue lifecycle and dispatch.
             */

            /** @brief Initializes queue state and stores allocator reference. */
            IAsynchronousWriteIoQueue::IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept
                : BufferAllocator(allocator)
                , disposed_(false)
                , sending_(false) {

            }

            /** @brief Releases resources and fails all pending write operations. */
            IAsynchronousWriteIoQueue::~IAsynchronousWriteIoQueue() noexcept {
                Finalize();
            }

            /** @brief Public disposal entry that finalizes queue state. */
            void IAsynchronousWriteIoQueue::Dispose() noexcept {
                Finalize();
            }

            /**
             * @brief Finalizes queue state and forwards failure to pending callbacks.
             *
             * The pending queue is moved out under lock, then callbacks are invoked without
             * holding the synchronization object to avoid lock re-entrancy issues.
             */
            void IAsynchronousWriteIoQueue::Finalize() noexcept {
                AsynchronousWriteIoContextQueue queues;
                for (;;) {
                    /** @brief Atomically transition to disposed state and detach pending queue. */
                    SynchronizedObjectScope scope(syncobj_);
                    disposed_ = true;
                    sending_ = false;

                    queues = std::move(queues_);
                    queues_.clear();
                    break;
                }

                for (AsynchronousWriteIoContextPtr& context : queues) {
                    context->Forward(false);
                }
            }

            /** @brief Creates a shared copy of raw bytes using configured allocator strategy. */
            std::shared_ptr<Byte> IAsynchronousWriteIoQueue::Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept {
                if (NULLPTR == data || datalen < 1) {
                    return NULLPTR;
                }

                std::shared_ptr<Byte> chunk;
                if (NULLPTR != allocator) {
                    chunk = allocator->MakeArray<Byte>(datalen);
                }
                else {
                    chunk = make_shared_alloc<Byte>(datalen);
                }

                if (NULLPTR != chunk) {
                    void* memory = chunk.get();
                    memcpy(memory, data, datalen);
                }

                return chunk;
            }

            /** @brief Coroutine-based write wrapper that dispatches through callback path. */
            bool IAsynchronousWriteIoQueue::WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                if (disposed_) {
                    return false;
                }

                return DoWriteYield<AsynchronousWriteBytesCallback>(y, packet, packet_length,
                    [this](const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                        return WriteBytes(packet, packet_length, cb);
                    });
            }

            /**
             * @brief Enqueues a write context or dispatches immediately when idle.
             *
             * Requests are serialized via @ref sending_ and @ref queues_ to guarantee
             * ordered completion callbacks.
             */
            bool IAsynchronousWriteIoQueue::WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                IAsynchronousWriteIoQueue* const q = this;
                if (q->disposed_) {
                    return false;
                }

                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                if (NULLPTR == cb) {
                    return false;
                }

                std::shared_ptr<AsynchronousWriteIoContext> context = make_shared_object<AsynchronousWriteIoContext>();
                if (NULLPTR == context) {
                    return false;
                }

                context->cb = cb;
                context->packet = packet;
                context->packet_length = packet_length;

                bool ok = false;
                while (NULLPTR != q) {
                    /** @brief Serialize either direct dispatch or deferred enqueue. */
                    SynchronizedObjectScope scope(q->syncobj_);
                    if (q->sending_) {
                        if (q->disposed_) {
                            break;
                        }

                        ok = true;
                        q->queues_.emplace_back(context);
                    }
                    else {
                        ok = q->DoTryWriteBytesUnsafe(context);
                    }

                    break;
                }

                if (ok) {
                    return true;
                }

                context->Clear();
                return false;
            }

            /**
             * @brief Attempts to start writing the provided context.
             *
             * On completion, this schedules progression to the next queued write and disposes
             * the queue when progression fails.
             */
            bool IAsynchronousWriteIoQueue::DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                auto evtf = 
                    [self, this, context](bool ok) noexcept {
                        int err = -1;
                        context->Forward(ok);

                        if (ok) {
                            err = DoTryWriteBytesNext();
                        }

                        if (err < 0) {
                            Dispose();
                        }
                    };

                bool ok = DoWriteBytes(context->packet, 0, context->packet_length, evtf);
                if (ok) {
                    sending_ = true;
                }

                return ok;
            }

            /**
             * @brief Advances the queue to the next pending write context.
             *
             * Returns 1 when another write is started, 0 when queue is empty, and -1 on
             * disposal or unrecoverable write start failure.
             */
            int IAsynchronousWriteIoQueue::DoTryWriteBytesNext() noexcept {
                bool ok = false;
                std::shared_ptr<AsynchronousWriteIoContext> context;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    sending_ = false;

                    if (disposed_) {
                        return -1;
                    }

                    do {
                        auto tail = queues_.begin();
                        auto endl = queues_.end();
                        if (tail == endl) {
                            return 0;
                        }

                        context = std::move(*tail);
                        queues_.erase(tail);
                    } while (NULLPTR == context);

                    ok = DoTryWriteBytesUnsafe(context);
                    break;
                }

                if (ok) {
                    return 1;
                }

                context->Forward(false);
                return -1;
            }
        }
    }
}
