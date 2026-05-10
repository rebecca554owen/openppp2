#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/Error.h>

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
                , sending_(false)
                , pending_items_(0)
                , pending_bytes_(0)
                , max_pending_items_(4096)
                , max_pending_bytes_(16 * 1024 * 1024) {

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
                /**
                 * @brief One-shot guard: atomically transition to disposed state.
                 *
                 * If already disposed (exchange returns true), another thread or
                 * a prior Dispose()/destructor call has already drained the queue.
                 * Returning early avoids re-acquiring syncobj_ and double-draining.
                 */
                if (disposed_.exchange(true, std::memory_order_acq_rel)) {
                    return;
                }

                /** @brief Detach the pending queue under lock. */
                AsynchronousWriteIoContextQueue queues;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    sending_ = false;

                    queues = std::move(queues_);
                    queues_.clear();
                }

                /** @brief Drain backpressure counters for all queued contexts being dropped. */
                int drain_items = 0;
                int drain_bytes = 0;
                for (AsynchronousWriteIoContextPtr& context : queues) {
                    if (NULLPTR != context) {
                        drain_items++;
                        drain_bytes += context->packet_length;
                    }
                    context->Forward(false);
                }

                if (drain_items > 0) {
                    pending_items_.fetch_sub(drain_items, std::memory_order_relaxed);
                }
                if (drain_bytes > 0) {
                    pending_bytes_.fetch_sub(drain_bytes, std::memory_order_relaxed);
                }
            }

            /** @brief Creates a shared copy of raw bytes using configured allocator strategy. */
            std::shared_ptr<Byte> IAsynchronousWriteIoQueue::Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept {
                if (NULLPTR == data || 1 > datalen) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueCopyInvalidArguments);
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
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueCopyAllocFailed);
                }

                return chunk;
            }

            /** @brief Coroutine-based write wrapper that dispatches through callback path. */
            bool IAsynchronousWriteIoQueue::WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
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
             *
             * @note Two-phase locking: sending_ is set to true under syncobj_ before the
             *       lock is released, then DoTryWriteBytesUnsafe() is called outside the
             *       lock.  This prevents the async-completion callback chain
             *       (evtf → DoTryWriteBytesNext → syncobj_) from re-entering the mutex
             *       while this call site still holds it.
             */
            bool IAsynchronousWriteIoQueue::WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                IAsynchronousWriteIoQueue* const q = this;
                if (q->disposed_.load(std::memory_order_acquire)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    return false;
                }

                if (NULLPTR == packet || 1 > packet_length) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueWriteInvalidPacket);
                    return false;
                }

                if (NULLPTR == cb) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueWriteNullCallback);
                    return false;
                }

                std::shared_ptr<AsynchronousWriteIoContext> context = make_shared_object<AsynchronousWriteIoContext>();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueWriteContextAllocFailed);
                    return false;
                }

                context->cb            = cb;
                context->packet        = packet;
                context->packet_length = packet_length;

                /** @brief Context to be dispatched outside the lock; null if this request was enqueued. */
                std::shared_ptr<AsynchronousWriteIoContext> ctx_to_send;

                {
                    SynchronizedObjectScope scope(q->syncobj_);
                    if (q->disposed_.load(std::memory_order_acquire)) {
                        context->Clear();
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                        return false;
                    }

                    /**
                     * @brief Backpressure check and counter reservation in one critical section.
                     *
                     * Checking threshold and incrementing counters under the same lock prevents
                     * concurrent WriteBytes() callers from all passing the check and then all
                     * incrementing, which would overshoot the configured limits.
                     */
                    int cur_items = q->pending_items_.load(std::memory_order_relaxed);
                    int cur_bytes = q->pending_bytes_.load(std::memory_order_relaxed);
                    int mpi = q->max_pending_items_.load(std::memory_order_relaxed);
                    int mpb = q->max_pending_bytes_.load(std::memory_order_relaxed);

                    if (mpi > 0 && cur_items >= mpi) {
                        context->Clear();
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueBackpressure);
                        return false;
                    }

                    if (mpb > 0 && cur_bytes + packet_length > mpb) {
                        context->Clear();
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueBackpressure);
                        return false;
                    }

                    /**
                     * @brief Reserve backpressure counters atomically with the accept decision.
                     *
                     * Incrementing here (inside the lock) together with the threshold check
                     * ensures that concurrent callers cannot collectively overshoot the limit.
                     * The counters are decremented on: (a) evtf completion callback,
                     * (b) write-start failure in this function, or (c) Finalize() drain.
                     */
                    q->pending_items_.fetch_add(1, std::memory_order_relaxed);
                    q->pending_bytes_.fetch_add(packet_length, std::memory_order_relaxed);

                    if (q->sending_) {
                        /** @brief Another write is in flight; defer this request into the pending queue. */
                        q->queues_.emplace_back(context);
                        return true;
                    }

                    /**
                     * @brief Pre-arm the sending guard under the lock before releasing it.
                     *
                     * Concurrent WriteBytes() callers observe sending_ = true and enqueue
                     * their contexts rather than attempting a second parallel write.
                     * DoTryWriteBytesUnsafe() is called below after the lock is released.
                     */
                    q->sending_ = true;
                    ctx_to_send = context;
                }

                /** @brief Initiate the write outside the lock. */
                bool write_ok = q->DoTryWriteBytesUnsafe(ctx_to_send);
                if (!write_ok) {
                    /**
                     * @brief Write failed to start.  Advance the queue so that any context
                     *        enqueued by a concurrent thread during the window between setting
                     *        sending_ = true and this failure is not silently abandoned.
                     */
                    int drain = DoTryWriteBytesNext();

                    /**
                     * @brief Save packet_length before Clear() zeros it.
                     *
                     * Clear() sets packet_length to 0, so we must capture the original
                     * value first to decrement pending_bytes_ correctly.
                     */
                    int saved_length = ctx_to_send->packet_length;
                    ctx_to_send->Clear();

                    /** @brief Decrement backpressure counters for the failed ctx_to_send (evtf will not fire). */
                    q->pending_items_.fetch_sub(1, std::memory_order_relaxed);
                    q->pending_bytes_.fetch_sub(saved_length, std::memory_order_relaxed);

                    if (drain < 0) {
                        Dispose();
                    }

                    if (q->disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    }
                    else {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                    }
                    return false;
                }

                return true;
            }

            /**
             * @brief Starts the physical write for the given context.
             *
             * Registers an async completion callback that either advances the queue
             * (DoTryWriteBytesNext) on success or disposes the queue on failure.
             *
             * @note The caller MUST set sending_ = true under syncobj_ before releasing
             *       the lock and then invoke this function OUTSIDE the lock.  This two-phase
             *       discipline prevents DoWriteBytes — and its async-completion chain through
             *       evtf (→ DoTryWriteBytesNext → syncobj_ acquisition) — from re-entering
             *       the mutex while the caller still holds it, which would deadlock on the
             *       non-recursive std::mutex.
             */
            bool IAsynchronousWriteIoQueue::DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    return false;
                }

                auto self = shared_from_this();
                auto evtf =
                    [self, this, context](bool ok) noexcept {
                        int err = -1;
                        context->Forward(ok);

                        /** @brief Decrement backpressure counters for the completed in-flight context. */
                        pending_items_.fetch_sub(1, std::memory_order_relaxed);
                        pending_bytes_.fetch_sub(context->packet_length, std::memory_order_relaxed);

                        if (ok) {
                            err = DoTryWriteBytesNext();
                        }

                        if (err < 0) {
                            Dispose();
                        }
                    };

                return DoWriteBytes(context->packet, 0, context->packet_length, evtf);
            }

            /**
             * @brief Advances the queue to the next pending write context.
             *
             * Returns 1 when another write is started, 0 when the queue is empty, and -1
             * on disposal or an unrecoverable write-start failure.
             *
             * @note Two-phase locking: sending_ is reset to false and then, when a next
             *       context is found, set back to true — all under syncobj_.
             *       DoTryWriteBytesUnsafe() is then called OUTSIDE the lock to avoid
             *       re-entering syncobj_ through the evtf completion callback chain.
             */
            int IAsynchronousWriteIoQueue::DoTryWriteBytesNext() noexcept {
                std::shared_ptr<AsynchronousWriteIoContext> context;

                {
                    SynchronizedObjectScope scope(syncobj_);
                    sending_ = false;

                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                        return -1;
                    }

                    /** @brief Skip null or already-cleared entries at the queue head. */
                    while (!queues_.empty()) {
                        context = std::move(queues_.front());
                        queues_.erase(queues_.begin());
                        if (NULLPTR != context) {
                            break;
                        }
                    }

                    if (NULLPTR == context) {
                        /** @brief Queue exhausted; sending_ stays false for the next caller. */
                        return 0;
                    }

                    /**
                     * @brief Pre-arm the sending guard before releasing the lock so that
                     *        concurrent WriteBytes() callers enqueue rather than attempt a
                     *        competing parallel write.
                     */
                    sending_ = true;
                }

                /** @brief Start the next write outside the lock to prevent re-entrancy through evtf. */
                bool ok = DoTryWriteBytesUnsafe(context);
                if (!ok) {
                    context->Forward(false);

                    /** @brief Decrement backpressure counters for the failed queued context (evtf will not fire). */
                    pending_items_.fetch_sub(1, std::memory_order_relaxed);
                    pending_bytes_.fetch_sub(context->packet_length, std::memory_order_relaxed);

                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    }
                    else {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                    }
                    return -1;
                }

                return 1;
            }
        }
    }
}
