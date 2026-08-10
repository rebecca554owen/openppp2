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
             * Disposal is linearized under the queue lock. The active context is claimed
             * there against its physical completion; waiting contexts are detached and
             * completed outside the lock without allocating callback storage.
             */
            void IAsynchronousWriteIoQueue::Finalize() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return;
                }

                AsynchronousWriteIoContextPtr active;
                AsynchronousWriteIoContextQueue waiting;
                AsynchronousWriteBytesCallback active_callback;
                int active_length = 0;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.exchange(true, std::memory_order_acq_rel)) {
                        return;
                    }

                    active = std::move(in_flight_);
                    waiting = std::move(queues_);
                    queues_.clear();
                    sending_ = false;
                    if (NULLPTR != active) {
                        active->Claim(active_callback, active_length);
                    }
                    pending_items_.store(0, std::memory_order_relaxed);
                    pending_bytes_.store(0, std::memory_order_relaxed);
                }

                if (NULLPTR != active_callback) {
                    active_callback(false);
                }
                for (AsynchronousWriteIoContextPtr& context : waiting) {
                    if (NULLPTR == context) {
                        continue;
                    }

                    AsynchronousWriteBytesCallback callback;
                    int packet_length = 0;
                    if (context->Claim(callback, packet_length) && NULLPTR != callback) {
                        callback(false);
                    }
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

            /**
             * @brief Zero-copy slice overload of @ref Copy.
             *
             * @warning The returned shared_ptr aliases @p owner's buffer WITHOUT
             *          copying. Callers MUST guarantee @p data points inside
             *          @p owner's allocation (i.e. the owner buffer is NOT reused
             *          or overwritten until the returned slice is consumed) and
             *          MUST consume the slice synchronously or keep the source
             *          region stable for the slice's whole lifetime. Reusing the
             *          source buffer before consumption silently corrupts data.
             *          Prefer the copy-based overload unless the fast path is
             *          proven safe on the calling path.
             */
            std::shared_ptr<Byte> IAsynchronousWriteIoQueue::Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<Byte>& owner, const void* data, int datalen) noexcept {
                if (NULLPTR == data || 1 > datalen) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueCopyInvalidArguments);
                    return NULLPTR;
                }

                // Zero-copy path: slice the owner buffer.
                // The slice must point at or after the owner allocation start;
                // anything before it cannot belong to the owner. The upper bound
                // is enforced by the calling contract (data must reside inside
                // owner's allocation).
                if (NULLPTR != owner) {
                    const ppp::Byte* owner_begin = owner.get();
                    const ppp::Byte* slice = reinterpret_cast<const ppp::Byte*>(data);
                    if (slice < owner_begin) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueCopyInvalidArguments);
                        return NULLPTR;
                    }
                    return ppp::wrap_shared_pointer(const_cast<ppp::Byte*>(slice), owner);
                }

                // Fallback: copy-based path.
                return Copy(allocator, data, datalen);
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
             *       lock. This prevents synchronous or asynchronous completion from
             *       re-entering syncobj_ while this call site still holds it.
             */
            bool IAsynchronousWriteIoQueue::WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    return false;
                }

                // add upper bound check to prevent overflow
                static constexpr int MAX_PACKET_LENGTH = 256 * 1024; // 256KB limit
                if (NULLPTR == packet || packet_length < 1 || packet_length > MAX_PACKET_LENGTH) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueWriteInvalidPacket);
                    return false;
                }

                if (NULLPTR == cb) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueWriteNullCallback);
                    return false;
                }

                AsynchronousWriteIoContextPtr context = make_shared_object<AsynchronousWriteIoContext>();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueWriteContextAllocFailed);
                    return false;
                }

                context->cb = cb;
                context->packet = packet;
                context->packet_length = packet_length;

                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                        return false;
                    }

                    const int cur_items = pending_items_.load(std::memory_order_relaxed);
                    const int cur_bytes = pending_bytes_.load(std::memory_order_relaxed);
                    const int mpi = max_pending_items_.load(std::memory_order_relaxed);
                    const int mpb = max_pending_bytes_.load(std::memory_order_relaxed);

                    // use int64_t to prevent addition overflow
                    if ((mpi > 0 && cur_items >= mpi) ||
                        (mpb > 0 && (static_cast<int64_t>(cur_bytes) + packet_length > mpb))) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueBackpressure);
                        return false;
                    }

                    pending_items_.fetch_add(1, std::memory_order_relaxed);
                    pending_bytes_.fetch_add(packet_length, std::memory_order_relaxed);
                    if (NULLPTR != in_flight_) {
                        queues_.emplace_back(context);
                        sending_ = true;
                        return true;
                    }

                    in_flight_ = context;
                    sending_ = true;
                }

                if (!DoTryWriteBytesUnsafe(context, false)) {
                    if (disposed_.load(std::memory_order_acquire)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionClosing);
                    }
                    else {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                    }
                    return false;
                }

                return true;
            }

            /** @brief Starts one preselected context without holding the queue lock. */
            bool IAsynchronousWriteIoQueue::DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context, bool callback_on_start_failure) noexcept {
                // drive the drain loop instead of recursing to avoid unbounded stack growth
                AsynchronousWriteIoContextPtr current = context;
                bool current_callback_on_failure = callback_on_start_failure;
                bool initial_start_failed = false;

                while (NULLPTR != current) {
                    auto self = shared_from_this();
                    auto evtf =
                        [self, this, current](bool ok) noexcept {
                            AsynchronousWriteBytesCallback callback;
                            AsynchronousWriteIoContextPtr next;
                            AsynchronousWriteIoContextQueue failed;
                            int packet_length = 0;
                            {
                                SynchronizedObjectScope scope(syncobj_);
                                if (current != in_flight_ || !current->Claim(callback, packet_length)) {
                                    return;
                                }

                                in_flight_.reset();
                                pending_items_.fetch_sub(1, std::memory_order_relaxed);
                                pending_bytes_.fetch_sub(packet_length, std::memory_order_relaxed);
                                if (!ok) {
                                    disposed_.store(true, std::memory_order_release);
                                    failed = std::move(queues_);
                                    queues_.clear();
                                    pending_items_.store(0, std::memory_order_relaxed);
                                    pending_bytes_.store(0, std::memory_order_relaxed);
                                }
                                elif(!disposed_.load(std::memory_order_acquire) && !queues_.empty()) {
                                    next = std::move(queues_.front());
                                    queues_.erase(queues_.begin());
                                    in_flight_ = next;
                                }
                                sending_ = NULLPTR != in_flight_;
                            }

                            callback(ok);
                            for (AsynchronousWriteIoContextPtr& waiting : failed) {
                                if (NULLPTR == waiting) {
                                    continue;
                                }
                                AsynchronousWriteBytesCallback failed_callback;
                                int failed_length = 0;
                                if (waiting->Claim(failed_callback, failed_length) && NULLPTR != failed_callback) {
                                    failed_callback(false);
                                }
                            }
                            if (NULLPTR != next) {
                                DoTryWriteBytesUnsafe(next, true);
                            }
                        };

                    std::shared_ptr<Byte> packet;
                    int packet_length = 0;
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        if (disposed_.load(std::memory_order_acquire) || current != in_flight_) {
                            return false;
                        }
                        packet = current->packet;
                        packet_length = current->packet_length;
                    }

                    if (DoWriteBytes(packet, 0, packet_length, evtf)) {
                        return !initial_start_failed;
                    }

                    AsynchronousWriteBytesCallback callback;
                    AsynchronousWriteIoContextPtr next;
                    AsynchronousWriteIoContextQueue failed;
                    int claimed_length = 0;
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        // A synchronous completion or Finalize already owns all terminal state.
                        if (!current->Claim(callback, claimed_length)) {
                            return !initial_start_failed;
                        }

                        if (!current_callback_on_failure) {
                            initial_start_failed = true;
                        }
                        if (current == in_flight_) {
                            in_flight_.reset();
                        }
                        pending_items_.fetch_sub(1, std::memory_order_relaxed);
                        pending_bytes_.fetch_sub(claimed_length, std::memory_order_relaxed);
                        if (current_callback_on_failure) {
                            disposed_.store(true, std::memory_order_release);
                            failed = std::move(queues_);
                            queues_.clear();
                            pending_items_.store(0, std::memory_order_relaxed);
                            pending_bytes_.store(0, std::memory_order_relaxed);
                        }
                        elif(!disposed_.load(std::memory_order_acquire) && !queues_.empty()) {
                            next = std::move(queues_.front());
                            queues_.erase(queues_.begin());
                            in_flight_ = next;
                        }
                        sending_ = NULLPTR != in_flight_;
                    }

                    if (current_callback_on_failure) {
                        callback(false);
                        for (AsynchronousWriteIoContextPtr& waiting : failed) {
                            if (NULLPTR == waiting) {
                                continue;
                            }
                            AsynchronousWriteBytesCallback failed_callback;
                            int failed_length = 0;
                            if (waiting->Claim(failed_callback, failed_length) && NULLPTR != failed_callback) {
                                failed_callback(false);
                            }
                        }
                    }

                    // loop to the next item to avoid recursion
                    if (NULLPTR != next) {
                        current = next;
                        current_callback_on_failure = true;
                    } else {
                        return false;
                    }
                }
                return false;
            }
        }
    }
}
