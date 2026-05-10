#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file IAsynchronousWriteIoQueue.h
 * @brief Declares a serialized asynchronous write queue abstraction.
 *
 * Problem statement
 * -----------------
 * Boost.Asio TCP and UDP sockets are NOT safe for concurrent async_write
 * calls.  Issuing a second async_write before the first completes results
 * in interleaved, corrupted output.  @ref IAsynchronousWriteIoQueue solves
 * this by serialising all outbound packets through an internal FIFO queue:
 * only one async write is in flight at any time; subsequent callers are
 * enqueued and dispatched in order.
 *
 * Design
 * ------
 * - The abstract @ref DoWriteBytes method is implemented by subclasses to
 *   perform the actual platform I/O (TCP send, UDP sendto, WebSocket write, …).
 * - The public @ref WriteBytes(packet, length, cb) entry point and its
 *   coroutine twin @ref WriteBytes(y, packet, length) both delegate to the
 *   queue logic, which calls @ref DoWriteBytes only when no prior write is
 *   pending.
 * - @ref Dispose / @ref Finalize fail all queued callbacks with `false` and
 *   prevent further enqueuing.  Both funnel through a one-shot `exchange` guard
 *   so that concurrent or repeated calls drain the queue exactly once.
 *
 * Thread safety
 * -------------
 * - The queue state (@ref disposed_, @ref sending_, @ref queues_) is protected
 *   by @ref syncobj_.
 * - @ref disposed_ is `std::atomic_bool` to allow lock-free early-exit reads
 *   in @ref WriteBytes / @ref DoTryWriteBytesUnsafe without acquiring @ref syncobj_.
 *   One-shot finalization uses `exchange(acq_rel)`; reads use `load(acquire)` to establish
 *   happens-before ordering with the full critical-section path.
 *
 * Coroutine support
 * -----------------
 * @ref DoWriteYield bridges the callback-based queue with Boost.Asio coroutines:
 * it posts the enqueue call onto the strand, suspends the coroutine, and resumes
 * it when the completion callback fires.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Serialized asynchronous write queue for packet-oriented output.
             *
             * This base class guarantees in-order write dispatch and provides both callback
             * and coroutine-friendly APIs for enqueueing outbound buffers.
             *
             * Subclasses must implement @ref DoWriteBytes to perform the actual I/O and
             * invoke the supplied callback upon completion (success or failure).
             */
            class IAsynchronousWriteIoQueue : public std::enable_shared_from_this<IAsynchronousWriteIoQueue> {
            public:
                /** @brief Completion callback invoked with `true` on success, `false` on failure. */
                typedef ppp::function<void(bool)>                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;
                /** @brief Coroutine yield context alias used by @ref DoWriteYield. */
                typedef ppp::coroutines::YieldContext                   YieldContext;
                /** @brief Buffer allocator used for copying packet memory during enqueue. */
                typedef ppp::threading::BufferswapAllocator             BufferswapAllocator;
                /** @brief Mutex type protecting queue flags and the pending-write list. */
                typedef std::mutex                                      SynchronizedObject;
                /** @brief RAII lock guard for synchronised sections. */
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                /** @brief Atomic integer alias used in coroutine suspension bookkeeping. */
                typedef std::atomic<int>                                atomic_int;
                /** @brief Atomic boolean represented as int (-1 = pending, 0 = false, 1 = true). */
                typedef atomic_int                                      atomic_boolean;

            public:
                /**
                 * @brief Shared allocator used when cloning packet memory into the queue.
                 *
                 * Callers may read this value to allocate compatible buffers before calling
                 * @ref WriteBytes.  Assigned once during construction and never changed.
                 */
                const std::shared_ptr<BufferswapAllocator>              BufferAllocator;

            public:
                /**
                 * @brief Initializes the queue with a packet allocator.
                 * @param allocator  Shared allocator forwarded to @ref BufferAllocator;
                 *                   may be NULLPTR when the subclass manages its own buffers.
                 */
                IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept;

                /**
                 * @brief Finalizes the queue and clears pending write contexts.
                 *
                 * Calls @ref Finalize internally; all queued @ref AsynchronousWriteBytesCallback
                 * instances are invoked with `false` before destruction completes.
                 */
                virtual ~IAsynchronousWriteIoQueue() noexcept;

            public:
                /**
                 * @brief Returns a shared reference to this queue instance.
                 * @return  shared_ptr keeping this object alive for at least one more scope.
                 */
                std::shared_ptr<IAsynchronousWriteIoQueue>              GetReference()          noexcept { return shared_from_this(); }

                /**
                 * @brief Returns the mutex guarding mutable queue state.
                 * @return  Reference to @ref syncobj_; callers may lock it for compound operations.
                 * @warning Holding this lock while calling any public method causes deadlock.
                 */
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }

                /**
                 * @brief Stops the queue and fails all pending operations.
                 *
                 * Delegates to @ref Finalize, which uses a one-shot `exchange` guard
                 * to ensure the queue is drained exactly once even when called
                 * concurrently from multiple threads or after the destructor.
                 * Subclasses should call this (or the base) from their own Dispose overrides.
                 */
                virtual void                                            Dispose() noexcept;

                /**
                 * @brief Copies raw bytes into a newly allocated shared buffer.
                 *
                 * Uses @p allocator when non-null; falls back to global `new[]` otherwise.
                 *
                 * @param allocator  Allocator to use; may be NULLPTR.
                 * @param data       Source data pointer.
                 * @param datalen    Number of bytes to copy; negative returns NULLPTR.
                 * @return           Shared byte buffer containing a copy of @p data, or NULLPTR
                 *                   on allocation failure.
                 */
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept;

                /**
                 * @brief Returns the number of write contexts currently accepted but not yet completed.
                 * @return  Pending item count (queued + in-flight).
                 */
                int                                                     GetPendingItems() const noexcept { return pending_items_.load(std::memory_order_relaxed); }

                /**
                 * @brief Returns the total bytes of write contexts currently accepted but not yet completed.
                 * @return  Pending byte count.
                 */
                int                                                     GetPendingBytes() const noexcept { return pending_bytes_.load(std::memory_order_relaxed); }

                /**
                 * @brief Returns the configured maximum pending item count (0 = unlimited).
                 * @return  Max items threshold.
                 */
                int                                                     GetMaxPendingItems() const noexcept { return max_pending_items_.load(std::memory_order_relaxed); }

                /**
                 * @brief Configures the maximum pending item count.
                 *
                 * Negative values are clamped to 0 (unlimited).
                 *
                 * @param value  Max items; 0 disables the limit.
                 */
                void                                                    SetMaxPendingItems(int value) noexcept { max_pending_items_.store(value < 0 ? 0 : value, std::memory_order_relaxed); }

                /**
                 * @brief Returns the configured maximum pending byte count (0 = unlimited).
                 * @return  Max bytes threshold.
                 */
                int                                                     GetMaxPendingBytes() const noexcept { return max_pending_bytes_.load(std::memory_order_relaxed); }

                /**
                 * @brief Configures the maximum pending byte count.
                 *
                 * Negative values are clamped to 0 (unlimited).
                 *
                 * @param value  Max bytes; 0 disables the limit.
                 */
                void                                                    SetMaxPendingBytes(int value) noexcept { max_pending_bytes_.store(value < 0 ? 0 : value, std::memory_order_relaxed); }

            private:
                /**
                 * @brief Set of coroutine yield contexts waiting for their write to complete.
                 *
                 * Used internally by @ref DoWriteYield; entries are erased when the
                 * corresponding write callback fires.
                 */
                typedef ppp::unordered_set<YieldContext*>               YieldContextSet;

                /**
                 * @brief Context for a single queued write request.
                 *
                 * Holds all state necessary to dispatch one async write and invoke
                 * its completion callback exactly once, even if destruction races
                 * with an in-flight callback.
                 *
                 * Structure layout:
                 *   packet        = std::shared_ptr<Byte>,                 ///< Packet buffer
                 *   packet_length = int,                                   ///< Bytes to send
                 *   cb            = AsynchronousWriteBytesCallback,        ///< Completion handler
                 *   lockobj       = SynchronizedObject                     ///< Per-context lock
                 */
                class AsynchronousWriteIoContext final {
                public:
                    /** @brief Packet buffer to be transmitted. */
                    std::shared_ptr<Byte>                               packet;
                    /** @brief Number of bytes to write from @ref packet offset 0. */
                    int                                                 packet_length = 0;
                    /** @brief Completion callback; invoked exactly once with true/false result. */
                    AsynchronousWriteBytesCallback                      cb;
                    /**
                     * @brief Per-context mutex that serializes @ref Forward and @ref Clear.
                     *
                     * Ensures the callback is not invoked twice if @ref Forward races with
                     * the destructor.
                     */
                    SynchronizedObject                                  lockobj;

                public:
                    /** @brief Constructs an empty write context with zero-initialized length. */
                    AsynchronousWriteIoContext() noexcept
                        : packet_length(0) {

                    }
                    /**
                     * @brief Ensures completion is signaled on destruction.
                     *
                     * If @ref Forward has not yet been called, the destructor calls it with
                     * `false` to prevent callback leaks.
                     */
                    ~AsynchronousWriteIoContext() noexcept {
                        Forward(false);
                    }

                public:
                    /**
                     * @brief Clears packet state and releases callback ownership.
                     *
                     * Called when the context is cancelled (e.g. during @ref Finalize).
                     * Acquires @ref lockobj before nulling @ref cb to avoid races.
                     */
                    void                                                Clear() noexcept {
                        SynchronizedObjectScope scope(lockobj);
                        cb = NULLPTR;
                        packet.reset();
                        packet_length = 0;
                    }

                    /**
                     * @brief Invokes the stored callback once with result status.
                     *
                     * Atomically replaces @ref cb with NULLPTR under @ref lockobj, then
                     * invokes the captured functor outside the lock.
                     *
                     * @param ok  true if the write succeeded; false on error or cancellation.
                     */
                    void                                                Forward(bool ok) noexcept {
                        AsynchronousWriteBytesCallback fx;
                        for (SynchronizedObjectScope scope(lockobj);;) {
                            fx = std::move(cb);
                            cb = NULLPTR;
                            break;
                        }

                        if (NULLPTR != fx) {
                            fx(ok);
                        }
                    }
                };

                /** @brief Shared pointer alias for write context objects. */
                typedef std::shared_ptr<AsynchronousWriteIoContext>     AsynchronousWriteIoContextPtr;
                /**
                 * @brief FIFO queue containing pending write contexts.
                 *
                 * Front element is the currently dispatched (or next-to-dispatch) context.
                 * Back elements are waiting for the front to complete.
                 */
                typedef ppp::list<AsynchronousWriteIoContextPtr>        AsynchronousWriteIoContextQueue;

            private:
                /**
                 * @brief Starts sending a context while the queue lock is held.
                 *
                 * Calls @ref DoWriteBytes with the context's packet data and a lambda
                 * that invokes @ref DoTryWriteBytesNext when the I/O completes.
                 *
                 * @param context  Write context to dispatch (must not be NULLPTR).
                 * @return         true if the async operation was accepted; false on error.
                 * @warning        Must be called with @ref syncobj_ already held.
                 */
                bool                                                    DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context) noexcept;

                /**
                 * @brief Advances queue processing after a write completion.
                 *
                 * Pops the front context, marks @ref sending_ = false, and dispatches
                 * the next context if the queue is non-empty.
                 *
                 * @return  Number of contexts remaining in the queue after advancement.
                 */
                int                                                     DoTryWriteBytesNext() noexcept;

                /**
                 * @brief One-shot finalization that fails all pending operations.
                 *
                 * Uses `disposed_.exchange(true, acq_rel)` to guarantee exactly-once
                 * semantics: the first caller drains the pending queue and decrements
                 * backpressure counters; subsequent callers (Dispose, destructor,
                 * or concurrent threads) return immediately without touching state.
                 *
                 * After the exchange succeeds, acquires @ref syncobj_ to reset
                 * @ref sending_ and detach the pending queue, then releases the lock
                 * before invoking @ref AsynchronousWriteIoContext::Forward(false) on
                 * each drained context to avoid lock re-entrancy.
                 */
                void                                                    Finalize() noexcept;

            protected:
                /**
                 * @brief Coroutine adapter that bridges callback-based writes to yield semantics.
                 *
                 * Posts the enqueue call onto the executor associated with @p y, suspends
                 * the coroutine, and resumes it when the callback fires.  Suitable for use
                 * inside Boost.Asio coroutine bodies (boost::asio::spawn).
                 *
                 * @tparam AsynchronousWriteCallback  Callback signature accepted by @p h.
                 * @tparam WriteHandler               Callable with signature
                 *   `bool(const PacketBuffer&, int, AsynchronousWriteCallback)`.
                 * @tparam PacketBuffer               Packet representation (e.g. shared_ptr<Byte>).
                 * @param y              Coroutine context used to suspend until completion.
                 * @param packet         Packet buffer passed to @p h.
                 * @param packet_length  Number of bytes to transmit.
                 * @param h              Write-starter callable that returns true when the async
                 *                       operation is accepted.
                 * @return               true if the I/O completed successfully; false on failure
                 *                       or if @p h rejected the operation.
                 */
                template <typename AsynchronousWriteCallback, typename WriteHandler, typename PacketBuffer>
                bool                                                    DoWriteYield(YieldContext& y, const PacketBuffer& packet, int packet_length, WriteHandler&& h) noexcept {
                    using atomic_int = std::atomic<int>;

                    std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                    if (NULLPTR == status) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AsyncWriteQueueYieldStatusAllocFailed);
                        return false;
                    }

                    boost::asio::io_context* context = addressof(y.GetContext());
                    boost::asio::strand<boost::asio::io_context::executor_type>* strand = y.GetStrand();

                    // Guard Suspend() behind the post result: if the executor is unavailable
                    // the lambda (and every ppp::coroutines::asio::R() inside it) will never
                    // run, so calling Suspend() would park the coroutine with no future
                    // Resume() – a permanent coroutine leak.
                    bool posted = ppp::threading::Executors::Post(context, strand,
                        [&y, status, h, packet, packet_length]() noexcept {
                            bool waiting = 
                                h(packet, packet_length,
                                    [&y, status](bool b) noexcept {
                                        ppp::coroutines::asio::R(y, *status, b);
                                    });

                            if (!waiting) {
                                ppp::coroutines::asio::R(y, *status, false);
                            }
                        });

                    if (false == posted) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                        return false;
                    }

                    y.Suspend();
                    return status->load() > 0;
                }

            protected:
                /**
                 * @brief Enqueues packet bytes for asynchronous transmission.
                 *
                 * If no write is currently in flight (@ref sending_ == false), the packet
                 * is dispatched immediately via @ref DoWriteBytes.  Otherwise it is
                 * appended to @ref queues_ and dispatched when the current write completes.
                 *
                 * @param packet        Shared buffer containing packet data.
                 * @param packet_length Number of valid bytes in @p packet.
                 * @param cb            Completion callback; invoked once when the write finishes.
                 * @return              true if the packet was accepted (queued or in flight);
                 *                      false when @ref disposed_ is true or @p packet is NULLPTR.
                 */
                virtual bool                                            WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                /**
                 * @brief Coroutine wrapper that waits for write completion.
                 *
                 * Internally calls @ref WriteBytes(packet, packet_length, cb) and suspends
                 * the coroutine until @p cb fires, then resumes returning the result.
                 *
                 * @param y              Coroutine context.
                 * @param packet         Shared buffer to transmit.
                 * @param packet_length  Number of bytes in @p packet.
                 * @return               true on write success; false on failure or disposal.
                 */
                bool                                                    WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

                /**
                 * @brief Subclass-implemented primitive that performs the actual I/O write.
                 *
                 * This pure-virtual method is called by the queue whenever the front packet
                 * is ready for transmission.  The implementation must call @p cb exactly once
                 * when the operation completes or fails.
                 *
                 * @param packet         Packet buffer; ownership is shared with the queue.
                 * @param offset         Byte offset into @p packet where data begins.
                 * @param packet_length  Number of bytes to send starting at @p offset.
                 * @param cb             Callback invoked with true on success, false on error.
                 * @return               true when the async operation was successfully initiated;
                 *                       false if the operation could not be started (in which case
                 *                       @p cb must NOT be called by the subclass).
                 */
                virtual bool                                            DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept = 0;

            private:
                /**
                 * @brief True once Dispose()/Finalize() has been called; read without the lock
                 *        only as an early-exit fast-path (the lock re-checks it to be definitive).
                 *
                 * @note  Stored as `std::atomic_bool` so that concurrent lock-free reads
                 *        (e.g. in WriteBytes/DoTryWriteBytesUnsafe) do not race with
                 *        lock-protected writes in Finalize().  One-shot finalization
                 *        uses `exchange(true, acq_rel)` to ensure exactly-once drain;
                 *        readers use `load(acquire)` to guarantee visibility of all
                 *        side-effects performed before the disposal flag was set.
                 */
                std::atomic_bool                                            disposed_{false};

                /**
                 * @brief True while an async write is in flight; always accessed under syncobj_.
                 *
                 * @note  Plain bool — safe because every read/write of sending_ is performed
                 *        while holding syncobj_, so no concurrent access exists.
                 */
                bool                                                    sending_  = false;

                /** @brief Mutex guarding @ref sending_ and @ref queues_; also used for the
                 *         lock-protected re-check of @ref disposed_ in WriteBytes(). */
                SynchronizedObject                                      syncobj_;

                /** @brief FIFO list of pending write contexts waiting for @ref DoWriteBytes. */
                AsynchronousWriteIoContextQueue                         queues_;

                /** @brief Number of write contexts accepted but not yet completed (queued + in-flight). */
                std::atomic<int>                                        pending_items_{0};

                /** @brief Total bytes of write contexts accepted but not yet completed. */
                std::atomic<int>                                        pending_bytes_{0};

                /**
                 * @brief Maximum number of pending write items before backpressure rejection.
                 *
                 * A value of 0 disables the item-count limit.  Default: 4096.
                 * Stored as std::atomic<int> to avoid data races between setter
                 * calls from configuration threads and lock-free reads in WriteBytes().
                 */
                std::atomic<int>                                        max_pending_items_{4096};

                /**
                 * @brief Maximum total bytes of pending writes before backpressure rejection.
                 *
                 * A value of 0 disables the byte-count limit.  Default: 16 MiB.
                 * Stored as std::atomic<int> to avoid data races between setter
                 * calls from configuration threads and lock-free reads in WriteBytes().
                 */
                std::atomic<int>                                        max_pending_bytes_{16 * 1024 * 1024};
            };
        }
    }
}
