#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file IAsynchronousWriteIoQueue.h
 * @brief Declares a serialized asynchronous write queue abstraction.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /**
             * @brief Serialized asynchronous write queue for packet-oriented output.
             *
             * This base class guarantees in-order write dispatch and provides both callback
             * and coroutine-friendly APIs for enqueueing outbound buffers.
             */
            class IAsynchronousWriteIoQueue : public std::enable_shared_from_this<IAsynchronousWriteIoQueue> {
            public:
                /** @brief Completion callback used by asynchronous write operations. */
                typedef ppp::function<void(bool)>                       AsynchronousWriteBytesCallback, AsynchronousWriteCallback;
                /** @brief Coroutine yield context alias. */
                typedef ppp::coroutines::YieldContext                   YieldContext;
                /** @brief Buffer allocator used for packet storage. */
                typedef ppp::threading::BufferswapAllocator             BufferswapAllocator;
                /** @brief Mutex type protecting queue state. */
                typedef std::mutex                                      SynchronizedObject;
                /** @brief RAII lock for synchronized sections. */
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                /** @brief Atomic integer alias. */
                typedef std::atomic<int>                                atomic_int;
                /** @brief Atomic boolean-like alias represented as integer. */
                typedef atomic_int                                      atomic_boolean;

            public:
                /** @brief Shared allocator used when cloning packet memory. */
                const std::shared_ptr<BufferswapAllocator>              BufferAllocator;

            public:
                /** @brief Initializes the queue with a packet allocator. */
                IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept;
                /** @brief Finalizes the queue and clears pending write contexts. */
                virtual ~IAsynchronousWriteIoQueue() noexcept;

            public:
                /** @brief Returns a shared reference to this queue instance. */
                std::shared_ptr<IAsynchronousWriteIoQueue>              GetReference()          noexcept { return shared_from_this(); }
                /** @brief Returns the mutex guarding mutable queue state. */
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }
                /** @brief Stops the queue and fails all pending operations. */
                virtual void                                            Dispose() noexcept;
                /** @brief Copies raw bytes into a newly allocated shared buffer. */
                static std::shared_ptr<Byte>                            Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept;

            private:
                /** @brief Set of coroutine waiters associated with pending writes. */
                typedef ppp::unordered_set<YieldContext*>               YieldContextSet;
                /**
                 * @brief Context for a single queued write request.
                 *
                 * Holds packet data, packet length, and completion callback for one
                 * outbound write entry.
                 */
                class AsynchronousWriteIoContext final {
                public:
                    /** @brief Packet buffer to be transmitted. */
                    std::shared_ptr<Byte>                               packet;
                    /** @brief Number of bytes to write from @ref packet. */
                    int                                                 packet_length = 0;
                    /** @brief Completion callback for this write request. */
                    AsynchronousWriteBytesCallback                      cb;
                    /** @brief Synchronizes callback forwarding and cleanup. */
                    SynchronizedObject                                  lockobj;

                public:
                    /** @brief Constructs an empty write context. */
                    AsynchronousWriteIoContext() noexcept
                        : packet_length(0) {

                    }
                    /** @brief Ensures completion is signaled on destruction. */
                    ~AsynchronousWriteIoContext() noexcept {
                        Forward(false);
                    }

                public:
                    /** @brief Clears packet state and releases callback ownership. */
                    void                                                Clear() noexcept {
                        SynchronizedObjectScope scope(lockobj);
                        cb = NULLPTR;
                        packet.reset();
                        packet_length = 0;
                    }
                    /** @brief Invokes the stored callback once with result status. */
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
                /** @brief FIFO queue containing pending write contexts. */
                typedef ppp::list<AsynchronousWriteIoContextPtr>        AsynchronousWriteIoContextQueue;

            private:
                /** @brief Starts sending a context while queue lock is held. */
                bool                                                    DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context) noexcept;
                /** @brief Advances queue processing after a write completion. */
                int                                                     DoTryWriteBytesNext() noexcept;
                /** @brief Marks queue as disposed and completes pending callbacks with failure. */
                void                                                    Finalize() noexcept;

            protected:
                /**
                 * @brief Coroutine adapter around callback-style asynchronous writes.
                 * @tparam AsynchronousWriteCallback Callback type consumed by @p h.
                 * @tparam WriteHandler Callable that starts the write operation.
                 * @tparam PacketBuffer Packet representation accepted by @p h.
                 * @param y Coroutine context used to suspend until completion.
                 * @param packet Packet buffer passed to the write handler.
                 * @param packet_length Number of bytes to transmit.
                 * @param h Write starter callable.
                 * @return true if completion callback reports success.
                 */
                template <typename AsynchronousWriteCallback, typename WriteHandler, typename PacketBuffer>
                bool                                                    DoWriteYield(YieldContext& y, const PacketBuffer& packet, int packet_length, WriteHandler&& h) noexcept {
                    using atomic_int = std::atomic<int>;

                    std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                    if (NULLPTR == status) {
                        return false;
                    }

                    boost::asio::io_context* context = addressof(y.GetContext());
                    boost::asio::strand<boost::asio::io_context::executor_type>* strand = y.GetStrand();

                    ppp::threading::Executors::Post(context, strand,
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

                    y.Suspend();
                    return status->load() > 0;
                }

            protected:
                /** @brief Enqueues packet bytes for asynchronous transmission. */
                virtual bool                                            WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;
                /** @brief Coroutine wrapper that waits for write completion. */
                bool                                                    WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
                /** @brief Subclass-implemented primitive that performs the actual write. */
                virtual bool                                            DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept = 0;

            private:
                /** @brief Bit-field flags representing queue lifecycle and active send state. */
                struct {
                    bool                                                disposed_  : 1;
                    bool                                                sending_   : 7;
                };
                /** @brief Mutex guarding flags and pending contexts. */
                SynchronizedObject                                      syncobj_;
                /** @brief Pending write contexts waiting for dispatch. */
                AsynchronousWriteIoContextQueue                         queues_;
            };
        }
    }
}
