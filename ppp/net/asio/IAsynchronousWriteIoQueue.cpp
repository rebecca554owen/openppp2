#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/collections/Dictionary.h>

namespace ppp {
    namespace net {
        namespace asio {
            // The security queue mode is set to false by default, and was previously agreed to default to true because it was not necessary.
            bool IAsynchronousWriteIoQueue::sq_ = false;

            IAsynchronousWriteIoQueue::IAsynchronousWriteIoQueue(const std::shared_ptr<BufferswapAllocator>& allocator) noexcept
                : BufferAllocator(allocator)
                , disposed_(false)
                , sending_(false) {
                
            }

            IAsynchronousWriteIoQueue::~IAsynchronousWriteIoQueue() noexcept {
                Finalize();
            }

            // For the setting of safe mode, it must be configured between enabling VPN and if you want to change its options midway, 
            // You must restart the application. Dynamic changes are not supported.
            bool IAsynchronousWriteIoQueue::SafeMode(bool* safe_mode) noexcept {
                bool safe_queue = safe_mode;
                if (NULL != safe_mode) {
                    sq_ = *safe_mode;
                }

                return safe_queue;
            }

            bool IAsynchronousWriteIoQueue::R(YieldContext& y) noexcept {
                YieldContext* co = y.GetPtr();
                if (NULL != co) {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = sy_.find(co);
                    auto endl = sy_.end();
                    if (tail != endl) {
                        sy_.erase(tail);
                    }
                    else {
                        return false;
                    }
                }
                else {
                    return false;
                }

                return y.R();
            }

            bool IAsynchronousWriteIoQueue::Y(YieldContext& y) noexcept {
                YieldContext* co = y.GetPtr();
                if (NULL != co) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return false;
                    }

                    auto r = sy_.emplace(co);
                    if (!r.second) {
                        return false;
                    }
                }
                else {
                    return false;
                }

                if (y.Suspend()) {
                    return true;
                }
                else {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = sy_.find(co);
                    auto endl = sy_.end();
                    if (tail != endl) {
                        sy_.erase(tail);
                    }

                    return false;
                }
            }

            void IAsynchronousWriteIoQueue::Dispose() noexcept {
                Finalize();
            }

            void IAsynchronousWriteIoQueue::Finalize() noexcept {
                AsynchronousWriteIoContextQueue queues; 
                YieldContextSet sy;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    disposed_ = true;
                    sending_ = false;
                    
                    sy = std::move(sy_);
                    sy_.clear();

                    queues = std::move(queues_);
                    queues_.clear();
                    break;
                }

                for (YieldContext* y : sy) {
                    y->R();
                }

                for (AsynchronousWriteIoContextPtr& context : queues) {
                    context->Forward(false);
                }
            }

            std::shared_ptr<Byte> IAsynchronousWriteIoQueue::Copy(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen) noexcept {
                if (NULL == data || datalen < 1) {
                    return NULL;
                }

                std::shared_ptr<Byte> chunk;
                if (NULL != allocator) {
                    chunk = allocator->MakeArray<Byte>(datalen);
                }
                else {
                    chunk = make_shared_alloc<Byte>(datalen);
                }

                if (NULL != chunk) {
                    void* memory = chunk.get();
                    memcpy(memory, data, datalen);
                }

                return chunk;
            }

            bool IAsynchronousWriteIoQueue::WriteBytes(YieldContext& y, const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                if (disposed_) {
                    return false;
                }

                return DoWriteYield<AsynchronousWriteBytesCallback>(y, packet, packet_length,
                    [this](const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                        return WriteBytes(packet, packet_length, cb);
                    });
            }

            bool IAsynchronousWriteIoQueue::WriteBytes(const std::shared_ptr<Byte>& packet, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                IAsynchronousWriteIoQueue* const q = this;
                if (q->disposed_) {
                    return false;
                }

                if (NULL == packet || packet_length < 1) {
                    return false;
                }

                if (NULL == cb) {
                    return false;
                }

                std::shared_ptr<AsynchronousWriteIoContext> context = make_shared_object<AsynchronousWriteIoContext>();
                if (NULL == context) {
                    return false;
                }

                context->cb = cb;
                context->packet = packet;
                context->packet_length = packet_length;

                bool ok = false;
                while (NULL != q) {
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

            bool IAsynchronousWriteIoQueue::DoTryWriteBytesUnsafe(const AsynchronousWriteIoContextPtr& context) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                auto evtf = 
                    [self, this, context](bool ok) noexcept -> void {
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
                    } while (NULL == context);

                    ok = DoTryWriteBytesUnsafe(context);
                    break;
                }

                if (ok) {
                    return 1;
                }
                
                context->Forward(false);
                return -1;
            }

            void IAsynchronousWriteIoQueue::AwaitInitiateAfterYieldCoroutine(YieldContext& y, std::atomic<int>& initiate) noexcept {
                int status = initiate.load();
                if (status > -1) {
                    if (sq_) {
                        R(y);
                    }
                    else {
                        y.R();
                    }
                }
                else {
                    boost::asio::io_context& context = y.GetContext();
                    ppp::threading::Executors::Post(&context, y.GetStrand(),
                        [this, &y, &initiate]() noexcept -> void {
                            AwaitInitiateAfterYieldCoroutine(y, initiate);
                        });
                }
            }
        }
    }
}