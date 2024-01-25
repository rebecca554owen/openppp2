#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
        static int ITransmissionQoS_ResumeAllContexts(ppp::list<YieldContext*>& contexts) noexcept {
            int events = 0;
            for (YieldContext* y : contexts) {
                boost::asio::io_context& context = y->GetContext();
                context.dispatch(std::bind(&YieldContext::Resume, y));
                events++;
            }
            return events;
        }

        ITransmissionQoS::ITransmissionQoS(const std::shared_ptr<boost::asio::io_context>& context, UInt32 bandwidth) noexcept
            : disposed_(false)
            , context_(context)
            , bandwidth_(bandwidth)
            , last_(0)
            , traffic_(0) {

        }

        ITransmissionQoS::~ITransmissionQoS() noexcept {
            Finalize();
        }

        void ITransmissionQoS::Finalize() noexcept {
            ppp::list<YieldContext*> contexts; {
                SynchronizedObjectScope scope(syncobj_);
                disposed_ = true;
                last_ = 0;
                traffic_ = 0;
                contexts = std::move(contexts_);
                contexts_.clear();
            }
            ITransmissionQoS_ResumeAllContexts(contexts);
        }

        void ITransmissionQoS::Dispose() noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            context->post(
                [self, this, context]() noexcept {
                    Finalize();
                });
        }

        std::shared_ptr<boost::asio::io_context> ITransmissionQoS::GetContext() noexcept {
            return context_;
        }

        std::shared_ptr<ITransmissionQoS> ITransmissionQoS::GetReference() noexcept {
            return shared_from_this();
        }

        UInt32 ITransmissionQoS::GetBandwidth() noexcept {
            return bandwidth_;
        }

        void ITransmissionQoS::SetBandwidth(int bandwidth) noexcept {
            bandwidth_ = bandwidth < 1 ? 0 : bandwidth; /* ReLU */
        }

        void ITransmissionQoS::Update(UInt64 tick) noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();
            context->post(
                [self, this, context, tick]() noexcept {
                    ppp::list<YieldContext*> contexts; {
                        SynchronizedObjectScope scope(syncobj_);
                        if (disposed_) {
                            return -1;
                        }

                        UInt32 now = (UInt32)(tick / 1000);
                        if (now != last_) {
                            last_ = now;
                            traffic_ = 0;
                            contexts = std::move(contexts_);
                            contexts_.clear();
                        }
                    }

                    return ITransmissionQoS_ResumeAllContexts(contexts);
                });
        }

        bool ITransmissionQoS::IsPeek() noexcept {
            // The unit "bps" stands for bits per second, where "b" represents bits.
            // Therefore, 1 Kbps can be correctly expressed in English as "one kilobit per second," 
            // Where "K" stands for kilo - (representing a factor of 1, 000).
            UInt32 bandwidth = bandwidth_;
            if (bandwidth < 1) {
                return false;
            }

            UInt64 traffic = traffic_ >> 7;
            return traffic >= bandwidth;
        }

        std::shared_ptr<Byte> ITransmissionQoS::ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallbackPtr& cb) noexcept {
            if (length < 1) {
                return NULL;
            }

            if (NULL == cb) {
                return NULL;
            }

            YieldContext* co = y.GetPtr();
            if (NULL == co) {
                return NULL;
            }

            bool bawait = false; { // co_await
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULL;
                }

                bawait = IsPeek();
                if (bawait) {
                    contexts_.emplace_back(co);
                }
            }

            if (bawait) {
                y.Suspend();
            }

            std::shared_ptr<Byte> packet = (*cb)(y, length);
            if (packet) {
                traffic_ += length;
            }
            return packet;
        }
    }
}