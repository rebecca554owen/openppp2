#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/threading/Executors.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file ITransmissionQoS.cpp
 * @brief Implements bandwidth-aware flow control for transmission reads.
 */

using ppp::threading::Executors;
using ppp::coroutines::YieldContext;

namespace ppp {
    namespace transmissions {
        using BeginReadAsynchronousCallback = ITransmissionQoS::BeginReadAsynchronousCallback;

        /**
         * @brief Initializes QoS state and applies initial bandwidth.
         */
        ITransmissionQoS::ITransmissionQoS(const std::shared_ptr<boost::asio::io_context>& context, Int64 bandwidth) noexcept
            : disposed_(false)
            , context_(context)
            , bandwidth_(0)
            , last_(0)
            , traffic_(0) {
            SetBandwidth(bandwidth);
        }

        /**
         * @brief Ensures pending operations are released during destruction.
         */
        ITransmissionQoS::~ITransmissionQoS() noexcept {
            Finalize();
        }

        /**
         * @brief Resumes all suspended coroutine contexts.
         * @param contexts Collection of coroutine handles awaiting resume.
         * @return Number of resumed contexts.
         */
        static int ITransmissionQoS_ResumeAllContexts(ppp::list<YieldContext*>& contexts) noexcept {
            int events = 0;
            for (YieldContext* y : contexts) {
                y->R();
                events++;
            }

            return events;
        }

        /**
         * @brief Executes all queued begin-read callbacks.
         * @param s Collection of begin-read callbacks.
         * @return Number of callbacks executed.
         */
        static int ITransmissionQoS_ResumeAllReads(ppp::list<BeginReadAsynchronousCallback>& s) noexcept {
            int events = 0;
            for (const BeginReadAsynchronousCallback& f : s) {
                f();
                events++;
            }

            return events;
        }

        /**
         * @brief Performs a throttled read under the current bandwidth policy.
         */
        std::shared_ptr<Byte> ITransmissionQoS::ReadBytes(YieldContext& y, int length, const ReadBytesAsynchronousCallback& cb) noexcept {
            if (length < 1) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::GenericInvalidArgument, NULLPTR);
            }

            if (NULLPTR == cb) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::GenericInvalidArgument, NULLPTR);
            }

            YieldContext* co = y.GetPtr();
            if (NULLPTR == co) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid, NULLPTR);
            }

            bool bawait = false; 
            /**
             * @brief Critical section deciding whether the coroutine must wait.
             */
            for (;;) { // co_await
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, NULLPTR);
                }

                bawait = IsPeek();
                if (bawait) {
                    contexts_.emplace_back(co);
                }

                break;
            }

            if (bawait) {
                bool suspend = y.Suspend();
                if (!suspend) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid, NULLPTR);
                }
            }

            std::shared_ptr<Byte> packet = cb(y, &length);
            if (length > 0) {
                if (packet) {
                    traffic_ += length;
                }
            }

            return packet;
        }

        /**
         * @brief Accounts bytes after a completed read operation.
         */
        bool ITransmissionQoS::EndRead(int bytes_transferred) noexcept {
            if (bytes_transferred < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                return false;
            }
            else {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }
            }

            traffic_ += bytes_transferred;
            return true;
        }

        /**
         * @brief Schedules or executes a read-start callback based on throttle state.
         */
        bool ITransmissionQoS::BeginRead(const BeginReadAsynchronousCallback& cb) noexcept {
            if (cb) {
                bool bawait = false; 
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    bawait = IsPeek();
                    if (bawait) {
                        reads_.emplace_back(cb);
                    }

                    break;
                }

                if (!bawait) {
                    cb();
                }

                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
            return false;
        }

        /**
         * @brief Marks the object disposed and releases all pending waits.
         */
        void ITransmissionQoS::Finalize() noexcept {
            ppp::list<BeginReadAsynchronousCallback> reads;
            ppp::list<YieldContext*> contexts; 

            /**
             * @brief Atomically switches to disposed state and drains wait queues.
             */
            for (;;) {
                SynchronizedObjectScope scope(syncobj_);
                disposed_ = true;
                last_     = 0;
                traffic_  = 0;

                reads     = std::move(reads_);
                reads_.clear();

                contexts  = std::move(contexts_);
                contexts_.clear();
                break;
            }

            ITransmissionQoS_ResumeAllReads(reads);
            ITransmissionQoS_ResumeAllContexts(contexts);
        }

        /**
         * @brief Posts deferred disposal work to the associated io_context.
         */
        void ITransmissionQoS::Dispose() noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();

            boost::asio::post(*context, 
                [self, this, context]() noexcept {
                    Finalize();
                });
        }

        /**
         * @brief Posts periodic QoS window refresh and waiter release logic.
         */
        void ITransmissionQoS::Update(UInt64 tick) noexcept {
            std::shared_ptr<ITransmissionQoS> self = GetReference();
            std::shared_ptr<boost::asio::io_context> context = GetContext();

            boost::asio::post(*context, 
                [self, this, context, tick]() noexcept {

                    ppp::list<BeginReadAsynchronousCallback> reads;
                    ppp::list<YieldContext*> contexts; 

                    /**
                     * @brief Releases deferred operations when a new second begins.
                     */
                    for (SynchronizedObjectScope scope(syncobj_);;) {
                        UInt64 now   = tick / 1000; 
                        if (now != last_) {
                            last_    = now;
                            traffic_ = 0;

                            reads    = std::move(reads_);
                            reads_.clear();

                            contexts = std::move(contexts_);
                            contexts_.clear();
                        }

                        break;
                    }

                    ITransmissionQoS_ResumeAllReads(reads);
                    ITransmissionQoS_ResumeAllContexts(contexts);
                });
        }
    }
}
