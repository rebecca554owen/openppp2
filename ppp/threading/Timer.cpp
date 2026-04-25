#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/net/Socket.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file Timer.cpp
 * @brief Implements asynchronous timer scheduling and timeout helpers.
 */

namespace ppp {
    namespace threading {
        /**
         * @brief Constructs a timer bound to the default executor context.
         */
        Timer::Timer()
            : Timer(Executors::GetDefault()) {

        }

        /**
         * @brief Constructs a timer bound to a specific io_context.
         * @param context Target io_context used for timer operations.
         */
        Timer::Timer(const std::shared_ptr<boost::asio::io_context>& context)
            : _disposed_(false)
            , _last(0)
            , _interval(0)
            , _context(context) {

            if (NULLPTR == context) {
                throw std::runtime_error("An NullReferences form of the context is not allowed.");
            }
        }

        /**
         * @brief Releases timer resources.
         */
        Timer::~Timer() noexcept {
            Finalize();
        }

        /**
         * @brief Marks timer disposed and clears active scheduling state.
         */
        void Timer::Finalize() noexcept {
            _disposed_ = true;
            Stop();
            TickEvent = NULLPTR;
        }

        /**
         * @brief Dispatches the tick callback when present.
         * @param e Tick event payload containing elapsed time.
         */
        void Timer::OnTick(TickEventArgs& e) noexcept {
            TickEventHandler eh = TickEvent;
            if (eh) {
                eh(this, e);
            }
        }

        /**
         * @brief Starts periodic scheduling using the configured interval.
         * @return true when scheduling is armed; otherwise false.
         */
        bool Timer::Start() noexcept {
            if (_disposed_) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }

            if (_interval < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TimerResolutionInvalid);
                return false;
            }
            else {
                Stop();
            }

            _last = 0;
            _deadline_timer = make_shared_object<boost::asio::steady_timer>(*_context);
            if (NULLPTR == _deadline_timer) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                return false;
            }

            bool ok = Next();
            if (!ok) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
            }

            return ok;
        }

        /**
         * @brief Schedules the next asynchronous wait cycle.
         * @return true when scheduling succeeds; otherwise false.
         */
        bool Timer::Next() noexcept {
            if (_disposed_) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }

            std::shared_ptr<boost::asio::steady_timer> t = _deadline_timer;
            if (NULLPTR == t) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                return false;
            }
            else {
                _last = Executors::GetTickCount();
            }

            std::shared_ptr<Timer> self = GetReference();
            boost::asio::steady_timer::duration durationTime = Timer::DurationTime(_interval);
            t->expires_from_now(durationTime);
            /**
             * @brief Wait callback that raises tick and chains subsequent scheduling.
             */
            t->async_wait(
                [self, this, t](const boost::system::error_code& ec) noexcept {
                    if (ec) {
                        _last = 0;
                    }
                    else {
                        TickEventArgs e(Executors::GetTickCount() - _last);
                        OnTick(e);
                        Next();
                    }
                });
            return true;
        }

        /**
         * @brief Stops the active timer and cancels pending async wait.
         * @return true when a timer instance was active; otherwise false.
         */
        bool Timer::Stop() noexcept {
            std::shared_ptr<boost::asio::steady_timer> t = std::move(_deadline_timer);
            if (t) {
                ppp::net::Socket::Cancel(*t);
            }

            _last = 0;
            _deadline_timer = NULLPTR;
            return NULLPTR != t;
        }

        /**
         * @brief Posts deferred disposal onto the timer context.
         */
        void Timer::Dispose() noexcept {
            auto self = shared_from_this();
            /**
             * @brief Executor-posted invoker that finalizes timer lifetime.
             */
            struct DisposeInvoker final {
                std::shared_ptr<Timer> self;
                void operator()() const noexcept {
                    self->Finalize();
                }
            } invoker{self};

            boost::asio::post(*_context, invoker);
        }

        /**
         * @brief Updates interval and optionally stops timer when disabled.
         * @param milliseconds Interval in milliseconds; values below 1 disable the timer.
         * @return Non-zero when the resulting interval is enabled; otherwise zero.
         */
        bool Timer::SetInterval(int milliseconds) noexcept {
            if (milliseconds < 1) {
                milliseconds = 0;
            }

            if (milliseconds < 1) {
                Stop();
            }

            _interval = milliseconds;
            return milliseconds;
        }

        /**
         * @brief Gets a shared reference to this timer.
         */
        std::shared_ptr<Timer> Timer::GetReference() noexcept {
            return shared_from_this();
        }

        /**
         * @brief Indicates whether a timer instance is currently scheduled.
         */
        bool Timer::IsEnabled() noexcept {
            return NULLPTR != _deadline_timer;
        }

        /**
         * @brief Enables or disables timer scheduling.
         * @param value true to start; false to stop.
         * @return true when requested transition succeeds; otherwise false.
         */
        bool Timer::SetEnabled(bool value) noexcept {
            return value ? this->Start() : this->Stop();
        }

        /**
         * @brief Gets current interval in milliseconds.
         */
        int Timer::GetInterval() noexcept {
            return _interval;
        }

        /**
         * @brief Constructs tick event args with elapsed milliseconds.
         * @param elapsedMilliseconds Elapsed time between ticks.
         */
        Timer::TickEventArgs::TickEventArgs(UInt64 elapsedMilliseconds) noexcept
            : ElapsedMilliseconds(elapsedMilliseconds) {

        }

        /**
         * @brief Constructs tick event args with zero elapsed time.
         */
        Timer::TickEventArgs::TickEventArgs() noexcept
            : ElapsedMilliseconds(0) {

        }

        /**
         * @brief Converts interval and unit into a monotonic steady timer duration.
         * @param interval Duration value.
         * @param durationType Duration unit selector.
         * @return Converted std::chrono-based duration (monotonic, immune to wall-clock jumps).
         * @note  Uses std::chrono so the timer is armed against CLOCK_MONOTONIC/steady_clock,
         *        avoiding wraparound when the system wall clock is adjusted forward/backward.
         */
        boost::asio::steady_timer::duration Timer::DurationTime(long long int interval, DurationType durationType) noexcept {
            switch (static_cast<int>(durationType))
            {
            case 0:
                return std::chrono::hours(interval);
            case 1:
                return std::chrono::minutes(interval);
            case 2:
                return std::chrono::seconds(interval);
            case 3:
                return std::chrono::milliseconds(interval);
            default:
                return std::chrono::milliseconds(interval);
            };
        }

        /**
         * @brief Creates a one-shot timeout timer on the default context.
         * @param milliseconds Timeout delay in milliseconds.
         * @param handler Callback invoked when timeout fires.
         * @return Created timer handle, or null on failure.
         */
        std::shared_ptr<Timer> Timer::Timeout(int milliseconds, const TimeoutEventHandler& handler) noexcept {
            std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
            return Timeout(context, milliseconds, handler);
        }

        /**
         * @brief Creates a one-shot timeout timer on a specific context.
         * @param context io_context that executes timer callbacks.
         * @param milliseconds Timeout delay in milliseconds.
         * @param handler Callback invoked when timeout fires.
         * @return Created timer handle, or null on failure.
         */
        std::shared_ptr<Timer> Timer::Timeout(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const TimeoutEventHandler& handler) noexcept {
            if (NULLPTR == handler) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TimerTimeoutNullHandler);
                return NULLPTR;
            }

            if (NULLPTR == context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                return NULLPTR;
            }

            if (milliseconds < 1) {
                milliseconds = 1;
            }

            std::shared_ptr<Timer> t = make_shared_object<Timer>(context);
            if (NULLPTR == t) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                return NULLPTR;
            }

            t->TickEvent = 
                [handler](Timer* sender, Timer::TickEventArgs& e) noexcept {
                    sender->Dispose();
                    handler(sender);
                };

            bool ok = t->SetInterval(milliseconds) && t->Start();
            if (ok) {
                return t;
            }
            else {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
                t->Dispose();
                return NULLPTR;
            }
        }

        /**
         * @brief Suspends a coroutine until timeout or immediate post.
         * @param milliseconds Timeout delay in milliseconds.
         * @param y Coroutine yield context.
         * @return true when wait completed without cancellation; otherwise false.
         */
        bool Timer::Timeout(int milliseconds, ppp::coroutines::YieldContext& y) noexcept {
            if (!y) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TimerTimeoutYieldInvalidContext);
                return false;
            }

            boost::asio::strand<boost::asio::io_context::executor_type>* strand = y.GetStrand();
            std::shared_ptr<boost::asio::steady_timer> deadlineTimer = strand ? 
                make_shared_object<boost::asio::steady_timer>(*strand) : 
                make_shared_object<boost::asio::steady_timer>(y.GetContext());

            if (NULLPTR == deadlineTimer) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                return false;
            }
            
            bool ok = false;
            if (milliseconds < 1) {
                boost::asio::post(deadlineTimer->get_executor(),
                    [&y, &ok]() noexcept {
                        ok = true;
                        y.R();
                    });
            }
            else {
                boost::asio::steady_timer::duration durationTime = Timer::DurationTime(milliseconds);
                deadlineTimer->expires_from_now(durationTime);
                deadlineTimer->async_wait(
                    [&y, &ok](const boost::system::error_code& ec) noexcept {
                        if (ec == boost::system::errc::success) {
                            ok = true;
                        }

                        y.R();
                    });
            }

            y.Suspend();
            return ok;
        }

        /**
         * @brief Releases and invokes all timeout handlers in a table.
         * @param timeouts Table containing timer-keyed timeout handlers.
         */
        void Timer::ReleaseAllTimeouts(TimeoutEventHandlerTable& timeouts) noexcept {
            TimeoutEventHandlerTable list = std::move(timeouts);
            timeouts.clear();

            for (auto&& kv : list) {
                std::shared_ptr<TimeoutEventHandler> h = kv.second;
                if (h) {
                    Timer* k = static_cast<Timer*>(kv.first);
                    (*h)(k);
                }
            }
        }
    }
}
