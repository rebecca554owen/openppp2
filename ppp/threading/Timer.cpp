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
         *
         * Crash story: on Android we observed a SIGSEGV (SI_KERNEL, fault addr
         * 0x0, ~2-frame backtrace) reliably ~10s after a successful connect,
         * with PC parked on the `bl operator=(nullptr_t)` for `TickEvent`
         * inside Finalize(). That signature is the kernel's stack-guard trip
         * — i.e. unbounded recursion. The immediate cause: clearing
         * `TickEvent` runs the destructor of whatever lambda is held, which
         * releases captured shared_ptrs; in some configurations one of those
         * captures owns (transitively) another Timer's last reference, whose
         * ~Timer() calls Finalize() again, and the chain re-enters ours
         * before this stack frame has unwound. We harden the routine in two
         * ways:
         *   1) A thread-local re-entrance guard short-circuits any nested
         *      call on the same thread.
         *   2) We *move* the callable into a local before this function
         *      returns, instead of operator=(nullptr) on the member. The
         *      member is left empty immediately; the held lambda's
         *      destruction happens after we set the guard back to false on
         *      our way out, so any cascading destructors execute against a
         *      consistent Timer state.
         */
        void Timer::Finalize() noexcept {
            static thread_local int s_finalize_depth = 0;
            if (s_finalize_depth > 0) {
                /* Re-entered while a previous Finalize() is still on the
                 * stack -- e.g. through a shared_ptr<Timer> capture in our
                 * own TickEvent. Just mark disposed and bail; the outer
                 * frame will finish the cleanup. */
                _disposed_ = true;
                tick_event_guard_.store(false, std::memory_order_release);
                return;
            }
            ++s_finalize_depth;

            _disposed_ = true;
            Stop();
            tick_event_guard_.store(false, std::memory_order_release);

            /* Detach the callable from the member without destroying it
             * inline. We deliberately do NOT destroy `held` inside this
             * function: the held lambda commonly captures shared_ptr<X>
             * where X owns this Timer. Releasing that shared_ptr can run
             * ~X, which runs ~Timer on `this`, which would corrupt the
             * stack frame we are currently executing in.
             *
             * Two-step deferral:
             *   1) swap() detaches the callable from `TickEvent` member.
             *   2) Post `held` to the io_context so its destructor runs
             *      AFTER this stack frame fully unwinds and we no longer
             *      touch `this`. If posting fails (context torn down),
             *      fall back to leaking `held` -- correctness over a tiny
             *      one-time leak during process teardown. */
            TickEventHandler* held = new (std::nothrow) TickEventHandler();
            if (held != NULLPTR) {
                held->swap(TickEvent);
                std::shared_ptr<boost::asio::io_context> ctx = _context;
                if (NULLPTR != ctx) {
                    boost::system::error_code ec;
                    try {
                        boost::asio::post(*ctx, [held]() noexcept { delete held; });
                    } catch (...) {
                        /* Posting failed (likely io_context stopped); leak
                         * `held` -- still safer than running its dtor here. */
                    }
                } /* else: context already gone -- leak held to avoid UAF. */
            } else {
                /* Allocation failed; fall back to inline clear. The
                 * recursion guard above prevents the stack-overflow path. */
                TickEvent = NULLPTR;
            }

            --s_finalize_depth;
        }

        /**
         * @brief Dispatches the tick callback when present.
         * @param e Tick event payload containing elapsed time.
         */
        void Timer::OnTick(TickEventArgs& e) noexcept {
            if (!tick_event_guard_.load(std::memory_order_acquire)) {
                return;
            }

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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeObjectDisposed);
                return false;
            }

            if (1 > _interval) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TimerResolutionInvalid);
                return false;
            }
            else {
                Stop();
            }

            _last = 0;
            _deadline_timer = make_shared_object<boost::asio::steady_timer>(*_context);
            if (NULLPTR == _deadline_timer) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }

            bool ok = Next();
            if (!ok) {
                _deadline_timer.reset();  // Clean up timer on failure
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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeObjectDisposed);
                return false;
            }

            std::shared_ptr<boost::asio::steady_timer> t = _deadline_timer;
            if (NULLPTR == t) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeObjectDisposed);
                return false;
            }
            else {
                _last = Executors::GetTickCount();
            }

            std::shared_ptr<Timer> self = GetReference();
            boost::asio::steady_timer::duration durationTime = Timer::DurationTime(_interval);
            t->expires_after(durationTime);
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
            if (1 > milliseconds) {
                milliseconds = 0;
            }

            if (1 > milliseconds) {
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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TimerContextMissing);
                return NULLPTR;
            }

            if (1 > milliseconds) {
                milliseconds = kMinimumInterval;
            }

            std::shared_ptr<Timer> t = make_shared_object<Timer>(context);
            if (NULLPTR == t) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return NULLPTR;
            }

            t->TickEvent = 
                [handler](Timer* sender, Timer::TickEventArgs& e) mutable noexcept {
                    sender->Dispose();
                    /* Move the user handler into a stack local so its
                     * destruction happens here on a fresh frame, not later
                     * inside the deferred Callable<outer-lambda> teardown.
                     * The deferred path runs several frames deep already
                     * (io_context dispatch -> ~function -> reset -> LockScope
                     * -> __on_zero_shared -> ~Callable<user_lambda> -> ...);
                     * cascading shared_ptr decrements inside the user
                     * handler's captures (e.g. shared_ptr<VEthernetNetworkSwitcher>
                     * and its owned Timers) can recurse deep enough to trip
                     * the kernel's stack-guard page (SIGSEGV, SI_KERNEL,
                     * single-frame backtrace) under DNS load. */
                    TimeoutEventHandler local = std::move(handler);
                    local(sender);
                    /* `local` destructs here, releasing user captures on
                     * this near-empty stack. */
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
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                return false;
            }
            
            bool ok = false;
            if (1 > milliseconds) {
                boost::asio::post(deadlineTimer->get_executor(),
                    [&y, &ok]() noexcept {
                        ok = true;
                        y.R();
                    });
            }
            else {
                boost::asio::steady_timer::duration durationTime = Timer::DurationTime(milliseconds);
                deadlineTimer->expires_after(durationTime);
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
