#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

#include <cstdio>
#include <cstdlib>
#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
#include <sanitizer/tsan_interface.h>
#endif

namespace ppp
{
    namespace coroutines
    {
        /**
         * @file YieldContext.cpp
         * @brief Implements stackful coroutine state transitions and scheduling glue.
         */

        /** @brief State: coroutine is currently resumed/running. */
        static constexpr int STATUS_RESUMED    = 0;
        /** @brief State: coroutine is entering suspend transition. */
        static constexpr int STATUS_SUSPENDING = 1;
        /** @brief State: coroutine is fully suspended and resumable. */
        static constexpr int STATUS_SUSPEND    = 2;
        /** @brief State: coroutine is entering resume transition. */
        static constexpr int STATUS_RESUMING   = -1;
        /** @brief State: coroutine handler returned; the context is being reclaimed. */
        static constexpr int STATUS_COMPLETED  = 3;

        /**
         * @brief Diagnostic counters for lost-wakeup forensics (env: OPENPPP2_YIELD_DIAG=1).
         *        All counters are process-global atomics; dumped by DumpYieldDiag().
         */
        struct YieldDiag {
            std::atomic<uint64_t> arm{0};              /**< Arm() published a new anchor */
            std::atomic<uint64_t> resume_latch{0};    /**< Resume() latched (coroutine still running) */
            std::atomic<uint64_t> resume_jump{0};     /**< Resume() jumped back into the parked coroutine */
            std::atomic<uint64_t> resume_stale{0};    /**< Resume() rejected the wakeup (finished / superseded anchor) */
            std::atomic<uint64_t> suspend_consume{0}; /**< Suspend() consumed a latched wakeup at entry */
            std::atomic<uint64_t> suspend_park{0};    /**< Suspend() jumped out (will park) */
            std::atomic<uint64_t> suspend_reject{0};  /**< Suspend() rejected the anchor or the state */
            std::atomic<uint64_t> switch_consume{0};  /**< Switch() consumed a latch racing the handoff */
            std::atomic<uint64_t> switch_park{0};     /**< Switch() published STATUS_SUSPEND */
            std::atomic<uint64_t> reenter{0};         /**< Switch() re-entered the coroutine after a latch consume */
            std::atomic<uint64_t> anchor_cas_fail{0}; /**< Anchor::R() lost the CAS (duplicate / stale wakeup) */
        };
        static YieldDiag& Diag() noexcept {
            static YieldDiag d;
            return d;
        }
        static const bool diag_enabled_ = []() noexcept {
            const char* v = std::getenv("OPENPPP2_YIELD_DIAG");
            return v && v[0] == '1';
        }();

        /**
         * @brief Constructs a coroutine context and allocates stack memory.
         */
        YieldContext::YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept
            : s_(0)
            , callee_(NULLPTR)
            , caller_(NULLPTR)
            , h_(std::move(spawn))
            , context_(context)
            , strand_(strand)
            , stack_size_(stack_size)
            , allocator_(allocator)
        {
            std::shared_ptr<ppp::threading::BufferswapAllocator> heap;
            if (allocator) 
            {
                heap = allocator->shared_from_this();
            }

#if defined(PPP_COROUTINE_BACKEND_COROCC) && defined(PPP_COROCC_GUARD_STACK)
            stack_ = backend::AllocateStack(stack_size);
#else
            stack_ = ppp::threading::BufferswapAllocator::MakeByteArray(heap, stack_size);
#endif

            cell_ = ppp::make_shared_object<AnchorCell>();
            if (cell_)
            {
                cell_->y       = this;
                cell_->context = &context;
                cell_->strand  = strand;
            }
#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
            sanitizer_fiber_ = __tsan_create_fiber(0);
#endif
        }

        /** @brief Releases references and owned state fields. */
        YieldContext::~YieldContext() noexcept
        {
            YieldContext* y = this;
            if (std::shared_ptr<AnchorCell> cell = std::move(y->cell_))
            {
                /** @brief Outstanding anchors may outlive this object; make every later R() fail. */
                std::lock_guard<std::mutex> scope(cell->syncobj);
                cell->armed.store(0, std::memory_order_release);
                cell->y = NULLPTR;
            }

#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
            if (y->sanitizer_fiber_)
            {
                __tsan_destroy_fiber(y->sanitizer_fiber_);
                y->sanitizer_fiber_ = NULLPTR;
            }
            y->sanitizer_caller_fiber_ = NULLPTR;
#endif
#if defined(PPP_COROUTINE_BACKEND_COROCC)
            backend::Destroy(y->backend_context_);
            y->backend_context_ = NULLPTR;
#endif
            y->h_          = NULLPTR;
            y->stack_      = NULLPTR;
            y->stack_size_ = 0;
            y->strand_     = NULLPTR;
            y->allocator_  = NULLPTR;
        }

        /**
         * @brief Arms the next suspension: increments the monotonic anchor and publishes it.
         */
        YieldContext::Anchor YieldContext::Arm() noexcept
        {
            YieldContext* y = this;
            const std::shared_ptr<AnchorCell>& cell = y->cell_;
            if (!cell)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return Anchor();
            }

            uint64_t value = y->anchor_sequence_.fetch_add(1, std::memory_order_acq_rel) + 1;
            if (0 == value)
            {
                /** @brief 0 means "nothing armed"; skip it if the counter ever wraps. */
                value = y->anchor_sequence_.fetch_add(1, std::memory_order_acq_rel) + 1;
            }

            {
                std::lock_guard<std::mutex> scope(cell->syncobj);
                if (y->s_.load() != STATUS_RESUMED)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    return Anchor();
                }

                /**
                 * @brief A latch can only belong to the previous anchor, which the caller
                 *        abandoned without suspending; it must not leak into this one.
                 */
                y->wakeup_pending_ = false;
                y->anchor_current_ = value;
                cell->armed.store(value, std::memory_order_release);
            }

            if (diag_enabled_) { Diag().arm.fetch_add(1, std::memory_order_relaxed); }

            return Anchor(cell, value);
        }

        /** @brief Suspends execution until the given anchor is consumed by its wakeup. */
        bool YieldContext::Suspend(const Anchor& anchor) noexcept
        {
            YieldContext* y = this;
            const std::shared_ptr<AnchorCell>& cell = y->cell_;
            if (!cell || anchor.cell_ != cell || 0 == anchor.value_)
            {
                if (diag_enabled_) { Diag().suspend_reject.fetch_add(1, std::memory_order_relaxed); }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }

            {
                std::lock_guard<std::mutex> scope(cell->syncobj);
                if (anchor.value_ != y->anchor_current_)
                {
                    /** @brief Not the armed anchor (stale, reused or foreign): never park on it. */
                    if (diag_enabled_) { Diag().suspend_reject.fetch_add(1, std::memory_order_relaxed); }
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    return false;
                }

                if (y->wakeup_pending_)
                {
                    /**
                     * @brief This anchor's wakeup was latched before the suspend could park
                     *        (completion-before-suspend); consume it without blocking.
                     */
                    y->wakeup_pending_ = false;
                    y->anchor_current_ = 0;
                    if (diag_enabled_) { Diag().suspend_consume.fetch_add(1, std::memory_order_relaxed); }
                    return true;
                }

                if (y->s_.load() != STATUS_RESUMED)
                {
                    if (diag_enabled_) { Diag().suspend_reject.fetch_add(1, std::memory_order_relaxed); }
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    return false;
                }

                y->s_.store(STATUS_SUSPENDING);
            }

            /** @brief The mutex is released before jumping; never hold it across fcontext switches. */
#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
            __tsan_switch_to_fiber(y->sanitizer_caller_fiber_, 0);
#endif
            if (diag_enabled_) { Diag().suspend_park.fetch_add(1, std::memory_order_relaxed); }
            y->caller_.exchange(
                backend::Jump(
                    y->caller_.exchange(NULLPTR), y).fctx);

            {
                /** @brief The resumer published STATUS_RESUMING before jumping back in. */
                std::lock_guard<std::mutex> scope(cell->syncobj);
                y->s_.store(STATUS_RESUMED);
            }

            return true;
        }

        /** @brief Resumes the coroutine for an anchor that already won its CAS. */
        bool YieldContext::Resume(const std::shared_ptr<AnchorCell>& cell, uint64_t value) noexcept
        {
            YieldContext* y = NULLPTR;
            {
                std::lock_guard<std::mutex> scope(cell->syncobj);
                y = cell->y;
                if (NULLPTR == y || value != y->anchor_current_)
                {
                    /**
                     * @brief The coroutine finished, or this anchor was abandoned and a newer
                     *        one armed after the CAS: the wakeup belongs to no suspension.
                     */
                    if (diag_enabled_) { Diag().resume_stale.fetch_add(1, std::memory_order_relaxed); }
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    return false;
                }

                int status = y->s_.load();
                if (status == STATUS_SUSPEND)
                {
                    y->s_.store(STATUS_RESUMING);
                    y->anchor_current_ = 0;
                }
                else if (status == STATUS_RESUMED || status == STATUS_SUSPENDING)
                {
                    /**
                     * @brief The coroutine has not published its park point yet (it is
                     *        still running, or is in the middle of the suspend handoff).
                     *        Latch the wakeup for this anchor so the matching Suspend()
                     *        consumes it; dropping it here permanently hangs the coroutine
                     *        when the io_context is driven by more than one run() thread.
                     */
                    y->wakeup_pending_ = true;
                    if (diag_enabled_) { Diag().resume_latch.fetch_add(1, std::memory_order_relaxed); }
                    return true;
                }
                else
                {
                    /** @brief STATUS_RESUMING or STATUS_COMPLETED: no suspension to deliver to. */
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    return false;
                }
            }

#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
            y->sanitizer_caller_fiber_ = __tsan_get_current_fiber();
            __tsan_switch_to_fiber(y->sanitizer_fiber_, 0);
#endif
            if (diag_enabled_) { Diag().resume_jump.fetch_add(1, std::memory_order_relaxed); }
            return Switch(
                backend::Jump(
                    y->callee_.exchange(NULLPTR), y), y);
        }

        /**
         * @brief Creates coroutine fcontext and performs initial handoff.
         */
        void YieldContext::Invoke() noexcept
        {
            YieldContext* y = this;
            Byte* stack = stack_.get(); 

            if (stack)
            {
                backend::Context callee =
                    backend::Make(stack + stack_size_, stack_size_, &YieldContext::Handle);
#if defined(PPP_COROUTINE_BACKEND_COROCC)
                y->backend_context_ = callee;
                if (!callee)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    YieldContext::Release(y);
                    return;
                }
#endif
#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
                y->sanitizer_caller_fiber_ = __tsan_get_current_fiber();
                __tsan_switch_to_fiber(y->sanitizer_fiber_, 0);
#endif
                Switch(backend::Jump(callee, y), y);
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                YieldContext::Release(y);
            }
        }

        /** @brief Performs guarded fcontext jump only when target is valid. */
        backend::Transfer YieldContext::Jump(backend::Context context, void* state) noexcept
        {
            if (context) 
            {
                return backend::Finish(context, state);
            }

            return backend::Transfer{ NULLPTR, NULLPTR };
        }

        /**
         * @brief Publishes the suspended state, or consumes a wakeup that raced the
         *        suspend handoff and requests immediate re-entry.
         */
        bool YieldContext::Switch() noexcept
        {
            YieldContext* y = this;
            std::lock_guard<std::mutex> scope(y->cell_->syncobj);

            if (y->s_.load() != STATUS_SUSPENDING)
            {
                /** @brief Defensive: the suspend handoff is single-threaded, so this is unreachable. */
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return true;
            }

            if (y->wakeup_pending_)
            {
                /**
                 * @brief A wakeup raced the suspend handoff; consume it and tell the
                 *        caller to re-enter the coroutine immediately so the suspend
                 *        never blocks.
                 */
                y->wakeup_pending_ = false;
                y->anchor_current_ = 0;
                y->s_.store(STATUS_RESUMING);
                if (diag_enabled_) { Diag().switch_consume.fetch_add(1, std::memory_order_relaxed); }
                return false;
            }

            y->s_.store(STATUS_SUSPEND);
            if (diag_enabled_) { Diag().switch_park.fetch_add(1, std::memory_order_relaxed); }
            return true;
        }

        /**
         * @brief Stores transfer context and finishes one switch cycle.
         */
        bool YieldContext::Switch(const backend::Transfer& t, YieldContext* y) noexcept
        {
            if (!t.data)
            {
                /** @brief Coroutine handler returned; mark completed and reclaim. */
                {
                    std::lock_guard<std::mutex> scope(y->cell_->syncobj);
                    y->s_.store(STATUS_COMPLETED);
                }

                YieldContext::Release(y);
                return true;
            }

            y->callee_.exchange(t.fctx);
            while (!y->Switch())
            {
                /**
                 * @brief A wakeup was latched while the coroutine was parking; re-enter
                 *        it immediately so the suspend is never allowed to block.
                 */
#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
                y->sanitizer_caller_fiber_ = __tsan_get_current_fiber();
                __tsan_switch_to_fiber(y->sanitizer_fiber_, 0);
#endif
                if (diag_enabled_) { Diag().reenter.fetch_add(1, std::memory_order_relaxed); }
                backend::Transfer r =
                    backend::Jump(
                        y->callee_.exchange(NULLPTR), y);

                if (!r.data)
                {
                    {
                        std::lock_guard<std::mutex> scope(y->cell_->syncobj);
                        y->s_.store(STATUS_COMPLETED);
                    }

                    YieldContext::Release(y);
                    return true;
                }

                y->callee_.exchange(r.fctx);
            }

            return true;
        }

        /**
         * @brief Coroutine trampoline that executes the user handler and performs final
         *        context handoff back to the caller.
         *
         * @param t  Transfer descriptor injected by jump_fcontext; t.data points to the
         *           owning YieldContext instance.
         *
         * @note  This function MUST be declared noexcept.  It is registered as the entry
         *        point for a Boost.Context fcontext stack via make_fcontext().  Any C++
         *        exception that propagates out of an fcontext trampoline crosses stack
         *        frames that were not constructed with exception support, producing
         *        undefined behaviour (typically silent memory corruption or a crash at
         *        the next unwind table lookup).
         *
         *        The error condition previously guarded by a throw — a non-null callee_
         *        after the final Jump() — indicates that a completed coroutine was
         *        accidentally resumed.  This is a caller-side programming error.  At
         *        this level we cannot throw, so we clear the stale callee_ reference
         *        and release the context to prevent a second invalid jump and a memory
         *        leak.
         */
        void YieldContext::Handle(backend::Transfer t) noexcept
        {
            YieldContext* y = (YieldContext*)t.data;
            if (y)
            {
                SpawnHander h = std::move(y->h_);
                y->h_ = NULLPTR;
                y->caller_.exchange(t.fctx);

                if (h)
                {
                    try
                {
                    h(*y);
                    }
                    catch (const std::exception&)
                    {
                        /* An exception escaping the handler would cross the fcontext
                         * boundary below (undefined behaviour per Boost.Context). Catch
                         * every exception here and convert it into an error code so the
                         * coroutine terminates gracefully instead of crashing. */
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineHandlerException);
                    }
                    catch (...)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineHandlerException);
                    }

                    h = NULLPTR;
                }

#if defined(PPP_COROUTINES_TSAN_ENABLED) && !defined(PPP_COROUTINE_BACKEND_COROCC)
                __tsan_switch_to_fiber(y->sanitizer_caller_fiber_, 0);
#endif
                Jump(y->caller_.exchange(NULLPTR), NULLPTR);

                // If execution reaches here the coroutine was resumed after completion.
                // This is a programming error (caller-side bug) that we cannot repair.
                // Clear the stale callee reference to prevent a second invalid jump,
                // then release the context so its memory is reclaimed.
                // We must NOT throw: propagating an exception across an fcontext
                // boundary is undefined behaviour per Boost.Context documentation.
                y->callee_.exchange(NULLPTR);
                YieldContext::Release(y);
            }
        }
 
        /**
         * @brief Allocates and schedules a new coroutine on context or strand.
         */
        bool YieldContext::Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept
        {
            if (!spawn)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::YieldContextSpawnNullHandler);
                return false;
            }

            stack_size = std::max<int>(stack_size, PPP_MEMORY_ALIGNMENT_SIZE);
#if defined(PPP_COROUTINES_TSAN_ENABLED)
            /** @brief TSan instrumentation needs substantially more stack than production code. */
            stack_size = std::max<int>(stack_size, 1 << 20);
#endif

            /**
             * @brief Instantiates context object before posting execution.
             *
             * Execution runs immediately when posting from the owner thread;
             * otherwise it is queued and driven by the context event loop.
             */
            YieldContext* y = New<YieldContext>(allocator, context, strand, std::move(spawn), stack_size);
            if (!y)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                return false;
            }

            if (!y->cell_)
            {
                YieldContext::Release(y);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                return false;
            }

            /** @brief Posted callable that starts coroutine invocation. */
            auto invoked =
                [y]() noexcept -> void
                {
                    y->Invoke();
                };

            if (strand)
            {
                boost::asio::post(*strand, invoked);
            }
            else
            {
                boost::asio::post(context, invoked);
            }

            return true;
        }

        /**
         * @brief Dumps the lost-wakeup forensic counters to stderr.
         * @note Diagnostic only; the counters are always valid and never influence the
         *       state machine.  Enable them with OPENPPP2_YIELD_DIAG=1.
         */
        void YieldContext::DumpYieldDiag() noexcept
        {
            YieldDiag& d = Diag();
            std::fprintf(stderr,
                "[yield-diag] arm=%llu latch=%llu jump=%llu stale=%llu "
                "susp_consume=%llu susp_park=%llu susp_reject=%llu "
                "sw_consume=%llu sw_park=%llu reenter=%llu cas_fail=%llu\n",
                (unsigned long long)d.arm.load(std::memory_order_relaxed),
                (unsigned long long)d.resume_latch.load(std::memory_order_relaxed),
                (unsigned long long)d.resume_jump.load(std::memory_order_relaxed),
                (unsigned long long)d.resume_stale.load(std::memory_order_relaxed),
                (unsigned long long)d.suspend_consume.load(std::memory_order_relaxed),
                (unsigned long long)d.suspend_park.load(std::memory_order_relaxed),
                (unsigned long long)d.suspend_reject.load(std::memory_order_relaxed),
                (unsigned long long)d.switch_consume.load(std::memory_order_relaxed),
                (unsigned long long)d.switch_park.load(std::memory_order_relaxed),
                (unsigned long long)d.reenter.load(std::memory_order_relaxed),
                (unsigned long long)d.anchor_cas_fail.load(std::memory_order_relaxed));
        }

        /**
         * @brief Consumes this anchor (CAS armed -> 0) and posts the resume.
         * @note Only the CAS winner posts; every duplicate, stale or post-completion wakeup
         *       fails the CAS on the shared cell and never dereferences the coroutine.
         *       The cell re-validates the anchor before re-entering, and Resume() latches
         *       a wakeup that races the matching Suspend() so it is never lost.
         */
        bool YieldContext::Anchor::R() const noexcept
        {
            const std::shared_ptr<AnchorCell> cell = cell_;
            if (NULLPTR == cell || 0 == value_)
            {
                return false;
            }

            uint64_t expected = value_;
            if (!cell->armed.compare_exchange_strong(expected, 0, std::memory_order_acq_rel, std::memory_order_acquire))
            {
                if (diag_enabled_) { Diag().anchor_cas_fail.fetch_add(1, std::memory_order_relaxed); }
                return false;
            }

            const uint64_t value = value_;
            auto invoked =
                [cell, value]() noexcept -> void
                {
                    YieldContext::Resume(cell, value);
                };

            bool ok = ppp::threading::Executors::Post(cell->context, cell->strand, invoked);
            if (!ok)
            {
                // Do not overwrite a newer arm or resurrect a completed coroutine.
                std::lock_guard<std::mutex> scope(cell->syncobj);
                if (cell->y && cell->y->anchor_current_ == value)
                {
                    uint64_t unarmed = 0;
                    cell->armed.compare_exchange_strong(unarmed, value,
                        std::memory_order_acq_rel, std::memory_order_acquire);
                }
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            }

            return ok;
        }

        /**
         * @brief Snapshots the coroutine state for hang forensics.
         * @details The snapshot is taken through the shared anchor cell while holding
         *           its mutex: the context destructor takes the same mutex before it
         *           clears the cell, so the context is guaranteed to stay alive for
         *           the duration of the read.
         * @param status Receives the coroutine state flag, or -1 when the coroutine
         *               has already been reclaimed.
         * @param wakeup_pending Receives the number of latched wakeups, or -1 when the
         *                        coroutine has already been reclaimed.
         */
        void YieldContext::Anchor::DebugState(int& status, int& wakeup_pending) const noexcept
        {
            const std::shared_ptr<AnchorCell> cell = cell_;
            if (NULLPTR == cell)
            {
                status = -1;
                wakeup_pending = -1;
                return;
            }

            std::lock_guard<std::mutex> scope(cell->syncobj);
            YieldContext* y = cell->y;
            if (NULLPTR == y)
            {
                /** @brief The coroutine has been reclaimed; only the cell survived. */
                status = -1;
                wakeup_pending = -1;
                return;
            }

            status = y->s_.load(std::memory_order_relaxed);
            wakeup_pending = y->wakeup_pending_ ? 1 : 0;
        }
    }
}
