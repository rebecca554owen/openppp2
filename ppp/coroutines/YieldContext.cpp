#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

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

            stack_ = ppp::threading::BufferswapAllocator::MakeByteArray(heap, stack_size);
        }

        /** @brief Releases references and owned state fields. */
        YieldContext::~YieldContext() noexcept
        {
            YieldContext* y = this;
            y->h_          = NULLPTR;
            y->stack_      = NULLPTR;
            y->stack_size_ = 0;
            y->strand_     = NULLPTR;
            y->allocator_  = NULLPTR;
        }

        /** @brief Suspends execution and switches back to caller context. */
        bool YieldContext::Suspend() noexcept
        {
            int L = STATUS_RESUMED;
            if (s_.compare_exchange_strong(L, STATUS_SUSPENDING))
            {
                YieldContext* y = this;
                y->caller_.exchange(
                    boost::context::detail::jump_fcontext(
                        y->caller_.exchange(NULLPTR), y).fctx);

                L = STATUS_RESUMING;
                return y->s_.compare_exchange_strong(L, STATUS_RESUMED);
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }
        }

        /** @brief Resumes execution from suspended coroutine context. */
        bool YieldContext::Resume() noexcept
        {
            int L = STATUS_SUSPEND;
            if (s_.compare_exchange_strong(L, STATUS_RESUMING))
            {
                YieldContext* y = this;
                return Switch(
                    boost::context::detail::jump_fcontext(
                        y->callee_.exchange(NULLPTR), y), y);
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                return false;
            }
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
                boost::context::detail::fcontext_t callee =
                    boost::context::detail::make_fcontext(stack + stack_size_, stack_size_, &YieldContext::Handle);
                Switch(boost::context::detail::jump_fcontext(callee, y), y);
            }
            else
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                YieldContext::Release(y);
            }
        }

        /** @brief Performs guarded fcontext jump only when target is valid. */
        boost::context::detail::transfer_t YieldContext::Jump(boost::context::detail::fcontext_t context, void* state) noexcept
        {
            if (context) 
            {
                return boost::context::detail::jump_fcontext(context, state);
            }

            return boost::context::detail::transfer_t{ NULLPTR, NULLPTR };
        }

        /**
         * @brief Finalizes suspend transition by atomically updating state.
         * @throw std::runtime_error Thrown when state machine is corrupted.
         */
        bool YieldContext::Switch() noexcept(false)
        {
            int L = STATUS_SUSPENDING;
            if (s_.compare_exchange_strong(L, STATUS_SUSPEND))
            {
                return true;
            }

            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
            
            throw std::runtime_error("The internal atomic state used for the yield_context switch was corrupted..");
        }

        /**
         * @brief Stores transfer context and finishes one switch cycle.
         */
        bool YieldContext::Switch(const boost::context::detail::transfer_t& t, YieldContext* y) noexcept
        {
            if (t.data)
            {
                y->callee_.exchange(t.fctx);
                return y->Switch();
            }
            else
            {
                YieldContext::Release(y);
                return true;
            }
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
        void YieldContext::Handle(boost::context::detail::transfer_t t) noexcept
        {
            YieldContext* y = (YieldContext*)t.data;
            if (y)
            {
                SpawnHander h = std::move(y->h_);
                y->h_ = NULLPTR;
                y->caller_.exchange(t.fctx);

                if (h)
                {
                    h(*y);
                    h = NULLPTR;
                }

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
         * @brief Posts a resume request to the strand.
         * @note Removed infinite retry loop - if Resume() fails, it indicates the coroutine
         *       is not in SUSPEND state (already completed or corrupted), retrying will not help.
         *       Caller must handle failure cases appropriately.
         */
        bool YieldContext::R() noexcept
        {
            YieldContext* y = this;
            auto invoked =
                [y]() noexcept -> void
                {
                    bool resumed = y->Resume();
                    if (!resumed)
                    {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeStateTransitionInvalid);
                    }
                };

            boost::asio::io_context* context = &y->context_;
            bool ok = ppp::threading::Executors::Post(context, y->strand_, invoked);
            if (!ok)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            }

            return ok;
        }
    }
}
