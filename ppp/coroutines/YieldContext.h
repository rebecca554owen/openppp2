#pragma once

#include <ppp/stdafx.h>
#include <boost/coroutine/detail/coroutine_context.hpp>
#include <boost/context/detail/fcontext.hpp>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp
{
    namespace coroutines
    {
        /**
         * @file YieldContext.h
         * @brief Declares stackful coroutine yield/resume context utilities.
         */

        /**
         * @brief Stackful coroutine context integrated with Boost.Asio execution.
         */
        class YieldContext final
        {
        public:
            /** @brief Coroutine entry handler signature. */
            typedef ppp::function<void(YieldContext&)>                          SpawnHander;

        public:
            /** @brief Attempts to resume a suspended coroutine context. */
            bool                                                                Resume() noexcept;
            /** @brief Suspends current coroutine and yields to caller context. */
            bool                                                                Suspend() noexcept;
            /** @brief Gets `this` as a raw pointer. */
            YieldContext*                                                       GetPtr() const noexcept        { return constantof(this);}
            /** @brief Gets bound Asio I/O context. */
            boost::asio::io_context&                                            GetContext() const noexcept    { return context_; }
            /** @brief Gets optional bound strand used for posting operations. */
            boost::asio::strand<boost::asio::io_context::executor_type>*        GetStrand() const noexcept     { return strand_; }

        public:
            /** @brief Returns whether internal state is non-zero. */
            bool                                                                S() noexcept { return s_.load() != 0; }
            /** @brief Convenience alias of `Suspend()`. */
            bool                                                                Y() noexcept { return Suspend(); }
            /** @brief Posts a resume operation back to the executor. */
            bool                                                                R() noexcept;

        public:
            /** @brief Always true for non-null `this`. */
            operator                                                            bool() const noexcept          { return NULLPTR != GetPtr(); }
            /** @brief Implicit conversion to raw pointer. */
            operator                                                            YieldContext*() const noexcept { return GetPtr();         }

        public:
            /**
             * @brief Spawns a coroutine using default stack size.
             */
            static bool                                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn) noexcept
            {
                return YieldContext::Spawn(context, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Spawns a coroutine with explicit stack size.
             */
            static bool                                                         Spawn(boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
            {
                ppp::threading::BufferswapAllocator* allocator = NULLPTR;
                return YieldContext::Spawn(allocator, context, std::move(spawn), stack_size);
            }

            /**
             * @brief Spawns a coroutine with optional custom allocator.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn) noexcept
            {
                return YieldContext::Spawn(allocator, context, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Spawns a coroutine with custom allocator and stack size.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, SpawnHander&& spawn, int stack_size) noexcept
            {
                boost::asio::strand<boost::asio::io_context::executor_type>* strand = NULLPTR;
                return YieldContext::Spawn(allocator, context, strand, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Spawns a coroutine and binds it to an optional strand.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn)
            {
                return YieldContext::Spawn(allocator, context, strand, std::move(spawn), PPP_COROUTINE_STACK_SIZE);
            }

            /**
             * @brief Spawns a coroutine with full control over allocator, strand, and stack size.
             */
            static bool                                                         Spawn(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept;

        private:
            /** @brief Builds and enters coroutine execution context. */
            void                                                                Invoke() noexcept;
            /** @brief Entry trampoline for newly created fcontext. */
            static void                                                         Handle(boost::context::detail::transfer_t t) noexcept(false);
            /** @brief Validates and transitions suspend state atomically. */
            bool                                                                Switch() noexcept(false);
            /** @brief Stores transfer context and finalizes switch step. */
            static bool                                                         Switch(const boost::context::detail::transfer_t& t, YieldContext* y) noexcept;

        private:
            template <typename T, typename... A>
            /**
             * @brief Allocates and constructs an object via optional custom allocator.
             */
            static T*                                                           New(ppp::threading::BufferswapAllocator* allocator, A&&... args) noexcept
            {
                if (NULLPTR == allocator)
                {
                    void* memory = Malloc(sizeof(T));
                    if (NULLPTR == memory)
                    {
                        return NULLPTR;
                    }

                    memset(memory, 0, sizeof(T)); /* -Wdynamic-class-memaccess */
                    return new (memory) T(allocator, std::forward<A&&>(args)...);
                }
                else
                {
                    void* memory = allocator->Alloc(sizeof(T));
                    if (NULLPTR == memory)
                    {
                        allocator = NULLPTR;
                        return New<T>(allocator, std::forward<A&&>(args)...);
                    }

                    memset(memory, 0, sizeof(T)); /* -Wdynamic-class-memaccess */
                    return new (memory) T(allocator, std::forward<A&&>(args)...);
                }
            }

            template <typename T>
            /**
             * @brief Destroys and frees an object created by `New`.
             */
            static bool                                                         Release(T* p) noexcept
            {
                if (NULLPTR == p)
                {
                    return false;
                }

                ppp::threading::BufferswapAllocator* const allocator = p->allocator_;
                p->~T();

                if (NULLPTR == allocator)
                {
                    Mfree(p);
                }
                else
                {
                    allocator->Free(p);
                }

                return true;
            }

            /**
             * @brief Performs safe context jump when target context is valid.
             */
            static boost::context::detail::transfer_t                           Jump(boost::context::detail::fcontext_t context, void* state) noexcept;

        private:
            YieldContext() = delete;
            YieldContext(YieldContext&&) = delete;
            YieldContext(const YieldContext&) = delete;
            YieldContext(ppp::threading::BufferswapAllocator* allocator, boost::asio::io_context& context, boost::asio::strand<boost::asio::io_context::executor_type>* strand, SpawnHander&& spawn, int stack_size) noexcept;
            ~YieldContext() noexcept;

        private:
            /** @brief Atomic coroutine state flag. */
            std::atomic<int>                                                    s_          = 0;
            /** @brief Stored callee context handle. */
            std::atomic<boost::context::detail::fcontext_t>                     callee_     = NULLPTR;
            /** @brief Stored caller context handle. */
            std::atomic<boost::context::detail::fcontext_t>                     caller_     = NULLPTR;
            /** @brief User-provided coroutine entry function. */
            SpawnHander                                                         h_;
            /** @brief Associated Asio I/O context. */
            boost::asio::io_context&                                            context_;
            /** @brief Optional strand for serialized callback dispatch. */
            boost::asio::strand<boost::asio::io_context::executor_type>*        strand_;
            /** @brief Allocated coroutine stack size in bytes. */
            int                                                                 stack_size_ = 0;
            /** @brief Backing storage for coroutine stack memory. */
            std::shared_ptr<Byte>                                               stack_;
            /** @brief Optional allocator used for context object allocation. */
            ppp::threading::BufferswapAllocator*                                allocator_  = NULLPTR;
        };
    }
}
