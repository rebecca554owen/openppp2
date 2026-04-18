#include <ppp/threading/SpinLock.h>
#include <ppp/threading/Thread.h>

/**
 * @file SpinLock.cpp
 * @brief Implements spin lock and recursive spin lock behavior.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Shared try-enter loop helper for lock-like objects.
         * @tparam LockObject Lock type exposing `TryEnter()`.
         * @param lock Lock instance to acquire.
         * @param loop Maximum retry attempts; negative means infinite retries.
         * @param timeout Timeout in milliseconds; negative means no timeout.
         * @return true if acquired; otherwise false.
         */
        template <class LockObject>
        static constexpr bool Lock_TryEnter(
            LockObject&                                             lock,
            int                                                     loop,
            int                                                     timeout) noexcept
        {
            /**
             * @brief Attempts one acquisition pass and evaluates timeout state.
             */
            auto tryEnter = 
                [&lock, timeout](uint64_t last) noexcept -> int
                {
                    bool lockTaken = lock.TryEnter();
                    if (lockTaken)
                    {
                        return 1;
                    }
                
                    if (timeout < 0)
                    {
                        return 0;
                    }
                
                    uint64_t now = GetTickCount();
                    return static_cast<int64_t>(now - last) < timeout ? 0 : -1;
                };

            uint64_t last = GetTickCount();
            if (loop > -1)
            {
                for (int i = 0; i < loop; i++)
                {
                    int status = tryEnter(last);
                    if (status != 0)
                    {
                        return status > 0;
                    }
                }

                return false;
            }
            
            for (;;)
            {
                int status = tryEnter(last);
                if (status != 0)
                {
                    return status > 0;
                }
            }
        }

        /**
         * @brief Shared recursive acquisition helper for recursive lock wrappers.
         * @tparam LockObject Recursive lock wrapper type.
         * @tparam LockInternalObject Internal non-recursive lock type.
         * @tparam TryEnterArguments Argument pack forwarded to internal `TryEnter`.
         * @param lock Recursive lock wrapper.
         * @param lock_internal Internal lock object.
         * @param tid Pointer to owner thread identifier storage.
         * @param reentries Recursive depth counter.
         * @param arguments Forwarded arguments for internal acquisition.
         * @return true when acquisition or legal re-entry succeeds; otherwise false.
         */
        template <class LockObject, class LockInternalObject, typename... TryEnterArguments>
        static constexpr bool RecursiveLock_TryEnter(LockObject&    lock, 
            LockInternalObject&                                     lock_internal, 
            volatile int64_t*                                       tid,
            std::atomic<int>&                                       reentries, 
            TryEnterArguments&&...                                  arguments)
        {
            int n = ++reentries;
            assert(n > 0);

            int64_t current_tid = GetCurrentThreadId(); /* std::hash<std::thread::id>{}(std::this_thread::get_id()); */
            if (n == 1)
            {
                bool lockTaken = lock_internal.TryEnter(std::forward<TryEnterArguments>(arguments)...);
                if (!lockTaken)
                {
                    reentries--;
                    return false;
                }

                Thread::MemoryBarrier();
                *tid = current_tid;
                Thread::MemoryBarrier();
            }
            else
            {
                Thread::MemoryBarrier();
                int lockTaken_tid = *tid;
                Thread::MemoryBarrier();

                if (lockTaken_tid != current_tid)
                {
                    reentries--;
                    return false;
                }
            }

            return true;
        }

        /**
         * @brief Constructs an unlocked spin lock.
         */
        SpinLock::SpinLock() noexcept
            : _(false)
        {

        }

        /**
         * @brief Ensures the lock is not held at destruction time.
         * @throws std::runtime_error Thrown when the lock is still held.
         */
        SpinLock::~SpinLock() noexcept(false)
        {
            bool lockTaken = IsLockTaken();
            if (lockTaken)
            {
                throw std::runtime_error("Failed to release the atomic lock.");
            }
        }

        /**
         * @brief Attempts to acquire with loop and timeout controls.
         */
        bool SpinLock::TryEnter(int loop, int timeout) noexcept
        {
            return Lock_TryEnter(*this, loop, timeout);
        }

        /**
         * @brief Attempts a single atomic acquisition.
         */
        bool SpinLock::TryEnter() noexcept 
        {
            int expected = FALSE;
            return _.compare_exchange_strong(expected, TRUE);
        }

        /**
         * @brief Releases the atomic lock state.
         * @throws std::runtime_error Thrown when lock ownership state is invalid.
         */
        void SpinLock::Leave()
        {
            int expected = TRUE;
            bool ok = _.compare_exchange_strong(expected, FALSE);
            if (!ok)
            {
                throw std::runtime_error("Failed to acquire the atomic lock.");
            }
        }

        /**
         * @brief Constructs an unlocked recursive spin lock.
         */
        RecursiveSpinLock::RecursiveSpinLock() noexcept
            : lockobj_()
            , tid_(0)
            , reentries_(0)
        {

        }

        /**
         * @brief Attempts to acquire recursively once.
         */
        bool RecursiveSpinLock::TryEnter() noexcept
        {
            return RecursiveLock_TryEnter(*this, lockobj_, &tid_, reentries_);
        }

        /**
         * @brief Attempts recursive acquisition with loop and timeout controls.
         */
        bool RecursiveSpinLock::TryEnter(int loop, int timeout) noexcept
        {
            return RecursiveLock_TryEnter(*this, lockobj_, &tid_, reentries_, loop, timeout);
        }

        /**
         * @brief Releases one recursion level and unlocks on final release.
         */
        void RecursiveSpinLock::Leave() 
        {
            int n = --reentries_;
            assert(n >= 0);

            if (n == 0)
            {
                lockobj_.Leave();
            }
        }
    }
}
