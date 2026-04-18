#pragma once

/**
 * @file Stopwatch.h
 * @brief Declares a thread-safe elapsed-time measurement utility.
 */

#include <ppp/stdafx.h>
#include <ppp/DateTime.h>

namespace ppp 
{
    namespace diagnostics 
    {
        /**
         * @brief Provides methods to accurately measure elapsed time.
         */
        class Stopwatch final
        {
            using clock_timepoint                   = std::chrono::high_resolution_clock::time_point;
            using SynchronizeObject                 = std::mutex;
            using SynchronizeObjectScope            = std::lock_guard<SynchronizeObject>;

        public:
            /**
             * @brief Starts measuring time if not already started.
             */
            void                                    Start() noexcept;

            /**
             * @brief Restarts the stopwatch and starts measuring immediately.
             */
            void                                    StartNew() noexcept { Restart(); }

            /**
             * @brief Stops measuring and captures the stop timestamp.
             */
            void                                    Stop() noexcept;

            /**
             * @brief Clears all state and resets elapsed time to zero.
             */
            void                                    Reset() noexcept;

            /**
             * @brief Resets and starts measuring from the current timestamp.
             */
            void                                    Restart() noexcept;

            /**
             * @brief Indicates whether the stopwatch is currently running.
             * @return True when started and not yet stopped.
             */
            bool                                    IsRunning() noexcept;

        public:
            /**
             * @brief Gets elapsed time in milliseconds.
             * @return Elapsed milliseconds.
             */
            int64_t                                 ElapsedMilliseconds() noexcept;

            /**
             * @brief Gets elapsed time in high-resolution tick units (nanoseconds).
             * @return Elapsed nanoseconds.
             */
            int64_t                                 ElapsedTicks() noexcept;

            /**
             * @brief Gets elapsed time as a DateTime-style duration value.
             * @return Elapsed duration represented from DateTime::MinValue().
             */
            DateTime                                Elapsed() noexcept;

        private:
            SynchronizeObject                       syncobj_;
            clock_timepoint                         start_;
            clock_timepoint                         stop_;
        };
    }
}
