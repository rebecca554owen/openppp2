#include <ppp/diagnostics/Stopwatch.h>

/**
 * @file Stopwatch.cpp
 * @brief Implements a thread-safe high-resolution stopwatch.
 */

#include <iostream>
#include <ctime>
#include <chrono>

/**
 * @brief Stopwatch implementation for high-resolution elapsed time measurement.
 */

namespace ppp 
{
    namespace diagnostics
    {
        /**
         * @brief Calculates elapsed ticks between two time points.
         * @tparam Duration Target duration unit for conversion.
         * @param start Start time point.
         * @param stop Stop time point; current time is used when default-initialized.
         * @return Elapsed duration count in the requested unit.
         */
        template <typename Duration>
        static constexpr int64_t ElapsedTimed(std::chrono::high_resolution_clock::time_point start, std::chrono::high_resolution_clock::time_point stop) noexcept
        {
            if (stop == std::chrono::high_resolution_clock::time_point())
            {
                stop = std::chrono::high_resolution_clock::now();
            }

            return std::chrono::duration_cast<Duration>(stop - start).count();
        }

        void Stopwatch::Start() noexcept
        {
            std::chrono::high_resolution_clock::time_point null_;
            /**
             * @brief Lock-protected start transition; preserves existing start timestamp.
             */
            do
            {
                SynchronizeObjectScope scope(syncobj_);
                stop_ = null_;

                if (start_ == null_)
                {
                    start_ = std::chrono::high_resolution_clock::now();
                }
            } while (false);
        }

        void Stopwatch::Stop() noexcept
        {
            std::chrono::high_resolution_clock::time_point null_;
            /**
             * @brief Lock-protected stop transition; records current time when running.
             */
            do
            {
                SynchronizeObjectScope scope(syncobj_);
                if (start_ == null_)
                {
                    start_ = null_;
                    stop_ = null_;
                }
                else
                {
                    stop_ = std::chrono::high_resolution_clock::now();
                }
            } while (false);
        }

        void Stopwatch::Reset() noexcept
        {
            std::chrono::high_resolution_clock::time_point null_;
            /**
             * @brief Lock-protected full state reset.
             */
            do
            {
                SynchronizeObjectScope scope(syncobj_);
                start_ = null_;
                stop_ = null_;
            } while (false);
        }

        void Stopwatch::Restart() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            start_ = std::chrono::high_resolution_clock::now();
            stop_ = std::chrono::high_resolution_clock::time_point();
        }

        int64_t Stopwatch::ElapsedMilliseconds() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            return ElapsedTimed<std::chrono::milliseconds>(start_, stop_);
        }

        int64_t Stopwatch::ElapsedTicks() noexcept
        {
            SynchronizeObjectScope scope(syncobj_);
            return ElapsedTimed<std::chrono::nanoseconds>(start_, stop_);
        }

        bool Stopwatch::IsRunning() noexcept
        {
            std::chrono::high_resolution_clock::time_point null_;
            do
            {
                SynchronizeObjectScope scope(syncobj_);
                return start_ != null_ && stop_ == null_;
            } while (false);
        }

        DateTime Stopwatch::Elapsed() noexcept
        {
            int64_t ms = ElapsedMilliseconds();
            return DateTime::MinValue().AddMilliseconds(ms);
        }
    }
}
