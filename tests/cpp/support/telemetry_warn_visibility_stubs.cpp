/**
 * @file telemetry_warn_visibility_stubs.cpp
 * @brief Minimal platform stubs for the telemetry warning-visibility test.
 *
 * Telemetry.cpp and ErrorHandler.cpp reach for the global clock helper through
 * ppp/threading/Executors.cpp, which in turn drags in the whole runtime.  The
 * test only needs the clock, so it is provided directly here.
 */

#include <ppp/threading/Executors.h>

#include <chrono>

namespace ppp {

uint64_t GetTickCount() noexcept {
    const auto now = std::chrono::steady_clock::now();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()).count());
}

namespace threading {

uint64_t Executors::GetTickCount() noexcept {
    return ::ppp::GetTickCount();
}

}

}
