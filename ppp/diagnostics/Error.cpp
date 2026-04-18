#include <ppp/diagnostics/Error.h>

/**
 * @file Error.cpp
 * @brief Implements thread-local error state and error handler registration.
 */

namespace {
    /** @brief Thread-local storage for the last error code. */
    thread_local ppp::diagnostics::ErrorCode    tls_last_error = ppp::diagnostics::ErrorCode::Success;
    /** @brief Synchronizes access to registered error handlers. */
    std::mutex                                  g_error_handlers_sync;
    /** @brief Process-wide callbacks notified for error events. */
    std::vector<ppp::function<void(int err)>>   g_error_handlers;
}

namespace ppp {
    namespace diagnostics {
        /** @brief Gets the calling thread's last error code. */
        ErrorCode GetLastErrorCode() noexcept {
            return tls_last_error;
        }

        /**
         * @brief Sets and returns the calling thread's last error code.
         * @param code Error code to store.
         * @return The same error code that was stored.
         */
        ErrorCode SetLastErrorCode(ErrorCode code) noexcept {
            tls_last_error = code;

            return code;
        }

        /**
         * @brief Converts an error code to a human-readable message.
         * @param code Error code value.
         * @return Static string describing the code, or "Unknown error".
         */
        const char* FormatErrorString(ErrorCode code) noexcept {
            switch (code) {
#define X(name, text) case ErrorCode::name: return text;
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
            default:
                return "Unknown error";
            }
        }

        /**
         * @brief Registers an error callback handler.
         * @param handler Callback receiving integer error code values.
         */
        void RegisterErrorHandler(ppp::function<void(int err)> handler) noexcept {
            if (!handler) {
                return;
            }

            std::lock_guard<std::mutex> scope(g_error_handlers_sync);
            g_error_handlers.emplace_back(std::move(handler));
        }
    }
}
