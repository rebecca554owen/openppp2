#pragma once

/**
 * @file Error.h
 * @brief Declares diagnostic error codes and thread-local error helpers.
 */

#include <cstdint>
#include <ppp/stdafx.h>

namespace ppp {
    namespace diagnostics {
        /**
         * @brief Enumerates framework-specific diagnostic error codes.
         */
        enum class ErrorCode : uint32_t {
#define X(name, text) name,
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
        };

        /**
         * @brief Gets the current thread's last diagnostic error code.
         * @return The current last error code.
         */
        ErrorCode                                                           GetLastErrorCode() noexcept;

        /**
         * @brief Sets the current thread's last diagnostic error code.
         * @param code Error code to store.
         * @return The same error code that was provided.
         */
        ErrorCode                                                           SetLastErrorCode(ErrorCode code) noexcept;

        /**
         * @brief Converts an error code to a readable static message.
         * @param code Error code to format.
         * @return Null-terminated message for the provided code.
         */
        const char*                                                         FormatErrorString(ErrorCode code) noexcept;

        /**
         * @brief Registers a callback for later error notifications.
         * @param handler Handler receiving the integer error value.
         * @note Registration only stores the callback and does not trigger it immediately.
         */
        void                                                                RegisterErrorHandler(ppp::function<void(int err)> handler) noexcept;
    }
}
