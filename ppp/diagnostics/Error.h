#pragma once

/**
 * @file Error.h
 * @brief Declares diagnostic error codes and thread-local error helpers.
 */

#include <cstdint>
#include <type_traits>
#include <ppp/stdafx.h>

namespace ppp {
    namespace diagnostics {
        /**
         * @brief Severity classification for diagnostic error codes.
         *
         * @details Severity levels are used to classify the urgency and
         *          recoverability of a diagnostic condition:
         *          - kInfo    : Normal informational state (no error).
         *          - kWarning : Recoverable condition; degraded service is possible.
         *          - kError   : Non-recoverable for the affected session or operation.
         *          - kFatal   : Unrecoverable; the process must halt or restart.
         */
        enum class ErrorSeverity : uint8_t
        {
            kInfo    = 0, ///< Informational; normal operation with no error condition.
            kWarning = 1, ///< Recoverable; degraded service may continue.
            kError   = 2, ///< Non-recoverable for the affected session or operation.
            kFatal   = 3, ///< Unrecoverable; process must halt or restart.
        };

        /**
         * @brief Enumerates framework-specific diagnostic error codes.
         */
        enum class ErrorCode : uint32_t {
#define X(name, text, severity) name,
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
         * @brief Gets the most recent process-wide error code snapshot.
         * @return Last observed error code across threads.
         */
        ErrorCode                                                           GetLastErrorCodeSnapshot() noexcept;

        /**
         * @brief Gets process-wide timestamp for the latest error update.
         * @return Tick count when last error code snapshot was set.
         */
        uint64_t                                                            GetLastErrorTimestamp() noexcept;

        /**
         * @brief Sets the last error code and returns a caller-provided value.
         * @tparam T Return type.
         * @param code Error code to store.
         * @param value Value to return.
         * @return The provided value.
         */
        template <typename T>
        T                                                                   SetLastError(ErrorCode code, T value) noexcept {
            SetLastErrorCode(code);
            return value;
        }

        /**
         * @brief Sets the last error code and returns false.
         * @param code Error code to store.
         * @return false.
         */
        inline bool                                                         SetLastError(ErrorCode code) noexcept {
            SetLastErrorCode(code);
            return false;
        }

        /**
         * @brief Sets the last error code and returns -1 for integer failure paths.
         * @tparam TInt Integral return type except bool.
         * @param code Error code to store.
         * @return -1 converted to TInt.
         */
        template <typename TInt, typename std::enable_if<std::is_integral<TInt>::value && !std::is_same<TInt, bool>::value, int>::type = 0>
        TInt                                                                SetLastError(ErrorCode code) noexcept {
            SetLastErrorCode(code);
            return static_cast<TInt>(-1);
        }

        /**
         * @brief Sets the last error code and returns NULLPTR for pointer failure paths.
         * @tparam TPointer Pointer return type.
         * @param code Error code to store.
         * @return NULLPTR.
         */
        template <typename TPointer, typename std::enable_if<std::is_pointer<TPointer>::value, int>::type = 0>
        TPointer                                                            SetLastError(ErrorCode code) noexcept {
            SetLastErrorCode(code);
            return NULLPTR;
        }

        /**
         * @brief Converts an error code to a readable static message.
         * @param code Error code to format.
         * @return Null-terminated message for the provided code.
         */
        const char*                                                         FormatErrorString(ErrorCode code) noexcept;

        /**
         * @brief Retrieves the severity level associated with a diagnostic error code.
         * @param code  The error code to classify.
         * @return      The ErrorSeverity value defined for the given code.
         * @note        Returns ErrorSeverity::kError for any unrecognized code value.
         */
        ErrorSeverity                                                       GetErrorSeverity(ErrorCode code) noexcept;

        /**
         * @brief Returns a short human-readable name for a severity level.
         * @param severity  The severity level to name.
         * @return          A null-terminated ASCII string: "INFO", "WARNING", "ERROR", or "FATAL".
         *                  Returns "UNKNOWN" for out-of-range values.
         */
        const char*                                                         GetErrorSeverityName(ErrorSeverity severity) noexcept;

        /**
         * @brief Formats a fully-qualified error triplet string for diagnostics output.
         * @param code  The error code to format.
         * @return      A ppp::string of the form "<uint32_id> <CodeName>: <message text>".
         *              Example: "305 IPv6LeasePoolExhausted: The IPv6 lease pool has no remaining addresses..."
         */
        ppp::string                                                         FormatErrorTriplet(ErrorCode code) noexcept;

        /**
         * @brief Tests whether an error code represents a fatal (unrecoverable) condition.
         * @param code  The error code to test.
         * @return      true if GetErrorSeverity(code) == ErrorSeverity::kFatal, false otherwise.
         */
        bool                                                                IsErrorFatal(ErrorCode code) noexcept;

        /**
         * @brief Registers or removes a named callback for later error notifications.
         * @param key Unique handler key used to update or remove a registration.
         * @param handler Handler receiving the integer error value.
         * @note Registration only stores the callback and does not trigger it immediately.
         * @note Registration is NOT thread-safe and must be completed before starting multi-thread runtime.
         */
        void                                                                RegisterErrorHandler(const ppp::string& key, const ppp::function<void(int err)>& handler) noexcept;
    }
}
