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
         * @brief Registers a callback for later error notifications.
         * @param handler Handler receiving the integer error value.
         * @note Registration only stores the callback and does not trigger it immediately.
         */
        void                                                                RegisterErrorHandler(ppp::function<void(int err)> handler) noexcept;
    }
}
