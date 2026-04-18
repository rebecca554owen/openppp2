#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/ErrorHandler.h>

namespace ppp {
    namespace diagnostics {
        /** @brief Gets the calling thread's last error code. */
        ErrorCode GetLastErrorCode() noexcept {
            return ErrorHandler::GetDefault().GetLastErrorCode();
        }

        ErrorCode GetLastErrorCodeSnapshot() noexcept {
            return ErrorHandler::GetDefault().GetLastErrorCodeSnapshot();
        }

        uint64_t GetLastErrorTimestamp() noexcept {
            return ErrorHandler::GetDefault().GetLastErrorTimestamp();
        }

        /**
         * @brief Sets and returns the calling thread's last error code.
         * @param code Error code to store.
         * @return The same error code that was stored.
         */
        ErrorCode SetLastErrorCode(ErrorCode code) noexcept {
            return ErrorHandler::GetDefault().SetLastErrorCode(code);
        }

        /**
         * @brief Converts an error code to a human-readable message.
         * @param code Error code value.
         * @return Static string describing the code, or "Unknown error".
         */
        const char* FormatErrorString(ErrorCode code) noexcept {
            return ErrorHandler::GetDefault().FormatErrorString(code);
        }

        /**
         * @brief Registers an error callback handler.
         * @param handler Callback receiving integer error code values.
         */
        void RegisterErrorHandler(ppp::function<void(int err)> handler) noexcept {
            ErrorHandler::GetDefault().RegisterErrorHandler(std::move(handler));
        }
    }
}
