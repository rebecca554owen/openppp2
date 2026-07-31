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
         * @brief Registers or removes a named error callback handler.
         * @param key Unique handler key.
         * @param handler Callback receiving integer error code values.
         */
        void RegisterErrorHandler(const ppp::string& key, const ppp::function<void(int err)>& handler) noexcept {
            ErrorHandler::GetDefault().RegisterErrorHandler(key, handler);
        }

        /**
         * @brief Returns the severity level for the given error code.
         * @param code  The error code to classify.
         * @return      ErrorSeverity as defined in ErrorCodes.def for this code.
         */
        ErrorSeverity GetErrorSeverity(ErrorCode code) noexcept {
            return ErrorHandler::GetDefault().GetErrorSeverity(code);
        }

        /**
         * @brief Returns a short ASCII name for a severity level.
         * @param severity  The severity level to name.
         * @return          "INFO", "WARNING", "ERROR", or "FATAL".
         */
        const char* GetErrorSeverityName(ErrorSeverity severity) noexcept {
            return ErrorHandler::GetDefault().GetErrorSeverityName(severity);
        }

        /**
         * @brief Formats a fully-qualified error triplet: "<id> <CodeName>: <message>".
         * @param code  The error code to format.
         * @return      Formatted ppp::string suitable for diagnostic output.
         */
        ppp::string FormatErrorTriplet(ErrorCode code) noexcept {
            return ErrorHandler::GetDefault().FormatErrorTriplet(code);
        }

        /**
         * @brief Tests whether an error code represents a fatal (unrecoverable) condition.
         * @param code  The error code to test.
         * @return      true if severity == ErrorSeverity::kFatal, false otherwise.
         */
        bool IsErrorFatal(ErrorCode code) noexcept {
            return ErrorHandler::GetDefault().IsErrorFatal(code);
        }
    }
}
