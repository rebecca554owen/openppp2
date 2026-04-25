#include <ppp/diagnostics/ErrorHandler.h>
#include <ppp/threading/Executors.h>
#include <ppp/diagnostics/Error.h>

namespace ppp {
    namespace diagnostics {
        ErrorCode& ErrorHandler::ThreadLastErrorCode() noexcept {
            static thread_local ErrorCode tls_last_error_code = ErrorCode::Success;
            return tls_last_error_code;
        }

        uint64_t& ErrorHandler::ThreadLastErrorTimestamp() noexcept {
            static thread_local uint64_t tls_last_error_timestamp = 0;
            return tls_last_error_timestamp;
        }

        ErrorHandler& ErrorHandler::GetDefault() noexcept {
            static ErrorHandler default_error_handler;

            return default_error_handler;
        }

        ErrorCode ErrorHandler::GetLastErrorCode() noexcept {
            return ThreadLastErrorCode();
        }

        ErrorCode ErrorHandler::GetLastErrorCodeSnapshot() noexcept {
            return static_cast<ErrorCode>(last_error_code_snapshot_.load(std::memory_order_relaxed));
        }

        uint64_t ErrorHandler::GetLastErrorTimestamp() noexcept {
            return last_error_timestamp_snapshot_.load(std::memory_order_relaxed);
        }

        ErrorCode ErrorHandler::SetLastErrorCode(ErrorCode code) noexcept {
            ErrorCode& tls_last_error_code = ThreadLastErrorCode();
            uint64_t&  tls_last_error_timestamp = ThreadLastErrorTimestamp();

            tls_last_error_code = code;
            tls_last_error_timestamp = ppp::threading::Executors::GetTickCount();
            last_error_code_snapshot_.store(static_cast<uint32_t>(code), std::memory_order_relaxed);
            last_error_timestamp_snapshot_.store(tls_last_error_timestamp, std::memory_order_relaxed);

            // Prevent recursive callback re-entry from repeatedly redispatching
            // handlers when a handler path calls SetLastErrorCode() again.
            static thread_local bool tls_error_handler_invoking = false;
            if (true == tls_error_handler_invoking) {
                return code;
            }

            struct RecursiveDispatchGuard {
                explicit RecursiveDispatchGuard(bool& flag_ref) noexcept : flag(flag_ref) {
                    flag = true;
                }

                ~RecursiveDispatchGuard() noexcept {
                    flag = false;
                }

                bool& flag;
            } recursive_dispatch_guard(tls_error_handler_invoking);

            // Registration is initialization-only; iterate handlers in-place to
            // avoid lock/copy overhead on hot SetLastErrorCode() paths.

            int error_value = static_cast<int>(code);
            for (const ErrorHandlerEntry& error_handler : error_handlers_) {
                if (NULLPTR == error_handler.handler) {
                    continue;
                }

                try {
                    error_handler.handler(error_value);
                } catch (...) {
                }
            }

            return code;
        }

        const char* ErrorHandler::FormatErrorString(ErrorCode code) noexcept {
            switch (code) {
#define X(name, text, severity) case ErrorCode::name: return text;
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
            default:
                return "Unknown error";
            }
        }

        ErrorSeverity ErrorHandler::GetErrorSeverity(ErrorCode code) noexcept {
            switch (code) {
#define X(name, text, severity) case ErrorCode::name: return severity;
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
            default:
                return ErrorSeverity::kError;
            }
        }

        const char* ErrorHandler::GetErrorSeverityName(ErrorSeverity severity) noexcept {
            switch (severity) {
            case ErrorSeverity::kInfo:
                return "INFO";
            case ErrorSeverity::kWarning:
                return "WARNING";
            case ErrorSeverity::kError:
                return "ERROR";
            case ErrorSeverity::kFatal:
                return "FATAL";
            default:
                return "UNKNOWN";
            }
        }

        ppp::string ErrorHandler::FormatErrorTriplet(ErrorCode code) noexcept {
            // Retrieve the numeric ID, code name, and message for the given code.
            uint32_t    numeric_id   = static_cast<uint32_t>(code);
            const char* code_name    = "Unknown";
            const char* code_message = "Unknown error";

            // Use X-macro expansion to map code → name string and message string.
            switch (code) {
#define X(name, text, severity) case ErrorCode::name: code_name = #name; code_message = text; break;
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
            default:
                break;
            }

            // Build the triplet: "<uint32_id> <CodeName>: <message>"
            ppp::string result;
            result.reserve(128);
            // std::to_string returns std::string (std::allocator); use c_str() to
            // append via const char* overload, which is compatible with ppp::string.
            result += std::to_string(numeric_id).c_str();
            result += ' ';
            result += code_name;
            result += ':';
            result += ' ';
            result += code_message;
            return result;
        }

        bool ErrorHandler::IsErrorFatal(ErrorCode code) noexcept {
            return ErrorSeverity::kFatal == GetErrorSeverity(code);
        }

        void ErrorHandler::RegisterErrorHandler(const ppp::string& key, const ppp::function<void(int err)>& handler) noexcept {
            for (auto it = error_handlers_.begin(); error_handlers_.end() != it; ++it) {
                if (it->key != key) {
                    continue;
                }

                if (NULLPTR == handler) {
                    error_handlers_.erase(it);
                } else {
                    it->handler = handler;
                }
                return;
            }

            if (NULLPTR == handler) {
                return;
            }

            ErrorHandlerEntry entry;
            entry.key = key;
            entry.handler = handler;
            error_handlers_.push_back(std::move(entry));
        }
    }
}
