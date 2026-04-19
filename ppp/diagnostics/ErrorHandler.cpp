#include <ppp/diagnostics/ErrorHandler.h>
#include <ppp/threading/Executors.h>

namespace ppp {
    namespace diagnostics {
        thread_local ErrorCode ErrorHandler::tls_last_error_code_ = ErrorCode::Success;
        thread_local uint64_t ErrorHandler::tls_last_error_timestamp_ = 0;

        ErrorHandler& ErrorHandler::GetDefault() noexcept {
            static ErrorHandler default_error_handler;

            return default_error_handler;
        }

        ErrorCode ErrorHandler::GetLastErrorCode() noexcept {
            return tls_last_error_code_;
        }

        ErrorCode ErrorHandler::GetLastErrorCodeSnapshot() noexcept {
            return static_cast<ErrorCode>(last_error_code_snapshot_.load(std::memory_order_relaxed));
        }

        uint64_t ErrorHandler::GetLastErrorTimestamp() noexcept {
            return last_error_timestamp_snapshot_.load(std::memory_order_relaxed);
        }

        ErrorCode ErrorHandler::SetLastErrorCode(ErrorCode code) noexcept {
            tls_last_error_code_ = code;
            tls_last_error_timestamp_ = ppp::threading::Executors::GetTickCount();
            last_error_code_snapshot_.store(static_cast<uint32_t>(code), std::memory_order_relaxed);
            last_error_timestamp_snapshot_.store(tls_last_error_timestamp_, std::memory_order_relaxed);

            ppp::unordered_map<ppp::string, ppp::function<void(int err)>> error_handlers;
            {
                std::lock_guard<std::mutex> scope(error_handlers_sync_);
                error_handlers = error_handlers_;
            }

            int error_value = static_cast<int>(code);
            for (auto&& error_handler : error_handlers) {
                if (NULLPTR == error_handler.second) {
                    continue;
                }

                try {
                    error_handler.second(error_value);
                } catch (...) {
                }
            }

            return code;
        }

        const char* ErrorHandler::FormatErrorString(ErrorCode code) noexcept {
            switch (code) {
#define X(name, text) case ErrorCode::name: return text;
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
            default:
                return "Unknown error";
            }
        }

        void ErrorHandler::RegisterErrorHandler(const ppp::string& key, const ppp::function<void(int err)>& handler) noexcept {
            std::lock_guard<std::mutex> scope(error_handlers_sync_);

            if (NULLPTR == handler) {
                error_handlers_.erase(key);
                return;
            }

            error_handlers_[key] = handler;
        }
    }
}
