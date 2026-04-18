#include <ppp/diagnostics/Error.h>

namespace {
    thread_local ppp::diagnostics::ErrorCode    tls_last_error = ppp::diagnostics::ErrorCode::Success;
    std::mutex                                  g_error_handlers_sync;
    std::vector<ppp::function<void(int err)>>   g_error_handlers;
}

namespace ppp {
    namespace diagnostics {
        ErrorCode GetLastErrorCode() noexcept {
            return tls_last_error;
        }

        ErrorCode SetLastErrorCode(ErrorCode code) noexcept {
            tls_last_error = code;

            std::vector<ppp::function<void(int err)>> handlers;
            {
                std::lock_guard<std::mutex> scope(g_error_handlers_sync);
                handlers = g_error_handlers;
            }

            for (auto& handler : handlers) {
                if (handler) {
                    handler(static_cast<int>(code));
                }
            }

            return code;
        }

        const char* FormatErrorString(ErrorCode code) noexcept {
            switch (code) {
#define X(name, text) case ErrorCode::name: return text;
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
            default:
                return "Unknown error";
            }
        }

        void RegisterErrorHandler(ppp::function<void(int err)> handler) noexcept {
            if (!handler) {
                return;
            }

            std::lock_guard<std::mutex> scope(g_error_handlers_sync);
            g_error_handlers.emplace_back(std::move(handler));
        }
    }
}
