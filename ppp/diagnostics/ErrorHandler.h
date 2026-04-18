#pragma once

#include <ppp/diagnostics/Error.h>
#include <atomic>

namespace ppp {
    namespace diagnostics {
        class ErrorHandler final {
        public:
            static ErrorHandler&                                                   GetDefault() noexcept;

        public:
            ErrorCode                                                              GetLastErrorCode() noexcept;
            ErrorCode                                                              GetLastErrorCodeSnapshot() noexcept;
            uint64_t                                                               GetLastErrorTimestamp() noexcept;
            ErrorCode                                                              SetLastErrorCode(ErrorCode code) noexcept;
            const char*                                                            FormatErrorString(ErrorCode code) noexcept;
            void                                                                   RegisterErrorHandler(ppp::function<void(int err)> handler) noexcept;

        private:
            ErrorHandler() noexcept = default;

            ErrorHandler(const ErrorHandler&) = delete;
            ErrorHandler& operator=(const ErrorHandler&) = delete;

        private:
            static thread_local ErrorCode                                          tls_last_error_code_;
            static thread_local uint64_t                                           tls_last_error_timestamp_;
            std::atomic<uint32_t>                                                  last_error_code_snapshot_{static_cast<uint32_t>(ErrorCode::Success)};
            std::atomic<uint64_t>                                                  last_error_timestamp_snapshot_{0};

            std::mutex                                                             error_handlers_sync_;
            std::vector<ppp::function<void(int err)>>                              error_handlers_;
        };
    }
}
