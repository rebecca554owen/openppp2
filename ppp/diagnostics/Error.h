#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace diagnostics {
        enum class ErrorCode : int {
#define X(name, text) name,
#include <ppp/diagnostics/ErrorCodes.def>
#undef X
        };

        ErrorCode                                                           GetLastErrorCode() noexcept;
        ErrorCode                                                           SetLastErrorCode(ErrorCode code) noexcept;
        const char*                                                         FormatErrorString(ErrorCode code) noexcept;
        void                                                                RegisterErrorHandler(ppp::function<void(int err)> handler) noexcept;
    }
}
