#include <ppp/stdafx.h>
#include <ppp/diagnostics/Error.h>

#include <cmath>

namespace ppp {

bool IsNaN(double d) noexcept {
    return std::isnan(d);
}

bool ToBoolean(const char* s) noexcept {
    if (NULLPTR == s || *s == '\x0') {
        return false;
    }

    char ch = s[0];
    if (ch == '0' || ch == ' ') {
        return false;
    }

    if (ch == 'f' || ch == 'F') {
        return false;
    }

    if (ch == 'n' || ch == 'N') {
        return false;
    }

    if (ch == 'c' || ch == 'C') {
        return false;
    }
    return true;
}

}  // namespace ppp

namespace ppp::diagnostics {

ErrorCode SetLastErrorCode(ErrorCode code) noexcept {
    return code;
}

}  // namespace ppp::diagnostics
