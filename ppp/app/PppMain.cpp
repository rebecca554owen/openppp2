#include <ppp/app/PppApplication.h>
#include <ppp/diagnostics/Error.h>

int main(int argc, const char* argv[]) noexcept {
    int rc = RunPppApplicationMain(argc, argv);
    const ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
    if (rc != 0 && code != ppp::diagnostics::ErrorCode::Success) {
        fputs(ppp::diagnostics::FormatErrorString(code), stdout);
        fputs("\r\n", stdout);
        fflush(stdout);
    }
    return rc;
}
