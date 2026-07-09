#include <ppp/facade/ApplicationBootstrap.h>

#include <ppp/app/PppApplication.h>
#include <ppp/diagnostics/Error.h>

#include <cstdio>

namespace ppp {
    namespace facade {

        int RunApplication(int argc, char** argv) noexcept {
            auto& app = ppp::app::PppApplication::GetInstance();
            int result = app.Run(argc, argv);
            if (result != 0) {
                if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
                    ppp::diagnostics::SetLastErrorCode(
                        ppp::diagnostics::ErrorCode::AppMainRunFailedWithoutSpecificError);
                }

                ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                const char* severity_name =
                    ppp::diagnostics::GetErrorSeverityName(ppp::diagnostics::GetErrorSeverity(code));
                ppp::string error_triplet = ppp::diagnostics::FormatErrorTriplet(code);
                fprintf(stderr, "[%s] %s\n", severity_name, error_triplet.data());
            }
            return result;
        }

    }
}
