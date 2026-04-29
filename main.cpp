/**
 * @file main.cpp
 * @brief Program entry point for launching the PPP application.
 */

#include "ppp/app/PppApplication.h"
#include "ppp/diagnostics/Error.h"

/**
 * @brief Starts the PPP application and reports startup failures.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument values.
 * @return Exit code returned by the application runtime.
 */
int main(int argc, char** argv) {
    auto& app = ppp::app::PppApplication::GetInstance();
    int result = app.Run(argc, argv);
    if (result != 0) {
        if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppMainRunFailedWithoutSpecificError);
        }

        ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
        const char* severity_name = ppp::diagnostics::GetErrorSeverityName(ppp::diagnostics::GetErrorSeverity(code));
        ppp::string error_triplet = ppp::diagnostics::FormatErrorTriplet(code);
        fprintf(stderr, "[%s] %s\n", severity_name, error_triplet.data());
    }
    return result;
}
