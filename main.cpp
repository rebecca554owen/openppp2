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
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericUnknown);
        }
        fprintf(stderr, "%s\n", ppp::diagnostics::FormatErrorString(ppp::diagnostics::GetLastErrorCode()));
    }
    return result;
}
