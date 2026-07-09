/**
 * @file main.cpp
 * @brief Program entry point for launching the PPP application.
 */

#include <ppp/facade/ApplicationBootstrap.h>

/**
 * @brief Starts the PPP application and reports startup failures.
 * @param argc Number of command-line arguments.
 * @param argv Command-line argument values.
 * @return Exit code returned by the application runtime.
 */
int main(int argc, char** argv) {
    return ppp::facade::RunApplication(argc, argv);
}
