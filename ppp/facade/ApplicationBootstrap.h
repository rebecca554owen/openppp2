#pragma once

/**
 * @file ApplicationBootstrap.h
 * @brief Thin process entry facade for launching the PPP runtime.
 */

namespace ppp {
    namespace facade {

        /**
         * @brief Runs the PPP application and prints a diagnostic triplet on failure.
         * @param argc Command-line argument count.
         * @param argv Command-line argument vector.
         * @return Process exit code from the application runtime.
         */
        int RunApplication(int argc, char** argv) noexcept;

    }
}
