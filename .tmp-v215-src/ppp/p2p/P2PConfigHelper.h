#pragma once

/**
 * @file P2PConfigHelper.h
 * @brief Helper to build P2PConfig from AppConfiguration.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace p2p {

        /**
         * @brief Builds a P2PConfig from the application configuration.
         *
         * @param app_config Application configuration snapshot.
         * @return Populated P2PConfig with validated defaults.
         */
        P2PConfig BuildP2PConfig(
                const ppp::configurations::AppConfiguration& app_config) noexcept;

    }
}
