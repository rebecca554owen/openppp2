#pragma once

/**
 * @file P2PConfigHelper.h
 * @brief Helper to build P2PConfig from AppConfiguration.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/p2p/P2PCrypto.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace p2p {

        /**
         * @brief Builds a P2PConfig from the application configuration.
         *
         * @param app_config Application configuration snapshot.
         * @return Populated P2PConfig with validated defaults.
         */
        inline P2PConfig BuildP2PConfig(
                const ppp::configurations::AppConfiguration& app_config) noexcept {
            P2PConfig cfg;
            cfg.max_probes          = app_config.p2p.max_probes;
            cfg.probe_timeout_ms    = app_config.p2p.probe_timeout_ms;
            cfg.heartbeat_interval_ms = app_config.p2p.heartbeat_interval_ms;
            cfg.heartbeat_miss_max  = app_config.p2p.heartbeat_miss_max;
            cfg.suspect_timeout_ms  = app_config.p2p.suspect_timeout_ms;
            cfg.migration_grace_ms  = app_config.p2p.migration_grace_ms;
            cfg.buffer_pool_count   = app_config.p2p.buffer_pool_count;
            cfg.preferred_cipher    = DetectPreferredCipher();
            return cfg;
        }

    }
}
