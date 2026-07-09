#pragma once

/**
 * @file ApplicationMode.h
 * @brief CLI application mode parsing helpers.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace app {

        /**
         * @brief Primary runtime role selected by --mode.
         */
        enum class ApplicationMode {
            Server,
            Client,
            Proxy,
        };

        /**
         * @brief Returns a stable printable name for an application mode value.
         */
        const char* ApplicationModeName(ApplicationMode mode) noexcept;

        /**
         * @brief True when the mode uses the client runtime object (client or proxy).
         */
        inline bool IsClientRuntimeMode(ApplicationMode mode) noexcept {
            return ApplicationMode::Client == mode || ApplicationMode::Proxy == mode;
        }

        /**
         * @brief Parses a normalized mode token (already lower-cased/trimmed).
         */
        ApplicationMode ParseApplicationModeString(const ppp::string& mode_string) noexcept;

        /**
         * @brief Parses `--mode=client|server|proxy` from argv.
         */
        ApplicationMode ResolveApplicationModeFromArgv(int argc, const char* argv[]) noexcept;

        /**
         * @brief Applies proxy-only listener defaults (forced loopback bind + standard ports).
         * @param http_bind HTTP proxy bind address (forced to loopback).
         * @param http_port HTTP proxy port (filled when invalid).
         * @param socks_bind SOCKS proxy bind address (forced to loopback).
         * @param socks_port SOCKS proxy port (filled when invalid).
         */
        void ApplyProxyOnlyListenerDefaults(
            ppp::string& http_bind,
            int& http_port,
            ppp::string& socks_bind,
            int& socks_port) noexcept;

    } // namespace app
} // namespace ppp
