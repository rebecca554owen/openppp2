#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {

        /**
         * @brief Structured DNS server entry with multi-protocol metadata.
         *
         * Shared between AppConfiguration and DNS reachability helpers so
         * consumers do not need the full configuration header.
         */
        struct DnsServerEntry final {
            ppp::string protocol;
            ppp::string url;
            ppp::string hostname;
            ppp::string address;
            ppp::vector<ppp::string> bootstrap;
        };

    }
}
