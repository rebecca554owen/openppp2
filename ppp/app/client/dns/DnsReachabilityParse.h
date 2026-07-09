#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                /** Parses an IPv4 literal for bypass-route installation. */
                bool ParseReachabilityIpv4(const ppp::string& address, uint32_t& ipnet) noexcept;

            }
        }
    }
}
