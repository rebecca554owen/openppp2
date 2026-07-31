#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        namespace detail {
            static inline ppp::string NormalizeDnsProtocol(const ppp::string& raw_protocol) noexcept {
                ppp::string proto = ToLower(LTrim(RTrim(raw_protocol)));
                if (proto == "doq") {
                    return "dot";
                }
                return proto;
            }

            static inline bool IsSupportedDnsProtocol(const ppp::string& protocol) noexcept {
                return protocol.empty() || protocol == "udp" || protocol == "tcp" || protocol == "doh" || protocol == "dot";
            }
        }
    }
}
