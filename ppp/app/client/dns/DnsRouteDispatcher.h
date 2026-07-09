#pragma once

/**
 * @file DnsRouteDispatcher.h
 * @brief Maps DnsRedirectPlan results to concrete DNS handler actions (P4 wiring).
 */

#include <ppp/app/client/dns/DnsRedirectPlan.h>
#include <ppp/stdafx.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                struct DnsRouteDispatcherPorts final {
                    ppp::function<bool()> drop;
                    ppp::function<bool()> defer_to_tunnel;
                    ppp::function<bool(const boost::asio::ip::address& relay_target)> udp_relay;
                    ppp::function<bool()> resolve_unmatched;
                    ppp::function<bool(const ppp::string& provider_name, bool domestic)> resolve_provider;
                };

                class DnsRouteDispatcher final {
                public:
                    static bool Dispatch(
                        const DnsRedirectPlanResult& plan,
                        const DnsRouteDispatcherPorts& ports) noexcept;
                };

            }
        }
    }
}
