#pragma once

/**
 * @file DnsReachability.h
 * @brief Collects upstream DNS server IPs for VPN bypass routing.
 */

#include <ppp/app/client/dns/Rule.h>
#include <ppp/configurations/DnsServerEntry.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/stdafx.h>

namespace ppp::configurations {
    class AppConfiguration;
}

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                class DnsReachability final {
                public:
                    static ppp::vector<ppp::dns::ServerEntry> BuildResolverEntries(
                        const ppp::vector<ppp::configurations::DnsServerEntry>& config_entries) noexcept;

                    static void CollectProviderIps(
                        const ppp::string& provider_name,
                        const ppp::function<void(uint32_t)>& add_ip) noexcept;

                    static void CollectServerEntryIps(
                        const ppp::vector<ppp::configurations::DnsServerEntry>& entries,
                        const ppp::function<void(uint32_t)>& add_ip) noexcept;

                    static void CollectInterceptReachabilityIps(
                        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                        const ppp::function<void(uint32_t)>& add_ip) noexcept;

                    static void CollectRuleTableReachabilityIps(
                        const ppp::unordered_map<ppp::string, Rule::Ptr>& rules,
                        const ppp::function<void(uint32_t)>& add_tunnel_ip,
                        const ppp::function<void(uint32_t)>& add_nic_ip) noexcept;

                    /** Parses an IPv4 literal for bypass-route installation. */
                    static bool ParseReachabilityIpv4(const ppp::string& address, uint32_t& ipnet) noexcept;
                };

            }
        }
    }
}
