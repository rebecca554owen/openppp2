#pragma once

/**
 * @file DnsInterceptor.h
 * @brief Owns DNS rules, resolver lifecycle, and intercepted query handling.
 */

#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/dns/IDnsPolicy.h>
#include <ppp/app/client/dns/FakeIpPool.h>
#include <ppp/app/client/dns/DnsRedirectPlan.h>
#include <ppp/app/client/dns/Rule.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/stdafx.h>

namespace ppp { namespace configurations { class AppConfiguration; } }
namespace ppp { namespace dns { class DnsResolver; } }

#if defined(_LINUX)
namespace ppp { namespace net { class ProtectorNetwork; } }
#endif

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace dns {

                class DnsInterceptor final : public IDnsPolicy {
                public:
                    using RuleMap = ppp::unordered_map<ppp::string, Rule::Ptr>;

                    DnsInterceptor() noexcept = default;

                    bool Open(
                        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                        const std::shared_ptr<boost::asio::io_context>& context,
                        bool proxy_only
#if defined(_LINUX)
                        , const std::shared_ptr<ppp::net::ProtectorNetwork>& protect_network
#endif
                    ) noexcept;

                    void Close() noexcept override;

                    void OnSessionInfo(
                        const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions,
                        bool allow_ipv6_response) noexcept;

                    int LoadRules(const ppp::string& rules, bool from_file = false) noexcept;

                    void CollectReachabilityIps(
                        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                        bool intercept_unmatched,
                        const ppp::function<void(uint32_t)>& add_tunnel_ip,
                        const ppp::function<void(uint32_t)>& add_nic_ip) noexcept;

                    bool HandleQuery(
                        const DnsHostPorts& host,
                        const std::shared_ptr<VEthernetExchanger>& exchanger,
                        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;

                    std::shared_ptr<ppp::dns::DnsResolver> GetResolver() const noexcept { return dns_resolver_; }

                    const RuleMap* RuleTables() const noexcept { return dns_ruless_; }

                    std::shared_ptr<const FakeIpPool> GetFakeIpPool() const noexcept { return std::atomic_load(&fake_ip_pool_); }

                private:
                    void SpawnFakeIpBackgroundResolve(
                        const DnsRedirectPlanResult& plan,
                        const Rule::Ptr& rule,
                        const ppp::string& hostname,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;

                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration_;
                    std::shared_ptr<ppp::dns::DnsResolver> dns_resolver_;
                    std::shared_ptr<FakeIpPool> fake_ip_pool_ = make_shared_object<FakeIpPool>();
                    RuleMap dns_ruless_[3];
                };

            }
        }
    }
}
