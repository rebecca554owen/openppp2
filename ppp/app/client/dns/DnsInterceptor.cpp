#include "DnsInterceptor.h"

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/dns/DnsReachability.h>
#include <ppp/app/client/dns/DnsFakeIpResponse.h>
#include <ppp/app/client/dns/DnsRedirectPlan.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/dns/DnsRouteDispatcher.h>
#include <ppp/app/client/dns/DnsUdpRelay.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/vdns.h>
#if defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/tap/ITap.h>

#if defined(_ANDROID)
#include <android/OpenPPP2VpnProtectBridge.h>
#include <android/log.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
#endif

#include <common/dnslib/message.h>

using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::tap::ITap;

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static bool ParseStunCandidate(const ppp::string& s, ppp::dns::StunCandidate& out) noexcept {
                    ppp::string text = ATrim(s);
                    if (text.empty()) {
                        return false;
                    }

                    int port = 3478;
                    ppp::string host;
                    std::size_t colon = text.rfind(':');
                    if (colon != ppp::string::npos && colon > 0) {
                        host = text.substr(0, colon);
                        ppp::string port_str = text.substr(colon + 1);
                        int p = atoi(port_str.data());
                        if (p > 0 && p <= 65535) {
                            port = p;
                        }
                    }
                    else {
                        host = text;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address ip = ppp::StringToAddress(host.data(), ec);
                    if (ec || ip.is_unspecified()) {
                        return false;
                    }

                    out.ip = ip;
                    out.port = port;
                    return true;
                }

                static bool ParseStunHostnameCandidate(
                    const ppp::string& s,
                    ppp::dns::StunHostnameCandidate& out) noexcept {

                    ppp::string text = ATrim(s);
                    if (text.empty()) {
                        return false;
                    }

                    out.port = 3478;
                    std::size_t colon = text.rfind(':');
                    if (colon != ppp::string::npos && colon > 0) {
                        out.hostname = text.substr(0, colon);
                        ppp::string port_str = text.substr(colon + 1);
                        int p = atoi(port_str.data());
                        if (p > 0 && p <= 65535) {
                            out.port = p;
                        }
                    }
                    else {
                        out.hostname = text;
                    }

                    if (out.hostname.empty()) {
                        return false;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address ip = ppp::StringToAddress(out.hostname.data(), ec);
                    return ec || ip.is_unspecified();
                }

                static DnsQueryType ToPlanQueryType(::dns::RecordType type) noexcept {
                    return type == ::dns::RecordType::kAAAA ? DnsQueryType::kAAAA : DnsQueryType::kA;
                }

                bool DnsInterceptor::Open(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                    const std::shared_ptr<boost::asio::io_context>& context,
                    bool proxy_only
#if defined(_LINUX)
                    , const std::shared_ptr<ppp::net::ProtectorNetwork>& protect_network
#endif
                ) noexcept {
                    configuration_ = configuration;
                    if (proxy_only || NULLPTR == context || NULLPTR == configuration) {
                        return true;
                    }

                    dns_resolver_ = make_shared_object<ppp::dns::DnsResolver>(*context);
                    if (NULLPTR == dns_resolver_) {
                        return true;
                    }

#if defined(_ANDROID)
                    dns_resolver_->SetProtectSocketCallback(
                        [](int handle) noexcept -> bool {
                            return ppp::android::ProtectSocketFd(handle);
                        });
#elif defined(_LINUX)
                    if (NULLPTR != protect_network) {
                        auto pn = protect_network;
                        dns_resolver_->SetProtectSocketCallback(
                            [pn](int handle) noexcept -> bool {
                                return pn->ProtectSync(handle);
                            });
                    }
                    else {
                        dns_resolver_->SetProtectSocketCallback(
                            [](int /*handle*/) noexcept -> bool {
                                return true;
                            });
                    }
#endif

                    ppp::string domestic = configuration->dns.servers.domestic;
                    ppp::string foreign = configuration->dns.servers.foreign;
                    if (!domestic.empty() || !foreign.empty()) {
                        dns_resolver_->SetDefaultProviders(domestic, foreign);
                    }

                    dns_resolver_->SetEcsConfig(
                        configuration->dns.ecs.enabled,
                        configuration->dns.ecs.override_ip);
                    dns_resolver_->SetTlsVerifyPeer(configuration->dns.tls.verify_peer);

                    if (!configuration->dns.stun.candidates.empty()) {
                        ppp::vector<ppp::dns::StunCandidate> stun_cands;
                        ppp::vector<ppp::dns::StunHostnameCandidate> stun_host_cands;
                        for (const ppp::string& cs : configuration->dns.stun.candidates) {
                            ppp::dns::StunCandidate sc;
                            if (ParseStunCandidate(cs, sc)) {
                                stun_cands.emplace_back(std::move(sc));
                                continue;
                            }

                            ppp::dns::StunHostnameCandidate hc;
                            if (ParseStunHostnameCandidate(cs, hc)) {
                                stun_host_cands.emplace_back(std::move(hc));
                                continue;
                            }

                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "client", "DNS STUN candidate ignored: %s", cs.c_str());
                        }
                        if (!stun_cands.empty()) {
                            dns_resolver_->SetStunCandidates(std::move(stun_cands));
                        }
                        if (!stun_host_cands.empty()) {
                            dns_resolver_->SetStunHostnameCandidates(std::move(stun_host_cands));
                        }
                    }

                    if (configuration->dns.fake_ip.enabled) {
                        std::shared_ptr<FakeIpPool> fake_ip_pool = std::atomic_load(&fake_ip_pool_);
                        if (NULLPTR == fake_ip_pool) {
                            fake_ip_pool = make_shared_object<FakeIpPool>();
                            std::atomic_store(&fake_ip_pool_, fake_ip_pool);
                        }
                        if (NULLPTR != fake_ip_pool) {
                            fake_ip_pool->Configure(configuration->dns.fake_ip.range);
                        }
                    }
                    else {
                        std::shared_ptr<FakeIpPool> fake_ip_pool = std::atomic_load(&fake_ip_pool_);
                        if (NULLPTR != fake_ip_pool) {
                            fake_ip_pool->Clear();
                        }
                    }

                    return true;
                }

                void DnsInterceptor::Close() noexcept {
                    std::shared_ptr<FakeIpPool> fake_ip_pool =
                        std::atomic_exchange(&fake_ip_pool_, std::shared_ptr<FakeIpPool>());
                    if (NULLPTR != fake_ip_pool) {
                        fake_ip_pool->Clear();
                    }
                    dns_resolver_.reset();
                    for (auto& table : dns_ruless_) {
                        table.clear();
                    }
                    configuration_.reset();
                }

                void DnsInterceptor::OnSessionInfo(
                    const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions,
                    bool allow_ipv6_response) noexcept {
                    if (NULLPTR == dns_resolver_) {
                        return;
                    }

                    if (!extensions.ClientExitIP.is_unspecified()) {
                        dns_resolver_->SetExitIP(extensions.ClientExitIP);
                    }

                    dns_resolver_->SetAllowIPv6Response(allow_ipv6_response);
                }

                int DnsInterceptor::LoadRules(const ppp::string& rules, bool from_file) noexcept {
                    if (from_file) {
                        return Rule::LoadFile(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                    }
                    return Rule::Load(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                }

                void DnsInterceptor::CollectReachabilityIps(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                    bool intercept_unmatched,
                    const ppp::function<void(uint32_t)>& add_tunnel_ip,
                    const ppp::function<void(uint32_t)>& add_nic_ip) noexcept {

                    for (const auto& table : dns_ruless_) {
                        DnsReachability::CollectRuleTableReachabilityIps(table, add_tunnel_ip, add_nic_ip);
                    }

                    if (intercept_unmatched) {
                        DnsReachability::CollectInterceptReachabilityIps(configuration, add_nic_ip);
                    }
                }

                static void ApplyFakeIpBackgroundResponse(
                    FakeIpPool& pool,
                    const ppp::string& hostname,
                    const ppp::vector<Byte>& response) noexcept {

                    if (response.empty()) {
                        return;
                    }

                    const uint32_t real_ip = DnsFakeIpResponse::ParseFirstARecordNetwork(
                        response.data(), static_cast<int>(response.size()));
                    if (real_ip == 0) {
                        return;
                    }

                    pool.SetRealIp(hostname, real_ip);
                    ppp::net::asio::vdns::AddCache(
                        response.data(), static_cast<int>(response.size()));
                    ppp::telemetry::Count("dns.fake_ip.resolved", 1);
                }

                void DnsInterceptor::SpawnFakeIpBackgroundResolve(
                    const DnsRedirectPlanResult& plan,
                    const Rule::Ptr& rule,
                    const ppp::string& hostname,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept {

                    std::shared_ptr<ppp::dns::DnsResolver> resolver = dns_resolver_;
                    if (NULLPTR == resolver || NULLPTR == configuration_ || NULLPTR == messages) {
                        return;
                    }

                    std::shared_ptr<FakeIpPool> pool = std::atomic_load(&fake_ip_pool_);
                    if (NULLPTR == pool) {
                        return;
                    }
                    const auto callback =
                        [pool, hostname](ppp::vector<Byte> response) noexcept {
                            ApplyFakeIpBackgroundResponse(*pool, hostname, response);
                        };

                    switch (plan.action) {
                    case DnsRouteAction::kResolveProvider:
                        resolver->ResolveAsync(
                            plan.provider_name, plan.provider_domestic,
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            callback);
                        return;

                    case DnsRouteAction::kResolveUnmatched:
                    case DnsRouteAction::kDeferToTunnel: {
                        ppp::vector<ppp::dns::ServerEntry> foreign_entries =
                            DnsReachability::BuildResolverEntries(configuration_->dns.servers.foreign_entries);
                        if (!foreign_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                foreign_entries, false,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return;
                        }

                        ppp::vector<ppp::dns::ServerEntry> domestic_entries =
                            DnsReachability::BuildResolverEntries(configuration_->dns.servers.domestic_entries);
                        if (!domestic_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                domestic_entries, true,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return;
                        }

                        resolver->ResolveAsyncWithFallback(
                            configuration_->dns.servers.foreign,
                            configuration_->dns.servers.domestic,
                            "cloudflare",
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            callback);
                        return;
                    }

                    case DnsRouteAction::kUdpRelay:
                        if (NULLPTR != rule && !rule->ProviderName.empty()) {
                            resolver->ResolveAsync(
                                rule->ProviderName, rule->Nic,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length,
                                callback);
                            return;
                        }

                        if (NULLPTR != rule && !rule->Server.is_unspecified()) {
                            ppp::dns::ServerEntry entry;
                            entry.protocol = ppp::dns::Protocol::UDP;
                            entry.address = rule->Server.to_string();
                            ppp::vector<ppp::dns::ServerEntry> entries;
                            entries.emplace_back(std::move(entry));
                            resolver->ResolveAsyncWithEntries(
                                entries, rule->Nic,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                        }
                        return;

                    default:
                        return;
                    }
                }

                bool DnsInterceptor::HandleQuery(
                    const DnsQueryContext& context,
                    const std::shared_ptr<const DnsSessionContext>& session,
                    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept {

                    if (!context.IsValid()) {
                        return false;
                    }

                    ::dns::Message m;
                    if (m.decode(static_cast<uint8_t*>(messages->Buffer.get()), messages->Length) != ::dns::BufferResult::NoError) {
                        return false;
                    }
                    if (m.questions.empty()) {
                        return false;
                    }

                    boost::asio::ip::address destinationIP = Ipep::ToAddress(packet->Destination);
                    ::dns::QuestionSection& qs = *m.questions.data();

                    if (qs.mType == ::dns::RecordType::kAAAA &&
                        NULLPTR != dns_resolver_ &&
                        !dns_resolver_->IsAllowIPv6Response()) {
                        ppp::vector<Byte> synthesized = ppp::dns::DnsResolver::BuildAaaaBlockedResponse(
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length);
                        if (!synthesized.empty()) {
                            ppp::telemetry::Count("dns.redirect.aaaa_blocked", 1);
                            return context.datagram_output(
                                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source),
                                boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT),
                                synthesized.data(), static_cast<int>(synthesized.size()), false);
                        }
                    }

                    if (!ppp::net::asio::vdns::QueryCache2(
                            qs.mName.data(), m,
                            qs.mType == ::dns::RecordType::kA ?
                                ppp::net::asio::vdns::AddressFamily::kA :
                                ppp::net::asio::vdns::AddressFamily::kAAAA).empty()) {
                        std::size_t dns_size = 0;
                        char dns_packet[PPP_MAX_DNS_PACKET_BUFFER_SIZE];
                        if (m.encode(dns_packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE, dns_size) == ::dns::BufferResult::NoError &&
                            dns_size > 0) {
                            return context.datagram_output(
                                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source),
                                boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT),
                                dns_packet, static_cast<int>(dns_size), false);
                        }
                    }

                    DnsRedirectPlanInput plan_input;
                    plan_input.qtype = ToPlanQueryType(qs.mType);
                    plan_input.destination = destinationIP;
                    plan_input.intercept_unmatched =
                        NULLPTR != configuration_ && configuration_->dns.intercept_unmatched;
                    plan_input.has_resolver = NULLPTR != dns_resolver_;
                    plan_input.allow_ipv6_response =
                        NULLPTR == dns_resolver_ || dns_resolver_->IsAllowIPv6Response();
#if !defined(_ANDROID)
                    plan_input.defer_same_destination_to_tunnel = true;
#endif

                    if (std::shared_ptr<ITap> tap = context.tap; NULLPTR != tap) {
                        const uint32_t dest = packet->Destination;
                        const uint32_t gw = IPEndPoint::ToEndPoint(
                            IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(tap->GatewayServer, IPEndPoint::MinPort)).GetAddress();
                        const uint32_t mask = IPEndPoint::ToEndPoint(
                            IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(tap->SubmaskAddress, IPEndPoint::MinPort)).GetAddress();
                        plan_input.is_gateway_query =
                            DnsRedirectPlan::IsGatewayDnsServer(dest, gw, mask);
                    }

                    plan_input.rule = Rule::Get(
                        stl::transform<ppp::string>(qs.mName),
                        dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);

                    if (plan_input.is_gateway_query) {
                        auto& dnsServers = ppp::net::asio::vdns::servers;
                        plan_input.gateway_upstream_available =
                            NULLPTR != dnsServers && !dnsServers->empty();
                        if (plan_input.gateway_upstream_available) {
                            plan_input.gateway_upstream = dnsServers->begin()->address();
                        }
                    }

                    const ppp::string hostname_lower = stl::transform<ppp::string>(qs.mName);
                    const DnsRedirectPlanResult plan = DnsRedirectPlan::Decide(plan_input);

                    const bool passthrough =
                        plan.action == DnsRouteAction::kUdpRelay &&
                        NULLPTR == plan_input.rule &&
                        !plan_input.is_gateway_query &&
                        !plan_input.intercept_unmatched;

                    std::shared_ptr<FakeIpPool> fake_ip_pool = std::atomic_load(&fake_ip_pool_);
                    if (!passthrough &&
                        plan.action != DnsRouteAction::kDrop &&
                        qs.mType == ::dns::RecordType::kA &&
                        NULLPTR != fake_ip_pool &&
                        fake_ip_pool->IsEnabled() &&
                        DnsFakeIpResponse::ShouldUseFakeIp(hostname_lower)) {

                        const uint32_t fake_ip_host = fake_ip_pool->Allocate(hostname_lower);
                        if (fake_ip_host != 0) {
                            ppp::vector<Byte> fake_response = DnsFakeIpResponse::BuildARecordResponse(
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length,
                                fake_ip_host);
                            if (!fake_response.empty()) {
                                const boost::asio::ip::udp::endpoint sourceEP =
                                    IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                                const boost::asio::ip::udp::endpoint destEP(destinationIP, PPP_DNS_SYS_PORT);
                                ppp::telemetry::Count("dns.fake_ip.allocated", 1);
                                context.datagram_output(
                                    sourceEP, destEP,
                                    fake_response.data(), static_cast<int>(fake_response.size()), false);
                                SpawnFakeIpBackgroundResolve(plan, plan_input.rule, hostname_lower, messages);
                                return true;
                            }
                        }
                    }

                    const boost::asio::ip::udp::endpoint sourceEP =
                        IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                    const boost::asio::ip::udp::endpoint destEP(destinationIP, PPP_DNS_SYS_PORT);

                    DnsRouteDispatcherPorts dispatch_ports;
                    dispatch_ports.drop = []() noexcept { return false; };
                    dispatch_ports.defer_to_tunnel = [&]() noexcept {
                        context.handle_resolver_response(messages, sourceEP, destEP, ppp::vector<Byte>{});
                        return true;
                    };
                    dispatch_ports.udp_relay = [&](const boost::asio::ip::address& relay_target) noexcept {
                        return DnsUdpRelay::Spawn(
                            context, session, packet, frame, messages, relay_target, destinationIP);
                    };
                    dispatch_ports.resolve_unmatched = [&]() noexcept {
                        std::shared_ptr<ppp::dns::DnsResolver> resolver = dns_resolver_;
                        auto callback =
                            [resolver, context, sourceEP, destEP, messages, packet](ppp::vector<Byte> response) noexcept {
                                (void)resolver;
                                (void)packet;
                                context.handle_resolver_response(messages, sourceEP, destEP, std::move(response));
                            };

                        ppp::vector<ppp::dns::ServerEntry> foreign_entries =
                            DnsReachability::BuildResolverEntries(configuration_->dns.servers.foreign_entries);
                        if (!foreign_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                foreign_entries, false,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return true;
                        }

                        ppp::vector<ppp::dns::ServerEntry> domestic_entries =
                            DnsReachability::BuildResolverEntries(configuration_->dns.servers.domestic_entries);
                        if (!domestic_entries.empty()) {
                            resolver->ResolveAsyncWithEntries(
                                domestic_entries, true,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length, callback);
                            return true;
                        }

                        resolver->ResolveAsyncWithFallback(
                            configuration_->dns.servers.foreign,
                            configuration_->dns.servers.domestic,
                            "cloudflare",
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            callback);
                        return true;
                    };
                    dispatch_ports.resolve_provider = [&](const ppp::string& provider_name, bool domestic) noexcept {
                        std::shared_ptr<ppp::dns::DnsResolver> resolver = dns_resolver_;
                        resolver->ResolveAsync(
                            provider_name, domestic,
                            static_cast<const Byte*>(messages->Buffer.get()),
                            messages->Length,
                            [resolver, context, sourceEP, destEP, messages, packet](ppp::vector<Byte> response) noexcept {
                                (void)resolver;
                                (void)packet;
                                context.handle_resolver_response(messages, sourceEP, destEP, std::move(response));
                            });
                        return true;
                    };

                    return DnsRouteDispatcher::Dispatch(plan, dispatch_ports);
                }

            }
        }
    }
}
