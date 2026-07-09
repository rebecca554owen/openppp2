#include <ppp/app/client/RouteTableManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/net/IPEndPoint.h>

#if defined(_MACOS)

#include <common/unix/UnixAfx.h>
#include <darwin/ppp/tap/TapDarwin.h>

#include <chrono>
#include <thread>

using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void RouteTableManager::AddRoute() noexcept {
                ppp::telemetry::SpanScope span("client.route.apply");
                struct ScopedRouteApplyHistogram final {
                    std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                    ~ScopedRouteApplyHistogram() noexcept {
                        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                        ppp::telemetry::Histogram("client.route.apply.us", elapsed);
                    }
                } route_apply_histogram;

                ppp::telemetry::Log(Level::kDebug, "client", "route add");
                ppp::telemetry::Count("client.route.add", 1);
                if (auto underlying_ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULLPTR != darwin_tap && !darwin_tap->IsPromisc()) {
                            for (auto&& [ip, gw] : underlying_ni->DefaultRoutes) {
                                ppp::darwin::tun::utun_del_route(ip, gw);
                            }
                        }
                    }

                    ppp::tap::TapDarwin::AddAllRoutes(owner_->rib_);
                }
                AddRouteWithDnsServers();
            }

            bool RouteTableManager::DeleteAllDefaultRoute() noexcept {
                if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                    auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                    if (NULLPTR != unix_tap && !unix_tap->IsPromisc()) {
                        auto rib = ppp::tap::TapDarwin::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                        if (NULLPTR != rib) {
                            for (auto&& [ip, gw] : *rib) {
                                ppp::darwin::tun::utun_del_route(ip, gw);
                            }
                        }
                        return true;
                    }
                }
                return false;
            }

            void RouteTableManager::DeleteRoute() noexcept {
                ppp::telemetry::Log(Level::kDebug, "client", "route delete");
                ppp::telemetry::Count("client.route.delete", 1);
                if (auto underlying_ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    ppp::tap::TapDarwin::DeleteAllRoutes(owner_->rib_);

                    if (auto tap = owner_->GetTap(); NULLPTR != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULLPTR != darwin_tap && !darwin_tap->IsPromisc()) {
                            for (auto&& [ip, gw] : underlying_ni->DefaultRoutes) {
                                ppp::darwin::tun::utun_add_route(ip, gw);
                            }
                        }
                    }
                }
            }

            bool RouteTableManager::AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
                return ppp::darwin::tun::utun_add_route(ip, prefix, gw);
            }

            bool RouteTableManager::DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
                return ppp::darwin::tun::utun_del_route(ip, prefix, gw);
            }

            void RouteTableManager::DeleteRouteWithDnsServers() noexcept {
                if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                    for (uint32_t ip : owner_->dns_serverss_[0]) {
                        DeleteRoute(ip, tap->GatewayServer, 32);
                    }
                }

                if (std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = owner_->underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
                        for (uint32_t ip : owner_->dns_serverss_[1]) {
                            DeleteRoute(ip, next_hop, 32);
                        }
                    }
                }

                for (auto& dns_servers : owner_->dns_serverss_) {
                    dns_servers.clear();
                }
            }

            void RouteTableManager::AddRouteWithDnsServers() noexcept {
                for (auto& dns_servers : owner_->dns_serverss_) {
                    dns_servers.clear();
                }

                auto add_dns_server_to_dns_servers =
                    [](const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& ni, ppp::unordered_set<uint32_t>& dns_servers) noexcept {
                        if (NULLPTR == ni) {
                            return false;
                        }

                        uint32_t ips[2] = { IPEndPoint::AnyAddress, IPEndPoint::AnyAddress };
                        boost::asio::ip::address nips[] = { ni->IPAddress, ni->SubmaskAddress };
                        for (int i = 0; i < arraysizeof(nips); i++) {
                            boost::asio::ip::address& ip = nips[i];
                            if (ip.is_v4()) {
                                ips[i] = ip.to_v4().to_uint();
                            }
                        }

                        uint32_t rip = ips[0] & ips[1];
                        for (boost::asio::ip::address& ip : ni->DnsAddresses) {
                            if (ip.is_v6()) {
                                continue;
                            }

                            if (!ip.is_v4()) {
                                continue;
                            }

                            if (ip.is_multicast()) {
                                continue;
                            }

                            if (ip.is_loopback()) {
                                continue;
                            }

                            if (ip.is_unspecified()) {
                                continue;
                            }

                            if (IPEndPoint::IsInvalid(ip)) {
                                continue;
                            }

                            uint32_t dip = ip.to_v4().to_uint();
                            uint32_t tip = (dip & ips[1]);
                            if (tip == rip) {
                                continue;
                            }

                            dip = htonl(dip);
                            dns_servers.emplace(dip);
                        }
                        return true;
                    };

                add_dns_server_to_dns_servers(owner_->tun_ni_, owner_->dns_serverss_[0]);
                add_dns_server_to_dns_servers(owner_->underlying_ni_, owner_->dns_serverss_[1]);

                if (NULLPTR != owner_->dns_interceptor_) {
                    owner_->dns_interceptor_->CollectReachabilityIps(
                        owner_->configuration_,
                        owner_->configuration_->dns.intercept_unmatched,
                        [this](uint32_t ip) noexcept {
                            owner_->dns_serverss_[0].emplace(ip);
                        },
                        [this](uint32_t ip) noexcept {
                            owner_->dns_serverss_[1].emplace(ip);
                        });

                    std::shared_ptr<const dns::FakeIpPool> fake_ip_pool = owner_->dns_interceptor_->GetFakeIpPool();
                    uint32_t fake_ip_route_network = 0;
                    int fake_ip_route_prefix = 0;
                    if (NULLPTR != fake_ip_pool && fake_ip_pool->GetRoute(fake_ip_route_network, fake_ip_route_prefix)) {
                        if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                            AddRoute(fake_ip_route_network, tap->GatewayServer, fake_ip_route_prefix);
                        }
                    }
                }

                ppp::collections::Dictionary::DeduplicationList(owner_->dns_serverss_[1], owner_->dns_serverss_[0]);

                if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                    for (uint32_t ip : owner_->dns_serverss_[0]) {
                        AddRoute(ip, tap->GatewayServer, 32);
                    }
                }

                if (std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = owner_->underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
                        for (uint32_t ip : owner_->dns_serverss_[1]) {
                            AddRoute(ip, next_hop, 32);
                        }
                    }
                }
            }

            bool RouteTableManager::ProtectDefaultRoute() noexcept {
                auto tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                if (NULLPTR == unix_tap || unix_tap->IsPromisc()) {
                    return false;
                }

                auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(owner_->shared_from_this());
                std::thread([self]() noexcept {
                    auto prepare = [self]() noexcept {
                        if (self->IsDisposed()) {
                            return false;
                        }

                        if (!self->route_added_) {
                            return false;
                        }

                        std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> underlying_ni = self->underlying_ni_;
                        if (NULLPTR == underlying_ni) {
                            return false;
                        }

                        boost::asio::ip::address gw = underlying_ni->GatewayServer;
                        if (!gw.is_v4()) {
                            return false;
                        }

                        return true;
                    };

                    ppp::SetThreadName("protector");
                    for (;;) {
                        uint64_t start = ppp::GetTickCount();

                        bool ok = prepare();
                        if (!ok) {
                            break;
                        }

                        if (self->prdr_.try_lock()) {
                            ok = prepare();
                            if (ok) {
                                ok = self->route_table_->DeleteAllDefaultRoute();
                            }

                            self->prdr_.unlock();
                            if (!ok) {
                                break;
                            }
                        }

                        uint64_t now = ppp::GetTickCount();
                        uint64_t delta = 0;
                        if (now >= start) {
                            delta = 1000 - std::min<uint64_t>(1000, now - start);
                        }

                        ppp::Sleep(delta);
                    }
                }).detach();
                return true;
            }

        }
    }
}

#endif
