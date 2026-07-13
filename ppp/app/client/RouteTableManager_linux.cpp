#include <ppp/app/client/RouteTableManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/route/LinuxRoutePlatform.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/RouteState.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)

#include <linux/ppp/tap/TapLinux.h>

#include <chrono>
#include <thread>

using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            std::unique_ptr<route::LinuxRoutePlatform>
            RouteTableManager::NewLinuxRoutePlatform() noexcept {
                if (NULLPTR == owner_) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                std::shared_ptr<ClientNetworkInterface> tap_ni = owner_->GetTapNetworkInterface();
                std::shared_ptr<ClientNetworkInterface> underlying_ni = owner_->GetUnderlyingNetworkInterface();
                ppp::tap::TapLinux* linux_tap =
                    NULLPTR == tap ? NULLPTR : dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                if (NULLPTR == tap || NULLPTR == tap_ni || NULLPTR == underlying_ni || NULLPTR == linux_tap) {
                    return NULLPTR;
                }

                std::unordered_map<uint32_t, std::string> nics;
                for (const auto& pair : owner_->nics_) {
                    nics.emplace(
                        pair.first,
                        std::string(pair.second.begin(), pair.second.end()));
                }

                return std::make_unique<route::LinuxRoutePlatform>(
                    tap->GatewayServer,
                    std::string(tap_ni->Name.begin(), tap_ni->Name.end()),
                    std::string(underlying_ni->Name.begin(), underlying_ni->Name.end()),
                    std::move(nics),
                    linux_tap->IsPromisc());
            }

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
                if (NULLPTR == route_state_) {
                    return;
                }

                route_state_->ReplaceRib(owner_->rib_);
                route_state_->ReplaceFib(owner_->fib_);
                std::unordered_map<uint32_t, std::string> nics;
                for (const auto& pair : owner_->nics_) {
                    nics.emplace(pair.first, std::string(pair.second.begin(), pair.second.end()));
                }
                route_state_->ReplaceNics(std::move(nics));

                std::unique_ptr<route::LinuxRoutePlatform> platform = NewLinuxRoutePlatform();
                if (NULLPTR == platform) {
                    return;
                }

                const route::RouteStateSnapshot snapshot = route_state_->Snapshot();
                std::vector<route::RouteSpec> specs = route::BuildRouteSpecs(snapshot.rib);
                route_coordinator_ = std::make_unique<route::RouteCoordinator>(
                    *route_state_,
                    std::move(platform));
                if (!route_coordinator_->Apply(specs)) {
                    route_coordinator_.reset();
                    return;
                }
                AddRouteWithDnsServers();
            }

            bool RouteTableManager::DeleteAllDefaultRoute() noexcept {
                std::unique_ptr<route::LinuxRoutePlatform> platform = NewLinuxRoutePlatform();
                if (NULLPTR == platform) {
                    return false;
                }
                route::RouteSnapshotPtr defaults = platform->CaptureDefaults();
                return platform->RemoveDefaults(defaults);
            }

            void RouteTableManager::DeleteRoute() noexcept {
                ppp::telemetry::Log(Level::kDebug, "client", "route delete");
                ppp::telemetry::Count("client.route.delete", 1);

                if (NULLPTR != route_coordinator_) {
                    route_coordinator_->Stop();
                    route_coordinator_.reset();
                }
            }

            bool RouteTableManager::AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
                std::unique_ptr<route::LinuxRoutePlatform> platform = NewLinuxRoutePlatform();
                if (NULLPTR == platform) {
                    return false;
                }
                route::RouteSpec spec;
                spec.network = ip;
                spec.gateway = gw;
                spec.prefix = prefix;
                return platform->Add(spec);
            }

            bool RouteTableManager::DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
                std::unique_ptr<route::LinuxRoutePlatform> platform = NewLinuxRoutePlatform();
                if (NULLPTR == platform) {
                    return false;
                }
                route::RouteSpec spec;
                spec.network = ip;
                spec.gateway = gw;
                spec.prefix = prefix;
                return platform->Delete(spec);
            }

            void RouteTableManager::DeleteRouteWithDnsServers() noexcept {
                if (NULLPTR == route_state_) {
                    return;
                }

                const route::RouteStateSnapshot snapshot = route_state_->Snapshot();
                if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                    for (uint32_t ip : snapshot.dns_servers[0]) {
                        DeleteRoute(ip, tap->GatewayServer, 32);
                    }
                }

                if (std::shared_ptr<ClientNetworkInterface> ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
                        for (uint32_t ip : snapshot.dns_servers[1]) {
                            DeleteRoute(ip, next_hop, 32);
                        }
                    }
                }

                route_state_->ClearDnsServers();
            }

            void RouteTableManager::AddRouteWithDnsServers() noexcept {
                if (NULLPTR == route_state_) {
                    return;
                }
                route_state_->ClearDnsServers();

                auto add_dns_server_to_dns_servers =
                    [this](const std::shared_ptr<ClientNetworkInterface>& ni, int bucket) noexcept {
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
                            route_state_->AddDnsServer(bucket, dip);
                        }
                        return true;
                    };

                add_dns_server_to_dns_servers(owner_->GetTapNetworkInterface(), 0);
                add_dns_server_to_dns_servers(owner_->GetUnderlyingNetworkInterface(), 1);

                if (NULLPTR != owner_->dns_interceptor_ && NULLPTR != owner_->configuration_) {
                    owner_->dns_interceptor_->CollectReachabilityIps(
                        owner_->configuration_,
                        owner_->configuration_->dns.intercept_unmatched,
                        [this](uint32_t ip) noexcept { route_state_->AddDnsServer(0, ip); },
                        [this](uint32_t ip) noexcept { route_state_->AddDnsServer(1, ip); });
                }

                if (std::shared_ptr<dns::DnsInterceptor> interceptor = owner_->dns_interceptor_; NULLPTR != interceptor) {
                    std::shared_ptr<const dns::FakeIpPool> fake_ip_pool = interceptor->GetFakeIpPool();
                    uint32_t fake_ip_route_network = 0;
                    int fake_ip_route_prefix = 0;
                    if (NULLPTR != fake_ip_pool && fake_ip_pool->GetRoute(fake_ip_route_network, fake_ip_route_prefix)) {
                        if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                            AddRoute(fake_ip_route_network, tap->GatewayServer, fake_ip_route_prefix);
                        }
                    }
                }

                route_state_->DeduplicateDnsServers();
                const route::RouteStateSnapshot snapshot = route_state_->Snapshot();

                if (std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap(); NULLPTR != tap) {
                    for (uint32_t ip : snapshot.dns_servers[0]) {
                        AddRoute(ip, tap->GatewayServer, 32);
                    }
                }

                if (std::shared_ptr<ClientNetworkInterface> ni = owner_->GetUnderlyingNetworkInterface(); NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
                        for (uint32_t ip : snapshot.dns_servers[1]) {
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

                auto unix_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
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
