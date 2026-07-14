#include <ppp/stdafx.h>
#include <ppp/app/client/RouteTableManager.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/app/client/route/RouteState.h>
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

            std::unique_ptr<route::DarwinRoutePlatform>
            RouteTableManager::NewDarwinRoutePlatform(const route::RoutePlanInput& input) noexcept {
                if (input.tap_gateway == 0) {
                    return NULLPTR;
                }
                return std::make_unique<route::DarwinRoutePlatform>(
                    input.tap_gateway,
                    input.tap_promiscuous);
            }

            void RouteTableManager::AddRoute(const route::RoutePlanInput& input) noexcept {
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
                std::unique_ptr<route::DarwinRoutePlatform> platform = NewDarwinRoutePlatform(input);
                if (NULLPTR == platform) {
                    return;
                }
                if (!route_coordinator_->SetPlatform(std::move(platform))) {
                    return;
                }
                if (!route_coordinator_->Apply(route::BuildRouteSpecs(Snapshot().rib))) {
                    return;
                }
                AddRouteWithDnsServers(input);
            }

            void RouteTableManager::DeleteRoute() noexcept {
                ppp::telemetry::Log(Level::kDebug, "client", "route delete");
                ppp::telemetry::Count("client.route.delete", 1);
                if (NULLPTR != route_coordinator_) {
                    route_coordinator_->Stop();
                }
            }

            bool RouteTableManager::AddRoute(const route::RoutePlanInput& input, uint32_t ip, uint32_t gw, int prefix) noexcept {
                std::unique_ptr<route::DarwinRoutePlatform> platform = NewDarwinRoutePlatform(input);
                return NULLPTR != platform && platform->Add(route::RouteSpec{ ip, gw, prefix, {} });
            }

            bool RouteTableManager::DeleteRoute(const route::RoutePlanInput& input, uint32_t ip, uint32_t gw, int prefix) noexcept {
                std::unique_ptr<route::DarwinRoutePlatform> platform = NewDarwinRoutePlatform(input);
                return NULLPTR != platform && platform->Delete(route::RouteSpec{ ip, gw, prefix, {} });
            }

            void RouteTableManager::DeleteRouteWithDnsServers(const route::RoutePlanInput& input) noexcept {
                const route::RouteStateSnapshot snapshot = Snapshot();
                for (uint32_t ip : snapshot.dns_servers[0]) {
                    DeleteRoute(input, ip, input.tap_gateway, 32);
                }
                const auto& gw = input.underlying_interface.gateway;
                if (gw.is_v4()) {
                    uint32_t next_hop = htonl(gw.to_v4().to_uint());
                    for (uint32_t ip : snapshot.dns_servers[1]) {
                        DeleteRoute(input, ip, next_hop, 32);
                    }
                }

                ClearDnsServers();
            }

            void RouteTableManager::AddRouteWithDnsServers(const route::RoutePlanInput& input) noexcept {
                ClearDnsServers();

                auto add_dns_server_to_dns_servers =
                    [this](const route::RouteInterfaceSnapshot& ni, int bucket) noexcept {
                        if (ni.name.empty()) {
                            return false;
                        }

                        uint32_t ips[2] = { IPEndPoint::AnyAddress, IPEndPoint::AnyAddress };
                        boost::asio::ip::address nips[] = { ni.ip, ni.submask };
                        for (int i = 0; i < arraysizeof(nips); i++) {
                            boost::asio::ip::address& ip = nips[i];
                            if (ip.is_v4()) {
                                ips[i] = ip.to_v4().to_uint();
                            }
                        }

                        uint32_t rip = ips[0] & ips[1];
                        for (const boost::asio::ip::address& ip : ni.dns) {
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
                            AddDnsServer(bucket, dip);
                        }
                        return true;
                    };

                add_dns_server_to_dns_servers(input.tap_interface, 0);
                add_dns_server_to_dns_servers(input.underlying_interface, 1);
                for (uint32_t ip : input.tunnel_dns) AddDnsServer(0, ip);
                for (uint32_t ip : input.underlying_dns) AddDnsServer(1, ip);
                if (input.has_fake_ip_route) {
                    AddRoute(input, input.fake_ip_route.network, input.tap_gateway, input.fake_ip_route.prefix);
                }

                DeduplicateDnsServers();
                const route::RouteStateSnapshot snapshot = Snapshot();

                for (uint32_t ip : snapshot.dns_servers[0]) {
                    AddRoute(input, ip, input.tap_gateway, 32);
                }
                const auto& gw = input.underlying_interface.gateway;
                if (gw.is_v4()) {
                    uint32_t next_hop = htonl(gw.to_v4().to_uint());
                    for (uint32_t ip : snapshot.dns_servers[1]) {
                        AddRoute(input, ip, next_hop, 32);
                    }
                }
            }

            bool RouteTableManager::ProtectDefaultRoute(const route::RoutePlanInput& input) noexcept {
                if (input.tap_promiscuous || !protection_) {
                    return false;
                }
                StopProtection();
                auto state = protection_;
                state->remove_defaults = [input]() noexcept {
                    auto platform = NewDarwinRoutePlatform(input);
                    if (!platform) return false;
                    auto defaults = platform->CaptureDefaults();
                    return platform->RemoveDefaults(defaults);
                };
                state->active.store(true, std::memory_order_release);
                std::thread([state]() noexcept {
                    ppp::SetThreadName("protector");
                    while (state->active.load(std::memory_order_acquire)) {
                        uint64_t start = ppp::GetTickCount();
                        {
                            std::lock_guard<std::mutex> lock(state->mutex);
                            if (!state->active.load(std::memory_order_acquire) ||
                                !state->remove_defaults || !state->remove_defaults()) {
                                state->active.store(false, std::memory_order_release);
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
                StopProtection();
