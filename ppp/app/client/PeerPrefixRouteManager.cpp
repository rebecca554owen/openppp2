#include <ppp/app/client/PeerPrefixRouteManager.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/RouteTableManager.h>
#include <ppp/app/protocol/PeerPrefixRoute.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

#if defined(_WIN32)
#include <windows/ppp/win32/network/Router.h>
#endif

using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void PeerPrefixRouteManager::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

            void PeerPrefixRouteManager::Clear() noexcept {
#if defined(_WIN32)
                auto mib = ppp::win32::network::Router::GetIpForwardTable();
#endif
                for (const auto& route : owner_->applied_peer_prefix_routes_) {
#if defined(_WIN32)
                    if (NULLPTR != mib) {
                        owner_->route_table_->DeleteRoute(mib, route.Destination, route.NextHop, route.Prefix);
                    }
#elif !defined(_ANDROID) && !defined(_IPHONE)
                    owner_->route_table_->DeleteRoute(route.Destination, route.NextHop, route.Prefix);
#endif
                }
                owner_->applied_peer_prefix_routes_.clear();
                const route::RouteStateSnapshot snapshot = owner_->route_state_.Snapshot();
                if (NULLPTR != snapshot.peer_prefix_rib) {
                    snapshot.peer_prefix_rib->Clear();
                }
                if (NULLPTR != snapshot.peer_prefix_fib) {
                    snapshot.peer_prefix_fib->Clear();
                }
                owner_->route_state_.ReplacePeerPrefix(NULLPTR, NULLPTR);
            }

            bool PeerPrefixRouteManager::Apply(const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions) noexcept {
                if (owner_->proxy_only_) {
                    return false;
                }

                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                Clear();

                VEthernetNetworkSwitcher::RouteInformationTablePtr rib =
                    make_shared_object<VEthernetNetworkSwitcher::RouteInformationTable>();
                if (NULLPTR == rib) {
                    return false;
                }

                const auto& dynamic_routes = extensions.PeerRouteTable.HasAny()
                    ? extensions.PeerRouteTable.routes
                    : owner_->dynamic_peer_routes_;

                auto install_route = [&](const ppp::app::protocol::PeerPrefixRouteEntry& route) -> bool {
                    if (!route.HasVia()) {
                        return false;
                    }

                    if (route.prefix <= 0 || route.prefix > ppp::net::native::MAX_PREFIX_VALUE_V4) {
                        return false;
                    }

                    uint32_t network = route.NetworkHost();
                    uint32_t via = route.ViaHost();
                    if (network == 0 || via == 0) {
                        return false;
                    }

                    if (via == tap->IPAddress) {
                        return false;
                    }

#if !defined(_ANDROID) && !defined(_IPHONE)
                    if (!owner_->route_table_->AddRoute(network, via, route.prefix)) {
                        return false;
                    }
#endif

                    if (!rib->AddRoute(network, route.prefix, via)) {
#if defined(_WIN32)
                        if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULLPTR != mib) {
                            owner_->route_table_->DeleteRoute(mib, network, via, route.prefix);
                        }
#elif !defined(_ANDROID) && !defined(_IPHONE)
                        owner_->route_table_->DeleteRoute(network, via, route.prefix);
#endif
                        return false;
                    }

                    ppp::net::native::RouteEntry entry;
                    entry.Destination = network;
                    entry.Prefix = route.prefix;
                    entry.NextHop = via;
                    owner_->applied_peer_prefix_routes_.emplace_back(entry);
                    return true;
                };

                bool any = false;
                if (NULLPTR != owner_->configuration_) {
                    for (const auto& route : owner_->configuration_->client.peer_routes) {
                        ppp::app::protocol::PeerPrefixRouteEntry entry;
                        entry.network = route.network;
                        entry.prefix = route.prefix;
                        entry.via = route.via;
                        any |= install_route(entry);
                    }
                }

                for (const auto& route : dynamic_routes) {
                    any |= install_route(route);
                }

                if (any) {
                    VEthernetNetworkSwitcher::ForwardInformationTablePtr fib =
                        make_shared_object<VEthernetNetworkSwitcher::ForwardInformationTable>();
                    if (NULLPTR != fib) {
                        fib->Fill(*rib);
                        if (fib->IsAvailable()) {
                            owner_->route_state_.ReplacePeerPrefix(rib, fib);
                        }
                    }

                    ppp::telemetry::Log(Level::kInfo, "client", "peer prefix routes applied: static+dynamic count=%zu",
                        owner_->applied_peer_prefix_routes_.size());
                    ppp::telemetry::Count("client.peer_routes.applied", 1);
                }

                return any;
            }

        }
    }
}
