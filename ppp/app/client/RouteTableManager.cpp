#include <ppp/app/client/RouteTableManager.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/diagnostics/Telemetry.h>

#include <chrono>

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#endif

using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            void RouteTableManager::Bind(VEthernetNetworkSwitcher* owner) noexcept {
                owner_ = owner;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool RouteTableManager::TryApplyHostedNetworkRoutes() noexcept {
                std::shared_ptr<ppp::tap::ITap> tap = owner_->GetTap();
                if (NULLPTR == tap || !tap->IsHostedNetwork()) {
                    return true;
                }

                if (owner_->route_added_) {
                    return true;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = owner_->exchanger_;
                const bool exchanger_established =
                    NULLPTR != exchanger && exchanger->GetNetworkState() == VEthernetExchanger::NetworkState_Established;
                if (ShouldDeferHostedRouteApply(owner_->route_apply_ready_, exchanger_established)) {
                    if (!owner_->route_apply_ready_) {
                        ppp::telemetry::Log(Level::kInfo, "client", "route setup deferred: Open() is still preparing route state");
                    } else {
                        ppp::telemetry::Log(Level::kInfo, "client", "route setup deferred: exchanger is not established");
                    }
                    ppp::telemetry::Count("client.route.defer", 1);
                    return true;
                }

                if (exchangeof(owner_->route_added_, true)) {
                    return true;
                }

#if defined(_WIN32)
                if (!owner_->UsePaperAirplaneController()) {
                    owner_->route_added_ = false;
                    ppp::telemetry::Log(Level::kInfo, "client", "route setup failed: paper-airplane controller unavailable");
                    ppp::telemetry::Count("client.route.fail.paper_airplane", 1);
                    return false;
                }
#endif

                AddRoute();

                {
                    ppp::telemetry::SpanScope span("client.dns.apply");
                    struct ScopedDnsApplyHistogram final {
                        std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                        ~ScopedDnsApplyHistogram() noexcept {
                            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                            ppp::telemetry::Histogram("client.dns.apply.us", elapsed);
                        }
                    } dns_apply_histogram;

#if defined(_WIN32)
                    auto tun_ni = owner_->tun_ni_;
                    if (NULLPTR != tun_ni) {
                        ppp::win32::network::SetAllNicsDnsAddresses(tun_ni->DnsAddresses, owner_->ni_dns_servers_);
                    }

                    ppp::tap::TapWindows::DnsFlushResolverCache();

                    auto underlying_ni = owner_->underlying_ni_;
                    if (NULLPTR != underlying_ni) {
                        ppp::win32::network::DeleteAllDefaultGatewayRoutes(underlying_ni->GatewayServer);
                    }
#else
                    auto tun_ni = owner_->tun_ni_;
                    if (NULLPTR != tun_ni) {
                        ppp::unix__::UnixAfx::SetDnsAddresses(tun_ni->DnsAddresses);
                    }
#endif
                }
                ppp::telemetry::Log(Level::kDebug, "client", "DNS setup");
                ppp::telemetry::Count("client.dns.setup", 1);

                ProtectDefaultRoute();

                ppp::telemetry::Log(Level::kInfo, "client", "route setup applied after exchanger established");
                return true;
            }
#endif

        }
    }
}
