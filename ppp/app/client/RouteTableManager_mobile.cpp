#include <ppp/app/client/RouteTableManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/route/MobileRoutePlatform.h>
#include <ppp/app/client/route/RouteState.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

#if defined(_ANDROID) || defined(_IPHONE)

#if defined(_ANDROID)
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

using ppp::net::IPEndPoint;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            bool RouteTableManager::AddAllRoute(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept {
                using RouteInformationTable = VEthernetNetworkSwitcher::RouteInformationTable;
                using RouteInformationTablePtr = VEthernetNetworkSwitcher::RouteInformationTablePtr;

                RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                if (NULLPTR == rib)  {
                    return false;
                }

                if (NULLPTR != route_state_) {
                    route_state_->ReplaceRib(rib);
                }

                uint32_t cidr = ntohl(tap->SubmaskAddress);
                cidr = cidr & ntohl(tap->IPAddress);
                cidr = htonl(cidr);

                if (ppp::string bypass_ip_list = std::move(owner_->bypass_ip_list_); bypass_ip_list.size() > 0) {
                    bool bypass_loaded = rib->AddAllRoutes(bypass_ip_list, IPEndPoint::LoopbackAddress);
#if defined(_ANDROID)
                    ANDROID_DNS_REDIRECT_TRACE("bypass_ip_list load len=%d ok=%d",
                        (int)bypass_ip_list.size(), bypass_loaded ? 1 : 0);
#endif
                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                }

                route::MobileRoutePlan plan;
                plan.tap_network = cidr;
                plan.tap_prefix = IPEndPoint::NetmaskToPrefix(tap->SubmaskAddress);
                plan.tap_gateway = tap->GatewayServer;
                plan.loopback_gateway = IPEndPoint::LoopbackAddress;
                if (NULLPTR != owner_->dns_interceptor_) {
                    owner_->dns_interceptor_->CollectReachabilityIps(
                        owner_->configuration_,
                        owner_->configuration_->dns.intercept_unmatched,
                        [&plan](uint32_t ip) noexcept {
                            plan.tunnel_dns.emplace(ip);
                        },
                        [&plan](uint32_t ip) noexcept {
                            plan.underlying_dns.emplace(ip);
                        });
                }

                route::MobileRoutePlatform platform(
                    [rib](const route::RouteSpec& spec) noexcept {
                        return rib->AddRoute(spec.network, spec.prefix, spec.gateway);
                    });
                return platform.ApplyAll(route::BuildMobileRouteSpecs(plan));
            }

        }
    }
}

#endif
