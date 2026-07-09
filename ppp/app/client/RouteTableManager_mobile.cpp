#include <ppp/app/client/RouteTableManager.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/collections/Dictionary.h>
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

                owner_->rib_ = rib;

                uint32_t cidr = ntohl(tap->SubmaskAddress);
                cidr = cidr & ntohl(tap->IPAddress);
                cidr = htonl(cidr);
                rib->AddRoute(cidr, IPEndPoint::NetmaskToPrefix(tap->SubmaskAddress), tap->GatewayServer);

                if (ppp::string bypass_ip_list = std::move(owner_->bypass_ip_list_); bypass_ip_list.size() > 0) {
                    bool bypass_loaded = rib->AddAllRoutes(bypass_ip_list, IPEndPoint::LoopbackAddress);
#if defined(_ANDROID)
                    ANDROID_DNS_REDIRECT_TRACE("bypass_ip_list load len=%d ok=%d",
                        (int)bypass_ip_list.size(), bypass_loaded ? 1 : 0);
#endif
                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                }

                uint32_t gws[] = {tap->GatewayServer, IPEndPoint::LoopbackAddress};
                ppp::unordered_set<uint32_t> dns_serverss_[2];
                if (NULLPTR != owner_->dns_interceptor_) {
                    owner_->dns_interceptor_->CollectReachabilityIps(
                        owner_->configuration_,
                        owner_->configuration_->dns.intercept_unmatched,
                        [&dns_serverss_](uint32_t ip) noexcept {
                            dns_serverss_[0].emplace(ip);
                        },
                        [&dns_serverss_](uint32_t ip) noexcept {
                            dns_serverss_[1].emplace(ip);
                        });
                }

                ppp::collections::Dictionary::DeduplicationList(dns_serverss_[1], dns_serverss_[0]);
                for (int i = 0; i < arraysizeof(gws); i++) {
                    uint32_t gw = gws[i];
                    for (auto& ip : dns_serverss_[i]) {
                        rib->AddRoute(ip, 32, gw);
                    }
                }

                return true;
            }

        }
    }
}

#endif
