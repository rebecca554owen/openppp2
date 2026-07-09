#include "DnsRouteDispatcher.h"

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                bool DnsRouteDispatcher::Dispatch(
                    const DnsRedirectPlanResult& plan,
                    const DnsRouteDispatcherPorts& ports) noexcept {

                    switch (plan.action) {
                    case DnsRouteAction::kBlockAAAA:
                    case DnsRouteAction::kDrop:
                        return static_cast<bool>(ports.drop) ? ports.drop() : false;
                    case DnsRouteAction::kDeferToTunnel:
                        return static_cast<bool>(ports.defer_to_tunnel) ? ports.defer_to_tunnel() : false;
                    case DnsRouteAction::kUdpRelay:
                        return static_cast<bool>(ports.udp_relay) ? ports.udp_relay(plan.udp_relay_target) : false;
                    case DnsRouteAction::kResolveUnmatched:
                        return static_cast<bool>(ports.resolve_unmatched) ? ports.resolve_unmatched() : false;
                    case DnsRouteAction::kResolveProvider:
                        return static_cast<bool>(ports.resolve_provider) ?
                            ports.resolve_provider(plan.provider_name, plan.provider_domestic) : false;
                    default:
                        return false;
                    }
                }

            }
        }
    }
}
