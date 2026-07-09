#pragma once

/**
 * @file RouteHost.h
 * @brief Narrow host surface for route operations without VEthernetNetworkSwitcher.h.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/rib_fwd.h>

namespace ppp {
    namespace tap {
        class ITap;
    }
}

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;
            class ClientNetworkInterface;

            namespace route {

                using RouteInformationTablePtr = std::shared_ptr<ppp::net::native::RouteInformationTable>;
                using ForwardInformationTablePtr = std::shared_ptr<ppp::net::native::ForwardInformationTable>;

                /** @brief Injectable switcher capabilities for route pipeline (no switcher header). */
                struct RouteHostPorts final {
                    ppp::function<std::shared_ptr<ppp::tap::ITap>()> get_tap;

                    ppp::function<std::shared_ptr<ClientNetworkInterface>()> get_tap_ni;

                    ppp::function<std::shared_ptr<ClientNetworkInterface>()> get_underlying_ni;

                    ppp::function<RouteInformationTablePtr()> get_rib;

                    ppp::function<void(RouteInformationTablePtr)> set_rib;

                    ppp::function<ForwardInformationTablePtr()> get_fib;

                    ppp::function<void(ForwardInformationTablePtr)> set_fib;

                    ppp::function<bool()> get_route_added;

                    ppp::function<void(bool)> set_route_added;

                    ppp::function<bool()> get_route_apply_ready;

                    ppp::function<void(uint32_t ip, int bucket)> add_dns_server_ip;

                    ppp::function<void()> collect_dns_reachability;

                    ppp::function<RouteInformationTablePtr()> get_default_routes;

                    ppp::function<void(RouteInformationTablePtr)> set_default_routes;

                    ppp::function<ppp::unordered_map<uint32_t, ppp::string>*()> get_nics;

                    bool IsValid() const noexcept {
                        return get_tap && get_tap_ni && get_underlying_ni && get_rib && set_rib && get_fib &&
                            set_fib && get_route_added && set_route_added && get_route_apply_ready &&
                            add_dns_server_ip && collect_dns_reachability && get_default_routes &&
                            set_default_routes && get_nics;
                    }
                };

                class IRouteBackend {
                public:
                    virtual ~IRouteBackend() noexcept = default;

                    virtual RouteHostPorts BuildRouteHostPorts() noexcept = 0;

#if !defined(_ANDROID) && !defined(_IPHONE)
                    virtual void AddRoute() noexcept = 0;

                    virtual void DeleteRoute() noexcept = 0;
#else
                    virtual bool AddAllRoute(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept = 0;
#endif
                };

                RouteHostPorts MakeRouteHostPorts(const std::shared_ptr<IRouteBackend>& host) noexcept;

                RouteHostPorts MakeRouteHostPorts(const std::shared_ptr<VEthernetNetworkSwitcher>& self) noexcept;

            }
        }
    }
}
