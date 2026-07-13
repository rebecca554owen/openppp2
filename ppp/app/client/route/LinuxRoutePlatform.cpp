#include <ppp/stdafx.h>
#include <ppp/app/client/route/LinuxRoutePlatform.h>

#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
#include <linux/ppp/tap/TapLinux.h>
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                static ppp::string ToPppString(const std::string& value) {
                    return ppp::string(value.begin(), value.end());
                }

                std::string SelectLinuxInterface(
                    uint32_t next_hop,
                    uint32_t tap_gateway,
                    const std::string& tap_interface,
                    const std::string& underlying_interface,
                    const std::unordered_map<uint32_t, std::string>& nics) noexcept {
                    if (next_hop == tap_gateway) {
                        return tap_interface;
                    }

                    auto tail = nics.find(next_hop);
                    if (tail != nics.end() && !tail->second.empty()) {
                        return tail->second;
                    }
                    return underlying_interface;
                }

                LinuxRoutePlatform::LinuxRoutePlatform(
                    uint32_t tap_gateway,
                    std::string tap_interface,
                    std::string underlying_interface,
                    std::unordered_map<uint32_t, std::string> nics,
                    bool promiscuous) noexcept
                    : LinuxRoutePlatform(
                        tap_gateway,
                        std::move(tap_interface),
                        std::move(underlying_interface),
                        std::move(nics),
                        promiscuous,
                        CreateSystemOperations()) {
                }

                LinuxRoutePlatform::LinuxRoutePlatform(
                    uint32_t tap_gateway,
                    std::string tap_interface,
                    std::string underlying_interface,
                    std::unordered_map<uint32_t, std::string> nics,
                    bool promiscuous,
                    LinuxRouteOperations operations) noexcept
                    : tap_gateway_(tap_gateway),
                      tap_interface_(std::move(tap_interface)),
                      underlying_interface_(std::move(underlying_interface)),
                      nics_(std::move(nics)),
                      promiscuous_(promiscuous),
                      operations_(std::move(operations)) {
                }

                RouteInformationTablePtr LinuxRoutePlatform::CaptureDefaults() noexcept {
                    if (promiscuous_ || !operations_.capture_defaults) {
                        return NULLPTR;
                    }
                    return operations_.capture_defaults(tap_gateway_);
                }

                bool LinuxRoutePlatform::RemoveDefaults(
                    const RouteInformationTablePtr& routes) noexcept {
                    if (promiscuous_ || NULLPTR == routes) {
                        return true;
                    }
                    return operations_.remove_all && operations_.remove_all(MakeResolver(), routes);
                }

                bool LinuxRoutePlatform::Add(const RouteSpec& route) noexcept {
                    return operations_.add && operations_.add(Resolve(route));
                }

                bool LinuxRoutePlatform::Delete(const RouteSpec& route) noexcept {
                    return operations_.remove && operations_.remove(Resolve(route));
                }

                bool LinuxRoutePlatform::RestoreDefaults(
                    const RouteInformationTablePtr& routes) noexcept {
                    if (promiscuous_ || NULLPTR == routes) {
                        return true;
                    }
                    return operations_.restore_all && operations_.restore_all(MakeResolver(), routes);
                }

                LinuxRouteInterfaceResolver LinuxRoutePlatform::MakeResolver() const noexcept {
                    const uint32_t tap_gateway = tap_gateway_;
                    const std::string tap_interface = tap_interface_;
                    const std::string underlying_interface = underlying_interface_;
                    const std::unordered_map<uint32_t, std::string> nics = nics_;
                    return [tap_gateway, tap_interface, underlying_interface, nics](
                        ppp::net::native::RouteEntry& entry) noexcept {
                        return SelectLinuxInterface(
                            entry.NextHop,
                            tap_gateway,
                            tap_interface,
                            underlying_interface,
                            nics);
                    };
                }

                RouteSpec LinuxRoutePlatform::Resolve(RouteSpec route) const noexcept {
                    if (route.interface_name.empty()) {
                        route.interface_name = SelectLinuxInterface(
                            route.gateway,
                            tap_gateway_,
                            tap_interface_,
                            underlying_interface_,
                            nics_);
                    }
                    return route;
                }

                LinuxRouteOperations LinuxRoutePlatform::CreateSystemOperations() noexcept {
                    LinuxRouteOperations operations;
#if defined(_LINUX) && !defined(_ANDROID) && !defined(_IPHONE)
                    operations.capture_defaults = [](uint32_t gateway) noexcept {
                        return ppp::tap::TapLinux::FindAllDefaultGatewayRoutes({ gateway });
                    };
                    operations.remove_all = [](
                        const LinuxRouteInterfaceResolver& resolve,
                        const RouteInformationTablePtr& routes) noexcept {
                        ppp::function<ppp::string(ppp::net::native::RouteEntry&)> resolver =
                            [resolve](ppp::net::native::RouteEntry& entry) noexcept {
                                return ToPppString(resolve(entry));
                            };
                        return ppp::tap::TapLinux::DeleteAllRoutes(resolver, routes);
                    };
                    operations.restore_all = [](
                        const LinuxRouteInterfaceResolver& resolve,
                        const RouteInformationTablePtr& routes) noexcept {
                        ppp::function<ppp::string(ppp::net::native::RouteEntry&)> resolver =
                            [resolve](ppp::net::native::RouteEntry& entry) noexcept {
                                return ToPppString(resolve(entry));
                            };
                        return ppp::tap::TapLinux::AddAllRoutes(resolver, routes);
                    };
                    operations.add = [](const RouteSpec& route) noexcept {
                        return ppp::tap::TapLinux::AddRoute(
                            ToPppString(route.interface_name),
                            route.network,
                            route.prefix,
                            route.gateway);
                    };
                    operations.remove = [](const RouteSpec& route) noexcept {
                        return ppp::tap::TapLinux::DeleteRoute(
                            ToPppString(route.interface_name),
                            route.network,
                            route.prefix,
                            route.gateway);
                    };
#endif
                    return operations;
                }

            }
        }
    }
}
