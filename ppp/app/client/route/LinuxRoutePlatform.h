#pragma once

#include <functional>
#include <string>
#include <unordered_map>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RouteState.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                using LinuxRouteInterfaceResolver =
                    std::function<std::string(ppp::net::native::RouteEntry&)>;

                struct LinuxRouteOperations final {
                    std::function<RouteInformationTablePtr(uint32_t gateway)> capture_defaults;
                    std::function<bool(
                        const LinuxRouteInterfaceResolver& resolve,
                        const RouteInformationTablePtr& routes)> remove_all;
                    std::function<bool(
                        const LinuxRouteInterfaceResolver& resolve,
                        const RouteInformationTablePtr& routes)> restore_all;
                    std::function<bool(const RouteSpec& route)> add;
                    std::function<bool(const RouteSpec& route)> remove;
                };

                std::string SelectLinuxInterface(
                    uint32_t next_hop,
                    uint32_t tap_gateway,
                    const std::string& tap_interface,
                    const std::string& underlying_interface,
                    const std::unordered_map<uint32_t, std::string>& nics) noexcept;

                class LinuxRoutePlatform final : public IRoutePlatform {
                public:
                    LinuxRoutePlatform(
                        uint32_t tap_gateway,
                        std::string tap_interface,
                        std::string underlying_interface,
                        std::unordered_map<uint32_t, std::string> nics,
                        bool promiscuous) noexcept;

                    LinuxRoutePlatform(
                        uint32_t tap_gateway,
                        std::string tap_interface,
                        std::string underlying_interface,
                        std::unordered_map<uint32_t, std::string> nics,
                        bool promiscuous,
                        LinuxRouteOperations operations) noexcept;

                    RouteInformationTablePtr CaptureDefaults() noexcept override;
                    bool RemoveDefaults(const RouteInformationTablePtr& routes) noexcept override;
                    bool Add(const RouteSpec& route) noexcept override;
                    bool Delete(const RouteSpec& route) noexcept override;
                    bool RestoreDefaults(const RouteInformationTablePtr& routes) noexcept override;

                private:
                    static LinuxRouteOperations CreateSystemOperations() noexcept;
                    LinuxRouteInterfaceResolver MakeResolver() const noexcept;
                    RouteSpec Resolve(RouteSpec route) const noexcept;

                    uint32_t tap_gateway_ = 0;
                    std::string tap_interface_;
                    std::string underlying_interface_;
                    std::unordered_map<uint32_t, std::string> nics_;
                    bool promiscuous_ = false;
                    LinuxRouteOperations operations_;
                };

            }
        }
    }
}
