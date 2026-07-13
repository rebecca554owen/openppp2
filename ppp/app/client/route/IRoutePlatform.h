#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include <ppp/net/native/rib_fwd.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                struct RouteSpec final {
                    uint32_t network = 0;
                    uint32_t gateway = 0;
                    int prefix = 0;
                    std::string interface_name;
                };

                class IRoutePlatform {
                public:
                    virtual ~IRoutePlatform() noexcept = default;

                    virtual std::shared_ptr<ppp::net::native::RouteInformationTable>
                        CaptureDefaults() noexcept = 0;
                    virtual bool RemoveDefaults(
                        const std::shared_ptr<ppp::net::native::RouteInformationTable>& routes) noexcept = 0;
                    virtual bool Add(const RouteSpec& route) noexcept = 0;
                    virtual bool Delete(const RouteSpec& route) noexcept = 0;
                    virtual bool RestoreDefaults(
                        const std::shared_ptr<ppp::net::native::RouteInformationTable>& routes) noexcept = 0;
                };

            }
        }
    }
}
