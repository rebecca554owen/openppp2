#pragma once

#include <cstdint>
#include <memory>
#include <string>

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

                class IRouteSnapshot {
                public:
                    virtual ~IRouteSnapshot() noexcept = default;
                };

                using RouteSnapshotPtr = std::shared_ptr<const IRouteSnapshot>;

                class IRoutePlatform {
                public:
                    virtual ~IRoutePlatform() noexcept = default;

                    virtual RouteSnapshotPtr CaptureDefaults() noexcept = 0;
                    virtual bool RemoveDefaults(const RouteSnapshotPtr& routes) noexcept = 0;
                    virtual bool Add(const RouteSpec& route) noexcept = 0;
                    virtual bool Delete(const RouteSpec& route) noexcept = 0;
                    virtual bool RestoreDefaults(const RouteSnapshotPtr& routes) noexcept = 0;
                };

            }
        }
    }
}
