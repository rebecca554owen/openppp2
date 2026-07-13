#pragma once

#include <functional>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

struct DarwinRouteOperations final {
    std::function<RouteSnapshotPtr()> capture_defaults;
    std::function<bool(const RouteSnapshotPtr&)> remove_defaults;
    std::function<bool(const RouteSpec&)> add;
    std::function<bool(const RouteSpec&)> remove;
    std::function<bool(const RouteSnapshotPtr&)> restore_defaults;
};

class DarwinRoutePlatform final : public IRoutePlatform {
public:
    DarwinRoutePlatform(uint32_t tap_gateway, bool promiscuous) noexcept;
    explicit DarwinRoutePlatform(DarwinRouteOperations operations) noexcept;

    RouteSnapshotPtr CaptureDefaults() noexcept override;
    bool RemoveDefaults(const RouteSnapshotPtr& routes) noexcept override;
    bool Add(const RouteSpec& route) noexcept override;
    bool Delete(const RouteSpec& route) noexcept override;
    bool RestoreDefaults(const RouteSnapshotPtr& routes) noexcept override;

private:
    static DarwinRouteOperations CreateSystemOperations(
        uint32_t tap_gateway,
        bool promiscuous) noexcept;

    DarwinRouteOperations operations_;
};

}
