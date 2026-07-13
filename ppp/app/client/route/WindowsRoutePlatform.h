#pragma once

#include <functional>
#include <string>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

struct WindowsRouteOperations final {
    std::function<RouteSnapshotPtr()> capture_defaults;
    std::function<bool(const RouteSnapshotPtr&)> remove_defaults;
    std::function<bool(const RouteSpec&)> add;
    std::function<bool(const RouteSpec&)> remove;
    std::function<bool(const RouteSnapshotPtr&)> restore_defaults;
};

class WindowsRoutePlatform final : public IRoutePlatform {
public:
    WindowsRoutePlatform(
        uint32_t tap_gateway,
        int underlying_interface_index,
        std::string underlying_gateway) noexcept;
    explicit WindowsRoutePlatform(WindowsRouteOperations operations) noexcept;

    RouteSnapshotPtr CaptureDefaults() noexcept override;
    bool RemoveDefaults(const RouteSnapshotPtr& routes) noexcept override;
    bool Add(const RouteSpec& route) noexcept override;
    bool Delete(const RouteSpec& route) noexcept override;
    bool RestoreDefaults(const RouteSnapshotPtr& routes) noexcept override;

private:
    static WindowsRouteOperations CreateSystemOperations(
        uint32_t tap_gateway,
        int underlying_interface_index,
        std::string underlying_gateway) noexcept;

    WindowsRouteOperations operations_;
};

}
