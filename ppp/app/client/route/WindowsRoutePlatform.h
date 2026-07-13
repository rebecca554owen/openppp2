#pragma once

#include <functional>

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
    explicit WindowsRoutePlatform(WindowsRouteOperations operations) noexcept;

    RouteSnapshotPtr CaptureDefaults() noexcept override;
    bool RemoveDefaults(const RouteSnapshotPtr& routes) noexcept override;
    bool Add(const RouteSpec& route) noexcept override;
    bool Delete(const RouteSpec& route) noexcept override;
    bool RestoreDefaults(const RouteSnapshotPtr& routes) noexcept override;

private:
    WindowsRouteOperations operations_;
};

}
