#include <ppp/stdafx.h>
#include <ppp/app/client/route/WindowsRoutePlatform.h>

namespace ppp::app::client::route {

WindowsRoutePlatform::WindowsRoutePlatform(WindowsRouteOperations operations) noexcept
    : operations_(std::move(operations)) {
}

RouteSnapshotPtr WindowsRoutePlatform::CaptureDefaults() noexcept {
    return operations_.capture_defaults ? operations_.capture_defaults() : RouteSnapshotPtr();
}

bool WindowsRoutePlatform::RemoveDefaults(const RouteSnapshotPtr& routes) noexcept {
    return operations_.remove_defaults && operations_.remove_defaults(routes);
}

bool WindowsRoutePlatform::Add(const RouteSpec& route) noexcept {
    return operations_.add && operations_.add(route);
}

bool WindowsRoutePlatform::Delete(const RouteSpec& route) noexcept {
    return operations_.remove && operations_.remove(route);
}

bool WindowsRoutePlatform::RestoreDefaults(const RouteSnapshotPtr& routes) noexcept {
    return operations_.restore_defaults && operations_.restore_defaults(routes);
}

}
