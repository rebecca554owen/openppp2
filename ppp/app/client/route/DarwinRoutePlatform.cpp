#include <ppp/stdafx.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>

namespace ppp::app::client::route {

DarwinRoutePlatform::DarwinRoutePlatform(DarwinRouteOperations operations) noexcept
    : operations_(std::move(operations)) {
}

RouteSnapshotPtr DarwinRoutePlatform::CaptureDefaults() noexcept {
    return operations_.capture_defaults ? operations_.capture_defaults() : RouteSnapshotPtr();
}

bool DarwinRoutePlatform::RemoveDefaults(const RouteSnapshotPtr& routes) noexcept {
    return operations_.remove_defaults && operations_.remove_defaults(routes);
}

bool DarwinRoutePlatform::Add(const RouteSpec& route) noexcept {
    return operations_.add && operations_.add(route);
}

bool DarwinRoutePlatform::Delete(const RouteSpec& route) noexcept {
    return operations_.remove && operations_.remove(route);
}

bool DarwinRoutePlatform::RestoreDefaults(const RouteSnapshotPtr& routes) noexcept {
    return operations_.restore_defaults && operations_.restore_defaults(routes);
}

}
