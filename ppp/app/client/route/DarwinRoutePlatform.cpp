#include <ppp/stdafx.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>

#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#include <darwin/ppp/tun/utun.h>
#endif

namespace ppp::app::client::route {

#if defined(_MACOS)
namespace {

class DarwinRouteSnapshot final : public IRouteSnapshot {
public:
    std::shared_ptr<ppp::tap::TapDarwin::RouteInformationTable> routes;
};

std::shared_ptr<const DarwinRouteSnapshot> AsDarwinSnapshot(
    const RouteSnapshotPtr& snapshot) noexcept {
    return std::dynamic_pointer_cast<const DarwinRouteSnapshot>(snapshot);
}

}
#endif

DarwinRoutePlatform::DarwinRoutePlatform(uint32_t tap_gateway, bool promiscuous) noexcept
    : DarwinRoutePlatform(CreateSystemOperations(tap_gateway, promiscuous)) {
}

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

DarwinRouteOperations DarwinRoutePlatform::CreateSystemOperations(
    uint32_t tap_gateway,
    bool promiscuous) noexcept {
    DarwinRouteOperations operations;
#if defined(_MACOS)
    operations.capture_defaults = [tap_gateway, promiscuous]() noexcept -> RouteSnapshotPtr {
        if (promiscuous) {
            return RouteSnapshotPtr();
        }
        auto snapshot = std::make_shared<DarwinRouteSnapshot>();
        snapshot->routes = ppp::tap::TapDarwin::FindAllDefaultGatewayRoutes({ tap_gateway });
        return snapshot;
    };
    operations.remove_defaults = [promiscuous](const RouteSnapshotPtr& value) noexcept {
        if (promiscuous) {
            return true;
        }
        auto snapshot = AsDarwinSnapshot(value);
        if (NULLPTR == snapshot || NULLPTR == snapshot->routes) {
            return false;
        }
        bool ok = true;
        for (const auto& pair : *snapshot->routes) {
            ok = ppp::darwin::tun::utun_del_route(pair.first, pair.second) && ok;
        }
        return ok;
    };
    operations.add = [](const RouteSpec& route) noexcept {
        return ppp::darwin::tun::utun_add_route(route.network, route.prefix, route.gateway);
    };
    operations.remove = [](const RouteSpec& route) noexcept {
        return ppp::darwin::tun::utun_del_route(route.network, route.prefix, route.gateway);
    };
    operations.restore_defaults = [promiscuous](const RouteSnapshotPtr& value) noexcept {
        if (promiscuous) {
            return true;
        }
        auto snapshot = AsDarwinSnapshot(value);
        if (NULLPTR == snapshot || NULLPTR == snapshot->routes) {
            return false;
        }
        bool ok = true;
        for (const auto& pair : *snapshot->routes) {
            ok = ppp::darwin::tun::utun_add_route(pair.first, pair.second) && ok;
        }
        return ok;
    };
#else
    (void)tap_gateway;
    (void)promiscuous;
#endif
    return operations;
}

}
