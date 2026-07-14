#include <ppp/stdafx.h>
#include <ppp/app/client/route/WindowsRoutePlatform.h>

#if defined(_WIN32)
#include <ppp/net/IPEndPoint.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/win32/network/Router.h>
#endif

namespace ppp::app::client::route {

#if defined(_WIN32)
namespace {

class WindowsRouteSnapshot final : public IRouteSnapshot {
public:
    ppp::vector<MIB_IPFORWARDROW> routes;
    bool valid = false;
};

std::shared_ptr<const WindowsRouteSnapshot> AsWindowsSnapshot(
    const RouteSnapshotPtr& snapshot) noexcept {
    return std::dynamic_pointer_cast<const WindowsRouteSnapshot>(snapshot);
}

}
#endif

WindowsRoutePlatform::WindowsRoutePlatform(
    uint32_t tap_gateway,
    int underlying_interface_index,
    std::string underlying_gateway) noexcept
    : WindowsRoutePlatform(CreateSystemOperations(
          tap_gateway,
          underlying_interface_index,
          std::move(underlying_gateway))) {
}

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

WindowsRouteOperations WindowsRoutePlatform::CreateSystemOperations(
    uint32_t tap_gateway,
    int underlying_interface_index,
    std::string underlying_gateway) noexcept {
    WindowsRouteOperations operations;
#if defined(_WIN32)
    operations.capture_defaults = [tap_gateway]() noexcept -> RouteSnapshotPtr {
        auto snapshot = std::make_shared<WindowsRouteSnapshot>();
        auto mib = ppp::win32::network::Router::GetIpForwardTable();
        if (NULLPTR == mib) {
            return snapshot;
        }

        const uint32_t mid = inet_addr("128.0.0.0");
        for (DWORD i = 0; i < mib->dwNumEntries; ++i) {
            const MIB_IPFORWARDROW& row = mib->table[i];
            const bool is_default =
                (row.dwForwardDest == ppp::net::IPEndPoint::AnyAddress &&
                    (row.dwForwardMask == mid || row.dwForwardMask == ppp::net::IPEndPoint::AnyAddress)) ||
                (row.dwForwardDest == mid && row.dwForwardMask == mid);
            if (is_default && row.dwForwardNextHop != tap_gateway) {
                snapshot->routes.emplace_back(row);
            }
        }
        snapshot->valid = true;
        return snapshot;
    };
    operations.remove_defaults = [](const RouteSnapshotPtr& value) noexcept {
        auto snapshot = AsWindowsSnapshot(value);
        if (NULLPTR == snapshot || !snapshot->valid) {
            return false;
        }
        bool ok = true;
        for (MIB_IPFORWARDROW row : snapshot->routes) {
            ok = ppp::win32::network::Router::Delete(row) && ok;
        }
        return ok;
    };
    operations.add = [](const RouteSpec& route) noexcept {
        MIB_IPFORWARDROW best;
        if (ppp::win32::network::Router::GetBestRoute(route.network, best) &&
            best.dwForwardDest == route.network && best.dwForwardNextHop != route.gateway) {
            ppp::win32::network::Router::Delete(best);
        }
        return ppp::win32::network::Router::Add(
            route.network,
            ppp::net::IPEndPoint::PrefixToNetmask(route.prefix),
            route.gateway,
            1);
    };
    operations.remove = [](const RouteSpec& route) noexcept {
        auto mib = ppp::win32::network::Router::GetIpForwardTable();
        return NULLPTR != mib && ppp::win32::network::Router::Delete(
            mib,
            route.network,
            ppp::net::IPEndPoint::PrefixToNetmask(route.prefix),
            route.gateway);
    };
    operations.restore_defaults = [underlying_interface_index, underlying_gateway](
        const RouteSnapshotPtr& value) noexcept {
        auto snapshot = AsWindowsSnapshot(value);
        if (NULLPTR == snapshot || !snapshot->valid) {
            return false;
        }
        ppp::vector<MIB_IPFORWARDROW> routes = snapshot->routes;
        const bool routes_ok = routes.empty() || ppp::win32::network::AddAllRoutes(routes);
        const bool gateway_ok = underlying_gateway.empty() ||
            ppp::win32::network::SetDefaultIPGateway(
                underlying_interface_index,
                ppp::vector<ppp::string>{
                    ppp::string(underlying_gateway.data(), underlying_gateway.size()) });
        return routes_ok && gateway_ok;
    };
#else
    (void)tap_gateway;
    (void)underlying_interface_index;
    (void)underlying_gateway;
#endif
    return operations;
}

}
