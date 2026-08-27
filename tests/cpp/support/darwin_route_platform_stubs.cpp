#include <darwin/ppp/tap/TapDarwin.h>
#include <darwin/ppp/tun/utun.h>

namespace ppp::tap {

bool TapDarwin::TryRouteExists(
    UInt32, int, UInt32, bool& exists) noexcept {
    exists = false;
    return false;
}

bool TapDarwin::TryFindAllDefaultGatewayRoutes(
    const ppp::unordered_set<uint32_t>&,
    std::shared_ptr<RouteInformationTable>& routes) noexcept {
    routes.reset();
    return false;
}

}

namespace ppp::darwin::tun {

RouteMutationResult utun_add_route_status(
    UInt32, int, UInt32) noexcept {
    return RouteMutationResult::Failed;
}

RouteMutationResult utun_del_route_status(
    UInt32, int, UInt32) noexcept {
    return RouteMutationResult::Failed;
}

}
