#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/net/native/rib.h>

namespace ppp::app::client::route {

std::vector<RouteSpec> BuildRouteSpecs(
    const std::shared_ptr<ppp::net::native::RouteInformationTable>& rib) noexcept {
    std::vector<RouteSpec> specs;
    if (NULLPTR == rib) {
        return specs;
    }

    for (const auto& pair : rib->GetAllRoutes()) {
        for (const ppp::net::native::RouteEntry& entry : pair.second) {
            specs.push_back(RouteSpec{
                entry.Destination,
                entry.NextHop,
                entry.Prefix,
                {},
            });
        }
    }
    return specs;
}

}
