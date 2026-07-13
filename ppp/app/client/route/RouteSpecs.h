#pragma once

#include <memory>
#include <vector>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/net/native/rib_fwd.h>

namespace ppp::app::client::route {

std::vector<RouteSpec> BuildRouteSpecs(
    const std::shared_ptr<ppp::net::native::RouteInformationTable>& rib) noexcept;

}
