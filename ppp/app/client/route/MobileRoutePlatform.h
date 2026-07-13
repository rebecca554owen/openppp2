#pragma once

#include <cstdint>
#include <unordered_set>
#include <vector>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

struct MobileRoutePlan final {
    uint32_t tap_ip = 0;
    uint32_t tap_mask = 0;
    uint32_t tap_gateway = 0;
    uint32_t loopback_gateway = 0;
    std::unordered_set<uint32_t> tunnel_dns;
    std::unordered_set<uint32_t> underlying_dns;
};

std::vector<RouteSpec> BuildMobileRouteSpecs(const MobileRoutePlan& plan) noexcept;

}
