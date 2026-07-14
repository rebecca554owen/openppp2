#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <boost/asio/ip/address.hpp>

#include <ppp/app/client/route/IRoutePlatform.h>

namespace ppp::app::client::route {

struct RouteInterfaceSnapshot final {
    std::string name;
    int index = -1;
    boost::asio::ip::address ip;
    boost::asio::ip::address gateway;
    boost::asio::ip::address submask;
    std::vector<boost::asio::ip::address> dns;
};

struct RoutePlanInput final {
    uint32_t tap_ip = 0;
    uint32_t tap_gateway = 0;
    uint32_t tap_submask = 0;
    bool tap_hosted = false;
    bool tap_promiscuous = false;
    RouteInterfaceSnapshot tap_interface;
    RouteInterfaceSnapshot underlying_interface;
    std::unordered_map<uint32_t, std::string> nics;
    std::string bypass_ip_list;
    std::unordered_set<uint32_t> tunnel_dns;
    std::unordered_set<uint32_t> underlying_dns;
    bool has_fake_ip_route = false;
    RouteSpec fake_ip_route;
};

}
