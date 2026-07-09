#pragma once

/**
 * @file ApplicationClientBootstrap.h
 * @brief Client-mode TAP/switcher startup for PppApplication (PR2c).
 */

#include <memory>

namespace boost::asio {
class io_context;
}

namespace ppp {
namespace configurations {
class AppConfiguration;
}
namespace app {
struct NetworkInterface;
namespace client {
class VEthernetNetworkSwitcher;
}

/** @brief Prepares client TAP, routes, and VEthernetNetworkSwitcher. */
bool PrepareClientLoopbackEnvironment(
    const std::shared_ptr<NetworkInterface>& network_interface,
    const std::shared_ptr<configurations::AppConfiguration>& configuration,
    const std::shared_ptr<boost::asio::io_context>& context,
    bool proxy_mode,
    std::shared_ptr<client::VEthernetNetworkSwitcher>& client_out) noexcept;

} // namespace app
} // namespace ppp
