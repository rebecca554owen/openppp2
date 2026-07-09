#pragma once

/**
 * @file ApplicationServerBootstrap.h
 * @brief Server-mode switcher startup for PppApplication (PR2c).
 */

#include <memory>

namespace ppp {
namespace configurations {
class AppConfiguration;
}
namespace app {
struct NetworkInterface;
namespace server {
class VirtualEthernetSwitcher;
}

/** @brief Prepares server VirtualEthernetSwitcher and listeners. */
bool PrepareServerLoopbackEnvironment(
    const std::shared_ptr<NetworkInterface>& network_interface,
    const std::shared_ptr<configurations::AppConfiguration>& configuration,
    std::shared_ptr<server::VirtualEthernetSwitcher>& server_out) noexcept;

} // namespace app
} // namespace ppp
