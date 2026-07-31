#pragma once

/**
 * @file VEthernetSocksProxySwitcher.h
 * @brief Declares the SOCKS local proxy switcher implementation.
 *
 * @details `VEthernetSocksProxySwitcher` is a concrete subclass of
 *          `VEthernetLocalProxySwitcher` that listens on the SOCKS bind
 *          address/port from `AppConfiguration` and creates
 *          `VEthernetSocksProxyConnection` objects for each accepted client.
 *
 *          The SOCKS proxy provides a standard SOCKS4/SOCKS5 entry point for
 *          local applications, forwarding their traffic through the VPN tunnel
 *          represented by the bound exchanger.
 *
 * @license GPL-3.0
 */

#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                /**
                 * @brief Local proxy switcher specialized for SOCKS proxy ingress.
                 *
                 * @details Overrides `MyLocalEndPoint()` to read the SOCKS bind address and
                 *          port from configuration, and overrides `NewConnection()` to
                 *          instantiate `VEthernetSocksProxyConnection` objects.
                 *
                 *          Lifecycle:
                 *          - Created and owned by `VEthernetNetworkSwitcher`.
                 *          - `Open()` (inherited) binds the TCP acceptor and starts the accept loop.
                 *          - `Dispose()` (inherited) closes the acceptor and all active connections.
                 *
                 *          Thread safety:
                 *          - All virtual overrides are called from the IO thread that owns the
                 *            parent `VEthernetNetworkSwitcher`.
                 */
                class VEthernetSocksProxySwitcher : public VEthernetLocalProxySwitcher {
                public:
                    /**
                     * @brief Constructs a SOCKS proxy switcher bound to an exchanger.
                     *
                     * @param exchanger Shared exchanger used for tunnel and configuration access.
                     *                  Must not be null; the constructor stores it for use by
                     *                  spawned connections and configuration queries.
                     */
                    VEthernetSocksProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                protected:
                    /**
                     * @brief Resolves the local bind address and port for the SOCKS listener.
                     *
                     * @details Reads `configuration->socks_proxy.bind` for the address string and
                     *          `configuration->socks_proxy.port` for the port.  Both are derived
                     *          from the configuration held by the exchanger.
                     *
                     * @param[in,out] bind_port On input, ignored.  On return, set to the configured
                     *                          SOCKS proxy listen port.
                     * @return Parsed local bind IP address.
                     */
                    virtual boost::asio::ip::address                        MyLocalEndPoint(int& bind_port) noexcept override;

                    /**
                     * @brief Allocates a new SOCKS connection for an accepted TCP client.
                     *
                     * @details Called by the base class accept loop for each successfully accepted
                     *          TCP socket.  Allocates a `VEthernetSocksProxyConnection`, which
                     *          handles SOCKS4/SOCKS5 negotiation and tunnels traffic through the VPN.
                     *
                     * @param context I/O context assigned to the new connection.
                     * @param strand  Execution strand that serializes all handlers for this connection.
                     * @param socket  Accepted TCP client socket (ownership transferred).
                     * @return Shared pointer to the newly created proxy connection object, or null
                     *         if allocation fails.
                     */
                    virtual std::shared_ptr<VEthernetLocalProxyConnection>  NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                };
            }
        }
    }
}
