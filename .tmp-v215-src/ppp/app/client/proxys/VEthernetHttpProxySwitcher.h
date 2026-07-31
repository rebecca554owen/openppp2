#pragma once

/**
 * @file VEthernetHttpProxySwitcher.h
 * @brief Declares the HTTP-specific local proxy switcher implementation.
 *
 * @details `VEthernetHttpProxySwitcher` is a concrete subclass of
 *          `VEthernetLocalProxySwitcher` that listens on the HTTP proxy bind
 *          address/port from `AppConfiguration` and creates
 *          `VEthernetHttpProxyConnection` objects for each accepted client.
 *
 *          The HTTP proxy acts as a transparent CONNECT/relay entry point for
 *          client applications that speak HTTP proxy protocol, forwarding their
 *          traffic through the VPN tunnel represented by the exchanger.
 *
 * @author  OpenPPP Contributors
 * @license GPL-3.0
 */

#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                /**
                 * @brief Local proxy switcher specialized for HTTP proxy ingress.
                 *
                 * @details Overrides `MyLocalEndPoint()` to read the HTTP bind address and
                 *          port from configuration, and overrides `NewConnection()` to
                 *          instantiate `VEthernetHttpProxyConnection` objects.
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
                class VEthernetHttpProxySwitcher : public VEthernetLocalProxySwitcher {
                public:
                    /**
                     * @brief Initializes an HTTP proxy switcher bound to an exchanger.
                     *
                     * @param exchanger Shared exchanger used for tunnel and configuration access.
                     *                  Must not be null; the constructor stores it for use by
                     *                  spawned connections and configuration queries.
                     */
                    VEthernetHttpProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                protected:
                    /**
                     * @brief Resolves the bind address and bind port for the local HTTP acceptor.
                     *
                     * @details Reads `configuration->http_proxy.bind` for the address string and
                     *          `configuration->http_proxy.port` for the port.  Both are derived
                     *          from the configuration held by the exchanger.
                     *
                     * @param[in,out] bind_port On input, ignored.  On return, set to the configured
                     *                          HTTP proxy listen port.
                     * @return Local IP address to bind for incoming HTTP proxy connections.
                     */
                    virtual boost::asio::ip::address                        MyLocalEndPoint(int& bind_port) noexcept override;

                    /**
                     * @brief Creates a new per-client HTTP proxy connection instance.
                     *
                     * @details Called by the base class accept loop for each successfully accepted
                     *          TCP socket.  Allocates a `VEthernetHttpProxyConnection`, which
                     *          performs HTTP CONNECT handshake and tunnels traffic through the VPN.
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
