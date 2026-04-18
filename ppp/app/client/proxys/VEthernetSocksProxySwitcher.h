#pragma once

/**
 * @file VEthernetSocksProxySwitcher.h
 * @brief Declares the SOCKS local proxy switcher.
 */

#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                /**
                 * @class VEthernetSocksProxySwitcher
                 * @brief Creates and manages SOCKS local proxy connections.
                 */
                class VEthernetSocksProxySwitcher : public VEthernetLocalProxySwitcher {
                public:
                    /**
                     * @brief Constructs a SOCKS proxy switcher bound to an exchanger.
                     * @param exchanger Shared exchanger used by spawned connections.
                     */
                    VEthernetSocksProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                protected:
                    /**
                     * @brief Resolves local bind address and port for the SOCKS listener.
                     * @param bind_port Output local bind port from configuration.
                     * @return Parsed local bind IP address.
                     */
                    virtual boost::asio::ip::address                        MyLocalEndPoint(int& bind_port) noexcept override;
                    /**
                     * @brief Allocates a new SOCKS connection for an accepted TCP client.
                     * @param context I/O context for the new connection.
                     * @param strand Strand that serializes connection handlers.
                     * @param socket Accepted client socket.
                     * @return New local proxy connection instance.
                     */
                    virtual std::shared_ptr<VEthernetLocalProxyConnection>  NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                };
            }
        }
    }
}
