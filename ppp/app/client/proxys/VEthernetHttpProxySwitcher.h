#pragma once

/**
 * @file VEthernetHttpProxySwitcher.h
 * @brief Declares the HTTP-specific local proxy switcher implementation.
 * @author OpenPPP Contributors
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
                 */
                class VEthernetHttpProxySwitcher : public VEthernetLocalProxySwitcher {
                public:
                    /**
                     * @brief Initializes an HTTP proxy switcher bound to an exchanger.
                     * @param exchanger Shared exchanger used for tunnel and configuration access.
                     */
                    VEthernetHttpProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                protected:
                    /**
                     * @brief Resolves the bind address and bind port for the local acceptor.
                     * @param bind_port Input/output bind port value.
                     * @return Local address to bind for incoming HTTP proxy connections.
                     */
                    virtual boost::asio::ip::address                        MyLocalEndPoint(int& bind_port) noexcept override;
                    /**
                     * @brief Creates a new per-client local proxy connection instance.
                     * @param context Target I/O context for async operations.
                     * @param strand Serialized execution strand.
                     * @param socket Accepted client socket.
                     * @return Newly created proxy connection object.
                     */
                    virtual std::shared_ptr<VEthernetLocalProxyConnection>  NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                };
            }
        }
    }
}
