/**
 * @file TVEthernetTcpipConnection.h
 * @brief Provides a templated adapter that binds concrete connection objects to virtual ethernet TCP/IP connections.
 * @license GPL-3.0
 */

#pragma once

#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>

namespace ppp {
    namespace app {
        namespace protocol {
            namespace templates {
                template <typename TConnection>
                /**
                 * @brief Wraps a concrete connection type with virtual ethernet TCP/IP lifecycle hooks.
                 * @tparam TConnection Underlying connection implementation type.
                 */
                class TVEthernetTcpipConnection : public ppp::app::protocol::VirtualEthernetTcpipConnection {
                public:
                    /**
                     * @brief Creates a templated virtual ethernet TCP/IP connection wrapper.
                     */
                    TVEthernetTcpipConnection(
                        const std::shared_ptr<TConnection>&                     connection,
                        const AppConfigurationPtr&                              configuration,
                        const ContextPtr&                                       context,
                        const ppp::threading::Executors::StrandPtr&             strand,
                        const Int128&                                           id,
                        const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                        : VirtualEthernetTcpipConnection(configuration, context, strand, id, socket)
                        , connection_(connection) {

                    }

                public:
                    /** @brief Disposes the wrapped connection and then base resources. */
                    virtual void                                                Dispose() noexcept override {
                        std::shared_ptr<TConnection> connection = std::move(connection_);
                        if (NULLPTR != connection) {
                            connection->Dispose();
                        }

                        VirtualEthernetTcpipConnection::Dispose();
                    }
                    /** @brief Updates the wrapped connection state if available. */
                    virtual void                                                Update() noexcept override {
                        std::shared_ptr<TConnection> connection = connection_;
                        if (NULLPTR != connection) {
                            connection->Update();
                        }
                    }
                    /** @brief Gets the wrapped concrete connection object. */
                    virtual std::shared_ptr<TConnection>                        GetConnection() noexcept { return connection_; }

                private:
                    std::shared_ptr<TConnection>                                connection_;
                };
            }
        }
    }
}
