#pragma once 

/**
 * @file VEthernetNetworkTcpipStack.h
 * @brief Declares the client TCP/IP virtual Ethernet stack facade.
 * @license GPL-3.0
 */

#include <ppp/ethernet/VEthernet.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            /**
             * @brief TCP/IP stack implementation used by the client network switcher.
             *
             * The stack creates per-connection TCP client handlers and provides timeout
             * values derived from application configuration.
             */
            class VEthernetNetworkTcpipStack : public ppp::ethernet::VNetstack {
            public:
                /** @brief Owning switcher used for exchanger and configuration access. */
                const std::shared_ptr<VEthernetNetworkSwitcher>         Ethernet;

            public:
                /** @brief Constructs the stack bound to a specific client switcher. */
                VEthernetNetworkTcpipStack(const std::shared_ptr<VEthernetNetworkSwitcher>& ethernet) noexcept;
                /** @brief Destroys the stack. */
                virtual ~VEthernetNetworkTcpipStack() noexcept = default; 

            protected:
                /** @brief Returns connect timeout in milliseconds for stack sockets. */
                virtual uint64_t                                        GetMaxConnectTimeout() noexcept override;
                /** @brief Returns inactive established timeout in milliseconds. */
                virtual uint64_t                                        GetMaxEstablishedTimeout() noexcept override;
                /** @brief Creates and opens a TCP client handler for an accepted flow. */
                virtual std::shared_ptr<TapTcpClient>                   BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept override;
            
            private:
                std::shared_ptr<ppp::configurations::AppConfiguration>  configuration_;
            };
        }
    }
}
