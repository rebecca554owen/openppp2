#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxyConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file VEthernetSocksProxySwitcher.cpp
 * @brief Implements SOCKS local proxy switcher and connection factory behavior.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief Constructs the SOCKS proxy switcher.
                 * @param exchanger Shared exchanger used by created proxy connections.
                 */
                VEthernetSocksProxySwitcher::VEthernetSocksProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept 
                    : VEthernetLocalProxySwitcher(exchanger) {

                }
                
                /**
                 * @brief Creates a new SOCKS proxy connection for an accepted client socket.
                 * @param context I/O context for asynchronous operations.
                 * @param strand Execution strand for serialized callbacks.
                 * @param socket Accepted client TCP socket.
                 * @return Allocated proxy connection instance.
                 */
                std::shared_ptr<VEthernetLocalProxyConnection> VEthernetSocksProxySwitcher::NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                    std::shared_ptr<VEthernetSocksProxySwitcher> self = std::dynamic_pointer_cast<VEthernetSocksProxySwitcher>(shared_from_this());
                    std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();

                    return make_shared_object<VEthernetSocksProxyConnection>(self, exchanger, context, strand, socket);
                }

                /**
                 * @brief Resolves the configured local SOCKS bind endpoint.
                 * @param bind_port Output bind port from the client SOCKS configuration.
                 * @return Local bind IP address parsed from configuration.
                 */
                boost::asio::ip::address VEthernetSocksProxySwitcher::MyLocalEndPoint(int& bind_port) noexcept {
                    std::shared_ptr<ppp::configurations::AppConfiguration>& configuration_ = GetConfiguration();
                    bind_port = configuration_->client.socks_proxy.port;

                    return ppp::net::Ipep::ToAddress(configuration_->client.socks_proxy.bind, true);
                }
            }
        }
    }
}
