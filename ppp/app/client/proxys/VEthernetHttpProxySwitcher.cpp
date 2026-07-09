#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file VEthernetHttpProxySwitcher.cpp
 * @brief HTTP proxy switcher factory and bind endpoint logic.
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief Constructs an HTTP proxy switcher instance.
                 * @param exchanger Shared exchanger instance.
                 * @return None.
                 * @note Delegates initialization to VEthernetLocalProxySwitcher.
                 */
                VEthernetHttpProxySwitcher::VEthernetHttpProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept 
                    : VEthernetLocalProxySwitcher(exchanger) {

                }
                
                /**
                 * @brief Creates a new HTTP proxy connection for an accepted socket.
                 * @param context Asio I/O context.
                 * @param strand Serialized executor strand.
                 * @param socket Accepted TCP client socket.
                 * @return New local proxy connection instance.
                 * @note The returned object type is VEthernetHttpProxyConnection.
                 */
                std::shared_ptr<VEthernetLocalProxyConnection> VEthernetHttpProxySwitcher::NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                    std::shared_ptr<VEthernetHttpProxySwitcher> self = std::dynamic_pointer_cast<VEthernetHttpProxySwitcher>(shared_from_this());
                    std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();

                    return make_shared_object<VEthernetHttpProxyConnection>(self, exchanger, context, strand, socket);
                }

                /**
                 * @brief Gets local bind address and port for HTTP proxy listening.
                 * @param bind_port Output bind port.
                 * @return Local bind IP address.
                 * @note Reads values from current application configuration.
                 */
                boost::asio::ip::address VEthernetHttpProxySwitcher::MyLocalEndPoint(int& bind_port) noexcept {
                    std::shared_ptr<ppp::configurations::AppConfiguration>& configuration_ = GetConfiguration();
                    bind_port = configuration_->client.http_proxy.port;

                    return ppp::net::Ipep::ToAddress(configuration_->client.http_proxy.bind, true);
                }
            }
        }
    }
}
