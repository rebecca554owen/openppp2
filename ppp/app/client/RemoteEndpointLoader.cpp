#include <ppp/app/client/RemoteEndpointLoader.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

namespace ppp::app::client {

void RemoteEndpointLoader::Bind(VEthernetNetworkSwitcher* owner) noexcept {
    owner_ = owner;
}

bool RemoteEndpointLoader::Apply(const boost::asio::ip::address& gw) noexcept {
    (void)gw;
    return false;
}

}  // namespace ppp::app::client
