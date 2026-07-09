#include <ppp/app/client/route/RouteHost.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                RouteHostPorts MakeRouteHostPorts(const std::shared_ptr<IRouteBackend>& host) noexcept {
                    return host->BuildRouteHostPorts();
                }

                RouteHostPorts MakeRouteHostPorts(const std::shared_ptr<VEthernetNetworkSwitcher>& self) noexcept {
                    return MakeRouteHostPorts(std::static_pointer_cast<IRouteBackend>(self));
                }

            }
        }
    }
}
