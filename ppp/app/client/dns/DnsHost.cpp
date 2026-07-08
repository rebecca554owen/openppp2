#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                DnsHostPorts MakeDnsHostPorts(
                    const std::shared_ptr<VEthernetNetworkSwitcher>& self,
                    const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {

                    return self->BuildDnsHostPorts(exchanger);
                }

            }
        }
    }
}
