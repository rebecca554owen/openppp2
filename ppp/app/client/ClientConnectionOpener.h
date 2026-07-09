#pragma once

#include <ppp/ethernet/VEthernet.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            class ClientConnectionOpener {
            public:
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;
                bool Open(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept;

            private:
                VEthernetNetworkSwitcher* owner_ = nullptr;
            };
        }
    }
}
