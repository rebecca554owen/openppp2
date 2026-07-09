#pragma once

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            class ClientConnectionTeardown {
            public:
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;
                void ReleaseAllObjects() noexcept;

            private:
                VEthernetNetworkSwitcher* owner_ = nullptr;
            };
        }
    }
}
