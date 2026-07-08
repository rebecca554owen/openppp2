#pragma once

namespace ppp {
    namespace app {
        namespace protocol {
            struct VirtualEthernetInformationExtensions;
            struct PeerPrefixRouteEntry;
        }
        namespace client {
            class VEthernetNetworkSwitcher;

            /**
             * @brief Installs and tears down peer-prefix routes on the owning switcher.
             */
            class PeerPrefixRouteManager {
            public:
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;

                bool Apply(const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions) noexcept;
                void Clear() noexcept;

            private:
                VEthernetNetworkSwitcher* owner_ = nullptr;
            };
        }
    }
}
