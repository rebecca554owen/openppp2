#pragma once

namespace ppp::app::client {
    class VEthernetNetworkSwitcher;

    class AggregatorLoader {
    public:
        void Bind(VEthernetNetworkSwitcher* owner) noexcept;
        bool Prepare() noexcept;

    private:
        VEthernetNetworkSwitcher* owner_ = nullptr;
    };
}
