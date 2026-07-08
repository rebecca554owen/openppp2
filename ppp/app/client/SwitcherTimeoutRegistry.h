#pragma once

#include <memory>
#include <ppp/collections/Dictionary.h>

namespace ppp { namespace threading { class Timer; } }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;

            class SwitcherTimeoutRegistry {
            public:
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;

                bool Emplace(void* key,
                    const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& handler) noexcept;

                bool Delete(void* key) noexcept;
                void ReleaseAll() noexcept;

            private:
                VEthernetNetworkSwitcher* owner_ = nullptr;
                ppp::unordered_map<void*, std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>> timeouts_;
            };
        }
    }
}
