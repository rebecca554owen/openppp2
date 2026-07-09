#pragma once

#include <memory>
#include <ppp/collections/Dictionary.h>
#include <ppp/ethernet/VEthernet.h>

namespace ppp { namespace threading { class Timer; } }

namespace ppp {
    namespace app {
        namespace client {

            class SwitcherTimeoutRegistry {
            public:
                void Bind(ppp::ethernet::VEthernet::SynchronizedObject* sync) noexcept;

                bool Emplace(void* key,
                    const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& handler) noexcept;

                bool Delete(void* key) noexcept;
                void ReleaseAll() noexcept;

            private:
                ppp::ethernet::VEthernet::SynchronizedObject* sync_ = nullptr;
                ppp::unordered_map<void*, std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>> timeouts_;
            };
        }
    }
}
