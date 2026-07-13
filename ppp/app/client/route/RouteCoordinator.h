#pragma once

#include <atomic>
#include <memory>
#include <vector>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RouteState.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                class RouteCoordinator final {
                public:
                    RouteCoordinator(
                        RouteState& state,
                        std::unique_ptr<IRoutePlatform> platform) noexcept;

                    bool Apply(const std::vector<RouteSpec>& routes) noexcept;
                    bool Stop() noexcept;

                private:
                    bool Rollback(const std::vector<RouteSpec>& applied) noexcept;

                    RouteState& state_;
                    std::unique_ptr<IRoutePlatform> platform_;
                    std::vector<RouteSpec> applied_;
                    std::atomic_bool stopped_{false};
                    std::atomic_bool stop_result_{true};
                };

            }
        }
    }
}
