#include <ppp/app/client/RouteTableManager.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/RouteState.h>

namespace ppp {
    namespace app {
        namespace client {

            RouteTableManager::RouteTableManager() noexcept
                : protection_(std::make_shared<ProtectionState>()),
                  route_coordinator_(std::make_unique<route::RouteCoordinator>(nullptr)) {
            }
            RouteTableManager::~RouteTableManager() noexcept {
                StopProtection();
            }

            route::RouteStateSnapshot RouteTableManager::Snapshot() const noexcept {
                return route_coordinator_->Snapshot();
            }

            void RouteTableManager::ReplaceRib(route::RouteInformationTablePtr value) noexcept {
                route_coordinator_->MutableState().ReplaceRib(std::move(value));
            }

            void RouteTableManager::ReplaceFib(route::ForwardInformationTablePtr value) noexcept {
                route_coordinator_->MutableState().ReplaceFib(std::move(value));
            }

            void RouteTableManager::ReplacePeerPrefix(
                route::RouteInformationTablePtr rib,
                route::ForwardInformationTablePtr fib) noexcept {
                route_coordinator_->MutableState().ReplacePeerPrefix(
                    std::move(rib), std::move(fib));
            }

            void RouteTableManager::AddNic(uint32_t gateway, std::string interface_name) noexcept {
                route_coordinator_->MutableState().AddNic(gateway, std::move(interface_name));
            }

            void RouteTableManager::MarkApplyReady(bool value) noexcept {
                route_coordinator_->MutableState().MarkApplyReady(value);
            }

            void RouteTableManager::Clear() noexcept {
                route_coordinator_->MutableState().Clear();
            }

            void RouteTableManager::ClearDnsServers() noexcept {
                route_coordinator_->MutableState().ClearDnsServers();
            }

            void RouteTableManager::AddDnsServer(int bucket, uint32_t ip) noexcept {
                route_coordinator_->MutableState().AddDnsServer(bucket, ip);
            }

            void RouteTableManager::DeduplicateDnsServers() noexcept {
                route_coordinator_->MutableState().DeduplicateDnsServers();
            }

            void RouteTableManager::StopProtection() noexcept {
                std::shared_ptr<ProtectionState> state = protection_;
                if (!state) {
                    return;
                }
                state->active.store(false, std::memory_order_release);
                std::lock_guard<std::mutex> lock(state->mutex);
                state->remove_defaults = {};
            }

        }
    }
}
