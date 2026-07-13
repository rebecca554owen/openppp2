#include <ppp/stdafx.h>
#include <ppp/app/client/route/RouteCoordinator.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace route {

                RouteCoordinator::RouteCoordinator(
                    RouteState& state,
                    std::unique_ptr<IRoutePlatform> platform) noexcept
                    : state_(state),
                      platform_(std::move(platform)) {
                }

                bool RouteCoordinator::Apply(const std::vector<RouteSpec>& routes) noexcept {
                    if (stopped_.load(std::memory_order_acquire) || NULLPTR == platform_) {
                        return false;
                    }

                    if (state_.Snapshot().applied) {
                        return false;
                    }

                    RouteInformationTablePtr defaults = platform_->CaptureDefaults();
                    state_.ReplaceDefaultRoutes(defaults);
                    if (!platform_->RemoveDefaults(defaults)) {
                        const bool restored = platform_->RestoreDefaults(defaults);
                        state_.ResetAfterRollback(restored);
                        return false;
                    }

                    std::vector<RouteSpec> applied;
                    applied.reserve(routes.size());
                    for (const RouteSpec& route : routes) {
                        if (!platform_->Add(route)) {
                            const bool rollback_complete = Rollback(applied);
                            if (rollback_complete) {
                                state_.ResetAfterRollback(true);
                            }
                            else {
                                applied_ = std::move(applied);
                                state_.MarkApplied(!applied_.empty());
                            }
                            return false;
                        }
                        applied.emplace_back(route);
                    }

                    applied_ = std::move(applied);
                    state_.MarkApplied(true);
                    return true;
                }

                bool RouteCoordinator::Stop() noexcept {
                    bool expected = false;
                    if (!stopped_.compare_exchange_strong(
                            expected,
                            true,
                            std::memory_order_acq_rel)) {
                        return stop_result_.load(std::memory_order_acquire);
                    }

                    if (applied_.empty() && !state_.Snapshot().applied) {
                        stop_result_.store(true, std::memory_order_release);
                        return true;
                    }

                    const bool rollback_complete = Rollback(applied_);
                    if (rollback_complete) {
                        applied_.clear();
                    }
                    state_.ResetAfterRollback(rollback_complete);
                    stop_result_.store(rollback_complete, std::memory_order_release);
                    return rollback_complete;
                }

                bool RouteCoordinator::Rollback(const std::vector<RouteSpec>& applied) noexcept {
                    bool rollback_complete = true;
                    for (auto tail = applied.rbegin(); tail != applied.rend(); ++tail) {
                        if (!platform_->Delete(*tail)) {
                            rollback_complete = false;
                        }
                    }

                    const RouteStateSnapshot snapshot = state_.Snapshot();
                    if (!platform_->RestoreDefaults(snapshot.default_routes)) {
                        rollback_complete = false;
                    }
                    return rollback_complete;
                }

            }
        }
    }
}
