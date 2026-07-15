#define BOOST_TEST_MODULE route_coordinator_test
#include <boost/test/included/unit_test.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <thread>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/app/client/route/WindowsRoutePlatform.h>
#include <ppp/net/native/rib.h>

namespace route = ppp::app::client::route;

#if !defined(_ANDROID) && !defined(_IPHONE)
BOOST_AUTO_TEST_CASE(defer_when_route_state_not_ready) {
    BOOST_TEST(route::RouteCoordinator::ShouldDeferHostedRouteApply(false, true));
}

BOOST_AUTO_TEST_CASE(defer_when_exchanger_not_established) {
    BOOST_TEST(route::RouteCoordinator::ShouldDeferHostedRouteApply(true, false));
}

BOOST_AUTO_TEST_CASE(defer_when_both_preconditions_missing) {
    BOOST_TEST(route::RouteCoordinator::ShouldDeferHostedRouteApply(false, false));
}

BOOST_AUTO_TEST_CASE(apply_when_route_state_ready_and_exchanger_established) {
    BOOST_TEST(!route::RouteCoordinator::ShouldDeferHostedRouteApply(true, true));
}
#endif

namespace {

class FakeRouteSnapshot final : public route::IRouteSnapshot {
public:
    explicit FakeRouteSnapshot(int id = 0) noexcept : id(id) {}
    int id;
};

int SnapshotId(const route::RouteSnapshotPtr& snapshot) noexcept {
    const auto value = std::dynamic_pointer_cast<const FakeRouteSnapshot>(snapshot);
    return value ? value->id : -1;
}

class FakeRoutePlatform final : public route::IRoutePlatform {
public:
    int fail_add_at = -1;
    int add_count = 0;
    bool capture_ok = true;
    bool delete_ok = true;
    int delete_failures_remaining = 0;
    bool remove_defaults_ok = true;
    bool restore_ok = true;
    int restore_failures_remaining = 0;
    std::atomic_int remove_defaults_count{0};
    std::atomic_int capture_count{0};
    std::promise<void>* remove_defaults_entered = nullptr;
    std::shared_future<void> remove_defaults_release;
    std::promise<void>* delete_entered = nullptr;
    std::shared_future<void> delete_release;
    std::promise<void>* restore_entered = nullptr;
    std::shared_future<void> restore_release;
    ppp::vector<ppp::string> calls;
    std::shared_ptr<ppp::vector<ppp::string>> external_calls;
    route::RouteSnapshotPtr defaults = std::make_shared<FakeRouteSnapshot>(1);
    std::vector<std::vector<route::RouteSnapshotPtr>> capture_results;
    std::vector<route::RouteSnapshotPtr> restored_snapshots;
    std::vector<route::RouteSpec> added_specs;
    std::vector<route::RouteSpec> deleted_specs;
    std::vector<route::RouteAddResult> add_results;
    route::RouteSnapshotPtr remove_failure_snapshot;
    int remove_snapshot_failures_remaining = 0;
    route::RouteSnapshotPtr restore_failure_snapshot;
    int restore_snapshot_failures_remaining = 0;
    std::mutex mutex;

    route::DefaultRouteCapture CaptureDefaults() noexcept override {
        std::lock_guard<std::mutex> lock(mutex);
        calls.emplace_back("capture");
        if (external_calls) external_calls->emplace_back("capture");
        capture_count.fetch_add(1, std::memory_order_relaxed);
        if (!capture_ok) {
            return std::nullopt;
        }
        if (!capture_results.empty()) {
            std::vector<route::RouteSnapshotPtr> result =
                std::move(capture_results.front());
            capture_results.erase(capture_results.begin());
            return result;
        }
        return defaults ? std::vector<route::RouteSnapshotPtr>{ defaults }
                        : std::vector<route::RouteSnapshotPtr>();
    }

    bool RemoveDefault(const route::RouteSnapshotPtr& snapshot) noexcept override {
        std::promise<void>* entered = nullptr;
        std::shared_future<void> release;
        bool fail = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            const std::string call = "remove:" + std::to_string(SnapshotId(snapshot));
            calls.emplace_back(call.begin(), call.end());
            if (external_calls) external_calls->emplace_back(call.begin(), call.end());
            remove_defaults_count.fetch_add(1, std::memory_order_relaxed);
            entered = remove_defaults_entered;
            remove_defaults_entered = nullptr;
            release = remove_defaults_release;
            if (remove_snapshot_failures_remaining > 0 &&
                snapshot == remove_failure_snapshot) {
                --remove_snapshot_failures_remaining;
                fail = true;
            }
        }
        if (entered) {
            entered->set_value();
            if (release.valid()) {
                release.wait();
            }
        }
        return !fail && remove_defaults_ok;
    }

    route::RouteAddResult Add(const route::RouteSpec& spec) noexcept override {
        std::lock_guard<std::mutex> lock(mutex);
        calls.emplace_back("add:" + std::to_string(spec.network));
        if (external_calls) external_calls->emplace_back("add:" + std::to_string(spec.network));
        added_specs.emplace_back(spec);
        ++add_count;
        if (!add_results.empty()) {
            const route::RouteAddResult result = add_results.front();
            add_results.erase(add_results.begin());
            return result;
        }
        return add_count == fail_add_at
            ? route::RouteAddResult::Failed
            : route::RouteAddResult::Created;
    }

    bool Delete(const route::RouteSpec& spec) noexcept override {
        std::promise<void>* entered = nullptr;
        std::shared_future<void> release;
        {
            std::lock_guard<std::mutex> lock(mutex);
            calls.emplace_back("delete:" + std::to_string(spec.network));
            deleted_specs.emplace_back(spec);
            if (external_calls) {
                external_calls->emplace_back("delete:" + std::to_string(spec.network));
            }
            entered = delete_entered;
            delete_entered = nullptr;
            release = delete_release;
        }
        if (entered) {
            entered->set_value();
            if (release.valid()) {
                release.wait();
            }
        }
        std::lock_guard<std::mutex> lock(mutex);
        if (delete_failures_remaining > 0) {
            --delete_failures_remaining;
            return false;
        }
        return delete_ok;
    }

    bool RestoreDefault(const route::RouteSnapshotPtr& snapshot) noexcept override {
        std::promise<void>* entered = nullptr;
        std::shared_future<void> release;
        bool fail = false;
        {
            std::lock_guard<std::mutex> lock(mutex);
            const std::string call = "restore:" + std::to_string(SnapshotId(snapshot));
            calls.emplace_back(call.begin(), call.end());
            if (external_calls) external_calls->emplace_back(call.begin(), call.end());
            restored_snapshots.emplace_back(snapshot);
            entered = restore_entered;
            restore_entered = nullptr;
            release = restore_release;
            if (restore_snapshot_failures_remaining > 0 &&
                snapshot == restore_failure_snapshot) {
                --restore_snapshot_failures_remaining;
                fail = true;
            }
            else if (restore_failures_remaining > 0) {
                --restore_failures_remaining;
                fail = true;
            }
        }
        if (entered) {
            entered->set_value();
            if (release.valid()) {
                release.wait();
            }
        }
        return !fail && restore_ok;
    }

    bool SameDefault(const route::RouteSnapshotPtr& left,
        const route::RouteSnapshotPtr& right) noexcept override {
        return SnapshotId(left) == SnapshotId(right);
    }
};

route::RouteSpec MakeRoute(uint32_t network) {
    route::RouteSpec spec;
    spec.network = network;
    spec.gateway = 0x01010101u;
    spec.prefix = 32;
    spec.interface_name = "eth0";
    return spec;
}

} // namespace

BOOST_AUTO_TEST_CASE(successful_apply_and_stop_are_ordered_and_idempotent) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(coordinator.Apply({ MakeRoute(1), MakeRoute(2) }));
    BOOST_TEST(coordinator.Snapshot().applied);
    BOOST_TEST(coordinator.Stop());
    BOOST_TEST(coordinator.Stop());

    const ppp::vector<ppp::string> expected = {
        "capture", "remove:1", "add:1", "add:2", "delete:2", "delete:1",
        "restore:1"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    BOOST_TEST(!coordinator.Snapshot().applied);
}

BOOST_AUTO_TEST_CASE(capture_failure_stops_before_any_route_mutation) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->capture_ok = false;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(3) }));
    const ppp::vector<ppp::string> expected = { "capture" };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    BOOST_TEST(!coordinator.Snapshot().applied);
}

BOOST_AUTO_TEST_CASE(empty_default_capture_is_a_successful_query) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->defaults.reset();
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(4) }));
    BOOST_REQUIRE(coordinator.Stop());
    const ppp::vector<ppp::string> expected = {
        "capture", "add:4", "delete:4"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(only_created_routes_are_owned_and_deleted_on_stop) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->defaults.reset();
    view->add_results = {
        route::RouteAddResult::Unchanged,
        route::RouteAddResult::Created,
    };
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(5), MakeRoute(6) }));
    BOOST_REQUIRE(coordinator.Stop());
    const ppp::vector<ppp::string> expected = {
        "capture", "add:5", "add:6", "delete:6"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(dynamic_delete_of_unchanged_route_is_a_noop) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->defaults.reset();
    route::RouteCoordinator coordinator(std::move(platform));
    BOOST_REQUIRE(coordinator.Apply({}));

    route::RoutePlanInput input;
    input.underlying_interface.name = "eth0";
    view->add_results = { route::RouteAddResult::Unchanged };
    BOOST_REQUIRE(coordinator.AddRoute(input, 7u, 8u, 32));
    BOOST_TEST(coordinator.DeleteRoute(input, 7u, 8u, 32));
    BOOST_REQUIRE(coordinator.Stop());

    BOOST_REQUIRE(view->added_specs.size() == 1u);
    BOOST_TEST(view->deleted_specs.empty());
}

BOOST_AUTO_TEST_CASE(partial_apply_failure_rolls_back_in_reverse_order) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->fail_add_at = 2;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(10), MakeRoute(20) }));

    const ppp::vector<ppp::string> expected = {
        "capture", "remove:1", "add:10", "add:20", "delete:10", "restore:1"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    const route::RouteStateSnapshot snapshot = coordinator.Snapshot();
    BOOST_TEST(!snapshot.applied);
    BOOST_TEST(snapshot.default_routes.empty());
}

BOOST_AUTO_TEST_CASE(rollback_failure_preserves_only_the_pending_undo_state) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->fail_add_at = 2;
    view->delete_ok = false;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(100), MakeRoute(200) }));

    const route::RouteStateSnapshot snapshot = coordinator.Snapshot();
    BOOST_TEST(snapshot.default_routes.empty());
    BOOST_TEST(snapshot.applied);
}

BOOST_AUTO_TEST_CASE(stop_before_apply_has_no_platform_side_effects) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(coordinator.Stop());
    BOOST_TEST(view->calls.empty());
}

BOOST_AUTO_TEST_CASE(mobile_add_all_route_rejects_after_stop_without_publishing_rib) {
    route::RouteCoordinator coordinator(nullptr);
    BOOST_REQUIRE(coordinator.Stop());

    route::RoutePlanInput input;
    BOOST_TEST(!coordinator.AddAllRoute(input));
    BOOST_TEST(coordinator.Snapshot().rib == nullptr);
}

BOOST_AUTO_TEST_CASE(mobile_add_all_route_publishes_committed_policy_state) {
    route::RouteCoordinator coordinator(nullptr);
    route::RoutePlanInput input;
    input.tap_ip = htonl(0x0a000002u);
    input.tap_gateway = htonl(0x0a000001u);
    input.tap_submask = htonl(0xffffff00u);

    BOOST_REQUIRE(coordinator.AddAllRoute(input));
    const route::RouteStateSnapshot snapshot = coordinator.Snapshot();
    BOOST_TEST(snapshot.rib != nullptr);
    BOOST_TEST(snapshot.applied);
}

BOOST_AUTO_TEST_CASE(failed_stop_attempt_can_be_retried_explicitly) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->delete_ok = false;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(coordinator.Apply({ MakeRoute(7) }));
    BOOST_TEST(!coordinator.Stop());
    view->delete_ok = true;
    BOOST_TEST(coordinator.Stop());
    BOOST_TEST(!coordinator.Snapshot().applied);
}

BOOST_AUTO_TEST_CASE(concurrent_stop_waits_for_failed_rollback_result) {
    std::promise<void> delete_entered;
    std::promise<void> release_delete;
    std::future<void> delete_entered_future = delete_entered.get_future();

    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(8) }));
    view->delete_failures_remaining = 1;
    view->delete_entered = &delete_entered;
    view->delete_release = release_delete.get_future().share();

    std::promise<void> second_started;
    std::future<void> second_started_future = second_started.get_future();
    std::promise<void> second_joined;
    std::future<void> second_joined_future = second_joined.get_future();
    coordinator.SetStopWaiterObserverForTesting(
        [&second_joined]() { second_joined.set_value(); });
    std::future<bool> first_stop = std::async(
        std::launch::async,
        [&coordinator]() { return coordinator.Stop(); });
    const bool delete_did_start =
        delete_entered_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!delete_did_start) {
        release_delete.set_value();
        BOOST_REQUIRE_MESSAGE(delete_did_start, "first Stop did not enter Delete");
    }
    std::future<bool> second_stop = std::async(
        std::launch::async,
        [&coordinator, &second_started]() {
            second_started.set_value();
            return coordinator.Stop();
        });
    const bool second_did_start =
        second_started_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!second_did_start) {
        release_delete.set_value();
        BOOST_REQUIRE_MESSAGE(second_did_start, "second Stop thread did not start");
    }
    const bool second_did_join =
        second_joined_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!second_did_join) {
        release_delete.set_value();
        BOOST_REQUIRE_MESSAGE(second_did_join, "second Stop did not join active attempt");
    }
    const bool second_is_waiting =
        second_stop.wait_for(std::chrono::milliseconds(0)) ==
        std::future_status::timeout;
    BOOST_TEST(second_is_waiting);
    release_delete.set_value();

    const bool first_result = first_stop.get();
    const bool second_result = second_stop.get();
    BOOST_TEST(!first_result);
    BOOST_TEST(!second_result);
    BOOST_TEST(coordinator.Stop());
}

BOOST_AUTO_TEST_CASE(successful_route_delete_is_not_repeated_when_default_restore_retries) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->restore_failures_remaining = 1;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(12) }));
    BOOST_TEST(!coordinator.Stop());
    BOOST_TEST(coordinator.Stop());

    BOOST_TEST(std::count(view->calls.begin(), view->calls.end(), "delete:12") == 1);
    BOOST_TEST(std::count(view->calls.begin(), view->calls.end(), "restore:1") == 2);
}

BOOST_AUTO_TEST_CASE(successful_default_restore_is_not_repeated_when_route_delete_retries) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->delete_failures_remaining = 1;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(13) }));
    BOOST_TEST(!coordinator.Stop());
    BOOST_TEST(coordinator.Stop());

    BOOST_TEST(std::count(view->calls.begin(), view->calls.end(), "delete:13") == 2);
    BOOST_TEST(std::count(view->calls.begin(), view->calls.end(), "restore:1") == 1);
}

BOOST_AUTO_TEST_CASE(partial_default_remove_failure_only_restores_removed_items) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteSnapshotPtr first = std::make_shared<FakeRouteSnapshot>(31);
    route::RouteSnapshotPtr second = std::make_shared<FakeRouteSnapshot>(32);
    view->capture_results = { { first, second } };
    view->remove_failure_snapshot = second;
    view->remove_snapshot_failures_remaining = 1;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(9) }));
    const ppp::vector<ppp::string> expected = {
        "capture", "remove:31", "remove:32", "restore:31"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    BOOST_REQUIRE(view->restored_snapshots.size() == 1u);
    BOOST_TEST(view->restored_snapshots[0] == first);
    BOOST_TEST(coordinator.Snapshot().default_routes.empty());
}

BOOST_AUTO_TEST_CASE(stop_retries_only_the_default_item_that_failed_to_restore) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteSnapshotPtr first = std::make_shared<FakeRouteSnapshot>(41);
    route::RouteSnapshotPtr second = std::make_shared<FakeRouteSnapshot>(42);
    view->capture_results = { { first, second } };
    view->restore_failure_snapshot = first;
    view->restore_snapshot_failures_remaining = 1;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_REQUIRE(coordinator.Apply({}));
    BOOST_TEST(!coordinator.Stop());
    const route::RouteStateSnapshot pending = coordinator.Snapshot();
    BOOST_REQUIRE(pending.default_routes.size() == 1u);
    BOOST_TEST(pending.default_routes[0] == first);
    BOOST_TEST(!pending.applied);

    BOOST_TEST(coordinator.Stop());
    BOOST_TEST(coordinator.Snapshot().default_routes.empty());
    BOOST_REQUIRE(view->restored_snapshots.size() == 3u);
    BOOST_TEST(view->restored_snapshots[0] == second);
    BOOST_TEST(view->restored_snapshots[1] == first);
    BOOST_TEST(view->restored_snapshots[2] == first);
}

BOOST_AUTO_TEST_CASE(stop_retries_restore_after_apply_rollback_restore_failure) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->fail_add_at = 1;
    view->restore_failures_remaining = 1;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(11) }));
    const route::RouteStateSnapshot pending = coordinator.Snapshot();
    BOOST_REQUIRE(pending.default_routes.size() == 1u);
    BOOST_TEST(pending.default_routes[0] == view->defaults);
    BOOST_TEST(coordinator.Stop());

    const ppp::vector<ppp::string> expected = {
        "capture", "remove:1", "add:11", "restore:1", "restore:1"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    BOOST_TEST(coordinator.Snapshot().default_routes.empty());
}

BOOST_AUTO_TEST_CASE(windows_failed_default_replacement_keeps_original_pending) {
    auto target = std::make_shared<FakeRouteSnapshot>(71);
    auto conflict = std::make_shared<FakeRouteSnapshot>(72);
    route::WindowsRouteOperations operations;
    operations.capture_defaults = [target]() noexcept {
        return std::vector<route::RouteSnapshotPtr>{ target };
    };
    operations.remove_default = [](const route::RouteSnapshotPtr&) noexcept {
        return true;
    };
    operations.add = [](const route::RouteSpec&) noexcept {
        return route::RouteAddResult::Created;
    };
    operations.remove = [](const route::RouteSpec&) noexcept { return true; };
    operations.exact_default_exists = [](const route::RouteSnapshotPtr&,
        bool& exists) noexcept {
        exists = false;
        return true;
    };
    operations.remove_conflicting_default =
        [conflict](const route::RouteSnapshotPtr&,
            route::RouteSnapshotPtr& removed) noexcept {
            removed = conflict;
            return true;
        };
    operations.restore_default =
        [target](const route::RouteSnapshotPtr& value) noexcept {
            return value != target;
        };
    operations.same_default = [](const route::RouteSnapshotPtr& left,
        const route::RouteSnapshotPtr& right) noexcept {
        return left == right;
    };

    route::RouteCoordinator coordinator(
        std::make_unique<route::WindowsRoutePlatform>(std::move(operations)));
    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(71) }));
    BOOST_TEST(!coordinator.Stop());

    const route::RouteStateSnapshot pending = coordinator.Snapshot();
    BOOST_REQUIRE(pending.default_routes.size() == 1u);
    BOOST_TEST(pending.default_routes[0] == target);
    BOOST_TEST(!pending.applied);
}

BOOST_AUTO_TEST_CASE(dynamic_routes_use_the_latest_plan_input_for_interfaces) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->defaults.reset();
    route::RouteCoordinator coordinator(std::move(platform));

    route::RoutePlanInput first;
    first.tap_gateway = 10u;
    first.tap_interface.name = "tap-old";
    first.underlying_interface.name = "eth-old";
    first.nics.emplace(20u, "wlan-old");
    BOOST_REQUIRE(coordinator.AddRoute(first));

    route::RoutePlanInput latest;
    latest.tap_gateway = 10u;
    latest.tap_interface.name = "tap-new";
    latest.underlying_interface.name = "eth-new";
    latest.nics.emplace(20u, "wlan-new");

    BOOST_REQUIRE(coordinator.AddRoute(latest, 101u, 10u, 32));
    BOOST_REQUIRE(coordinator.AddRoute(latest, 102u, 20u, 32));
    BOOST_REQUIRE(coordinator.AddRoute(latest, 103u, 30u, 32));
    BOOST_REQUIRE(coordinator.DeleteRoute(latest, 101u, 10u, 32));
    BOOST_REQUIRE(coordinator.DeleteRoute(latest, 102u, 20u, 32));
    BOOST_REQUIRE(coordinator.Stop());

    BOOST_REQUIRE(view->added_specs.size() == 3u);
    BOOST_TEST(view->added_specs[0].interface_name == "tap-new");
    BOOST_TEST(view->added_specs[1].interface_name == "wlan-new");
    BOOST_TEST(view->added_specs[2].interface_name == "eth-new");
    BOOST_REQUIRE(view->deleted_specs.size() == 3u);
    BOOST_TEST(view->deleted_specs[0].interface_name == "tap-new");
    BOOST_TEST(view->deleted_specs[1].interface_name == "wlan-new");
    BOOST_TEST(view->deleted_specs[2].interface_name == "eth-new");
}

BOOST_AUTO_TEST_CASE(clear_does_not_discard_failed_rollback_state) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->delete_ok = false;
    route::RouteCoordinator coordinator(std::move(platform));

    route::RoutePlanInput input;
    input.tunnel_dns.emplace(0x08080808u);
    BOOST_REQUIRE(coordinator.AddRoute(input));
    BOOST_TEST(!coordinator.Stop());
    coordinator.Clear();

    const route::RouteStateSnapshot snapshot = coordinator.Snapshot();
    BOOST_TEST(snapshot.applied);
    BOOST_TEST(snapshot.default_routes.empty());
    BOOST_TEST(snapshot.dns_servers[0].count(0x08080808u) == 1u);
}

BOOST_AUTO_TEST_CASE(underlying_default_repair_rejects_after_stop) {
    route::RouteCoordinator coordinator(nullptr);
    BOOST_REQUIRE(coordinator.Stop());

    route::RoutePlanInput input;
    input.underlying_interface.gateway =
        boost::asio::ip::make_address("192.0.2.1");
    BOOST_TEST(!coordinator.EnsureUnderlyingDefault(input));
}

#if !defined(_ANDROID) && !defined(_IPHONE)
BOOST_AUTO_TEST_CASE(protector_snapshots_are_restored_in_reverse_capture_order) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteSnapshotPtr initial_defaults = std::make_shared<FakeRouteSnapshot>(51);
    route::RouteSnapshotPtr protected_defaults = std::make_shared<FakeRouteSnapshot>(52);
    view->capture_results = { { initial_defaults }, { protected_defaults } };
    route::RouteCoordinator coordinator(std::move(platform));
    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(21) }));

    std::promise<void> protector_entered;
    std::promise<void> release_protector;
    std::future<void> protector_entered_future = protector_entered.get_future();
    view->remove_defaults_entered = &protector_entered;
    view->remove_defaults_release = release_protector.get_future().share();
    route::RoutePlanInput input;
    BOOST_REQUIRE(coordinator.ProtectDefaultRoute(input));
    const bool protector_started =
        protector_entered_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!protector_started) {
        release_protector.set_value();
        BOOST_REQUIRE_MESSAGE(protector_started, "protector did not remove captured defaults");
    }

    std::promise<void> stop_started;
    std::future<void> stop_started_future = stop_started.get_future();
    std::future<bool> stop = std::async(
        std::launch::async,
        [&coordinator, &stop_started]() {
            stop_started.set_value();
            return coordinator.Stop();
        });
    const bool stop_did_start =
        stop_started_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!stop_did_start) {
        release_protector.set_value();
        BOOST_REQUIRE(stop_did_start);
    }
    release_protector.set_value();

    BOOST_TEST(stop.get());
    BOOST_REQUIRE(view->restored_snapshots.size() == 2u);
    BOOST_TEST(view->restored_snapshots[0] == protected_defaults);
    BOOST_TEST(view->restored_snapshots[1] == initial_defaults);
}

BOOST_AUTO_TEST_CASE(protector_recapture_of_initial_default_is_restored_once) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteSnapshotPtr initial_defaults = std::make_shared<FakeRouteSnapshot>(61);
    route::RouteSnapshotPtr recaptured_defaults = std::make_shared<FakeRouteSnapshot>(61);
    view->capture_results = { { initial_defaults }, { recaptured_defaults } };
    route::RouteCoordinator coordinator(std::move(platform));
    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(24) }));

    std::promise<void> protector_entered;
    std::promise<void> release_protector;
    std::future<void> protector_entered_future = protector_entered.get_future();
    view->remove_defaults_entered = &protector_entered;
    view->remove_defaults_release = release_protector.get_future().share();
    route::RoutePlanInput input;
    BOOST_REQUIRE(coordinator.ProtectDefaultRoute(input));
    const bool protector_started =
        protector_entered_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!protector_started) {
        release_protector.set_value();
        BOOST_REQUIRE_MESSAGE(protector_started, "protector did not remove recaptured default");
    }

    std::future<bool> stop = std::async(
        std::launch::async,
        [&coordinator]() { return coordinator.Stop(); });
    release_protector.set_value();

    BOOST_TEST(stop.get());
    BOOST_REQUIRE(view->restored_snapshots.size() == 1u);
    BOOST_TEST(view->restored_snapshots[0] == initial_defaults);
    BOOST_TEST(coordinator.Snapshot().default_routes.empty());
}

BOOST_AUTO_TEST_CASE(consecutive_empty_protector_captures_leave_no_pending_restore) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->defaults.reset();
    view->capture_results = { {}, {}, {} };
    route::RouteCoordinator coordinator(std::move(platform));
    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(25) }));

    route::RoutePlanInput input;
    BOOST_REQUIRE(coordinator.ProtectDefaultRoute(input));
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (view->capture_count.load(std::memory_order_relaxed) < 3 &&
        std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const bool captured_twice =
        view->capture_count.load(std::memory_order_relaxed) >= 3;

    BOOST_TEST(coordinator.Stop());
    BOOST_REQUIRE_MESSAGE(captured_twice, "protector did not complete two empty captures");
    BOOST_TEST(view->remove_defaults_count.load(std::memory_order_relaxed) == 0);
    BOOST_TEST(view->restored_snapshots.empty());
    BOOST_TEST(coordinator.Snapshot().default_routes.empty());
}

BOOST_AUTO_TEST_CASE(failed_protector_snapshot_restore_is_the_only_retry) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteSnapshotPtr initial_defaults = std::make_shared<FakeRouteSnapshot>(71);
    route::RouteSnapshotPtr protected_defaults = std::make_shared<FakeRouteSnapshot>(72);
    view->capture_results = { { initial_defaults }, { protected_defaults } };
    view->restore_failure_snapshot = protected_defaults;
    view->restore_snapshot_failures_remaining = 1;
    route::RouteCoordinator coordinator(std::move(platform));
    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(22) }));

    std::promise<void> protector_entered;
    std::promise<void> release_protector;
    std::future<void> protector_entered_future = protector_entered.get_future();
    view->remove_defaults_entered = &protector_entered;
    view->remove_defaults_release = release_protector.get_future().share();
    route::RoutePlanInput input;
    BOOST_REQUIRE(coordinator.ProtectDefaultRoute(input));
    const bool protector_started =
        protector_entered_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!protector_started) {
        release_protector.set_value();
        BOOST_REQUIRE_MESSAGE(protector_started, "protector did not remove captured defaults");
    }

    std::promise<void> stop_started;
    std::future<void> stop_started_future = stop_started.get_future();
    std::future<bool> first_stop = std::async(
        std::launch::async,
        [&coordinator, &stop_started]() {
            stop_started.set_value();
            return coordinator.Stop();
        });
    const bool stop_did_start =
        stop_started_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!stop_did_start) {
        release_protector.set_value();
        BOOST_REQUIRE(stop_did_start);
    }
    release_protector.set_value();

    BOOST_TEST(!first_stop.get());
    BOOST_TEST(coordinator.Stop());
    BOOST_REQUIRE(view->restored_snapshots.size() == 3u);
    BOOST_TEST(view->restored_snapshots[0] == protected_defaults);
    BOOST_TEST(view->restored_snapshots[1] == initial_defaults);
    BOOST_TEST(view->restored_snapshots[2] == protected_defaults);
}

BOOST_AUTO_TEST_CASE(restart_waits_for_old_protector_inside_stop_operation_domain) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteCoordinator coordinator(std::move(platform));
    BOOST_REQUIRE(coordinator.Apply({ MakeRoute(23) }));

    std::promise<void> protector_entered;
    std::promise<void> release_protector;
    std::future<void> protector_entered_future = protector_entered.get_future();
    view->remove_defaults_entered = &protector_entered;
    view->remove_defaults_release = release_protector.get_future().share();
    route::RoutePlanInput input;
    BOOST_REQUIRE(coordinator.ProtectDefaultRoute(input));
    const bool protector_started =
        protector_entered_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!protector_started) {
        release_protector.set_value();
        BOOST_REQUIRE_MESSAGE(protector_started, "old protector did not enter RemoveDefault");
    }

    route::RoutePlanInput disabled_input;
    disabled_input.tap_promiscuous = true;
    std::promise<void> restart_started;
    std::future<void> restart_started_future = restart_started.get_future();
    std::future<bool> restart = std::async(
        std::launch::async,
        [&coordinator, &disabled_input, &restart_started]() {
            restart_started.set_value();
            return coordinator.ProtectDefaultRoute(disabled_input);
        });
    const bool restart_did_start =
        restart_started_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!restart_did_start) {
        release_protector.set_value();
        BOOST_REQUIRE(restart_did_start);
    }

    std::promise<void> stop_started;
    std::future<void> stop_started_future = stop_started.get_future();
    std::future<bool> stop = std::async(
        std::launch::async,
        [&coordinator, &stop_started]() {
            stop_started.set_value();
            return coordinator.Stop();
        });
    const bool stop_did_start =
        stop_started_future.wait_for(std::chrono::seconds(2)) ==
        std::future_status::ready;
    if (!stop_did_start) {
        release_protector.set_value();
        BOOST_REQUIRE(stop_did_start);
    }
    const bool stop_finished_before_worker_release =
        stop.wait_for(std::chrono::milliseconds(250)) == std::future_status::ready;
    release_protector.set_value();

    BOOST_TEST(!restart.get());
    BOOST_TEST(stop.get());
    BOOST_TEST(!stop_finished_before_worker_release);
    BOOST_TEST(view->remove_defaults_count.load(std::memory_order_relaxed) == 2);
}
#endif

BOOST_AUTO_TEST_CASE(destruction_rolls_back_an_applied_transaction) {
    auto calls = std::make_shared<ppp::vector<ppp::string>>();
    {
        auto platform = std::make_unique<FakeRoutePlatform>();
        platform->external_calls = calls;
        route::RouteCoordinator coordinator(std::move(platform));
        BOOST_TEST(coordinator.Apply({ MakeRoute(42) }));
    }

    const ppp::vector<ppp::string> expected = {
        "capture", "remove:1", "add:42", "delete:42", "restore:1"
    };
    BOOST_TEST(*calls == expected, boost::test_tools::per_element());
}
