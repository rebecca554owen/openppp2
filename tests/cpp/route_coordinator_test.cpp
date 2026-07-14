#define BOOST_TEST_MODULE route_coordinator_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/IRoutePlatform.h>
#include <ppp/app/client/route/RouteCoordinator.h>
#include <ppp/net/native/rib.h>

namespace route = ppp::app::client::route;

namespace {

class FakeRouteSnapshot final : public route::IRouteSnapshot {
};

class FakeRoutePlatform final : public route::IRoutePlatform {
public:
    int fail_add_at = -1;
    int add_count = 0;
    bool delete_ok = true;
    bool remove_defaults_ok = true;
    bool restore_ok = true;
    ppp::vector<ppp::string> calls;
    std::shared_ptr<const route::IRouteSnapshot> defaults =
        std::make_shared<FakeRouteSnapshot>();

    std::shared_ptr<const route::IRouteSnapshot> CaptureDefaults() noexcept override {
        calls.emplace_back("capture");
        return defaults;
    }

    bool RemoveDefaults(const std::shared_ptr<const route::IRouteSnapshot>&) noexcept override {
        calls.emplace_back("remove-defaults");
        return remove_defaults_ok;
    }

    bool Add(const route::RouteSpec& spec) noexcept override {
        calls.emplace_back("add:" + std::to_string(spec.network));
        ++add_count;
        return add_count != fail_add_at;
    }

    bool Delete(const route::RouteSpec& spec) noexcept override {
        calls.emplace_back("delete:" + std::to_string(spec.network));
        return delete_ok;
    }

    bool RestoreDefaults(const std::shared_ptr<const route::IRouteSnapshot>&) noexcept override {
        calls.emplace_back("restore");
        return restore_ok;
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
        "capture", "remove-defaults", "add:1", "add:2", "delete:2", "delete:1", "restore"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    BOOST_TEST(!coordinator.Snapshot().applied);
}

BOOST_AUTO_TEST_CASE(partial_apply_failure_rolls_back_in_reverse_order) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->fail_add_at = 2;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(10), MakeRoute(20) }));

    const ppp::vector<ppp::string> expected = {
        "capture", "remove-defaults", "add:10", "add:20", "delete:10", "restore"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    const route::RouteStateSnapshot snapshot = coordinator.Snapshot();
    BOOST_TEST(!snapshot.applied);
    BOOST_TEST(snapshot.default_routes == nullptr);
}

BOOST_AUTO_TEST_CASE(rollback_failure_preserves_state_for_diagnostics) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->fail_add_at = 2;
    view->delete_ok = false;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(100), MakeRoute(200) }));

    const route::RouteStateSnapshot snapshot = coordinator.Snapshot();
    BOOST_TEST(snapshot.default_routes == view->defaults);
    BOOST_TEST(snapshot.applied);
}

BOOST_AUTO_TEST_CASE(stop_before_apply_has_no_platform_side_effects) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(coordinator.Stop());
    BOOST_TEST(view->calls.empty());
}

BOOST_AUTO_TEST_CASE(failed_stop_is_idempotent_and_keeps_reporting_failure) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->delete_ok = false;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(coordinator.Apply({ MakeRoute(7) }));
    BOOST_TEST(!coordinator.Stop());
    const size_t calls_after_first_stop = view->calls.size();
    BOOST_TEST(!coordinator.Stop());
    BOOST_TEST(view->calls.size() == calls_after_first_stop);
    BOOST_TEST(coordinator.Snapshot().applied);
}

BOOST_AUTO_TEST_CASE(default_removal_failure_restores_baseline_before_returning) {
    auto platform = std::make_unique<FakeRoutePlatform>();
    FakeRoutePlatform* view = platform.get();
    view->remove_defaults_ok = false;
    route::RouteCoordinator coordinator(std::move(platform));

    BOOST_TEST(!coordinator.Apply({ MakeRoute(9) }));
    const ppp::vector<ppp::string> expected = {
        "capture", "remove-defaults", "restore"
    };
    BOOST_TEST(view->calls == expected, boost::test_tools::per_element());
    BOOST_TEST(coordinator.Snapshot().default_routes == nullptr);
}
