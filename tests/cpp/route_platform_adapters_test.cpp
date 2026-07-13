#define BOOST_TEST_MODULE route_platform_adapters_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/WindowsRoutePlatform.h>
#include <ppp/app/client/route/DarwinRoutePlatform.h>
#include <ppp/app/client/route/MobileRoutePlatform.h>

namespace route = ppp::app::client::route;

namespace {

class Snapshot final : public route::IRouteSnapshot {};

template <typename Operations, typename Platform>
void VerifyDesktopAdapter() {
    std::vector<std::string> calls;
    auto baseline = std::make_shared<Snapshot>();
    Operations operations;
    operations.capture_defaults = [baseline, &calls]() noexcept {
        calls.emplace_back("capture");
        return baseline;
    };
    operations.remove_defaults = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("remove-defaults");
        return true;
    };
    operations.add = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("add:" + std::to_string(spec.network));
        return true;
    };
    operations.remove = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("delete:" + std::to_string(spec.network));
        return true;
    };
    operations.restore_defaults = [&calls](const route::RouteSnapshotPtr&) noexcept {
        calls.emplace_back("restore");
        return true;
    };

    Platform platform(std::move(operations));
    route::RouteSpec spec;
    spec.network = 7;
    route::RouteSnapshotPtr snapshot = platform.CaptureDefaults();
    BOOST_TEST(snapshot == baseline);
    BOOST_TEST(platform.RemoveDefaults(snapshot));
    BOOST_TEST(platform.Add(spec));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(platform.RestoreDefaults(snapshot));
    const std::vector<std::string> expected = {
        "capture", "remove-defaults", "add:7", "delete:7", "restore"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

}

BOOST_AUTO_TEST_CASE(windows_adapter_owns_platform_operation_boundary) {
    VerifyDesktopAdapter<route::WindowsRouteOperations, route::WindowsRoutePlatform>();
}

BOOST_AUTO_TEST_CASE(darwin_adapter_owns_platform_operation_boundary) {
    VerifyDesktopAdapter<route::DarwinRouteOperations, route::DarwinRoutePlatform>();
}

BOOST_AUTO_TEST_CASE(mobile_adapter_builds_deduplicated_all_route_plan) {
    route::MobileRoutePlan plan;
    plan.tap_network = 0x0a000000u;
    plan.tap_prefix = 24;
    plan.tap_gateway = 0x0a000001u;
    plan.loopback_gateway = 0x7f000001u;
    plan.tunnel_dns = { 1u, 2u };
    plan.underlying_dns = { 2u, 3u };

    std::vector<route::RouteSpec> specs = route::BuildMobileRouteSpecs(plan);
    BOOST_REQUIRE(specs.size() == 4u);
    BOOST_TEST(specs[0].network == 0x0a000000u);
    BOOST_TEST(specs[0].prefix == 24);
    BOOST_TEST(specs[0].gateway == plan.tap_gateway);
    BOOST_TEST(specs[1].gateway == plan.tap_gateway);
    BOOST_TEST(specs[2].gateway == plan.tap_gateway);
    BOOST_TEST(specs[3].network == 3u);
    BOOST_TEST(specs[3].gateway == plan.loopback_gateway);

    std::vector<uint32_t> applied;
    route::MobileRoutePlatform platform(
        [&applied](const route::RouteSpec& spec) noexcept {
            applied.emplace_back(spec.network);
            return true;
        });
    BOOST_TEST(platform.ApplyAll(specs));
    BOOST_TEST(applied.size() == specs.size());
}
