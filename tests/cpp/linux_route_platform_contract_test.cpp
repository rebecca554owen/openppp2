#define BOOST_TEST_MODULE linux_route_platform_contract_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/LinuxRoutePlatform.h>
#include <ppp/app/client/route/RouteSpecs.h>
#include <ppp/net/native/rib.h>

namespace route = ppp::app::client::route;

BOOST_AUTO_TEST_CASE(interface_selection_uses_tap_known_nic_then_underlying) {
    const std::unordered_map<uint32_t, std::string> nics = {
        { 20u, "wlan0" },
    };

    BOOST_TEST(route::SelectLinuxInterface(10u, 10u, "tap0", "eth0", nics) == "tap0");
    BOOST_TEST(route::SelectLinuxInterface(20u, 10u, "tap0", "eth0", nics) == "wlan0");
    BOOST_TEST(route::SelectLinuxInterface(30u, 10u, "tap0", "eth0", nics) == "eth0");
}

BOOST_AUTO_TEST_CASE(platform_delegates_operations_with_stable_interface_snapshot) {
    ppp::vector<ppp::string> calls;
    auto defaults = std::make_shared<ppp::net::native::RouteInformationTable>();

    route::LinuxRouteOperations operations;
    operations.capture_defaults =
        [&calls, defaults](uint32_t gateway) noexcept {
            calls.emplace_back("capture:" + std::to_string(gateway));
            return defaults;
        };
    operations.remove_all =
        [&calls](const route::LinuxRouteInterfaceResolver& resolve,
            const route::RouteInformationTablePtr&) noexcept {
            ppp::net::native::RouteEntry entry{ 0u, 0, 20u };
            calls.emplace_back("remove:" + resolve(entry));
            return true;
        };
    operations.restore_all =
        [&calls](const route::LinuxRouteInterfaceResolver& resolve,
            const route::RouteInformationTablePtr&) noexcept {
            ppp::net::native::RouteEntry entry{ 0u, 0, 10u };
            calls.emplace_back("restore:" + resolve(entry));
            return true;
        };
    operations.add = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("add:" + spec.interface_name);
        return true;
    };
    operations.remove = [&calls](const route::RouteSpec& spec) noexcept {
        calls.emplace_back("delete:" + spec.interface_name);
        return true;
    };

    route::LinuxRoutePlatform platform(
        10u,
        "tap0",
        "eth0",
        { { 20u, "wlan0" } },
        false,
        std::move(operations));

    route::RouteSpec spec;
    spec.network = 1u;
    spec.gateway = 20u;
    spec.prefix = 32;
    route::RouteSnapshotPtr snapshot = platform.CaptureDefaults();
    BOOST_REQUIRE(snapshot != nullptr);
    BOOST_TEST(platform.RemoveDefaults(snapshot));
    BOOST_TEST(platform.Add(spec));
    BOOST_TEST(platform.Delete(spec));
    BOOST_TEST(platform.RestoreDefaults(snapshot));

    const ppp::vector<ppp::string> expected = {
        "capture:10", "remove:wlan0", "add:wlan0", "delete:wlan0", "restore:tap0"
    };
    BOOST_TEST(calls == expected, boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(promiscuous_mode_does_not_remove_or_restore_defaults) {
    int default_mutations = 0;
    route::LinuxRouteOperations operations;
    operations.capture_defaults = [](uint32_t) noexcept {
        return route::RouteInformationTablePtr();
    };
    operations.remove_all = [&default_mutations](const auto&, const auto&) noexcept {
        ++default_mutations;
        return true;
    };
    operations.restore_all = [&default_mutations](const auto&, const auto&) noexcept {
        ++default_mutations;
        return true;
    };
    operations.add = [](const route::RouteSpec&) noexcept { return true; };
    operations.remove = [](const route::RouteSpec&) noexcept { return true; };

    route::LinuxRoutePlatform platform(10u, "tap0", "eth0", {}, true, std::move(operations));
    BOOST_TEST(platform.CaptureDefaults() == nullptr);
    BOOST_TEST(platform.RemoveDefaults(nullptr));
    BOOST_TEST(platform.RestoreDefaults(nullptr));
    BOOST_TEST(default_mutations == 0);
}

BOOST_AUTO_TEST_CASE(rib_is_converted_to_route_specs_without_host_dependencies) {
    auto rib = std::make_shared<ppp::net::native::RouteInformationTable>();
    BOOST_TEST(rib->AddRoute(0x0a000000u, 8, 10u));
    BOOST_TEST(rib->AddRoute(0xc0a80000u, 16, 20u));

    std::vector<route::RouteSpec> specs = route::BuildRouteSpecs(rib);
    BOOST_REQUIRE(specs.size() == 2u);
    std::sort(specs.begin(), specs.end(), [](const auto& left, const auto& right) {
        return left.network < right.network;
    });
    BOOST_TEST(specs[0].network == 0x0a000000u);
    BOOST_TEST(specs[0].prefix == 8);
    BOOST_TEST(specs[0].gateway == 10u);
    BOOST_TEST(specs[0].interface_name.empty());
    BOOST_TEST(specs[1].network == 0xc0a80000u);
    BOOST_TEST(specs[1].prefix == 16);
    BOOST_TEST(specs[1].gateway == 20u);
}
