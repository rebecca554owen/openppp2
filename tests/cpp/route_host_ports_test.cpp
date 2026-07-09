#define BOOST_TEST_MODULE route_host_ports_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/RouteHost.h>

namespace route_client = ppp::app::client::route;

namespace {

route_client::RouteHostPorts MakeFilledHost() noexcept {
    route_client::RouteHostPorts host;
    host.get_tap = []() noexcept { return std::shared_ptr<ppp::tap::ITap>(); };
    host.get_tap_ni = []() noexcept { return std::shared_ptr<ppp::app::client::ClientNetworkInterface>(); };
    host.get_underlying_ni = []() noexcept { return std::shared_ptr<ppp::app::client::ClientNetworkInterface>(); };
    host.get_rib = []() noexcept { return route_client::RouteInformationTablePtr(); };
    host.set_rib = [](route_client::RouteInformationTablePtr) noexcept {};
    host.get_fib = []() noexcept { return route_client::ForwardInformationTablePtr(); };
    host.set_fib = [](route_client::ForwardInformationTablePtr) noexcept {};
    host.get_route_added = []() noexcept { return false; };
    host.set_route_added = [](bool) noexcept {};
    host.get_route_apply_ready = []() noexcept { return false; };
    host.add_dns_server_ip = [](uint32_t, int) noexcept {};
    host.collect_dns_reachability = []() noexcept {};
    host.get_default_routes = []() noexcept { return route_client::RouteInformationTablePtr(); };
    host.set_default_routes = [](route_client::RouteInformationTablePtr) noexcept {};
    host.get_nics = []() noexcept -> ppp::unordered_map<uint32_t, ppp::string>* {
        static ppp::unordered_map<uint32_t, ppp::string> nics;
        return &nics;
    };
    return host;
}

}  // namespace

BOOST_AUTO_TEST_CASE(default_host_is_invalid) {
    route_client::RouteHostPorts host;
    BOOST_TEST(!host.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_host_is_valid) {
    route_client::RouteHostPorts host = MakeFilledHost();
    BOOST_TEST(host.IsValid());
}

BOOST_AUTO_TEST_CASE(make_route_host_ports_delegates) {
    struct RecordingBackend final : route_client::IRouteBackend {
        int build_calls = 0;

        route_client::RouteHostPorts BuildRouteHostPorts() noexcept override {
            ++build_calls;
            return MakeFilledHost();
        }

#if !defined(_ANDROID) && !defined(_IPHONE)
        void AddRoute() noexcept override {}
        void DeleteRoute() noexcept override {}
#else
        bool AddAllRoute(const std::shared_ptr<ppp::tap::ITap>&) noexcept override { return true; }
#endif
    };

    auto backend = std::make_shared<RecordingBackend>();
    route_client::RouteHostPorts ports = route_client::MakeRouteHostPorts(backend);
    BOOST_TEST(backend->build_calls == 1);
    BOOST_TEST(ports.IsValid());
}
