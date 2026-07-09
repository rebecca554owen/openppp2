#define BOOST_TEST_MODULE route_host_interface_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/RouteHost.h>

namespace route_client = ppp::app::client::route;

struct FakeRouteBackend final : route_client::IRouteBackend {
    route_client::RouteHostPorts BuildRouteHostPorts() noexcept override {
        return route_client::RouteHostPorts{};
    }

#if !defined(_ANDROID) && !defined(_IPHONE)
    void AddRoute() noexcept override { add_route_calls++; }

    void DeleteRoute() noexcept override { delete_route_calls++; }

    int add_route_calls = 0;
    int delete_route_calls = 0;
#else
    bool AddAllRoute(const std::shared_ptr<ppp::tap::ITap>&) noexcept override {
        add_all_route_calls++;
        return true;
    }

    int add_all_route_calls = 0;
#endif
};

BOOST_AUTO_TEST_CASE(iroute_backend_is_polymorphic) {
    FakeRouteBackend host;
    route_client::IRouteBackend& iface = host;
    BOOST_TEST(!iface.BuildRouteHostPorts().IsValid());
#if !defined(_ANDROID) && !defined(_IPHONE)
    iface.AddRoute();
    iface.DeleteRoute();
    BOOST_TEST(host.add_route_calls == 1);
    BOOST_TEST(host.delete_route_calls == 1);
#else
    BOOST_TEST(iface.AddAllRoute({}));
    BOOST_TEST(host.add_all_route_calls == 1);
#endif
}
