#define BOOST_TEST_MODULE fake_ip_pool_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/FakeIpPool.h>

namespace client_dns = ppp::app::client::dns;

BOOST_AUTO_TEST_CASE(configure_and_allocate) {
    client_dns::FakeIpPool pool;
    BOOST_TEST(pool.Configure("198.18.0.1/16"));
    BOOST_TEST(pool.IsEnabled());

    boost::system::error_code ec;
    const uint32_t sample_host =
        boost::asio::ip::make_address_v4("198.18.0.5", ec).to_uint();
    BOOST_REQUIRE(!ec);
    BOOST_TEST(pool.ContainsHostOrder(sample_host));

    const uint32_t first = pool.Allocate("example.com");
    const uint32_t second = pool.Allocate("example.com");
    BOOST_TEST(first != 0);
    BOOST_TEST(first == second);

    const uint32_t other = pool.Allocate("other.example");
    BOOST_TEST(other != 0);
    BOOST_TEST(other != first);
}

BOOST_AUTO_TEST_CASE(set_and_lookup_real_ip) {
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));

    const uint32_t fake_host = pool.Allocate("api.example.com");
    BOOST_REQUIRE(fake_host != 0);
    BOOST_TEST(pool.LookupRealIpHostOrder(fake_host) == 0);

    pool.SetRealIp("api.example.com", 0x08080808u); // 8.8.8.8
    BOOST_TEST(pool.LookupRealIpHostOrder(fake_host) == 0x08080808u);
    BOOST_TEST(pool.LookupHostname(fake_host) == "api.example.com");
}

BOOST_AUTO_TEST_CASE(invalid_cidr_disables_pool) {
    client_dns::FakeIpPool pool;
    BOOST_TEST(!pool.Configure("not-a-cidr"));
    BOOST_TEST(!pool.IsEnabled());
}

BOOST_AUTO_TEST_CASE(invalid_cidr_clears_existing_pool) {
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));
    const uint32_t fake_host = pool.Allocate("api.example.com");
    BOOST_REQUIRE(fake_host != 0);

    BOOST_TEST(!pool.Configure("not-a-cidr"));
    BOOST_TEST(!pool.IsEnabled());
    BOOST_TEST(pool.LookupHostname(fake_host).empty());

    uint32_t route_network = 123;
    int route_prefix = 45;
    BOOST_TEST(!pool.GetRoute(route_network, route_prefix));
    BOOST_TEST(route_network == 0u);
    BOOST_TEST(route_prefix == 0);
}

BOOST_AUTO_TEST_CASE(route_snapshot_reports_configured_route) {
    client_dns::FakeIpPool pool;
    BOOST_REQUIRE(pool.Configure("198.18.0.1/16"));

    uint32_t route_network = 0;
    int route_prefix = 0;
    BOOST_TEST(pool.GetRoute(route_network, route_prefix));
    BOOST_TEST(route_network == htonl(0xC6120000u));
    BOOST_TEST(route_prefix == 16);
}
