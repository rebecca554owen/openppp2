#define BOOST_TEST_MODULE route_state_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/route/RouteState.h>
#include <ppp/net/native/rib.h>

namespace route = ppp::app::client::route;

BOOST_AUTO_TEST_CASE(snapshot_is_isolated_from_state) {
    route::RouteState state;
    auto rib = std::make_shared<ppp::net::native::RouteInformationTable>();
    auto fib = std::make_shared<ppp::net::native::ForwardInformationTable>();

    state.ReplaceRib(rib);
    state.ReplaceFib(fib);
    state.ReplaceNics({ { 0x01020304u, "eth0" } });
    state.AddDnsServer(0, 0x08080808u);
    state.MarkApplied(true);
    state.MarkApplyReady(true);

    route::RouteStateSnapshot snapshot = state.Snapshot();
    BOOST_TEST(snapshot.rib == rib);
    BOOST_TEST(snapshot.fib == fib);
    BOOST_TEST(snapshot.nics.at(0x01020304u) == "eth0");
    BOOST_TEST(snapshot.dns_servers[0].count(0x08080808u) == 1u);
    BOOST_TEST(snapshot.applied);
    BOOST_TEST(snapshot.apply_ready);

    snapshot.nics.clear();
    snapshot.dns_servers[0].clear();
    const route::RouteStateSnapshot unchanged = state.Snapshot();
    BOOST_TEST(unchanged.nics.size() == 1u);
    BOOST_TEST(unchanged.dns_servers[0].size() == 1u);
}

BOOST_AUTO_TEST_CASE(reset_requires_completed_rollback) {
    route::RouteState state;
    state.MarkApplied(true);
    state.MarkApplyReady(true);
    state.AddDnsServer(1, 0x01010101u);

    BOOST_TEST(!state.ResetAfterRollback(false));
    BOOST_TEST(state.Snapshot().applied);

    BOOST_TEST(state.ResetAfterRollback(true));
    const route::RouteStateSnapshot snapshot = state.Snapshot();
    BOOST_TEST(!snapshot.applied);
    BOOST_TEST(!snapshot.apply_ready);
    BOOST_TEST(snapshot.dns_servers[1].empty());
}

BOOST_AUTO_TEST_CASE(invalid_dns_bucket_is_ignored) {
    route::RouteState state;
    state.AddDnsServer(-1, 0x08080808u);
    state.AddDnsServer(3, 0x01010101u);

    const route::RouteStateSnapshot snapshot = state.Snapshot();
    BOOST_TEST(snapshot.dns_servers[0].empty());
    BOOST_TEST(snapshot.dns_servers[1].empty());
    BOOST_TEST(snapshot.dns_servers[2].empty());
}

BOOST_AUTO_TEST_CASE(peer_prefix_and_default_routes_are_replaced_together) {
    route::RouteState state;
    auto peer_rib = std::make_shared<ppp::net::native::RouteInformationTable>();
    auto peer_fib = std::make_shared<ppp::net::native::ForwardInformationTable>();
    auto defaults = std::make_shared<ppp::net::native::RouteInformationTable>();

    state.ReplacePeerPrefix(peer_rib, peer_fib);
    state.ReplaceDefaultRoutes(defaults);

    const route::RouteStateSnapshot snapshot = state.Snapshot();
    BOOST_TEST(snapshot.peer_prefix_rib == peer_rib);
    BOOST_TEST(snapshot.peer_prefix_fib == peer_fib);
    BOOST_TEST(snapshot.default_routes == defaults);
}

BOOST_AUTO_TEST_CASE(dns_servers_can_be_deduplicated_and_cleared) {
    route::RouteState state;
    state.AddDnsServer(0, 0x08080808u);
    state.AddDnsServer(1, 0x08080808u);
    state.AddDnsServer(1, 0x01010101u);

    state.DeduplicateDnsServers();
    route::RouteStateSnapshot snapshot = state.Snapshot();
    BOOST_TEST(snapshot.dns_servers[0].size() == 1u);
    BOOST_TEST(snapshot.dns_servers[1].count(0x08080808u) == 0u);
    BOOST_TEST(snapshot.dns_servers[1].count(0x01010101u) == 1u);

    state.ClearDnsServers();
    snapshot = state.Snapshot();
    BOOST_TEST(snapshot.dns_servers[0].empty());
    BOOST_TEST(snapshot.dns_servers[1].empty());
    BOOST_TEST(snapshot.dns_servers[2].empty());
}
