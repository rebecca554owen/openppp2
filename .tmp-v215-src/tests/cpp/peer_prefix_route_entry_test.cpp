#define BOOST_TEST_MODULE peer_prefix_route_entry_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/PeerPrefixRoute.h>

namespace protocol = ppp::app::protocol;

namespace {

protocol::PeerPrefixRouteEntry MakeEntry(
    const char* network,
    int prefix,
    const char* via = "10.1.0.2") {
    protocol::PeerPrefixRouteEntry entry;
    entry.network = network;
    entry.prefix = prefix;
    entry.via = via;
    return entry;
}

}  // namespace

BOOST_AUTO_TEST_CASE(has_any_requires_network_and_prefix) {
    protocol::PeerPrefixRouteEntry entry;
    BOOST_TEST(!entry.HasAny());

    entry.network = "10.0.0.0";
    BOOST_TEST(!entry.HasAny());

    entry.prefix = 24;
    BOOST_TEST(entry.HasAny());
}

BOOST_AUTO_TEST_CASE(has_via_requires_gateway) {
    protocol::PeerPrefixRouteEntry entry = MakeEntry("10.0.0.0", 24, "");
    BOOST_TEST(!entry.HasVia());

    entry.via = "10.1.0.2";
    BOOST_TEST(entry.HasVia());
}

BOOST_AUTO_TEST_CASE(network_host_applies_prefix_mask) {
    const auto entry = MakeEntry("10.0.0.5", 24);
    BOOST_TEST(entry.NetworkHost() == htonl(0x0a000000u));
}

BOOST_AUTO_TEST_CASE(via_host_parses_ipv4) {
    const auto entry = MakeEntry("10.0.0.0", 24, "10.1.0.2");
    BOOST_TEST(entry.ViaHost() == htonl(0x0a010002u));
}

BOOST_AUTO_TEST_CASE(matches_destination_within_prefix) {
    const auto entry = MakeEntry("10.0.0.0", 24);
    BOOST_TEST(entry.MatchesDestination(htonl(0x0a0000ffu)));
    BOOST_TEST(!entry.MatchesDestination(htonl(0x0a010001u)));
}
