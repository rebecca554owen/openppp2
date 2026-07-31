#define BOOST_TEST_MODULE peer_prefix_route_from_json_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>
#include <json/json.h>

#include <ppp/app/protocol/PeerPrefixRoute.h>

namespace protocol = ppp::app::protocol;

BOOST_AUTO_TEST_CASE(from_json_parses_valid_entry) {
    Json::Value json;
    json["network"] = "10.0.0.0";
    json["prefix"] = 24;
    json["via"] = "10.1.0.2";

    protocol::PeerPrefixRouteEntry entry;
    BOOST_TEST(protocol::PeerPrefixRouteEntry::FromJson(entry, json));
    BOOST_TEST(entry.network == "10.0.0.0");
    BOOST_TEST(entry.prefix == 24);
    BOOST_TEST(entry.via == "10.1.0.2");
}

BOOST_AUTO_TEST_CASE(from_json_rejects_non_object) {
    protocol::PeerPrefixRouteEntry entry;

    Json::Value array(Json::arrayValue);
    array.append("10.0.0.0/24");
    BOOST_TEST(!protocol::PeerPrefixRouteEntry::FromJson(entry, array));
    BOOST_TEST(!entry.HasAny());

    Json::Value str("10.0.0.0/24");
    BOOST_TEST(!protocol::PeerPrefixRouteEntry::FromJson(entry, str));
    BOOST_TEST(!entry.HasAny());
}

BOOST_AUTO_TEST_CASE(from_json_rejects_missing_prefix) {
    Json::Value json;
    json["network"] = "10.0.0.0";

    protocol::PeerPrefixRouteEntry entry;
    BOOST_TEST(!protocol::PeerPrefixRouteEntry::FromJson(entry, json));
    BOOST_TEST(!entry.HasAny());
}

BOOST_AUTO_TEST_CASE(from_json_rejects_empty_network) {
    Json::Value json;
    json["prefix"] = 24;

    protocol::PeerPrefixRouteEntry entry;
    BOOST_TEST(!protocol::PeerPrefixRouteEntry::FromJson(entry, json));
    BOOST_TEST(!entry.HasAny());

    json["network"] = "";
    BOOST_TEST(!protocol::PeerPrefixRouteEntry::FromJson(entry, json));
    BOOST_TEST(!entry.HasAny());
}
