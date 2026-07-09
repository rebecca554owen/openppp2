#define BOOST_TEST_MODULE client_bypass_route_loader_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/ClientBypassRouteLoader.h>

namespace client = ppp::app::client;

namespace {

boost::asio::ip::address MakeAddress(const char* text) {
    boost::system::error_code ec;
    return boost::asio::ip::make_address(text, ec);
}

}  // namespace

BOOST_AUTO_TEST_CASE(rejects_non_ipv4_before_tap_lookup) {
    BOOST_TEST(client::ClientBypassRouteLoader::RejectsBypassBeforeTapLookup(MakeAddress("2001:db8::1")));
}

BOOST_AUTO_TEST_CASE(rejects_unspecified_before_tap_lookup) {
    BOOST_TEST(client::ClientBypassRouteLoader::RejectsBypassBeforeTapLookup(MakeAddress("0.0.0.0")));
}

BOOST_AUTO_TEST_CASE(rejects_multicast_before_tap_lookup) {
    BOOST_TEST(client::ClientBypassRouteLoader::RejectsBypassBeforeTapLookup(MakeAddress("224.0.0.1")));
}

BOOST_AUTO_TEST_CASE(accepts_public_ipv4_for_tap_lookup) {
    BOOST_TEST(!client::ClientBypassRouteLoader::RejectsBypassBeforeTapLookup(MakeAddress("8.8.8.8")));
}

#if !defined(_ANDROID) && !defined(_IPHONE)
BOOST_AUTO_TEST_CASE(route_list_path_empty_check) {
    BOOST_TEST(client::ClientBypassRouteLoader::IsRouteListPathEmpty(""));
    BOOST_TEST(!client::ClientBypassRouteLoader::IsRouteListPathEmpty("routes.txt"));
}
#endif
