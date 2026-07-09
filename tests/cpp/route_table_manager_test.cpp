#define BOOST_TEST_MODULE route_table_manager_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/RouteTableManager.h>

namespace client = ppp::app::client;

#if !defined(_ANDROID) && !defined(_IPHONE)

BOOST_AUTO_TEST_CASE(defer_when_route_state_not_ready) {
    BOOST_TEST(client::RouteTableManager::ShouldDeferHostedRouteApply(false, true));
}

BOOST_AUTO_TEST_CASE(defer_when_exchanger_not_established) {
    BOOST_TEST(client::RouteTableManager::ShouldDeferHostedRouteApply(true, false));
}

BOOST_AUTO_TEST_CASE(defer_when_both_preconditions_missing) {
    BOOST_TEST(client::RouteTableManager::ShouldDeferHostedRouteApply(false, false));
}

BOOST_AUTO_TEST_CASE(apply_when_route_state_ready_and_exchanger_established) {
    BOOST_TEST(!client::RouteTableManager::ShouldDeferHostedRouteApply(true, true));
}

#endif
