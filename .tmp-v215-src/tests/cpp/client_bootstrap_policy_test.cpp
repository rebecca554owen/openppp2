#define BOOST_TEST_MODULE client_bootstrap_policy_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/ApplicationClientBootstrap.h>

using ppp::app::NormalizeClientStaticMode;

BOOST_AUTO_TEST_CASE(static_mode_respects_proxy_only_runtime) {
    BOOST_TEST(!NormalizeClientStaticMode(false, false));
    BOOST_TEST(NormalizeClientStaticMode(true, false));
    BOOST_TEST(!NormalizeClientStaticMode(false, true));
    BOOST_TEST(!NormalizeClientStaticMode(true, true));
}
