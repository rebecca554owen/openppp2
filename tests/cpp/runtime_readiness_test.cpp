#define BOOST_TEST_MODULE runtime_readiness_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeReadiness.h>

using ppp::app::runtime::GateConnectedPhase;
using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeReadiness;

BOOST_AUTO_TEST_CASE(connected_requires_every_readiness_fact) {
    RuntimeReadiness readiness;
    readiness.session = true;
    readiness.adapter = true;
    readiness.route = true;
    readiness.dns = true;

    BOOST_TEST(!readiness.IsFullyReady());
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Connected, readiness)) ==
               static_cast<int>(RuntimePhase::ApplyingPolicy));

    readiness.policy = true;
    BOOST_TEST(readiness.IsFullyReady());
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Connected, readiness)) ==
               static_cast<int>(RuntimePhase::Connected));
}

BOOST_AUTO_TEST_CASE(non_connected_phases_are_not_rewritten) {
    const RuntimeReadiness readiness;
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Reconnecting, readiness)) ==
               static_cast<int>(RuntimePhase::Reconnecting));
    BOOST_TEST(static_cast<int>(GateConnectedPhase(RuntimePhase::Failed, readiness)) ==
               static_cast<int>(RuntimePhase::Failed));
}
