#define BOOST_TEST_MODULE vmux_negotiation_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxRuntimeState.h>

namespace mux = ppp::app::mux;

BOOST_AUTO_TEST_CASE(old_peer_falls_back_without_changing_requested_mode) {
    const auto state = mux::NegotiateMuxRuntimeState("balance", true, false, 2);

    BOOST_TEST(state.requested_mode == "balance");
    BOOST_TEST(state.effective_mode == "compat");
    BOOST_TEST(state.receiver_ordering == "compat");
    BOOST_TEST(state.active_links == 2u);
    BOOST_TEST(state.fallback_reason == "peer_missing_flow_v2");
}

BOOST_AUTO_TEST_CASE(flow_v2_peer_keeps_requested_mode) {
    const auto state = mux::NegotiateMuxRuntimeState("flow", true, true, 1);

    BOOST_TEST(state.effective_mode == "flow");
    BOOST_TEST(state.receiver_ordering == "flow_v2");
    BOOST_TEST(state.fallback_reason.empty());
}
