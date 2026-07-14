#define BOOST_TEST_MODULE tui_runtime_adapter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/tui/TuiRuntimeAdapter.h>

using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeSnapshot;
using ppp::app::tui::BuildStatusLines;
using ppp::app::tui::ContainsLine;

BOOST_AUTO_TEST_CASE(connected_snapshot_renders_effective_mux_state) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Connected;
    snapshot.requested_mux_mode = "balance";
    snapshot.effective_mux_mode = "compat";
    snapshot.mux_fallback_reason = "peer_missing_flow_v2";

    const auto lines = BuildStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Connected"));
    BOOST_TEST(ContainsLine(lines, "effective mux=compat"));
    BOOST_TEST(ContainsLine(lines, "requested mux=balance"));
    BOOST_TEST(ContainsLine(lines, "fallback=peer_missing_flow_v2"));
}

BOOST_AUTO_TEST_CASE(stopping_is_not_rendered_as_idle) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Stopping;
    const auto lines = BuildStatusLines(snapshot);

    BOOST_TEST(ContainsLine(lines, "Stopping"));
    BOOST_TEST(!ContainsLine(lines, "Idle"));
    BOOST_TEST(!ContainsLine(lines, "Disconnected"));
}

BOOST_AUTO_TEST_CASE(failed_snapshot_renders_error_triplet) {
    RuntimeSnapshot snapshot;
    snapshot.phase = RuntimePhase::Failed;
    snapshot.last_error.code = 42;
    snapshot.last_error.severity = "error";
    snapshot.last_error.user_message_key = "LinkFailed";
    snapshot.last_error.diagnostic_detail = "handshake timeout";

    const auto lines = BuildStatusLines(snapshot);
    BOOST_TEST(ContainsLine(lines, "Failed"));
    BOOST_TEST(ContainsLine(lines, "code=42"));
    BOOST_TEST(ContainsLine(lines, "severity=error"));
    BOOST_TEST(ContainsLine(lines, "key=LinkFailed"));
    BOOST_TEST(ContainsLine(lines, "handshake timeout"));
}
