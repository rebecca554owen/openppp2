#define BOOST_TEST_MODULE mux_runtime_counters_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/mux/MuxRuntimeCounters.h>
#include <ppp/app/runtime/RuntimeStatsJson.h>

#include <json/json.h>

#include <string>
#include <vector>

namespace mux = ppp::app::mux;
namespace runtime = ppp::app::runtime;

namespace {

/// The JSON key of every counter is the telemetry counter it mirrors, so the
/// stats NDJSON and the telemetry export speak the same vocabulary. A rename
/// on either side must fail this list.
const std::vector<std::string>& ExpectedCounterKeys() {
    static const std::vector<std::string> keys = {
        "mux.link.send",
        "mux.link.recv",
        "mux.rx.flow.unknown_cid",
        "mux.rx.flow.refused",
        "mux.rx.flow.reack",
        "mux.rx.closed_flow.drop",
        "mux.rx.closed_flow.reack",
        "mux.rx.flow.reset",
        "mux.rx.compat.gap_timeout",
        "mux.rx.flow.max_open",
        "mux.tx.flow.after_fin",
        "mux.rtx.pto",
        "mux.rtx.exhausted",
        "mux.rtx.exhausted.connection",
        "mux.rx.flow.refuse_post_failed",
        "mux.rx.syn_ok.refused",
        "mux.rx.syn_ok.refused.no_socket",
        "mux.tx.flow.overflow",
        "mux.tx.ctrl.cap",
        "mux.tx.ctrl.cap.reject",
        "mux.ack.suppressed",
    };
    return keys;
}

}  // namespace

BOOST_AUTO_TEST_CASE(registry_accumulates_every_counter) {
    mux::MuxRuntimeCounterRegistry::Reset();

    mux::MuxRuntimeCounterRegistry::AddTxFrames(3);
    mux::MuxRuntimeCounterRegistry::AddRxFrames(4);
    mux::MuxRuntimeCounterRegistry::AddRxFlowUnknownCid();
    mux::MuxRuntimeCounterRegistry::AddRxFlowRefused();
    mux::MuxRuntimeCounterRegistry::AddRxFlowReack();
    mux::MuxRuntimeCounterRegistry::AddRxClosedFlowDrop();
    mux::MuxRuntimeCounterRegistry::AddRxClosedFlowReack();
    mux::MuxRuntimeCounterRegistry::AddRxFlowReset();
    mux::MuxRuntimeCounterRegistry::AddRxGapTimeout();
    mux::MuxRuntimeCounterRegistry::AddRxFlowMaxOpen();
    mux::MuxRuntimeCounterRegistry::AddTxFlowAfterFin();
    mux::MuxRuntimeCounterRegistry::AddTxRtxPto();
    mux::MuxRuntimeCounterRegistry::AddTxRtxExhausted();
    mux::MuxRuntimeCounterRegistry::AddTxRtxExhaustedConnection(2);
    mux::MuxRuntimeCounterRegistry::AddRxFlowRefusePostFailed();
    mux::MuxRuntimeCounterRegistry::AddRxSynOkRefused();
    mux::MuxRuntimeCounterRegistry::AddRxSynOkRefusedNoSocket(3);
    mux::MuxRuntimeCounterRegistry::AddTxFlowOverflow();
    mux::MuxRuntimeCounterRegistry::AddTxCtrlCap(2);
    mux::MuxRuntimeCounterRegistry::AddTxCtrlCapRejected();
    mux::MuxRuntimeCounterRegistry::AddTxAckSuppressed(4);

    const mux::MuxRuntimeCounters snap = mux::MuxRuntimeCounterRegistry::GetSnapshot();
    BOOST_TEST(snap.tx_frames == 3u);
    BOOST_TEST(snap.rx_frames == 4u);
    BOOST_TEST(snap.rx_flow_unknown_cid == 1u);
    BOOST_TEST(snap.rx_flow_refused == 1u);
    BOOST_TEST(snap.rx_flow_reack == 1u);
    BOOST_TEST(snap.rx_closed_flow_drop == 1u);
    BOOST_TEST(snap.rx_closed_flow_reack == 1u);
    BOOST_TEST(snap.rx_flow_reset == 1u);
    BOOST_TEST(snap.rx_gap_timeout == 1u);
    BOOST_TEST(snap.rx_flow_max_open == 1u);
    BOOST_TEST(snap.tx_flow_after_fin == 1u);
    BOOST_TEST(snap.tx_rtx_pto == 1u);
    BOOST_TEST(snap.tx_rtx_exhausted == 1u);
    BOOST_TEST(snap.tx_rtx_exhausted_connection == 2u);
    BOOST_TEST(snap.rx_flow_refuse_post_failed == 1u);
    BOOST_TEST(snap.rx_syn_ok_refused == 1u);
    BOOST_TEST(snap.rx_syn_ok_refused_no_socket == 3u);
    BOOST_TEST(snap.tx_flow_overflow == 1u);
    BOOST_TEST(snap.tx_ctrl_cap == 2u);
    BOOST_TEST(snap.tx_ctrl_cap_rejected == 1u);
    BOOST_TEST(snap.tx_ack_suppressed == 4u);

    mux::MuxRuntimeCounterRegistry::Reset();
    const mux::MuxRuntimeCounters zero = mux::MuxRuntimeCounterRegistry::GetSnapshot();
    BOOST_TEST(zero.tx_frames == 0u);
    BOOST_TEST(zero.tx_rtx_exhausted_connection == 0u);
    BOOST_TEST(zero.rx_flow_refuse_post_failed == 0u);
    BOOST_TEST(zero.rx_syn_ok_refused == 0u);
    BOOST_TEST(zero.rx_syn_ok_refused_no_socket == 0u);
}

BOOST_AUTO_TEST_CASE(stats_json_exposes_the_mux_counters) {
    runtime::RuntimeStatsSample sample;
    sample.mux_counters.rx_flow_unknown_cid = 7;
    sample.mux_counters.rx_flow_refused = 5;
    sample.mux_counters.tx_rtx_exhausted = 3;
    sample.mux_counters.tx_flow_after_fin = 11;

    Json::Value root;
    Json::Reader reader;
    const std::string encoded = runtime::SerializeRuntimeStats(sample);
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_REQUIRE(root["mux_counters"].isObject());
    BOOST_TEST(root["mux_counters"]["mux.rx.flow.unknown_cid"].asUInt64() == 7u);
    BOOST_TEST(root["mux_counters"]["mux.rx.flow.refused"].asUInt64() == 5u);
    BOOST_TEST(root["mux_counters"]["mux.rtx.exhausted"].asUInt64() == 3u);
    BOOST_TEST(root["mux_counters"]["mux.tx.flow.after_fin"].asUInt64() == 11u);
}

BOOST_AUTO_TEST_CASE(stats_json_always_emits_every_counter_key) {
    Json::Value root;
    Json::Reader reader;
    const std::string encoded = runtime::SerializeRuntimeStats(runtime::RuntimeStatsSample());
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_REQUIRE(root["mux_counters"].isObject());

    Json::Value counters = root["mux_counters"];
    for (const std::string& key : ExpectedCounterKeys()) {
        BOOST_TEST(counters.isMember(key.c_str()));
        BOOST_TEST(counters[key.c_str()].isUInt64());
    }
    // The counter object must not drift away from the telemetry vocabulary.
    BOOST_TEST(counters.getMemberNames().size() == ExpectedCounterKeys().size());
}

BOOST_AUTO_TEST_CASE(stats_json_keeps_the_v1_contract_intact) {
    Json::Value root;
    Json::Reader reader;
    const std::string encoded = runtime::SerializeRuntimeStats(runtime::RuntimeStatsSample());
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_TEST(root["type"].asString() == "ppp-stats");
    BOOST_TEST(root["version"].asUInt() == 1u);
    BOOST_REQUIRE(root["link"].isObject());
    BOOST_REQUIRE(root["runtime"].isObject());
    BOOST_TEST(encoded.find('\n') == std::string::npos);
}
