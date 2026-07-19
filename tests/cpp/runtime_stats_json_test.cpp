#define BOOST_TEST_MODULE runtime_stats_json_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeStatsJson.h>

#include <json/json.h>

namespace runtime = ppp::app::runtime;

BOOST_AUTO_TEST_CASE(stats_json_preserves_v1_contract) {
    runtime::RuntimeStatsSample sample;
    sample.monotonic_ms = 8080123;
    sample.rx_bytes = 1932734464;
    sample.tx_bytes = 224690176;
    sample.link.quality_percent = 99.2;
    sample.link.grade = "Good";
    sample.link.error_count = 12;
    sample.link.success_count = 14803;
    sample.runtime.generation = 7;
    sample.runtime.phase = runtime::RuntimePhase::Connected;
    sample.runtime.role = "client";
    sample.runtime.mux_active_links = 4;
    sample.runtime.p2p_state = ppp::p2p::P2PState::Direct;

    Json::Value root;
    Json::Reader reader;
    const std::string encoded = runtime::SerializeRuntimeStats(sample);
    BOOST_REQUIRE(reader.parse(encoded.data(), encoded.data() + encoded.size(), root));
    BOOST_TEST(root["type"].asString() == "ppp-stats");
    BOOST_TEST(root["version"].asUInt() == 1u);
    BOOST_TEST(root["monotonic_ms"].asUInt64() == 8080123u);
    BOOST_TEST(root["rx_bytes"].asUInt64() == 1932734464u);
    BOOST_TEST(root["tx_bytes"].asUInt64() == 224690176u);
    BOOST_TEST(root["link"]["quality_percent"].asDouble() == 99.2);
    BOOST_TEST(root["link"]["grade"].asString() == "Good");
    BOOST_TEST(root["link"]["error_count"].asUInt64() == 12u);
    BOOST_TEST(root["link"]["success_count"].asUInt64() == 14803u);
    BOOST_TEST(root["runtime"]["phase"].asString() == "connected");
    BOOST_TEST(root["runtime"]["role"].asString() == "client");
    BOOST_TEST(root["runtime"]["mux_active_links"].asUInt() == 4u);
    BOOST_TEST(root["runtime"]["effective_path"].asString() == "direct");
}

BOOST_AUTO_TEST_CASE(stats_json_is_a_single_ndjson_record_without_newline) {
    const std::string json = runtime::SerializeRuntimeStats(runtime::RuntimeStatsSample());
    BOOST_TEST(!json.empty());
    BOOST_TEST(json.find('\n') == std::string::npos);
    BOOST_TEST(json.find('\r') == std::string::npos);
}
