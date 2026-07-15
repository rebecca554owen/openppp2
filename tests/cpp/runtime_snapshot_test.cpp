#define BOOST_TEST_MODULE runtime_snapshot_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeSnapshotJson.h>

#include <fstream>
#include <iterator>
#include <string>

#ifndef OPENPPP2_RUNTIME_FIXTURE_DIR
#define OPENPPP2_RUNTIME_FIXTURE_DIR "tests/contracts/runtime-snapshot"
#endif

namespace runtime = ppp::app::runtime;

namespace {

std::string ReadFixture(const char* name) {
    const std::string path = std::string(OPENPPP2_RUNTIME_FIXTURE_DIR) + "/" + name;
    std::ifstream input(path, std::ios::binary);
    BOOST_REQUIRE_MESSAGE(input.good(), "unable to open runtime fixture: " << path);
    return std::string(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>());
}

}

BOOST_AUTO_TEST_CASE(runtime_phase_round_trip) {
    BOOST_TEST(std::string(runtime::ToString(runtime::RuntimePhase::Connected)) == "connected");
    BOOST_TEST(
        static_cast<int>(runtime::ParseRuntimePhase("reconnecting")) ==
        static_cast<int>(runtime::RuntimePhase::Reconnecting));
}

BOOST_AUTO_TEST_CASE(default_snapshot_is_idle_and_versioned) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(snapshot.schema_version == 1u);
    BOOST_TEST(snapshot.generation == 0u);
    BOOST_TEST(static_cast<int>(snapshot.phase) == static_cast<int>(runtime::RuntimePhase::Idle));
}

BOOST_AUTO_TEST_CASE(snapshot_json_preserves_generation_phase_and_error) {
    runtime::RuntimeSnapshot source;
    source.generation = 7;
    source.phase = runtime::RuntimePhase::Connected;
    source.requested_mux_mode = "balance";
    source.effective_mux_mode = "compat";
    source.mux_receiver_ordering = "compat";
    source.mux_active_links = 2;
    source.last_error.code = 42;
    source.last_error.retryable = true;

    const std::string json = runtime::SerializeRuntimeSnapshot(source);
    runtime::RuntimeSnapshot decoded;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(json, decoded));
    BOOST_TEST(decoded.generation == 7u);
    BOOST_TEST(static_cast<int>(decoded.phase) == static_cast<int>(runtime::RuntimePhase::Connected));
    BOOST_TEST(decoded.requested_mux_mode == "balance");
    BOOST_TEST(decoded.effective_mux_mode == "compat");
    BOOST_TEST(decoded.mux_receiver_ordering == "compat");
    BOOST_TEST(decoded.mux_active_links == 2u);
    BOOST_TEST(decoded.last_error.code == 42u);
    BOOST_TEST(decoded.last_error.retryable);
}

BOOST_AUTO_TEST_CASE(valid_contract_fixtures_parse) {
    const char* fixtures[] = {
        "idle.json",
        "connected.json",
        "reconnecting.json",
        "failed.json",
    };

    for (const char* fixture : fixtures) {
        runtime::RuntimeSnapshot snapshot;
        BOOST_TEST_CONTEXT(fixture) {
            BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture(fixture), snapshot));
            BOOST_TEST(snapshot.schema_version == runtime::RuntimeSnapshot::SchemaVersion);
        }
    }
}

BOOST_AUTO_TEST_CASE(unsupported_schema_is_rejected) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(ReadFixture("unsupported-schema.json"), snapshot));
}

BOOST_AUTO_TEST_CASE(parsed_snapshot_records_schema_version) {
    runtime::RuntimeSnapshot snapshot;
    snapshot.schema_version = 0;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture("idle.json"), snapshot));
    BOOST_TEST(snapshot.schema_version == 1u);
}

BOOST_AUTO_TEST_CASE(unknown_optional_fields_are_ignored) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_REQUIRE(runtime::ParseRuntimeSnapshot(ReadFixture("connected.json"), snapshot));
    BOOST_TEST(snapshot.generation == 7u);
    BOOST_TEST(snapshot.effective_mux_mode == "flow");
}

BOOST_AUTO_TEST_CASE(unknown_phase_is_rejected) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"generation\":1,\"monotonic_ms\":1,\"phase\":\"teleporting\"}",
        snapshot));
}

BOOST_AUTO_TEST_CASE(generation_and_monotonic_time_are_required) {
    runtime::RuntimeSnapshot snapshot;
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"monotonic_ms\":1,\"phase\":\"idle\"}",
        snapshot));
    BOOST_TEST(!runtime::ParseRuntimeSnapshot(
        "{\"schema_version\":1,\"generation\":1,\"phase\":\"idle\"}",
        snapshot));
}
