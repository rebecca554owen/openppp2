#define BOOST_TEST_MODULE runtime_lifecycle_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/runtime/RuntimeLifecycle.h>

using ppp::app::runtime::RuntimeError;
using ppp::app::runtime::RuntimeLifecycle;
using ppp::app::runtime::RuntimePhase;
using ppp::app::runtime::RuntimeReadiness;
using ppp::app::runtime::RuntimeSnapshot;

namespace {

RuntimeReadiness FullyReady() {
    RuntimeReadiness value;
    value.session = true;
    value.adapter = true;
    value.route = true;
    value.dns = true;
    value.policy = true;
    return value;
}

}

BOOST_AUTO_TEST_CASE(generations_are_monotonic_and_begin_at_starting) {
    RuntimeLifecycle lifecycle;
    RuntimeSnapshot seed;
    seed.role = "client";

    BOOST_TEST(lifecycle.Begin(seed, 10) == 1u);
    BOOST_TEST(lifecycle.GetSnapshot().generation == 1u);
    BOOST_TEST(lifecycle.GetSnapshot().monotonic_ms == 10u);
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Starting));
    BOOST_TEST(lifecycle.GetSnapshot().role == "client");

    BOOST_TEST(lifecycle.Begin(seed, 1) == 2u);
    BOOST_TEST(lifecycle.GetSnapshot().generation == 2u);
    BOOST_TEST(lifecycle.GetSnapshot().monotonic_ms > 10u);
}

BOOST_AUTO_TEST_CASE(connected_is_promoted_only_after_all_readiness_facts) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);

    BOOST_TEST(lifecycle.Transition(generation, RuntimePhase::Connected, 2));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::ApplyingPolicy));

    BOOST_TEST(lifecycle.UpdateReadiness(generation, FullyReady(), 3));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Connected));

    RuntimeReadiness lost = FullyReady();
    lost.route = false;
    BOOST_TEST(lifecycle.UpdateReadiness(generation, lost, 4));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::ApplyingPolicy));
}

BOOST_AUTO_TEST_CASE(stale_generation_cannot_publish_or_stop_current_session) {
    RuntimeLifecycle lifecycle;
    const std::uint64_t old_generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    const std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 2);

    BOOST_TEST(!lifecycle.Transition(old_generation, RuntimePhase::Connected, 3));
    BOOST_TEST(!lifecycle.TryBeginStop(old_generation, 4));
    BOOST_TEST(lifecycle.TryBeginStop(generation, 5));
    BOOST_TEST(!lifecycle.TryBeginStop(generation, 6));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Stopping));
}

BOOST_AUTO_TEST_CASE(stop_completion_publishes_idle_or_failed) {
    RuntimeLifecycle lifecycle;
    std::uint64_t generation = lifecycle.Begin(RuntimeSnapshot(), 1);
    BOOST_REQUIRE(lifecycle.TryBeginStop(generation, 2));
    BOOST_TEST(lifecycle.CompleteStop(generation, true, RuntimeError(), 3));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Idle));

    generation = lifecycle.Begin(RuntimeSnapshot(), 4);
    BOOST_REQUIRE(lifecycle.TryBeginStop(generation, 5));
    RuntimeError error;
    error.code = 91;
    error.severity = "error";
    error.user_message_key = "CleanupFailed";
    BOOST_TEST(lifecycle.CompleteStop(generation, false, error, 6));
    BOOST_TEST(static_cast<int>(lifecycle.GetSnapshot().phase) ==
               static_cast<int>(RuntimePhase::Failed));
    BOOST_TEST(lifecycle.GetSnapshot().last_error.code == 91u);
}
