#define BOOST_TEST_MODULE vmux_backlog_watchdog_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <vector>

#include <ppp/app/mux/MuxBacklogWatchdog.h>
#include <ppp/app/mux/MuxRetransmitBuffer.h>
#include <ppp/stdafx.h>

namespace mux = ppp::app::mux;

namespace {
    std::shared_ptr<std::uint8_t> make_frame(int value) {
        return std::make_shared<std::uint8_t>(static_cast<std::uint8_t>(value));
    }
}

// ---------------------------------------------------------------------------
// D11 stall watchdog
// ---------------------------------------------------------------------------

// A queue that never reaches the high-water mark cannot wedge the session.
BOOST_AUTO_TEST_CASE(queue_below_the_high_water_never_wedges) {
    mux::MuxBacklogWatchdog watchdog;
    for (std::uint64_t now = 1000; now < 60000; now += 1000) {
        BOOST_TEST(!watchdog.Observe(10, 4096, now, 8000, 0));
    }
}

// A genuinely stuck queue (depth frozen, no carrier write completed) must
// still be caught, otherwise a wedged session would hang forever.
BOOST_AUTO_TEST_CASE(stuck_queue_wedges_after_the_stall_window) {
    mux::MuxBacklogWatchdog watchdog;
    BOOST_TEST(!watchdog.Observe(4097, 4096, 1000, 8000, 0));  // arm
    BOOST_TEST(!watchdog.Observe(4097, 4096, 5000, 8000, 0));  // inside the window
    BOOST_TEST(watchdog.Observe(4097, 4096, 9000, 8000, 0));   // 8000ms elapsed -> wedged
    BOOST_TEST(watchdog.baseline_tick() == 0u);                // disarmed after firing
}

// The regression this watchdog exists for: a FULL queue that is still being
// drained is a slow path, not a dead one. On a congested public path the old
// rule tore down all eleven carriers of the session roughly every twelve
// minutes, throwing away the congestion window and restarting from
// slow-start on the very same slow path.
BOOST_AUTO_TEST_CASE(a_draining_queue_is_slow_not_wedged) {
    mux::MuxBacklogWatchdog watchdog;
    std::uint64_t now = 1000;
    std::size_t depth = 4097;
    BOOST_TEST(!watchdog.Observe(depth, 4096, now, 8000, 0));
    for (int i = 0; i < 20; ++i) {
        now += 1000;
        depth -= 1;  // the carrier keeps draining
        BOOST_TEST(!watchdog.Observe(depth, 4096, now, 8000, now));
    }
}

// A frozen depth is not enough on its own: if a carrier write completed
// recently, the send side is alive.
BOOST_AUTO_TEST_CASE(recent_drain_keeps_a_full_queue_alive) {
    mux::MuxBacklogWatchdog watchdog;
    BOOST_TEST(!watchdog.Observe(4097, 4096, 1000, 8000, 0));
    BOOST_TEST(!watchdog.Observe(4097, 4096, 9000, 8000, 8000));    // drained 1s ago
    BOOST_TEST(!watchdog.Observe(4097, 4096, 17000, 8000, 16000));  // drained 1s ago
}

// Progress re-baselines the window: the stall clock restarts from the moment
// the queue was last seen shrinking.
BOOST_AUTO_TEST_CASE(a_shrink_rebaselines_the_stall_window) {
    mux::MuxBacklogWatchdog watchdog;
    BOOST_TEST(!watchdog.Observe(4097, 4096, 1000, 8000, 0));
    BOOST_TEST(!watchdog.Observe(4096, 4096, 9000, 8000, 9000));  // shrank -> re-baseline
    BOOST_TEST(watchdog.baseline_tick() == 9000u);
    BOOST_TEST(watchdog.baseline_depth() == 4096u);
    BOOST_TEST(!watchdog.Observe(4096, 4096, 16000, 8000, 0));    // 7s since the re-baseline
    BOOST_TEST(watchdog.Observe(4096, 4096, 17000, 8000, 0));     // 8s since the re-baseline
}

// ---------------------------------------------------------------------------
// Retransmit budget: the age floor
// ---------------------------------------------------------------------------

// A frame that spent its attempt budget is only failed once it ALSO aged
// past the fail deadline: the attempt budget is derived from the probe
// timeout, which on a fast path is a few hundred milliseconds, while the
// carrier underneath may need tens of seconds of RTO backoff to deliver.
BOOST_AUTO_TEST_CASE(exhausted_frames_need_both_the_budget_and_the_age) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(7, 1, make_frame(1), 100, 1000, 1 << 20));
    const std::uint64_t key = mux::MuxRetransmitBuffer::Key(7, 1);

    std::vector<std::uint64_t> exhausted;
    rtx.CollectExhausted(2000, 8, 30000, exhausted);
    BOOST_TEST(exhausted.empty());  // budget not spent yet

    for (int i = 0; i < 8; ++i) {
        rtx.MarkRetransmitted(key, 1500);  // the attempt budget is now spent
    }
    rtx.CollectExhausted(2000, 8, 30000, exhausted);
    BOOST_TEST(exhausted.empty());  // budget spent, but the frame is young

    exhausted.clear();
    rtx.CollectExhausted(40000, 8, 30000, exhausted);
    BOOST_TEST(exhausted.size() == 1u);
    BOOST_TEST(exhausted[0] == key);
}

// Once the budget is spent the re-send cadence relaxes, so the grace window
// does not flood a congested carrier with retransmissions.
BOOST_AUTO_TEST_CASE(a_spent_budget_frame_is_resent_on_the_relaxed_cadence) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));
    const std::uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 0; i < 8; ++i) {
        rtx.MarkRetransmitted(key, 1200);
    }

    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(3000, 200, 32, expired, 8, 5000);
    BOOST_TEST(expired.empty());  // 1800ms since the last send, below the 5s cadence

    expired.clear();
    rtx.CollectExpired(6300, 200, 32, expired, 8, 5000);
    BOOST_TEST(expired.size() == 1u);
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

// The receiver must outlast the sender's fail deadline. Otherwise the
// receiver would evict a flow the sender is still legitimately retrying and
// the two sides would race; the sender failing its own flow is the clean
// outcome, and a gap timeout must stay the exception, not the rule.
BOOST_AUTO_TEST_CASE(the_gap_timeout_ceiling_outlasts_the_sender_budget) {
    const std::uint64_t grace = (std::uint64_t)PPP_MUX_RELIABILITY_RTX_FAIL_GRACE_MS;
    const std::uint64_t margin = (std::uint64_t)PPP_MUX_RELIABILITY_RTX_FAIL_MARGIN_MS;
    const std::uint64_t ceiling = (std::uint64_t)PPP_MUX_RELIABILITY_GAP_TIMEOUT_MAX;
    const std::uint64_t worst_window = mux::MuxRetransmitBuffer::TotalBackoffWindow(
        (std::uint64_t)PPP_MUX_RELIABILITY_PTO_MAX,
        (std::uint32_t)PPP_MUX_RELIABILITY_RTX_MAX_ATTEMPTS);

    BOOST_TEST(ceiling >= grace + margin);
    BOOST_TEST(ceiling >= worst_window + margin);
}

// The grace floor has to cover the whole backoff window of the attempt
// budget, otherwise it never takes effect on a fast path (where the budget
// is spent in a couple of seconds).
BOOST_AUTO_TEST_CASE(the_grace_floor_covers_the_fast_path_backoff_window) {
    const std::uint64_t grace = (std::uint64_t)PPP_MUX_RELIABILITY_RTX_FAIL_GRACE_MS;
    const std::uint64_t fast_window = mux::MuxRetransmitBuffer::TotalBackoffWindow(
        (std::uint64_t)PPP_MUX_RELIABILITY_PTO_MIN,
        (std::uint32_t)PPP_MUX_RELIABILITY_RTX_MAX_ATTEMPTS);
    BOOST_TEST(grace >= fast_window);
}
