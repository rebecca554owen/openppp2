#define BOOST_TEST_MODULE vmux_backlog_watchdog_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>

#include <ppp/app/mux/MuxBacklogWatchdog.h>

namespace mux = ppp::app::mux;

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
// drained is a slow path, not a dead one.  On a congested public path the old
// rule tore down all the carriers of the session over and over, throwing away
// the congestion window and restarting from slow-start on the very same slow
// path.
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
