#define BOOST_TEST_MODULE vmux_ack_pending_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <vector>

#include <ppp/app/mux/MuxAckTracker.h>

namespace mux = ppp::app::mux;

/**
 * A tracker keeps its delivered set for the lifetime of a sequence space, so
 * a space that once received a frame is never empty again.  An ACK frame
 * carries a bounded number of spaces, so a session with more logical flows
 * than that bound must encode only the spaces that gained a sequence since
 * the last ACK -- and send as many frames as needed to cover them all.
 * Otherwise the same subset is reported forever and the remaining flows are
 * never acknowledged: their frames sit in the peer's retransmit buffer until
 * it declares them unrecoverable and resets the flow.
 */

BOOST_AUTO_TEST_CASE(a_fresh_tracker_has_nothing_pending) {
    mux::MuxAckTracker tracker;
    BOOST_TEST(!tracker.pending());
}

BOOST_AUTO_TEST_CASE(a_space_is_pending_after_it_gains_a_sequence) {
    mux::MuxAckTracker tracker;
    tracker.Add(7, 24);
    tracker.MarkPending();

    BOOST_TEST(tracker.pending());
    BOOST_TEST(tracker.largest() == 7u);
}

BOOST_AUTO_TEST_CASE(clearing_the_pending_flag_keeps_the_delivered_set) {
    mux::MuxAckTracker tracker;
    tracker.Add(1, 24);
    tracker.Add(2, 24);
    tracker.MarkPending();
    tracker.ClearPending();

    // The pending flag is what decides whether the space is encoded again;
    // the delivered set itself is what the acknowledgement reports.
    BOOST_TEST(!tracker.pending());
    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.largest() == 2u);
}

BOOST_AUTO_TEST_CASE(a_space_gains_pending_again_after_it_receives_more) {
    mux::MuxAckTracker tracker;
    tracker.Add(1, 24);
    tracker.MarkPending();
    tracker.ClearPending();

    tracker.Add(2, 24);
    tracker.MarkPending();

    BOOST_TEST(tracker.pending());
    BOOST_TEST(tracker.largest() == 2u);
}

BOOST_AUTO_TEST_CASE(a_reack_marks_the_space_pending_again) {
    // Answering a retransmitted frame re-marks the space: the peer is
    // waiting for exactly that answer and must not be reported only once.
    mux::MuxAckTracker tracker;
    tracker.Add(5, 24);
    tracker.MarkPending();
    tracker.ClearPending();

    // The duplicate sequence is already part of the delivered set, so adding
    // it again is idempotent, but the space becomes pending again.
    tracker.Add(5, 24);
    tracker.MarkPending();

    BOOST_TEST(tracker.pending());
    BOOST_REQUIRE_EQUAL(tracker.size(), 1u);
    BOOST_TEST(tracker.largest() == 5u);
}

BOOST_AUTO_TEST_CASE(pending_spaces_survive_beyond_the_block_cap) {
    // More spaces than one ACK frame can carry: every one of them must be
    // reported, otherwise the flows behind the cap are never acknowledged.
    const std::size_t block_cap = 8;
    std::vector<mux::MuxAckTracker> trackers(block_cap + 4);

    for (std::size_t i = 0; i < trackers.size(); i++) {
        trackers[i].Add(static_cast<std::uint32_t>(i + 1), 24);
        trackers[i].MarkPending();
    }

    std::size_t pending = 0;
    for (const mux::MuxAckTracker& tracker : trackers) {
        if (tracker.pending()) {
            pending++;
        }
    }
    BOOST_TEST(pending == trackers.size());
}
