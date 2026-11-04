#define BOOST_TEST_MODULE vmux_retransmit_buffer_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <vector>

#include <ppp/app/mux/MuxRetransmitBuffer.h>

namespace mux = ppp::app::mux;

namespace {
    std::shared_ptr<std::uint8_t> make_frame(int value) {
        auto buffer = std::make_shared<std::uint8_t>(static_cast<std::uint8_t>(value));
        return buffer;
    }
}

BOOST_AUTO_TEST_CASE(track_retain_and_release_on_ack) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(7, 1, make_frame(1), 100, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(7, 2, make_frame(2), 100, 1010, 1 << 20));
    BOOST_TEST(rtx.size() == 2u);
    BOOST_TEST(rtx.bytes() == 200u);

    std::vector<mux::MuxAckRange> ranges = { {1, 1} };
    const std::uint64_t sample = rtx.Ack(7, 1, ranges, 1100);

    BOOST_TEST(sample == 100u); // 1100 - 1000, entry never retransmitted.
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 100u);
}

BOOST_AUTO_TEST_CASE(track_refuses_to_exceed_the_byte_cap) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 400, 1000, 500));
    BOOST_TEST(!rtx.Track(0, 2, make_frame(2), 400, 1000, 500));
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 400u);
}

BOOST_AUTO_TEST_CASE(ack_releases_below_the_cumulative_frontier) {
    mux::MuxRetransmitBuffer rtx;
    for (std::uint32_t seq = 1; seq <= 6; ++seq) {
        BOOST_TEST(rtx.Track(3, seq, make_frame((int)seq), 10, 1000, 1 << 20));
    }

    // Cumulative largest=6 releases everything at or below it: the receiver
    // delivers strictly in order, so "largest" implies full consumption of
    // 1..6.
    std::vector<mux::MuxAckRange> ranges = { {4, 6} };
    rtx.Ack(3, 6, ranges, 2000);

    BOOST_TEST(rtx.size() == 0u); // 1..6 all released by the cumulative ACK.
}

BOOST_AUTO_TEST_CASE(no_rtt_sample_from_retransmitted_frames) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));
    rtx.MarkRetransmitted(mux::MuxRetransmitBuffer::Key(0, 1), 1500);

    std::vector<mux::MuxAckRange> ranges = { {1, 1} };
    const std::uint64_t sample = rtx.Ack(0, 1, ranges, 2000);
    BOOST_TEST(sample == 0u); // Karn's rule: retransmitted frames give no sample.
}

BOOST_AUTO_TEST_CASE(collect_expired_respects_pto_and_count_bound) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, 2, make_frame(2), 10, 1500, 1 << 20));
    BOOST_TEST(rtx.Track(0, 3, make_frame(3), 10, 1900, 1 << 20));

    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(2000, 400, 32, expired); // entries idle >= 400ms: seq 1 and 2
    BOOST_REQUIRE_EQUAL(expired.size(), 2u);

    std::vector<std::uint64_t> bounded;
    rtx.CollectExpired(2000, 400, 1, bounded);
    BOOST_REQUIRE_EQUAL(bounded.size(), 1u);

    std::vector<std::uint64_t> none;
    rtx.CollectExpired(1100, 400, 32, none);
    BOOST_TEST(none.empty());
}

BOOST_AUTO_TEST_CASE(collect_expired_backs_off_with_the_attempt_count) {
    // Loss is detected by the probe timeout, and the timeout backs off
    // exponentially: a fixed window spends the whole retransmit budget inside
    // one or two round trips, which a congested link exhausts before the
    // peer's acknowledgement can even arrive.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));

    // No attempt yet: the window is the base PTO.
    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(1100, 200, 32, expired);
    BOOST_TEST(expired.empty());

    rtx.CollectExpired(1200, 200, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);

    // One attempt: the window doubled, so the same elapsed time is not
    // enough any more.
    rtx.MarkRetransmitted(mux::MuxRetransmitBuffer::Key(0, 1), 1200);
    std::vector<std::uint64_t> expired_again;
    rtx.CollectExpired(1400, 200, 32, expired_again);
    BOOST_TEST(expired_again.empty());

    rtx.CollectExpired(1600, 200, 32, expired_again);
    BOOST_REQUIRE_EQUAL(expired_again.size(), 1u);
}

BOOST_AUTO_TEST_CASE(erase_cid_drops_only_that_space) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(1, 1, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(2, 1, make_frame(2), 20, 1000, 1 << 20));

    rtx.EraseCid(1);
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 20u);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(2, 1)) != nullptr);

    rtx.Clear();
    BOOST_TEST(rtx.size() == 0u);
    BOOST_TEST(rtx.bytes() == 0u);
}

BOOST_AUTO_TEST_CASE(duplicate_track_is_a_noop) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 5, make_frame(5), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, 5, make_frame(5), 10, 2000, 1 << 20));
    BOOST_TEST(rtx.size() == 1u);
    BOOST_TEST(rtx.bytes() == 10u);
}

BOOST_AUTO_TEST_CASE(ack_membership_survives_sequence_wrap) {
    // Regression for the production rtx-exhaustion stalls: an ACK range that
    // crosses the 2^32 wrap boundary must still release tracked entries.
    mux::MuxRetransmitBuffer rtx;
    const std::uint32_t high = 0xFFFFFFFEu; // Just below the wrap.
    const std::uint32_t wrapped = 0x00000002u; // Already past it.
    BOOST_TEST(rtx.Track(0, high, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, wrapped, make_frame(2), 10, 1010, 1 << 20));
    BOOST_TEST(rtx.Track(0, 0x00000005u, make_frame(3), 10, 1020, 1 << 20));

    // SACK range [0xFFFFFFFE .. 0x00000003]: covers high and wrapped, spans the wrap.
    std::vector<mux::MuxAckRange> ranges = { {high, 0x00000003u} };
    rtx.Ack(0, 0x00000003u, ranges, 2000);

    BOOST_TEST(rtx.size() == 1u); // Only seq=5 survives.
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(0, 0x00000005u)) != nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(0, high)) == nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(0, wrapped)) == nullptr);
}

BOOST_AUTO_TEST_CASE(cumulative_release_survives_wrap) {
    // largest wrapped to a small value while older entries sit just below 2^32.
    // Cumulative semantics: largest=4 releases everything within signed reach
    // of it — both entries are "behind" largest in wrap-safe terms, so they
    // release outright. The old unsigned rule (largest > seq) misjudged this
    // case entirely and starved the entries until attempts were exhausted.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(9, 0xFFFFFFFDu, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(9, 0xFFFFFFFEu, make_frame(2), 10, 1000, 1 << 20));

    std::vector<mux::MuxAckRange> ranges = {};
    rtx.Ack(9, 0x00000004u, ranges, 2000); // largest already wrapped.

    BOOST_TEST(rtx.size() == 0u); // Both released by the cumulative ACK.
}

BOOST_AUTO_TEST_CASE(cumulative_ack_releases_entries_missing_from_ranges) {
    // Regression for the production truncation: the receiver's tracker may
    // reset (wrap heuristic) and drop older SACK ranges. The cumulative
    // largest must still release everything at or below it — the receiver
    // delivers strictly in order, so "largest" implies full consumption.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 100, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, 101, make_frame(2), 10, 1005, 1 << 20));
    BOOST_TEST(rtx.Track(0, 102, make_frame(3), 10, 1010, 1 << 20));

    // Peer tracker reset: empty ranges, only cumulative largest survives.
    std::vector<mux::MuxAckRange> ranges = {};
    rtx.Ack(0, 101, ranges, 2000);

    BOOST_TEST(rtx.size() == 1u); // Only seq=102 remains in flight.
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(0, 102)) != nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(0, 100)) == nullptr);
    BOOST_TEST(rtx.Find(mux::MuxRetransmitBuffer::Key(0, 101)) == nullptr);
}
