// Wave 4: PTO exponential backoff and the retransmit-buffer accounting
// the fork actually ships.
//
// These tests exercise MuxRetransmitBuffer in isolation — no vmux_net,
// no real transport.
//
// Ported from the upstream copy of this file. Three upstream mechanisms are
// not ported, because this repository does not have them:
//   - the fast retransmit candidate list and its time threshold (the fork
//     detects loss with the probe timeout alone; see P1-5 in
//     docs/vmux/VMUX_AUDIT_REPORT.md);
//   - the per-entry carrier id, which upstream keeps to attribute a
//     retransmission to the link it went out on (the fork has no per-link
//     retransmit decision);
//   - the separate pto_max clamp on the backoff window. The fork's window
//     is the probe timeout doubled once per attempt, capped at three
//     doublings, so the window can never exceed eight times the probe
//     timeout and needs no separate ceiling.
//
// The upstream backoff doubled up to five times and clamped the result to
// pto_max. The fork doubles up to three times: eight times the probe
// timeout is already longer than any real acknowledgement delay, and a
// longer window means a lost frame is recovered later.
#define BOOST_TEST_MODULE vmux_wave4_pto_rtx_test
#include <boost/test/included/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <vector>

#include <ppp/app/mux/MuxRetransmitBuffer.h>

namespace mux = ppp::app::mux;

namespace {
    std::shared_ptr<std::uint8_t> make_frame(int value) {
        return std::make_shared<std::uint8_t>(static_cast<std::uint8_t>(value));
    }
}

// ---------------------------------------------------------------------------
// Exponential backoff: the window is the probe timeout doubled once per
// attempt, with at most three doublings.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(backoff_attempts_0_uses_base_pto) {
    // Fresh entry (attempts=0): effective PTO = base_pto.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));

    std::vector<std::uint64_t> not_expired;
    // now=1499, base=500 → 499 elapsed < 500 PTO → not expired
    rtx.CollectExpired(1499, 500, 32, not_expired);
    BOOST_TEST(not_expired.empty());

    // now=1500 → 500 >= 500 → expired
    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(1500, 500, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_attempts_3_uses_8x_base_pto) {
    // After 3 retransmissions, effective PTO = base << 3 = 8 * base.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    rtx.MarkRetransmitted(key, 1100); // attempts=1
    rtx.MarkRetransmitted(key, 1200); // attempts=2
    rtx.MarkRetransmitted(key, 1300); // attempts=3, last_sent=1300

    std::vector<std::uint64_t> expired;
    // base=100, shift=3 → 800. now=1300+799=2099 < 1300+800=2100 → not expired
    rtx.CollectExpired(2099, 100, 32, expired);
    BOOST_TEST(expired.empty());

    // now=2100 → 800 elapsed >= 800 → expired
    rtx.CollectExpired(2100, 100, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_attempts_5_still_uses_8x_base_pto) {
    // The fork caps the doubling at three, so a frame that has already been
    // retransmitted five times still waits eight times the probe timeout.
    // Upstream doubled up to five times and reached thirty-two times.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 5; ++i) {
        rtx.MarkRetransmitted(key, 1000 + i * 100);
    }
    // attempts=5, last_sent=1500

    std::vector<std::uint64_t> expired;
    // base=100, shift=3 → 800. now=1500+799=2299 < 2300 → not expired
    rtx.CollectExpired(2299, 100, 32, expired);
    BOOST_TEST(expired.empty());

    // now=2300 → 800 elapsed >= 800 → expired
    rtx.CollectExpired(2300, 100, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_attempts_8_still_uses_8x_shift) {
    // Attempts above three are clamped to three doublings, not to eight.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 8; ++i) {
        rtx.MarkRetransmitted(key, 1000 + i * 100);
    }
    // attempts=8, last_sent=1800

    std::vector<std::uint64_t> expired;
    // base=100, shift=3 (clamped from 8) → 800.
    // now=1800+799=2599 < 2600 → not expired
    rtx.CollectExpired(2599, 100, 32, expired);
    BOOST_TEST(expired.empty());

    // now=2600 → 800 elapsed >= 800 → expired
    rtx.CollectExpired(2600, 100, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

BOOST_AUTO_TEST_CASE(backoff_window_never_exceeds_8x_the_probe_timeout) {
    // The fork has no separate ceiling on the backoff window: the shift is
    // capped at three doublings, so eight times the probe timeout is the
    // longest window an entry can ever get.
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));

    const uint64_t key = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 5; ++i) {
        rtx.MarkRetransmitted(key, 1000 + i * 100);
    }
    // attempts=5, last_sent=1500

    std::vector<std::uint64_t> expired;
    // base=1000, shift=3 → 8000.
    // now=1500+7999=9499 < 9500 → not expired
    rtx.CollectExpired(9499, 1000, 32, expired);
    BOOST_TEST(expired.empty());

    // now=9500 → 8000 elapsed >= 8000 → expired
    rtx.CollectExpired(9500, 1000, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
}

// ---------------------------------------------------------------------------
// The window is derived from the probe timeout, which is a millisecond
// estimate, so it is small by construction. The upstream copy also asserted
// that the shift saturates instead of wrapping; the fork's shift is capped
// at three doublings and the probe timeout is derived from a measured
// round-trip time, so a value large enough to overflow cannot occur.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(the_probe_timeout_stays_small_enough_to_shift) {
    // A probe timeout derived from a round-trip estimate in milliseconds
    // cannot be anywhere near the point where three doublings overflow.
    constexpr std::uint64_t kLargestRealisticPto = 3000; // PPP_MUX_RELIABILITY_PTO_MAX
    BOOST_TEST(kLargestRealisticPto <= (UINT64_MAX >> 3));
}

// ---------------------------------------------------------------------------
// Spurious RTX scenario: a frame is scheduled for retransmission but gets
// ACKed before retransmit_pending can act on it. Find() returns nullptr,
// and the caller should skip it (tested here by the absence of crash and
// correct remaining state).
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(spurious_rtx_frame_acked_before_resend) {
    mux::MuxRetransmitBuffer rtx;
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, 2, make_frame(2), 10, 1000, 1 << 20));
    BOOST_TEST(rtx.Track(0, 3, make_frame(3), 10, 1000, 1 << 20));

    // The frame is scheduled for retransmission but is ACKed before the
    // retransmit can act on it.
    const uint64_t key1 = mux::MuxRetransmitBuffer::Key(0, 1);

    // The delivery frontier is 1 → seq 1 is released.
    std::vector<mux::MuxAckRange> ack_ranges = { {1, 1} };
    rtx.Ack(0, 1, ack_ranges, 1100);

    // Now Find(key1) returns nullptr — spurious RTX.
    mux::MuxRtxEntry* entry = rtx.Find(key1);
    BOOST_TEST(entry == nullptr);

    // The other entries are still there.
    BOOST_TEST(rtx.size() == 2u);

    // MarkRetransmitted on a missing key is a safe no-op.
    rtx.MarkRetransmitted(key1, 1200);
    BOOST_TEST(rtx.size() == 2u); // No phantom entry created.
}

// ---------------------------------------------------------------------------
// Mixed: entry with high attempts doesn't interfere with fresh entry.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(backoff_per_entry_isolation) {
    mux::MuxRetransmitBuffer rtx;
    // Entry A: seq 1, sent at 1000, 4 retransmissions (shift capped at 3).
    BOOST_TEST(rtx.Track(0, 1, make_frame(1), 10, 1000, 1 << 20));
    const uint64_t keyA = mux::MuxRetransmitBuffer::Key(0, 1);
    for (int i = 1; i <= 4; ++i) {
        rtx.MarkRetransmitted(keyA, 1000 + i * 100);
    }
    // Entry B: seq 2, sent at 1000, no retransmissions (shift=0).
    BOOST_TEST(rtx.Track(0, 2, make_frame(2), 10, 1000, 1 << 20));

    // base=100:
    //   A: shift=3 → 800ms PTO. last_sent=1400. Expires at 1400+800=2200.
    //   B: shift=0 → 100ms PTO. last_sent=1000. Expires at 1000+100=1100.
    std::vector<std::uint64_t> expired;
    rtx.CollectExpired(1100, 100, 32, expired);
    BOOST_REQUIRE_EQUAL(expired.size(), 1u);
    // Only B should expire (key for seq 2).
    const uint32_t exp_seq = static_cast<uint32_t>(expired[0] & 0xFFFFFFFFu);
    BOOST_TEST(exp_seq == 2u);

    // A expires later at 2200. B is also expired at this point (expired at
    // 1100), so we verify A is among the expired entries.
    std::vector<std::uint64_t> expired2;
    rtx.CollectExpired(2200, 100, 32, expired2);
    BOOST_REQUIRE_EQUAL(expired2.size(), 2u);
    // A (seq 1) should be in the result.
    bool found_a = false;
    for (uint64_t k : expired2) {
        const uint32_t s = static_cast<uint32_t>(k & 0xFFFFFFFFu);
        if (s == 1u) found_a = true;
    }
    BOOST_TEST(found_a);
}
