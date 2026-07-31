#define BOOST_TEST_MODULE quic_reject_rate_limit_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/QuicRejectRateLimiter.h>

BOOST_AUTO_TEST_CASE(empty_key_for_null_frames) {
    ppp::app::client::QuicRejectRateLimiter limiter;
    BOOST_TEST(limiter.BuildKey(nullptr, nullptr).empty());
}

BOOST_AUTO_TEST_CASE(rate_limit_blocks_second_emit_within_window) {
    ppp::app::client::QuicRejectRateLimiter limiter;
    ppp::string key = "flow-a";
    const ppp::UInt64 t0 = 1000;
    BOOST_TEST(limiter.ShouldEmit(key, t0));
    BOOST_TEST(!limiter.ShouldEmit(key, t0 + 100));
    BOOST_TEST(limiter.ShouldEmit(key, t0 + 1001));
}

BOOST_AUTO_TEST_CASE(clear_resets_rate_limit_state) {
    ppp::app::client::QuicRejectRateLimiter limiter;
    const ppp::string key = "flow-b";
    const ppp::UInt64 t0 = 5000;
    BOOST_TEST(limiter.ShouldEmit(key, t0));
    BOOST_TEST(!limiter.ShouldEmit(key, t0 + 1));

    limiter.Clear();
    BOOST_TEST(limiter.ShouldEmit(key, t0 + 2));
}
