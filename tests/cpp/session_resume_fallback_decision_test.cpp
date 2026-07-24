#define BOOST_TEST_MODULE session_resume_fallback_decision_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/server/SessionResumeFallbackDecision.h>

namespace server = ppp::app::server;

BOOST_AUTO_TEST_CASE(only_lookup_miss_starts_fresh_session) {
    BOOST_TEST(static_cast<int>(server::DecideSessionResumeFallback(
        server::SessionResumeFallbackReason::LookupMiss)) ==
        static_cast<int>(server::SessionResumeFallbackDecision::Fresh));
}

BOOST_AUTO_TEST_CASE(existing_session_failures_reject_candidate_carrier) {
    BOOST_TEST(static_cast<int>(server::DecideSessionResumeFallback(
        server::SessionResumeFallbackReason::BeginRejected)) ==
        static_cast<int>(server::SessionResumeFallbackDecision::Reject));
    BOOST_TEST(static_cast<int>(server::DecideSessionResumeFallback(
        server::SessionResumeFallbackReason::OtherResumeFailure)) ==
        static_cast<int>(server::SessionResumeFallbackDecision::Reject));
}
