#define BOOST_TEST_MODULE base64_test
#include <boost/test/included/unit_test.hpp>

#include <common/base64/base64.h>

// Aim: known ASCII input encodes to the expected string and round-trips.
BOOST_AUTO_TEST_CASE(base64_roundtrip_ascii) {
    const ppp::string input = "openppp2";
    const ppp::string encoded = base64_encode(input);
    BOOST_TEST(encoded == "b3BlbnBwcDI=");
    BOOST_TEST(base64_decode(encoded) == input);
}

// Aim: non-alphabet characters in the payload throw on decode.
BOOST_AUTO_TEST_CASE(base64_rejects_invalid_characters) {
    BOOST_CHECK_THROW(base64_decode(ppp::string("not*valid!")), std::runtime_error);
}

// Aim: empty input encodes/decodes to empty (boundary case).
BOOST_AUTO_TEST_CASE(base64_boundary_empty) {
    BOOST_TEST(base64_encode(ppp::string()) == "");
    BOOST_TEST(base64_decode(ppp::string()) == "");
}
