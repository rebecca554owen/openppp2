#define BOOST_TEST_MODULE dns_wire_validation_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/dns/DnsWireValidation.h>

BOOST_AUTO_TEST_CASE(dns_wire_validation_accepts_matching_response_id) {
    ppp::Byte query[12] = {0x12, 0x34, 0x01, 0x00};
    ppp::Byte response[12] = {0x12, 0x34, 0x81, 0x80};

    BOOST_TEST(ppp::dns::detail::IsDnsResponseForQuery(query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(dns_wire_validation_rejects_wrong_id) {
    ppp::Byte query[12] = {0x12, 0x34, 0x01, 0x00};
    ppp::Byte response[12] = {0x12, 0x35, 0x81, 0x80};

    BOOST_TEST(!ppp::dns::detail::IsDnsResponseForQuery(query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(dns_wire_validation_rejects_query_packets_and_short_responses) {
    ppp::Byte query[12] = {0x12, 0x34, 0x01, 0x00};
    ppp::Byte response_query[12] = {0x12, 0x34, 0x01, 0x00};
    ppp::Byte short_response[2] = {0x12, 0x34};

    BOOST_TEST(!ppp::dns::detail::IsDnsResponseForQuery(query, sizeof(query), response_query, sizeof(response_query)));
    BOOST_TEST(!ppp::dns::detail::IsDnsResponseForQuery(query, sizeof(query), short_response, sizeof(short_response)));
}
