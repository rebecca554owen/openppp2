#define BOOST_TEST_MODULE dns_server_validation_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/configurations/DnsServerValidation.h>

namespace detail = ppp::configurations::detail;

BOOST_AUTO_TEST_CASE(dns_server_protocol_accepts_supported_values) {
    BOOST_TEST(detail::IsSupportedDnsProtocol(""));
    BOOST_TEST(detail::IsSupportedDnsProtocol("udp"));
    BOOST_TEST(detail::IsSupportedDnsProtocol("tcp"));
    BOOST_TEST(detail::IsSupportedDnsProtocol("doh"));
    BOOST_TEST(detail::IsSupportedDnsProtocol("dot"));
}

BOOST_AUTO_TEST_CASE(dns_server_protocol_normalizes_doq_to_dot) {
    BOOST_TEST(detail::NormalizeDnsProtocol(" DoQ ") == "dot");
    BOOST_TEST(detail::IsSupportedDnsProtocol(detail::NormalizeDnsProtocol("DoQ")));
}

BOOST_AUTO_TEST_CASE(dns_server_protocol_rejects_unknown_values) {
    BOOST_TEST(!detail::IsSupportedDnsProtocol(detail::NormalizeDnsProtocol("dohh")));
    BOOST_TEST(!detail::IsSupportedDnsProtocol(detail::NormalizeDnsProtocol("https")));
    BOOST_TEST(!detail::IsSupportedDnsProtocol(detail::NormalizeDnsProtocol("quic")));
}
