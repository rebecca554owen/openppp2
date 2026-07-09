#define BOOST_TEST_MODULE dns_fake_ip_response_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsFakeIpResponse.h>

namespace client_dns = ppp::app::client::dns;

namespace {

// Query: example.com A IN
const unsigned char kExampleQuery[] = {
    0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01, 0x00, 0x01
};

}  // namespace

BOOST_AUTO_TEST_CASE(should_skip_reverse_and_local_names) {
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("1.2.3.4.in-addr.arpa"));
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("localhost"));
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("printer.local"));
    BOOST_TEST(!client_dns::DnsFakeIpResponse::ShouldUseFakeIp("nas.lan"));
    BOOST_TEST(client_dns::DnsFakeIpResponse::ShouldUseFakeIp("example.com"));
}

BOOST_AUTO_TEST_CASE(build_a_record_response) {
    const ppp::vector<ppp::Byte> response = client_dns::DnsFakeIpResponse::BuildARecordResponse(
        kExampleQuery, static_cast<int>(sizeof(kExampleQuery)), 0xC6120005u);
    BOOST_TEST(!response.empty());
    BOOST_TEST((response[2] & 0x80) != 0);
    BOOST_TEST(response[response.size() - 4] == 0xC6);
    BOOST_TEST(response[response.size() - 3] == 0x12);
    BOOST_TEST(response[response.size() - 2] == 0x00);
    BOOST_TEST(response[response.size() - 1] == 0x05);
}

BOOST_AUTO_TEST_CASE(parse_first_a_record_network) {
    const ppp::vector<ppp::Byte> response = client_dns::DnsFakeIpResponse::BuildARecordResponse(
        kExampleQuery, static_cast<int>(sizeof(kExampleQuery)), 0xC6120005u);
    const uint32_t parsed = client_dns::DnsFakeIpResponse::ParseFirstARecordNetwork(
        response.data(), static_cast<int>(response.size()));
    BOOST_TEST(parsed == 0xC6120005u);
}
