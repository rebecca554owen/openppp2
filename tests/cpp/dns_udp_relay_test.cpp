#define BOOST_TEST_MODULE dns_udp_relay_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsUdpRelay.h>

namespace client_dns = ppp::app::client::dns;

namespace {

boost::asio::ip::udp::endpoint MakeEndpoint(const char* address, uint16_t port) {
    boost::system::error_code ec;
    return boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address(address, ec), port);
}

}  // namespace

BOOST_AUTO_TEST_CASE(accepts_matching_source_and_transaction_id) {
    const auto server = MakeEndpoint("1.1.1.1", 53);
    const auto received = MakeEndpoint("1.1.1.1", 53);
    const ppp::Byte query[12] = { 0x12, 0x34, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0x12, 0x34, 0x81, 0x80 };

    BOOST_TEST(client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(rejects_mismatched_source_endpoint) {
    const auto server = MakeEndpoint("1.1.1.1", 53);
    const auto received = MakeEndpoint("8.8.8.8", 53);
    const ppp::Byte query[12] = { 0x12, 0x34, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0x12, 0x34, 0x81, 0x80 };

    BOOST_TEST(!client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(rejects_mismatched_transaction_id) {
    const auto server = MakeEndpoint("9.9.9.9", 53);
    const auto received = MakeEndpoint("9.9.9.9", 53);
    const ppp::Byte query[12] = { 0x12, 0x34, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0x12, 0x35, 0x81, 0x80 };

    BOOST_TEST(!client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(rejects_wrong_source_port) {
    const auto server = MakeEndpoint("1.1.1.1", 53);
    const auto received = MakeEndpoint("1.1.1.1", 5353);
    const ppp::Byte query[12] = { 0xab, 0xcd, 0x01, 0x00 };
    const ppp::Byte response[12] = { 0xab, 0xcd, 0x81, 0x80 };

    BOOST_TEST(!client_dns::DnsUdpRelay::ShouldAcceptRelayResponse(
        received, server, query, sizeof(query), response, sizeof(response)));
}

BOOST_AUTO_TEST_CASE(spawn_rejects_invalid_context_or_session) {
    client_dns::DnsQueryContext context;
    BOOST_TEST(!client_dns::DnsUdpRelay::CanSpawn(context, nullptr));
}
