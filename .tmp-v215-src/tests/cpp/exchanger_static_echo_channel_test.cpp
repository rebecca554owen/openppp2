#define BOOST_TEST_MODULE exchanger_static_echo_channel_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/ExchangerStaticEchoChannel.h>

namespace client = ppp::app::client;

namespace {

boost::asio::ip::address MakeAddress(const char* text) {
    boost::system::error_code ec;
    return boost::asio::ip::make_address(text, ec);
}

}  // namespace

BOOST_AUTO_TEST_CASE(valid_server_port_accepts_ephemeral_range) {
    BOOST_TEST(client::ExchangerStaticEchoChannel::IsValidServerPort(8080));
    BOOST_TEST(client::ExchangerStaticEchoChannel::IsValidServerPort(ppp::net::IPEndPoint::MaxPort));
}

BOOST_AUTO_TEST_CASE(valid_server_port_rejects_reserved_and_invalid) {
    BOOST_TEST(!client::ExchangerStaticEchoChannel::IsValidServerPort(ppp::net::IPEndPoint::MinPort));
    BOOST_TEST(!client::ExchangerStaticEchoChannel::IsValidServerPort(0));
}

BOOST_AUTO_TEST_CASE(balance_pool_accepts_ipv6_only) {
    BOOST_TEST(client::ExchangerStaticEchoChannel::AcceptsBalancePoolEndpoint(MakeAddress("2001:db8::1")));
    BOOST_TEST(!client::ExchangerStaticEchoChannel::AcceptsBalancePoolEndpoint(MakeAddress("8.8.8.8")));
}
