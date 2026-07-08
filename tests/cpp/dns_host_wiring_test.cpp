#define BOOST_TEST_MODULE dns_host_wiring_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <cstring>

#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/packet/IPFrame.h>

#include "support/dns_host_wiring_switcher_stub.h"
#include "support/dns_host_wiring_test_owner.h"

namespace client = ppp::app::client;
namespace client_dns = client::dns;
namespace wiring_test = client::dns::test;

namespace {

boost::asio::ip::udp::endpoint MakeEndpoint(const char* address, uint16_t port) {
    boost::system::error_code ec;
    return boost::asio::ip::udp::endpoint(
        boost::asio::ip::make_address(address, ec), port);
}

std::shared_ptr<ppp::configurations::AppConfiguration> MakeConfiguration(bool enable_cache) {
    auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
    configuration->udp.dns.cache = enable_cache;
    return configuration;
}

std::shared_ptr<client::VEthernetNetworkSwitcher> MakeSwitcher(bool enable_cache, bool inject_ok) {
    wiring_test::SetDnsHostInjectOk(inject_ok);
    auto context = std::make_shared<boost::asio::io_context>();
    auto configuration = MakeConfiguration(enable_cache);
    return std::make_shared<client::VEthernetNetworkSwitcher>(context, false, false, false, configuration);
}

std::shared_ptr<ppp::net::packet::BufferSegment> MakeQuerySegment(const char* payload) {
    auto segment = ppp::make_shared_object<ppp::net::packet::BufferSegment>();
    const std::size_t length = std::strlen(payload);
    segment->Buffer = std::shared_ptr<ppp::Byte>(new ppp::Byte[length], std::default_delete<ppp::Byte[]>());
    std::memcpy(segment->Buffer.get(), payload, length);
    segment->Length = static_cast<int>(length);
    return segment;
}

}  // namespace

BOOST_AUTO_TEST_CASE(make_dns_host_ports_sets_valid_callbacks_without_exchanger) {
    const auto switcher = MakeSwitcher(false, true);
    const client_dns::DnsHostPorts ports = client_dns::MakeDnsHostPorts(switcher, nullptr);

    BOOST_TEST(ports.IsValid());
    BOOST_TEST(static_cast<bool>(ports.datagram_output));
    BOOST_TEST(static_cast<bool>(ports.get_tap));
    BOOST_TEST(static_cast<bool>(ports.get_configuration));
    BOOST_TEST(static_cast<bool>(ports.get_buffer_allocator));
    BOOST_TEST(static_cast<bool>(ports.emplace_timeout));
    BOOST_TEST(static_cast<bool>(ports.delete_timeout));
    BOOST_TEST(static_cast<bool>(ports.handle_resolver_response));
#if defined(_LINUX)
    BOOST_TEST(static_cast<bool>(ports.get_protector_network));
#endif
}

BOOST_AUTO_TEST_CASE(same_exchanger_returns_cached_ports_reference) {
    const auto switcher = MakeSwitcher(false, true);
    wiring_test::DnsHostWiringTestOwner owner(switcher);

    const client_dns::DnsHostPorts& first = owner.DnsHostPortsFor(nullptr);
    const client_dns::DnsHostPorts& second = owner.DnsHostPortsFor(nullptr);

    BOOST_TEST(&first == &second);
}

BOOST_AUTO_TEST_CASE(invalidate_dns_host_ports_rebuilds_cache) {
    const auto switcher = MakeSwitcher(false, true);
    wiring_test::DnsHostWiringTestOwner owner(switcher);

    const client_dns::DnsHostPorts& cached = owner.DnsHostPortsFor(nullptr);
    const client_dns::DnsHostPorts& cached_again = owner.DnsHostPortsFor(nullptr);
    BOOST_TEST(&cached == &cached_again);

    owner.InvalidateDnsHostPorts();

    const client_dns::DnsHostPorts& rebuilt = owner.DnsHostPortsFor(nullptr);
    const client_dns::DnsHostPorts& rebuilt_again = owner.DnsHostPortsFor(nullptr);
    BOOST_TEST(&rebuilt == &rebuilt_again);
    BOOST_TEST(rebuilt.IsValid());
}

BOOST_AUTO_TEST_CASE(handle_resolver_response_delegates_to_datagram_output) {
    const auto switcher = MakeSwitcher(false, true);
    wiring_test::ResetDnsHostWiringSpy();
    const client_dns::DnsHostPorts ports = client_dns::MakeDnsHostPorts(switcher, nullptr);

    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    auto query = MakeQuerySegment("query");
    ppp::vector<ppp::Byte> response = { 0x12, 0x34, 0x81, 0x80 };

    ports.handle_resolver_response(query, source, dest, std::move(response));

    BOOST_TEST(wiring_test::DnsHostDatagramOutputCalled());
    BOOST_TEST(wiring_test::DnsHostDatagramOutputBytes() == 4);
}

BOOST_AUTO_TEST_CASE(handle_resolver_response_attempts_inject_before_drop_without_exchanger) {
    const auto switcher = MakeSwitcher(false, false);
    wiring_test::ResetDnsHostWiringSpy();
    const client_dns::DnsHostPorts ports = client_dns::MakeDnsHostPorts(switcher, nullptr);

    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    auto query = MakeQuerySegment("fallback-query");
    ppp::vector<ppp::Byte> response = { 0xab, 0xcd, 0x81, 0x80 };

    ports.handle_resolver_response(query, source, dest, std::move(response));

    BOOST_TEST(wiring_test::DnsHostDatagramOutputCalled());
}
