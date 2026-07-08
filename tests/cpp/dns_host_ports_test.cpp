#define BOOST_TEST_MODULE dns_host_ports_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/dns/DnsUdpRelay.h>

namespace ppp::app::client {
class VEthernetExchanger;
}

namespace client_dns = ppp::app::client::dns;

namespace {

client_dns::DnsHostPorts MakeFilledHost() noexcept {
    client_dns::DnsHostPorts host;
    host.datagram_output =
        [](const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            void*,
            int,
            bool) noexcept { return true; };
    host.get_tap = []() noexcept { return std::shared_ptr<ppp::tap::ITap>(); };
    host.get_configuration = []() noexcept {
        return std::shared_ptr<ppp::configurations::AppConfiguration>();
    };
    host.get_buffer_allocator = []() noexcept {
        return std::shared_ptr<ppp::threading::BufferswapAllocator>();
    };
    host.emplace_timeout =
        [](void*, const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>&) noexcept {
            return true;
        };
    host.delete_timeout = [](void*) noexcept { return true; };
#if defined(_LINUX)
    host.get_protector_network = []() noexcept {
        return std::shared_ptr<ppp::net::ProtectorNetwork>();
    };
#endif
    host.handle_resolver_response =
        [](const std::shared_ptr<ppp::net::packet::BufferSegment>&,
            const boost::asio::ip::udp::endpoint&,
            const boost::asio::ip::udp::endpoint&,
            ppp::vector<ppp::Byte>) noexcept {};
    return host;
}

std::shared_ptr<ppp::app::client::VEthernetExchanger> NonNullExchanger() noexcept {
    static char sentinel;
    return std::shared_ptr<ppp::app::client::VEthernetExchanger>(
        reinterpret_cast<ppp::app::client::VEthernetExchanger*>(&sentinel),
        [](ppp::app::client::VEthernetExchanger*) noexcept {});
}

}  // namespace

BOOST_AUTO_TEST_CASE(default_host_is_invalid) {
    client_dns::DnsHostPorts host;
    BOOST_TEST(!host.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_host_is_valid_on_non_linux) {
#if !defined(_LINUX)
    BOOST_TEST(MakeFilledHost().IsValid());
#endif
}

#if defined(_LINUX)
BOOST_AUTO_TEST_CASE(filled_host_without_protector_is_invalid_on_linux) {
    auto host = MakeFilledHost();
    host.get_protector_network = nullptr;
    BOOST_TEST(!host.IsValid());
}

BOOST_AUTO_TEST_CASE(filled_host_with_protector_is_valid_on_linux) {
    BOOST_TEST(MakeFilledHost().IsValid());
}
#endif

BOOST_AUTO_TEST_CASE(can_spawn_requires_valid_host_and_exchanger) {
    const auto exchanger = NonNullExchanger();
    BOOST_TEST(!client_dns::DnsUdpRelay::CanSpawn(client_dns::DnsHostPorts(), exchanger));
    BOOST_TEST(!client_dns::DnsUdpRelay::CanSpawn(MakeFilledHost(), nullptr));
#if !defined(_LINUX)
    BOOST_TEST(client_dns::DnsUdpRelay::CanSpawn(MakeFilledHost(), exchanger));
#endif
}
