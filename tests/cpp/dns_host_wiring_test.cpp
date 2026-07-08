#define BOOST_TEST_MODULE dns_host_wiring_test
#include <ppp/stdafx.h>
#include <boost/test/included/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

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

using Clock = std::chrono::steady_clock;

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

std::shared_ptr<client::VEthernetExchanger> MakeFakeExchanger() {
    struct ExchangerToken final {
        alignas(client::VEthernetExchanger) unsigned char storage[sizeof(client::VEthernetExchanger)];
    };

    auto* token = new ExchangerToken();
    return std::shared_ptr<client::VEthernetExchanger>(
        reinterpret_cast<client::VEthernetExchanger*>(token),
        [token](client::VEthernetExchanger*) noexcept { delete token; });
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

BOOST_AUTO_TEST_CASE(different_exchanger_builds_valid_ports) {
    const auto switcher = MakeSwitcher(false, true);
    const auto exchanger_a = MakeFakeExchanger();
    const auto exchanger_b = MakeFakeExchanger();

    const client_dns::DnsHostPorts ports_a = client_dns::MakeDnsHostPorts(switcher, exchanger_a);
    const client_dns::DnsHostPorts ports_b = client_dns::MakeDnsHostPorts(switcher, exchanger_b);

    BOOST_TEST(ports_a.IsValid());
    BOOST_TEST(ports_b.IsValid());
    BOOST_TEST(exchanger_a != exchanger_b);
}

BOOST_AUTO_TEST_CASE(expired_exchanger_weak_ptr_still_rebuilds_valid_ports) {
    const auto switcher = MakeSwitcher(false, true);
    wiring_test::DnsHostWiringTestOwner owner(switcher);
    auto exchanger = MakeFakeExchanger();

    const client_dns::DnsHostPorts& bound = owner.DnsHostPortsFor(exchanger);
    BOOST_TEST(bound.IsValid());
    exchanger.reset();
    const client_dns::DnsHostPorts& rebound = owner.DnsHostPortsFor(nullptr);
    BOOST_TEST(rebound.IsValid());
}

BOOST_AUTO_TEST_CASE(cache_hits_are_faster_than_repeated_rebuilds) {
    const auto switcher = MakeSwitcher(false, true);
    wiring_test::DnsHostWiringTestOwner owner(switcher);
    (void)owner.DnsHostPortsFor(nullptr);

    constexpr int hit_iterations = 2000;
    const auto hit_start = Clock::now();
    for (int i = 0; i < hit_iterations; ++i) {
        (void)owner.DnsHostPortsFor(nullptr);
    }
    const auto hit_elapsed =
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - hit_start).count();

    constexpr int rebuild_iterations = 200;
    const auto rebuild_start = Clock::now();
    for (int i = 0; i < rebuild_iterations; ++i) {
        owner.InvalidateDnsHostPorts();
        (void)owner.DnsHostPortsFor(nullptr);
    }
    const auto rebuild_elapsed =
        std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now() - rebuild_start).count();

    BOOST_TEST(hit_elapsed / hit_iterations < rebuild_elapsed / rebuild_iterations);
    BOOST_TEST(hit_elapsed / hit_iterations < 2'000'000);
}

BOOST_AUTO_TEST_CASE(isolated_parallel_switchers_remain_valid_under_load) {
    constexpr int worker_count = 8;
    constexpr int iterations_per_worker = 250;
    std::atomic<int> failures{0};
    std::vector<std::thread> workers;
    workers.reserve(worker_count);

    for (int worker = 0; worker < worker_count; ++worker) {
        workers.emplace_back([&failures]() {
            try {
                const auto switcher = MakeSwitcher(false, true);
                wiring_test::DnsHostWiringTestOwner owner(switcher);
                for (int i = 0; i < iterations_per_worker; ++i) {
                    if (!owner.DnsHostPortsFor(nullptr).IsValid()) {
                        failures.fetch_add(1, std::memory_order_relaxed);
                    }
                }
            } catch (...) {
                failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (std::thread& worker : workers) {
        worker.join();
    }

    BOOST_TEST(failures.load(std::memory_order_relaxed) == 0);
}

BOOST_AUTO_TEST_CASE(dispatch_dns_fallback_path_uses_resolver_callback) {
    const auto switcher = MakeSwitcher(false, true);
    wiring_test::ResetDnsHostWiringSpy();
    wiring_test::DnsHostWiringTestOwner owner(switcher);

    const client_dns::DnsHostPorts& ports = owner.DnsHostPortsFor(nullptr);
    const auto source = MakeEndpoint("10.0.0.2", 5353);
    const auto dest = MakeEndpoint("10.0.0.1", 53);
    auto query = MakeQuerySegment("dispatch-fallback");
    ppp::vector<ppp::Byte> response = { 0x01, 0x02, 0x81, 0x80 };

  // Mirrors ClientPacketDispatchHandler UDP/53 fallback after RedirectDnsServer miss.
    ports.handle_resolver_response(query, source, dest, std::move(response));

    BOOST_TEST(wiring_test::DnsHostDatagramOutputCalled());
    BOOST_TEST(wiring_test::DnsHostDatagramOutputBytes() == 4);
}
