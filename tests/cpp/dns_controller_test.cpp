#define BOOST_TEST_MODULE dns_controller_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsController.h>

namespace dns = ppp::app::client::dns;

namespace {

class FakeTimers final : public dns::IDnsTimerScheduler {
public:
    int cancel_all = 0;
    uint64_t Schedule(int64_t, std::function<void()>) noexcept override { return 1; }
    bool Cancel(uint64_t) noexcept override { return true; }
    void CancelAll() noexcept override { ++cancel_all; }
};

class FakeTransport final : public dns::IDnsTunnelTransport {
public:
    bool SendDnsDatagram(
        const boost::asio::ip::udp::endpoint&,
        const boost::asio::ip::udp::endpoint&,
        const void*, int) noexcept override { return true; }
};

class FakePolicy final : public dns::IDnsPolicy {
public:
    bool HandleQuery(
        const dns::DnsQueryContext&,
        const std::shared_ptr<const dns::DnsSessionContext>&,
        const std::shared_ptr<ppp::net::packet::IPFrame>&,
        const std::shared_ptr<ppp::net::packet::UdpFrame>&,
        const std::shared_ptr<ppp::net::packet::BufferSegment>&) noexcept override {
        return false;
    }
    void Close() noexcept override {}
};

}

BOOST_AUTO_TEST_CASE(new_session_replaces_previous_generation) {
    auto timers = std::make_shared<FakeTimers>();
    dns::DnsController controller(std::make_unique<FakePolicy>(), timers);
    auto first = controller.OpenSession(std::make_shared<FakeTransport>());
    auto second = controller.OpenSession(std::make_shared<FakeTransport>());
    BOOST_REQUIRE(first != nullptr);
    BOOST_REQUIRE(second != nullptr);
    BOOST_TEST(first->Generation() == 1u);
    BOOST_TEST(second->Generation() == 2u);
    BOOST_TEST(!first->IsActive());
    BOOST_TEST(second->IsActive());
    BOOST_TEST(controller.HasActiveSession());
    BOOST_TEST(!controller.IsConfigured());
}

BOOST_AUTO_TEST_CASE(close_stops_session_and_timers_and_rejects_new_sessions) {
    auto timers = std::make_shared<FakeTimers>();
    dns::DnsController controller(std::make_unique<FakePolicy>(), timers);
    auto session = controller.OpenSession(std::make_shared<FakeTransport>());
    controller.Close();
    controller.Close();
    BOOST_TEST(!session->IsActive());
    BOOST_TEST(timers->cancel_all == 1);
    BOOST_TEST(!controller.HasActiveSession());
    BOOST_TEST(!controller.IsConfigured());
    BOOST_TEST(controller.OpenSession(std::make_shared<FakeTransport>()) == nullptr);
}

BOOST_AUTO_TEST_CASE(fake_ip_rewrite_is_owned_by_controller) {
    auto timers = std::make_shared<FakeTimers>();
    dns::DnsController controller(std::make_unique<FakePolicy>(), timers);
    const auto ipv4 = boost::asio::ip::make_address("10.0.0.7");
    const auto ipv6 = boost::asio::ip::make_address("2001:db8::7");
    BOOST_TEST(controller.RewriteFakeIpAddress(ipv4) == ipv4);
    BOOST_TEST(controller.RewriteFakeIpAddress(ipv6) == ipv6);
}

BOOST_AUTO_TEST_CASE(query_context_accepts_standard_allocator_fallback) {
    dns::DnsQueryContext context;
    context.datagram_output = [](const auto&, const auto&, void*, int, bool) { return true; };
    context.tap = std::shared_ptr<ppp::tap::ITap>(reinterpret_cast<ppp::tap::ITap*>(1), [](auto*) {});
    context.configuration = std::shared_ptr<ppp::configurations::AppConfiguration>(
        reinterpret_cast<ppp::configurations::AppConfiguration*>(1), [](auto*) {});
    context.io_context = std::make_shared<boost::asio::io_context>();
    context.emplace_timeout = [](void*, const auto&) { return true; };
    context.delete_timeout = [](void*) { return true; };
    context.handle_resolver_response = [](const auto&, const auto&, const auto&, auto) {};

    BOOST_TEST(context.allocator == nullptr);
    BOOST_TEST(context.IsValid());
}
