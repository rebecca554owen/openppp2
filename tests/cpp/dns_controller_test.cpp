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

}

BOOST_AUTO_TEST_CASE(new_session_replaces_previous_generation) {
    auto timers = std::make_shared<FakeTimers>();
    dns::DnsController controller(nullptr, timers);
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
    dns::DnsController controller(nullptr, timers);
    auto session = controller.OpenSession(std::make_shared<FakeTransport>());
    controller.Close();
    controller.Close();
    BOOST_TEST(!session->IsActive());
    BOOST_TEST(timers->cancel_all == 1);
    BOOST_TEST(!controller.HasActiveSession());
    BOOST_TEST(!controller.IsConfigured());
    BOOST_TEST(controller.OpenSession(std::make_shared<FakeTransport>()) == nullptr);
}
