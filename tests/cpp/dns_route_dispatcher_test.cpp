#define BOOST_TEST_MODULE dns_route_dispatcher_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/dns/DnsRouteDispatcher.h>

namespace client_dns = ppp::app::client::dns;

namespace {

boost::asio::ip::address MakeAddress(const char* text) {
    boost::system::error_code ec;
    return boost::asio::ip::make_address(text, ec);
}

client_dns::DnsRouteDispatcherPorts MakeTrackingPorts(
    int& drop_calls,
    int& defer_calls,
    int& relay_calls,
    int& unmatched_calls,
    int& provider_calls,
    boost::asio::ip::address& relay_target,
    ppp::string& provider_name,
    bool& provider_domestic) {

    client_dns::DnsRouteDispatcherPorts ports;
    ports.drop = [&drop_calls]() noexcept {
        ++drop_calls;
        return false;
    };
    ports.defer_to_tunnel = [&defer_calls]() noexcept {
        ++defer_calls;
        return true;
    };
    ports.udp_relay = [&](const boost::asio::ip::address& target) noexcept {
        ++relay_calls;
        relay_target = target;
        return true;
    };
    ports.resolve_unmatched = [&unmatched_calls]() noexcept {
        ++unmatched_calls;
        return true;
    };
    ports.resolve_provider = [&](const ppp::string& name, bool domestic) noexcept {
        ++provider_calls;
        provider_name = name;
        provider_domestic = domestic;
        return true;
    };
    return ports;
}

}  // namespace

BOOST_AUTO_TEST_CASE(drop_actions_invoke_drop_port) {
    int drop_calls = 0;
    int defer_calls = 0;
    int relay_calls = 0;
    int unmatched_calls = 0;
    int provider_calls = 0;
    boost::asio::ip::address relay_target;
    ppp::string provider_name;
    bool provider_domestic = false;
    auto ports = MakeTrackingPorts(
        drop_calls, defer_calls, relay_calls, unmatched_calls, provider_calls,
        relay_target, provider_name, provider_domestic);

    client_dns::DnsRedirectPlanResult drop_plan;
    drop_plan.action = client_dns::DnsRouteAction::kDrop;
    BOOST_TEST(!client_dns::DnsRouteDispatcher::Dispatch(drop_plan, ports));
    BOOST_TEST(drop_calls == 1);

    client_dns::DnsRedirectPlanResult block_plan;
    block_plan.action = client_dns::DnsRouteAction::kBlockAAAA;
    BOOST_TEST(!client_dns::DnsRouteDispatcher::Dispatch(block_plan, ports));
    BOOST_TEST(drop_calls == 2);
    BOOST_TEST(defer_calls == 0);
}

BOOST_AUTO_TEST_CASE(defer_to_tunnel_port_handles_tunnel_fallback) {
    int drop_calls = 0;
    int defer_calls = 0;
    int relay_calls = 0;
    int unmatched_calls = 0;
    int provider_calls = 0;
    boost::asio::ip::address relay_target;
    ppp::string provider_name;
    bool provider_domestic = false;
    auto ports = MakeTrackingPorts(
        drop_calls, defer_calls, relay_calls, unmatched_calls, provider_calls,
        relay_target, provider_name, provider_domestic);

    client_dns::DnsRedirectPlanResult plan;
    plan.action = client_dns::DnsRouteAction::kDeferToTunnel;

    BOOST_TEST(client_dns::DnsRouteDispatcher::Dispatch(plan, ports));
    BOOST_TEST(defer_calls == 1);
    BOOST_TEST(relay_calls == 0);
}

BOOST_AUTO_TEST_CASE(udp_relay_port_receives_target_from_plan) {
    int drop_calls = 0;
    int defer_calls = 0;
    int relay_calls = 0;
    int unmatched_calls = 0;
    int provider_calls = 0;
    boost::asio::ip::address relay_target;
    ppp::string provider_name;
    bool provider_domestic = false;
    auto ports = MakeTrackingPorts(
        drop_calls, defer_calls, relay_calls, unmatched_calls, provider_calls,
        relay_target, provider_name, provider_domestic);

    client_dns::DnsRedirectPlanResult plan;
    plan.action = client_dns::DnsRouteAction::kUdpRelay;
    plan.udp_relay_target = MakeAddress("1.1.1.1");

    BOOST_TEST(client_dns::DnsRouteDispatcher::Dispatch(plan, ports));
    BOOST_TEST(relay_calls == 1);
    BOOST_TEST(relay_target == plan.udp_relay_target);
}

BOOST_AUTO_TEST_CASE(resolve_unmatched_port_is_used) {
    int drop_calls = 0;
    int defer_calls = 0;
    int relay_calls = 0;
    int unmatched_calls = 0;
    int provider_calls = 0;
    boost::asio::ip::address relay_target;
    ppp::string provider_name;
    bool provider_domestic = false;
    auto ports = MakeTrackingPorts(
        drop_calls, defer_calls, relay_calls, unmatched_calls, provider_calls,
        relay_target, provider_name, provider_domestic);

    client_dns::DnsRedirectPlanResult plan;
    plan.action = client_dns::DnsRouteAction::kResolveUnmatched;

    BOOST_TEST(client_dns::DnsRouteDispatcher::Dispatch(plan, ports));
    BOOST_TEST(unmatched_calls == 1);
}

BOOST_AUTO_TEST_CASE(resolve_provider_port_receives_name_and_domestic_flag) {
    int drop_calls = 0;
    int defer_calls = 0;
    int relay_calls = 0;
    int unmatched_calls = 0;
    int provider_calls = 0;
    boost::asio::ip::address relay_target;
    ppp::string provider_name;
    bool provider_domestic = false;
    auto ports = MakeTrackingPorts(
        drop_calls, defer_calls, relay_calls, unmatched_calls, provider_calls,
        relay_target, provider_name, provider_domestic);

    client_dns::DnsRedirectPlanResult plan;
    plan.action = client_dns::DnsRouteAction::kResolveProvider;
    plan.provider_name = "cloudflare";
    plan.provider_domestic = false;

    BOOST_TEST(client_dns::DnsRouteDispatcher::Dispatch(plan, ports));
    BOOST_TEST(provider_calls == 1);
    BOOST_TEST(provider_name == "cloudflare");
    BOOST_TEST(!provider_domestic);
}

BOOST_AUTO_TEST_CASE(missing_port_callbacks_return_false) {
    client_dns::DnsRedirectPlanResult plan;
    plan.action = client_dns::DnsRouteAction::kUdpRelay;
    plan.udp_relay_target = MakeAddress("9.9.9.9");

    client_dns::DnsRouteDispatcherPorts ports;
    BOOST_TEST(!client_dns::DnsRouteDispatcher::Dispatch(plan, ports));
}
