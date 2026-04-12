#include <ppp/ipv6/IPv6Auxiliary.h>

#if defined(_WIN32)
#include <windows/ppp/ipv6/IPv6Auxiliary.h>
#elif defined(_MACOS)
#include <darwin/ppp/ipv6/IPv6Auxiliary.h>
#elif defined(_LINUX)
#include <linux/ppp/ipv6/IPv6Auxiliary.h>
#endif

namespace ppp {
    namespace ipv6 {
        namespace auxiliary {
        bool PrepareServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic) noexcept {
#if defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::PrepareServerEnvironment(configuration, preferred_nic);
#else
            (void)configuration;
            (void)preferred_nic;
            return true;
#endif
        }

        bool ClientSupportsManaged() noexcept {
#if defined(_WIN32) || defined(_LINUX) || defined(_MACOS)
            return true;
#else
            return false;
#endif
        }

        void CaptureClientOriginalState(const ClientContext& context, bool nat_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            ppp::win32::ipv6::auxiliary::CaptureClientOriginalState(context, nat_mode, state);
#elif defined(_MACOS)
            ppp::darwin::ipv6::auxiliary::CaptureClientOriginalState(context, nat_mode, state);
#elif defined(_LINUX)
            ppp::linux::ipv6::auxiliary::CaptureClientOriginalState(context, nat_mode, state);
#else
            (void)context;
            (void)nat_mode;
            (void)state;
#endif
        }

        bool ApplyClientAddress(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            return ppp::win32::ipv6::auxiliary::ApplyClientAddress(context, address, prefix_length, gua_mode, state);
#elif defined(_MACOS)
            return ppp::darwin::ipv6::auxiliary::ApplyClientAddress(context, address, prefix_length, gua_mode, state);
#elif defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::ApplyClientAddress(context, address, prefix_length, gua_mode, state);
#else
            (void)context;
            (void)address;
            (void)prefix_length;
            (void)gua_mode;
            (void)state;
            return false;
#endif
        }

        bool ApplyClientDefaultRoute(const ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            return ppp::win32::ipv6::auxiliary::ApplyClientDefaultRoute(context, gateway, nat_mode, state);
#elif defined(_MACOS)
            return ppp::darwin::ipv6::auxiliary::ApplyClientDefaultRoute(context, gateway, nat_mode, state);
#elif defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::ApplyClientDefaultRoute(context, gateway, nat_mode, state);
#else
            (void)context;
            (void)gateway;
            (void)nat_mode;
            (void)state;
            return false;
#endif
        }

        bool ApplyClientDns(const ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ClientState& state) noexcept {
#if defined(_WIN32)
            return ppp::win32::ipv6::auxiliary::ApplyClientDns(context, dns_servers, state);
#elif defined(_MACOS)
            return ppp::darwin::ipv6::auxiliary::ApplyClientDns(context, dns_servers, state);
#elif defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::ApplyClientDns(context, dns_servers, state);
#else
            (void)context;
            (void)dns_servers;
            (void)state;
            return false;
#endif
        }

        void RestoreClientConfiguration(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            ppp::win32::ipv6::auxiliary::RestoreClientConfiguration(context, address, prefix_length, nat_mode, state);
#elif defined(_MACOS)
            ppp::darwin::ipv6::auxiliary::RestoreClientConfiguration(context, address, prefix_length, nat_mode, state);
#elif defined(_LINUX)
            ppp::linux::ipv6::auxiliary::RestoreClientConfiguration(context, address, prefix_length, nat_mode, state);
#else
            (void)context;
            (void)address;
            (void)prefix_length;
            (void)nat_mode;
            (void)state;
#endif
        }
        }
    }
}
