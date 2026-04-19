#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file IPv6Auxiliary.cpp
 * @brief Dispatches IPv6 auxiliary operations to platform-specific implementations.
 */

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
        /**
         * @brief Prepares server-side IPv6 environment for managed operation.
         * @return true on success or when the current platform does not require preparation.
         */
        bool PrepareServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept {
#if defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::PrepareServerEnvironment(configuration, preferred_nic, transit_ifname);
#else
            if (NULLPTR == configuration) {
                return false;
            }

            auto mode = configuration->server.ipv6.mode;
            if (ppp::configurations::AppConfiguration::IPv6Mode_Gua == mode || ppp::configurations::AppConfiguration::IPv6Mode_Nat66 == mode) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::PlatformNotSupportGUAMode);
                return false;
            }

            return true;
#endif
        }

        /**
         * @brief Reverts server-side IPv6 environment preparation steps.
         */
        void FinalizeServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept {
#if defined(_LINUX)
            ppp::linux::ipv6::auxiliary::FinalizeServerEnvironment(configuration, preferred_nic, transit_ifname);
#else
#endif
        }

        /**
         * @brief Reports whether client managed IPv6 configuration is supported on this OS.
         * @return true for supported desktop/server targets.
         */
        bool ClientSupportsManaged() noexcept {
#if defined(_WIN32) || defined(_LINUX) || defined(_MACOS)
            return true;
#else
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6Unsupported);
#endif
        }

        /**
         * @brief Captures the current client networking state before managed changes.
         */
        void CaptureClientOriginalState(const ClientContext& context, bool nat_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            ppp::win32::ipv6::auxiliary::CaptureClientOriginalState(context, nat_mode, state);
#elif defined(_MACOS)
            ppp::darwin::ipv6::auxiliary::CaptureClientOriginalState(context, nat_mode, state);
#elif defined(_LINUX)
            ppp::linux::ipv6::auxiliary::CaptureClientOriginalState(context, nat_mode, state);
#else
#endif
        }

        /**
         * @brief Applies an IPv6 address to the client using platform-specific logic.
         * @return true when address application succeeds.
         */
        bool ApplyClientAddress(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            return ppp::win32::ipv6::auxiliary::ApplyClientAddress(context, address, prefix_length, gua_mode, state);
#elif defined(_MACOS)
            return ppp::darwin::ipv6::auxiliary::ApplyClientAddress(context, address, prefix_length, gua_mode, state);
#elif defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::ApplyClientAddress(context, address, prefix_length, gua_mode, state);
#else
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6Unsupported);
#endif
        }

        /**
         * @brief Applies the client default IPv6 route.
         * @return true when route application succeeds.
         */
        bool ApplyClientDefaultRoute(const ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            return ppp::win32::ipv6::auxiliary::ApplyClientDefaultRoute(context, gateway, nat_mode, state);
#elif defined(_MACOS)
            return ppp::darwin::ipv6::auxiliary::ApplyClientDefaultRoute(context, gateway, nat_mode, state);
#elif defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::ApplyClientDefaultRoute(context, gateway, nat_mode, state);
#else
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6Unsupported);
#endif
        }

        /**
         * @brief Applies a client subnet route toward the specified gateway.
         * @return true when route application succeeds.
         */
        bool ApplyClientSubnetRoute(const ClientContext& context, const boost::asio::ip::address& prefix, int prefix_length, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            return ppp::win32::ipv6::auxiliary::ApplyClientSubnetRoute(context, prefix, prefix_length, gateway, nat_mode, state);
#elif defined(_MACOS)
            return ppp::darwin::ipv6::auxiliary::ApplyClientSubnetRoute(context, prefix, prefix_length, gateway, nat_mode, state);
#elif defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::ApplyClientSubnetRoute(context, prefix, prefix_length, gateway, nat_mode, state);
#else
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6Unsupported);
#endif
        }

        /**
         * @brief Applies DNS servers to the client network interface.
         * @return true when DNS application succeeds.
         */
        bool ApplyClientDns(const ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ClientState& state) noexcept {
#if defined(_WIN32)
            return ppp::win32::ipv6::auxiliary::ApplyClientDns(context, dns_servers, state);
#elif defined(_MACOS)
            return ppp::darwin::ipv6::auxiliary::ApplyClientDns(context, dns_servers, state);
#elif defined(_LINUX)
            return ppp::linux::ipv6::auxiliary::ApplyClientDns(context, dns_servers, state);
#else
            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6Unsupported);
#endif
        }

        /**
         * @brief Restores client networking configuration from captured state.
         */
        void RestoreClientConfiguration(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ClientState& state) noexcept {
#if defined(_WIN32)
            ppp::win32::ipv6::auxiliary::RestoreClientConfiguration(context, address, prefix_length, nat_mode, state);
#elif defined(_MACOS)
            ppp::darwin::ipv6::auxiliary::RestoreClientConfiguration(context, address, prefix_length, nat_mode, state);
#elif defined(_LINUX)
            ppp::linux::ipv6::auxiliary::RestoreClientConfiguration(context, address, prefix_length, nat_mode, state);
#else
#endif
        }
        }
    }
}
