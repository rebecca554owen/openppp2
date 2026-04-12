#include <linux/ppp/ipv6/IPv6Auxiliary.h>

#include <ppp/net/IPEndPoint.h>
#include <common/unix/UnixAfx.h>
#include <linux/ppp/tap/TapLinux.h>

namespace {
    static bool IsSafeShellToken(const ppp::string& value) noexcept {
        if (value.empty()) {
            return false;
        }

        for (char ch : value) {
            bool ok =
                (ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') ||
                ch == ':' || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '/';
            if (!ok) {
                return false;
            }
        }

        return true;
    }

    static bool IsSafeShellRoute(const ppp::string& value) noexcept {
        if (value.empty()) {
            return false;
        }

        for (char ch : value) {
            bool ok =
                (ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') ||
                ch == ':' || ch == '.' || ch == '_' || ch == '-' || ch == '%' || ch == '/' || ch == ' ';
            if (!ok) {
                return false;
            }
        }

        return true;
    }

    static bool LinuxExecuteCommand(const ppp::string& command) noexcept {
        if (command.empty()) {
            return false;
        }
        return system(command.data()) == 0;
    }

    static ppp::string ExtractRouteInterface(const ppp::string& route) noexcept {
        static const char token[] = " dev ";

        std::size_t pos = route.find(token);
        if (pos == ppp::string::npos) {
            return ppp::string();
        }

        pos += sizeof(token) - 1;
        std::size_t end = route.find(' ', pos);
        ppp::string interface_name = end == ppp::string::npos ? route.substr(pos) : route.substr(pos, end - pos);
        if (!IsSafeShellToken(interface_name)) {
            return ppp::string();
        }

        return interface_name;
    }

    static int LinuxExecuteCommandWithStatus(const ppp::string& command) noexcept {
        if (command.empty()) {
            return -1;
        }
        return system(command.data());
    }

    static ppp::string BuildIpv6ForwardRules(bool add_rules, const ppp::string& prefix, int prefix_length) noexcept {
        if (prefix.empty()) {
            return ppp::string();
        }

        char command[2048];
        if (add_rules) {
            snprintf(command, sizeof(command),
                "ip6tables -C FORWARD -s %s/%d -j ACCEPT >/dev/null 2>&1 || "
                "ip6tables -A FORWARD -s %s/%d -j ACCEPT >/dev/null 2>&1; "
                "ip6tables -C FORWARD -d %s/%d -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || "
                "ip6tables -A FORWARD -d %s/%d -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1",
                prefix.data(), prefix_length,
                prefix.data(), prefix_length,
                prefix.data(), prefix_length,
                prefix.data(), prefix_length);
        }
        else {
            snprintf(command, sizeof(command),
                "ip6tables -D FORWARD -s %s/%d -j ACCEPT >/dev/null 2>&1; "
                "ip6tables -D FORWARD -d %s/%d -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1",
                prefix.data(), prefix_length,
                prefix.data(), prefix_length);
        }

        return ppp::string(command);
    }

    static ppp::string ResolveIpv6UplinkInterface(const ppp::string& preferred_nic) noexcept {
        ppp::string interface_name;
        ppp::UInt32 ip = ppp::net::IPEndPoint::AnyAddress;
        ppp::UInt32 gw = ppp::net::IPEndPoint::AnyAddress;
        ppp::UInt32 mask = ppp::net::IPEndPoint::AnyAddress;
        if (ppp::tap::TapLinux::GetPreferredNetworkInterface(interface_name, ip, mask, gw, preferred_nic)) {
            return interface_name;
        }
        return ppp::string();
    }

    static bool ParseIpv6Cidr(const ppp::string& cidr, ppp::string& prefix, int& prefix_length) noexcept {
        prefix.clear();
        prefix_length = 0;
        if (cidr.empty()) {
            return false;
        }

        std::size_t slash = cidr.find('/');
        if (slash == ppp::string::npos) {
            prefix = cidr;
            prefix_length = 128;
            return true;
        }

        prefix = cidr.substr(0, slash);
        prefix_length = atoi(cidr.substr(slash + 1).c_str());
        prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
        return !prefix.empty();
    }

    static void CleanupServerRules(ppp::configurations::AppConfiguration::IPv6Mode mode, const ppp::string& prefix, int prefix_length, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept {
        if (prefix.empty()) {
            return;
        }

        ppp::string uplink_name = ResolveIpv6UplinkInterface(preferred_nic);
        if (!uplink_name.empty() && !IsSafeShellToken(uplink_name)) {
            uplink_name.clear();
        }

        char command[4096];
        ppp::string forward_cleanup = BuildIpv6ForwardRules(false, prefix, prefix_length);
        if (mode == ppp::configurations::AppConfiguration::IPv6Mode_Nat66) {
            if (uplink_name.empty()) {
                snprintf(command, sizeof(command),
                    "%s; "
                    "ip6tables -t nat -D POSTROUTING -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                    forward_cleanup.data(),
                    prefix.data(), prefix_length);
            }
            else {
                snprintf(command, sizeof(command),
                    "%s; "
                    "ip6tables -t nat -D POSTROUTING -o %s -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                    forward_cleanup.data(),
                    uplink_name.data(), prefix.data(), prefix_length);
            }
            LinuxExecuteCommand(command);
        }
        else if (mode == ppp::configurations::AppConfiguration::IPv6Mode_Gua) {
            LinuxExecuteCommand(forward_cleanup);
            if (!uplink_name.empty()) {
                snprintf(command, sizeof(command), "ip -6 neigh flush proxy dev %s >/dev/null 2>&1", uplink_name.data());
                LinuxExecuteCommand(command);
                ppp::tap::TapLinux::DisableIPv6NeighborProxy(uplink_name);
            }
        }

        if (!transit_ifname.empty() && IsSafeShellToken(transit_ifname)) {
            snprintf(command, sizeof(command), "ip -6 route flush dev %s >/dev/null 2>&1; ip -6 addr flush dev %s >/dev/null 2>&1", transit_ifname.data(), transit_ifname.data());
            LinuxExecuteCommand(command);
        }
    }
}

namespace ppp {
    namespace linux {
        namespace ipv6 {
            namespace auxiliary {
            ppp::string ReadDefaultRoute() noexcept {
                FILE* pipe = popen("ip -6 route show default 2>/dev/null", "r");
                if (NULLPTR == pipe) {
                    return ppp::string();
                }

                char buffer[1024];
                ppp::string route;
                while (fgets(buffer, sizeof(buffer), pipe) != NULLPTR) {
                    route = buffer;
                    while (!route.empty() && (route.back() == '\n' || route.back() == '\r')) {
                        route.pop_back();
                    }
                    if (!route.empty()) {
                        break;
                    }
                }
                pclose(pipe);
                return route;
            }

            ppp::string ComputeNetworkAddress(const boost::asio::ip::address_v6& address, int prefix_length) noexcept {
                boost::asio::ip::address_v6::bytes_type bytes = address.to_bytes();
                prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));

                int full_bytes = prefix_length / 8;
                int remainder_bits = prefix_length % 8;
                if (full_bytes < 16) {
                    if (remainder_bits != 0) {
                        unsigned char mask = static_cast<unsigned char>(0xff << (8 - remainder_bits));
                        bytes[full_bytes] &= mask;
                        full_bytes++;
                    }

                    for (int i = full_bytes; i < 16; ++i) {
                        bytes[i] = 0;
                    }
                }

                return boost::asio::ip::address_v6(bytes).to_string();
            }

            bool ApplyDefaultRouteCommand(const ppp::string& route) noexcept {
                if (route.empty() || !IsSafeShellRoute(route)) {
                    return false;
                }

                char command[1600];
                snprintf(command, sizeof(command), "ip -6 route replace %s > /dev/null 2>&1", route.data());
                return system(command) == 0;
            }

            bool PrepareServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept {
                if (NULLPTR == configuration) {
                    return false;
                }

                const auto& ipv6 = configuration->server.ipv6;
                auto mode = ipv6.mode;
                if (mode != ppp::configurations::AppConfiguration::IPv6Mode_Nat66 && mode != ppp::configurations::AppConfiguration::IPv6Mode_Gua) {
                    return true;
                }

                ppp::string prefix;
                int prefix_length = 0;
                if (!ParseIpv6Cidr(ipv6.cidr, prefix, prefix_length) && mode == ppp::configurations::AppConfiguration::IPv6Mode_Nat66) {
                    prefix = "fd42:4242:4242::";
                    prefix_length = 64;
                }

                if (!prefix.empty() && !IsSafeShellToken(prefix)) {
                    fprintf(stdout, "Linux IPv6 server prepare failed: invalid ipv6 prefix.\r\n");
                    return false;
                }

                CleanupServerRules(mode, prefix, prefix_length, preferred_nic, transit_ifname);

                char sysctl_command[512];
                snprintf(sysctl_command, sizeof(sysctl_command), "sysctl -w net.ipv6.conf.all.forwarding=1 net.ipv6.conf.default.forwarding=1 > /dev/null 2>&1");
                if (!LinuxExecuteCommand(sysctl_command)) {
                    fprintf(stdout, "Linux IPv6 server prepare failed: cannot enable ipv6 forwarding.\r\n");
                    return false;
                }

                ppp::string uplink_name = ResolveIpv6UplinkInterface(preferred_nic);
                char ip6tables_command[3072];
                if (!uplink_name.empty() && !IsSafeShellToken(uplink_name)) {
                    fprintf(stdout, "Linux IPv6 server prepare failed: invalid uplink interface.\r\n");
                    return false;
                }

                ppp::string forward_rules = BuildIpv6ForwardRules(true, prefix, prefix_length);
                if (forward_rules.empty()) {
                    fprintf(stdout, "Linux IPv6 server prepare failed: invalid ipv6 forward rules.\r\n");
                    return false;
                }

                if (mode == ppp::configurations::AppConfiguration::IPv6Mode_Gua) {
                    if (LinuxExecuteCommandWithStatus(forward_rules) == 0) {
                        return true;
                    }

                    fprintf(stdout, "Linux IPv6 server prepare failed: ip6tables forward rules failed.\r\n");
                    return false;
                }

                if (uplink_name.empty()) {
                    snprintf(ip6tables_command, sizeof(ip6tables_command),
                        "%s; "
                        "ip6tables -t nat -C POSTROUTING -s %s/%d -j MASQUERADE >/dev/null 2>&1 || "
                        "ip6tables -t nat -A POSTROUTING -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                        forward_rules.data(),
                        prefix.data(), prefix_length,
                        prefix.data(), prefix_length);
                }
                else {
                    snprintf(ip6tables_command, sizeof(ip6tables_command),
                        "%s; "
                        "ip6tables -t nat -C POSTROUTING -o %s -s %s/%d -j MASQUERADE >/dev/null 2>&1 || "
                        "ip6tables -t nat -A POSTROUTING -o %s -s %s/%d -j MASQUERADE >/dev/null 2>&1",
                        forward_rules.data(),
                        uplink_name.data(), prefix.data(), prefix_length,
                        uplink_name.data(), prefix.data(), prefix_length);
                }

                if (LinuxExecuteCommandWithStatus(ip6tables_command) == 0) {
                    return true;
                }

                fprintf(stdout, "Linux IPv6 server prepare failed: ip6tables rules failed.\r\n");
                return false;
            }

            void CaptureClientOriginalState(const ::ppp::ipv6::auxiliary::ClientContext& context, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                (void)context;
                (void)nat_mode;
                state.OriginalDnsConfiguration = ppp::unix__::UnixAfx::GetDnsResolveConfiguration();
                state.OriginalDefaultRoute = ReadDefaultRoute();
                state.DefaultRouteWasPresent = !state.OriginalDefaultRoute.empty();
                state.OriginalDefaultRouteInterface = ExtractRouteInterface(state.OriginalDefaultRoute);
            }

            bool ApplyClientAddress(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (NULLPTR == context.Tap || context.InterfaceName.empty() || !address.is_v6()) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(context.Tap);
                if (NULLPTR == linux_tap) {
                    return false;
                }

                ppp::string addr_str = address.to_string();
                if (!ppp::tap::TapLinux::SetIPv6Address(context.InterfaceName, addr_str, prefix_length)) {
                    return false;
                }

                state.AddressApplied = true;
                state.Address = addr_str;
                (void)gua_mode;
                return true;
            }

            bool ApplyClientDefaultRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (NULLPTR == context.Tap || context.InterfaceName.empty()) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(context.Tap);
                if (NULLPTR == linux_tap) {
                    return false;
                }

                ppp::string gateway_string;
                if (gateway.is_v6()) {
                    gateway_string = gateway.to_string();
                }
                else if (!nat_mode) {
                    return false;
                }

                if (!ppp::tap::TapLinux::AddRoute6(context.InterfaceName, "::", 0, gateway_string)) {
                    return false;
                }

                state.DefaultRouteApplied = true;
                state.DefaultRouteGateway = gateway_string;
                return true;
            }

            bool ApplyClientSubnetRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& prefix, int prefix_length, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (NULLPTR == context.Tap || context.InterfaceName.empty() || !prefix.is_v6()) {
                    return false;
                }

                ppp::string gateway_string;
                if (gateway.is_v6()) {
                    gateway_string = gateway.to_string();
                }
                else if (!nat_mode) {
                    return false;
                }

                ppp::string prefix_string = prefix.to_string();
                prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
                if (!ppp::tap::TapLinux::AddRoute6(context.InterfaceName, prefix_string, prefix_length, gateway_string)) {
                    return false;
                }

                state.SubnetRouteApplied = true;
                state.SubnetRoutePrefix = prefix_string;
                state.SubnetRoutePrefixLength = prefix_length;
                return true;
            }

            bool ApplyClientDns(const ::ppp::ipv6::auxiliary::ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                (void)context;
                if (dns_servers.empty()) {
                    return false;
                }

                ppp::vector<boost::asio::ip::address> dns_addrs;
                ppp::vector<boost::asio::ip::address> current_addrs;
                ppp::unix__::UnixAfx::GetDnsAddresses(current_addrs);
                for (auto& s : dns_servers) {
                    boost::system::error_code ec;
                    auto addr = StringToAddress(s, ec);
                    if (!ec && addr.is_v6()) {
                        dns_addrs.emplace_back(addr);
                    }
                }

                if (dns_addrs.empty() || !ppp::unix__::UnixAfx::MergeDnsAddresses(dns_addrs, current_addrs)) {
                    return false;
                }

                state.DnsApplied = true;
                state.DnsServers = dns_servers;
                return true;
            }

            void RestoreClientConfiguration(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (NULLPTR == context.Tap || context.InterfaceName.empty()) {
                    return;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(context.Tap);
                if (NULLPTR == linux_tap) {
                    return;
                }

                if (state.SubnetRouteApplied && !state.SubnetRoutePrefix.empty()) {
                    ppp::tap::TapLinux::DeleteRoute6(context.InterfaceName, state.SubnetRoutePrefix, state.SubnetRoutePrefixLength, state.DefaultRouteGateway);
                }

                if (state.DefaultRouteApplied && nat_mode && state.DefaultRouteGateway.empty()) {
                    ppp::tap::TapLinux::DeleteRoute6(context.InterfaceName, "::", 0, ppp::string());
                }
                else if (state.DefaultRouteApplied) {
                    ppp::tap::TapLinux::DeleteRoute6(context.InterfaceName, "::", 0, state.DefaultRouteGateway);
                }

                if (state.AddressApplied && address.is_v6() && !state.Address.empty()) {
                    ppp::tap::TapLinux::DeleteIPv6Address(context.InterfaceName, state.Address, prefix_length);
                }

                if (state.DnsApplied) {
                    ppp::unix__::UnixAfx::SetDnsResolveConfiguration(state.OriginalDnsConfiguration);
                }
                if (state.DefaultRouteApplied && state.DefaultRouteWasPresent && !state.OriginalDefaultRoute.empty()) {
                    ApplyDefaultRouteCommand(state.OriginalDefaultRoute);
                }
            }
            }
        }
    }
}
