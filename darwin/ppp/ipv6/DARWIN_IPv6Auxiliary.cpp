#include <darwin/ppp/ipv6/IPv6Auxiliary.h>

#include <common/unix/UnixAfx.h>

namespace ppp {
    namespace darwin {
        namespace ipv6 {
            namespace auxiliary {
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

            void ReadPrimaryDefaultRoute(ppp::string& interface_name, ppp::string& gateway) noexcept {
                interface_name.clear();
                gateway.clear();

                FILE* pipe = popen("route -n get -inet6 default 2>/dev/null", "r");
                if (NULLPTR == pipe) {
                    return;
                }

                char buffer[1024];
                while (fgets(buffer, sizeof(buffer), pipe) != NULLPTR) {
                    ppp::string line = buffer;
                    if (auto position = line.find("interface:"); position != ppp::string::npos) {
                        ppp::string value = ATrim(line.substr(position + 10));
                        while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
                            value.pop_back();
                        }
                        interface_name = value;
                    }

                    if (auto position = line.find("gateway:"); position != ppp::string::npos) {
                        ppp::string value = ATrim(line.substr(position + 8));
                        while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) {
                            value.pop_back();
                        }
                        if (value != "default") {
                            gateway = value;
                        }
                    }
                }

                pclose(pipe);
            }

            bool SetRoute(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
                if (ifrName.empty() || addressIP.empty()) {
                    return false;
                }

                char cmd[1200];
                if (addressIP == "::" && prefix_length == 0) {
                    if (gw.empty()) {
                        snprintf(cmd, sizeof(cmd), "route -n add -inet6 default -interface %s > /dev/null 2>&1", ifrName.data());
                    }
                    else {
                        snprintf(cmd, sizeof(cmd), "route -n add -inet6 default %s > /dev/null 2>&1", gw.data());
                    }
                }
                else if (gw.empty()) {
                    snprintf(cmd, sizeof(cmd), "route -n add -inet6 %s/%d -interface %s > /dev/null 2>&1", addressIP.data(), std::max<int>(0, std::min<int>(128, prefix_length)), ifrName.data());
                }
                else {
                    snprintf(cmd, sizeof(cmd), "route -n add -inet6 %s/%d %s > /dev/null 2>&1", addressIP.data(), std::max<int>(0, std::min<int>(128, prefix_length)), gw.data());
                }
                return system(cmd) == 0;
            }

            bool DeleteRoute(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept {
                if (ifrName.empty() || addressIP.empty()) {
                    return false;
                }

                char cmd[1200];
                if (addressIP == "::" && prefix_length == 0) {
                    if (gw.empty()) {
                        snprintf(cmd, sizeof(cmd), "route -n delete -inet6 default -interface %s > /dev/null 2>&1", ifrName.data());
                    }
                    else {
                        snprintf(cmd, sizeof(cmd), "route -n delete -inet6 default %s > /dev/null 2>&1", gw.data());
                    }
                }
                else if (gw.empty()) {
                    snprintf(cmd, sizeof(cmd), "route -n delete -inet6 %s/%d -interface %s > /dev/null 2>&1", addressIP.data(), std::max<int>(0, std::min<int>(128, prefix_length)), ifrName.data());
                }
                else {
                    snprintf(cmd, sizeof(cmd), "route -n delete -inet6 %s/%d %s > /dev/null 2>&1", addressIP.data(), std::max<int>(0, std::min<int>(128, prefix_length)), gw.data());
                }
                return system(cmd) == 0;
            }

            void CaptureClientOriginalState(const ::ppp::ipv6::auxiliary::ClientContext& context, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                (void)context;
                (void)nat_mode;
                state.OriginalDnsConfiguration = ppp::unix__::UnixAfx::GetDnsResolveConfiguration();
                ReadPrimaryDefaultRoute(state.OriginalDefaultRouteInterface, state.OriginalDefaultRoute);
                state.DefaultRouteWasPresent = !state.OriginalDefaultRouteInterface.empty();
            }

            bool ApplyClientAddress(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool prefix_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (context.InterfaceName.empty() || !address.is_v6()) {
                    return false;
                }

                ppp::string addr_str = address.to_string();
                char cmd[600];
                snprintf(cmd, sizeof(cmd), "ifconfig %s inet6 %s prefixlen %d alias > /dev/null 2>&1", context.InterfaceName.data(), addr_str.data(), prefix_length);
                if (system(cmd) != 0) {
                    return false;
                }

                state.AddressApplied = true;
                state.Address = addr_str;
                if (prefix_mode) {
                    ppp::string route_prefix = ComputeNetworkAddress(address.to_v6(), prefix_length);
                    state.NetworkRouteApplied = SetRoute(context.InterfaceName, route_prefix, prefix_length, ppp::string());
                }
                return true;
            }

            bool ApplyClientDefaultRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (context.InterfaceName.empty()) {
                    return false;
                }

                ppp::string gateway_string;
                if (gateway.is_v6()) {
                    gateway_string = gateway.to_string();
                }
                else if (!nat_mode) {
                    return false;
                }

                if (!SetRoute(context.InterfaceName, "::", 0, gateway_string)) {
                    return false;
                }

                state.DefaultRouteApplied = true;
                state.DefaultRouteGateway = gateway_string;
                state.DefaultRouteAppliedByInterface = gateway_string.empty();
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
                (void)nat_mode;
                if (context.InterfaceName.empty()) {
                    return;
                }

                if (state.DefaultRouteApplied) {
                    DeleteRoute(context.InterfaceName, "::", 0, state.DefaultRouteGateway);
                }

                if (state.AddressApplied && address.is_v6() && !state.Address.empty()) {
                    if (state.NetworkRouteApplied) {
                        ppp::string route_prefix = ComputeNetworkAddress(address.to_v6(), prefix_length);
                        DeleteRoute(context.InterfaceName, route_prefix, prefix_length, ppp::string());
                    }

                    char cmd[600];
                    snprintf(cmd, sizeof(cmd), "ifconfig %s inet6 %s delete > /dev/null 2>&1", context.InterfaceName.data(), state.Address.data());
                    system(cmd);
                }

                if (state.DnsApplied && !state.OriginalDnsConfiguration.empty()) {
                    ppp::unix__::UnixAfx::SetDnsResolveConfiguration(state.OriginalDnsConfiguration);
                }
                if (state.DefaultRouteApplied && state.DefaultRouteWasPresent && !state.OriginalDefaultRouteInterface.empty()) {
                    SetRoute(state.OriginalDefaultRouteInterface, "::", 0, state.OriginalDefaultRoute);
                }
            }
            }
        }
    }
}
