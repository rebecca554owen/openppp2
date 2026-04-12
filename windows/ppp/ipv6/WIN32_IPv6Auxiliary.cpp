#include <windows/ppp/ipv6/IPv6Auxiliary.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>
#include <iphlpapi.h>

#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/NetworkInterface.h>

namespace ppp {
    namespace win32 {
        namespace ipv6 {
            namespace auxiliary {
            bool QueryOriginalDefaultRoute(int& interface_index, ppp::string& gateway) noexcept {
                interface_index = -1;
                gateway.clear();

                PMIB_IPFORWARD_TABLE2 table = NULLPTR;
                if (::GetIpForwardTable2(AF_INET6, &table) != NO_ERROR || NULLPTR == table) {
                    return false;
                }

                ULONG best_metric = ULONG_MAX;
                bool found = false;
                for (ULONG i = 0; i < table->NumEntries; ++i) {
                    const MIB_IPFORWARD_ROW2& row = table->Table[i];
                    if (row.DestinationPrefix.PrefixLength != 0) {
                        continue;
                    }

                    const SOCKADDR_INET& prefix = row.DestinationPrefix.Prefix;
                    if (prefix.si_family != AF_INET6) {
                        continue;
                    }

                    const IN6_ADDR& prefix_addr = prefix.Ipv6.sin6_addr;
                    if (memcmp(&prefix_addr, &in6addr_any, sizeof(prefix_addr)) != 0) {
                        continue;
                    }

                    if (!found || row.Metric < best_metric) {
                        best_metric = row.Metric;
                        interface_index = (int)row.InterfaceIndex;
                        found = true;

                        char text[INET6_ADDRSTRLEN] = { 0 };
                        const IN6_ADDR& next_hop = row.NextHop.Ipv6.sin6_addr;
                        if (memcmp(&next_hop, &in6addr_any, sizeof(next_hop)) == 0) {
                            gateway.clear();
                        }
                        else if (NULLPTR != inet_ntop(AF_INET6, &next_hop, text, sizeof(text))) {
                            gateway = text;
                        }
                        else {
                            gateway.clear();
                        }
                    }
                }

                ::FreeMibTable(table);
                return found;
            }

            void CaptureClientOriginalState(const ::ppp::ipv6::auxiliary::ClientContext& context, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                (void)nat_mode;
                state.DefaultRouteWasPresent = QueryOriginalDefaultRoute(state.OriginalDefaultRouteInterfaceIndex, state.OriginalDefaultRoute);
                if (auto current_ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(context.InterfaceIndex); NULLPTR != current_ni) {
                    state.OriginalDnsServers = current_ni->DnsAddresses;
                }
            }

            bool ApplyClientAddress(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool prefix_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                (void)prefix_mode;
                if (!address.is_v6()) {
                    return false;
                }

                std::string addr_std = address.to_string();
                ppp::string addr_str(addr_std.data(), addr_std.size());
                if (!ppp::win32::network::SetIPv6Address(context.InterfaceIndex, addr_str, prefix_length)) {
                    return false;
                }

                state.AddressApplied = true;
                state.Address = addr_str;
                return true;
            }

            bool ApplyClientDefaultRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (gateway.is_v6()) {
                    std::string gw_std = gateway.to_string();
                    ppp::string gw_str(gw_std.data(), gw_std.size());
                    if (!ppp::win32::network::SetIPv6DefaultGateway(context.InterfaceIndex, gw_str, 0)) {
                        return false;
                    }

                    state.DefaultRouteApplied = true;
                    state.DefaultRouteGateway = gw_str;
                    return true;
                }

                if (!nat_mode || !ppp::win32::network::SetIPv6DefaultRoute(context.InterfaceIndex, 0)) {
                    return false;
                }

                state.DefaultRouteApplied = true;
                state.DefaultRouteGateway.clear();
                return true;
            }

            bool ApplyClientDns(const ::ppp::ipv6::auxiliary::ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                if (!ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, dns_servers)) {
                    return false;
                }

                state.DnsApplied = true;
                state.DnsServers = dns_servers;
                ppp::tap::TapWindows::DnsFlushResolverCache();
                return true;
            }

            void RestoreClientConfiguration(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                (void)prefix_length;
                (void)nat_mode;

                if (state.DefaultRouteApplied) {
                    ppp::win32::network::DeleteIPv6DefaultGateway(context.InterfaceIndex, state.DefaultRouteGateway);
                }

                if (state.AddressApplied && address.is_v6() && !state.Address.empty()) {
                    ppp::win32::network::DeleteIPv6Address(context.InterfaceIndex, state.Address);
                }

                if (state.DnsApplied) {
                    ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, state.OriginalDnsServers);
                    ppp::tap::TapWindows::DnsFlushResolverCache();
                }

                if (state.DefaultRouteApplied && state.DefaultRouteWasPresent && state.OriginalDefaultRouteInterfaceIndex != -1) {
                    if (state.OriginalDefaultRoute.empty()) {
                        ppp::win32::network::SetIPv6DefaultRoute(state.OriginalDefaultRouteInterfaceIndex, 1);
                    }
                    else {
                        ppp::win32::network::SetIPv6DefaultGateway(state.OriginalDefaultRouteInterfaceIndex, state.OriginalDefaultRoute, 1);
                    }
                }
            }
            }
        }
    }
}
