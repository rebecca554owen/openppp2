#include <windows/ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/diagnostics/Error.h>

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
                namespace {
                    struct DefaultRouteSnapshot {
                        int InterfaceIndex = -1;
                        int Metric = -1;
                        ppp::string Gateway;
                    };

                    static bool QueryOriginalDefaultRoutes(ppp::vector<DefaultRouteSnapshot>& routes) noexcept {
                        routes.clear();

                        PMIB_IPFORWARD_TABLE2 table = NULLPTR;
                        if (::GetIpForwardTable2(AF_INET6, &table) != NO_ERROR || NULLPTR == table) {
                            return false;
                        }

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

                            DefaultRouteSnapshot snapshot;
                            snapshot.InterfaceIndex = (int)row.InterfaceIndex;
                            snapshot.Metric = (int)row.Metric;

                            char text[INET6_ADDRSTRLEN] = { 0 };
                            const IN6_ADDR& next_hop = row.NextHop.Ipv6.sin6_addr;
                            if (memcmp(&next_hop, &in6addr_any, sizeof(next_hop)) != 0) {
                                if (NULLPTR != inet_ntop(AF_INET6, &next_hop, text, sizeof(text))) {
                                    snapshot.Gateway = text;
                                }
                            }

                            routes.emplace_back(std::move(snapshot));
                        }

                        ::FreeMibTable(table);
                        std::sort(routes.begin(), routes.end(), 
                            [](const DefaultRouteSnapshot& left, const DefaultRouteSnapshot& right) noexcept {
                                if (left.Metric != right.Metric) {
                                    return left.Metric < right.Metric;
                                }

                                if (left.InterfaceIndex != right.InterfaceIndex) {
                                    return left.InterfaceIndex < right.InterfaceIndex;
                                }
                                return left.Gateway < right.Gateway;
                            });
                        return !routes.empty();
                    }

                    static bool RestoreDefaultRouteSnapshot(const DefaultRouteSnapshot& route) noexcept {
                        if (route.InterfaceIndex < 0) {
                            return false;
                        }

                        int metric = route.Metric > 0 ? route.Metric : 1;
                        if (route.Gateway.empty()) {
                            return ppp::win32::network::SetIPv6DefaultRoute(route.InterfaceIndex, metric);
                        }

                        return ppp::win32::network::SetIPv6DefaultGateway(route.InterfaceIndex, route.Gateway, metric);
                    }
                }

                bool QueryOriginalDefaultRoute(int& interface_index, ppp::string& gateway, int& metric) noexcept {
                    interface_index = -1;
                    gateway.clear();
                    metric = -1;

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
                            metric = (int)row.Metric;
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
                    int metric = -1;
                    state.DefaultRouteWasPresent = QueryOriginalDefaultRoute(state.OriginalDefaultRouteInterfaceIndex, state.OriginalDefaultRoute, metric);
                    state.OriginalDefaultRouteMetric = metric;

                    ppp::vector<DefaultRouteSnapshot> routes;
                    if (QueryOriginalDefaultRoutes(routes)) {
                        state.OriginalDefaultRoutes.reserve(routes.size());
                        for (const DefaultRouteSnapshot& route : routes) {
                            ppp::string encoded = "if=" + stl::to_string<ppp::string>(route.InterfaceIndex) + ";metric=" +
                                stl::to_string<ppp::string>(route.Metric) + ";gw=" + route.Gateway;
                            state.OriginalDefaultRoutes.emplace_back(std::move(encoded));
                        }
                    }
                    
                    if (auto current_ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(context.InterfaceIndex); NULLPTR != current_ni) {
                        state.OriginalDnsServers = current_ni->DnsAddresses;
                    }
                }

                bool ApplyClientAddress(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty() || !address.is_v6()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                    }

                    boost::asio::ip::address_v6 addr_v6 = address.to_v6();
                    // Reject non-routable or interface-scoped address categories.
                    // Link-local (fe80::/10) addresses must not be applied to the
                    // TAP adapter as client addresses because they are interface-scoped
                    // and cannot participate in global routing.
                    if (addr_v6.is_unspecified() || addr_v6.is_multicast() || addr_v6.is_loopback() || addr_v6.is_link_local()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6AddressUnsafe);
                    }

                    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
                    if (prefix_length < ppp::ipv6::IPv6_MAX_PREFIX_LENGTH && addr_v6 == ppp::ipv6::ComputeNetworkAddress(addr_v6, prefix_length)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6AddressUnsafe);
                    }

                    std::string addr_std = address.to_string();
                    ppp::string addr_str(addr_std.data(), addr_std.size());
                    if (!ppp::win32::network::SetIPv6Address(context.InterfaceIndex, addr_str, prefix_length)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientAddressApplyFailed);
                    }

                    state.AddressApplied = true;
                    state.Address = addr_str;
                    return true;
                }

                bool ApplyClientDefaultRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        return false;
                    }

                    if (gateway.is_v6()) {
                        std::string gw_std = gateway.to_string();
                        ppp::string gw_str(gw_std.data(), gw_std.size());
                        if (!ppp::win32::network::SetIPv6DefaultGateway(context.InterfaceIndex, gw_str, 0)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed);
                            return false;
                        }

                        state.DefaultRouteApplied = true;
                        state.DefaultRouteGateway = gw_str;
                        return true;
                    }

                    if (!nat_mode || !ppp::win32::network::SetIPv6DefaultRoute(context.InterfaceIndex, 0)) {
                        ppp::diagnostics::SetLastErrorCode(!nat_mode ?
                            ppp::diagnostics::ErrorCode::IPv6GatewayMissing :
                            ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed);
                        return false;
                    }

                    state.DefaultRouteApplied = true;
                    state.DefaultRouteGateway.clear();
                    return true;
                }

                bool ApplyClientSubnetRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& prefix, int prefix_length, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (!nat_mode) {
                        return true;
                    }

                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty() || !prefix.is_v6()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
                        return false;
                    }

                    std::string prefix_std = prefix.to_string();
                    ppp::string prefix_str(prefix_std.data(), prefix_std.size());
                    prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));

                    ppp::string gateway_str;
                    if (gateway.is_v6()) {
                        std::string gw_std = gateway.to_string();
                        gateway_str.assign(gw_std.data(), gw_std.size());
                    }
                    else if (!nat_mode) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6GatewayMissing);
                    }

                    if (!ppp::win32::network::AddIPv6Route(context.InterfaceIndex, prefix_str, prefix_length, gateway_str, 0)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ClientRouteApplyFailed);
                        return false;
                    }

                    state.SubnetRouteApplied = true;
                    state.SubnetRoutePrefix = prefix_str;
                    state.SubnetRoutePrefixLength = prefix_length;
                    state.SubnetRouteGateway = gateway_str;
                    return true;
                }

                bool ApplyClientDns(const ::ppp::ipv6::auxiliary::ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty() || dns_servers.empty()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed);
                    }

                    if (!ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, dns_servers)) {
                        ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, state.OriginalDnsServers);
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::IPv6ClientDnsApplyFailed);
                    }

                    state.DnsApplied = true;
                    state.DnsServers = dns_servers;
                    ppp::tap::TapWindows::DnsFlushResolverCache();
                    return true;
                }

                void RestoreClientConfiguration(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept {
                    if (NULLPTR == context.Tap || context.InterfaceIndex < 0 || context.InterfaceName.empty()) {
                        return;
                    }


                    if (state.DefaultRouteApplied) {
                        ppp::win32::network::DeleteIPv6DefaultGateway(context.InterfaceIndex, state.DefaultRouteGateway);
                    }

                    if (state.SubnetRouteApplied && !state.SubnetRoutePrefix.empty()) {
                        ppp::win32::network::DeleteIPv6Route(context.InterfaceIndex, state.SubnetRoutePrefix, state.SubnetRoutePrefixLength, state.SubnetRouteGateway);
                    }

                    if (state.AddressApplied && address.is_v6() && !state.Address.empty()) {
                        ppp::win32::network::DeleteIPv6Address(context.InterfaceIndex, state.Address);
                    }

                    if (state.DnsApplied) {
                        ppp::win32::network::SetDnsAddressesV6(context.InterfaceIndex, state.OriginalDnsServers);
                        ppp::tap::TapWindows::DnsFlushResolverCache();
                    }

                    if (state.DefaultRouteApplied && state.DefaultRouteWasPresent) {
                        bool restored = false;
                        for (const ppp::string& encoded : state.OriginalDefaultRoutes) {
                            ppp::vector<ppp::string> segments;
                            if (ppp::Tokenize<ppp::string>(encoded, segments, ";") < 3) {
                                continue;
                            }

                            DefaultRouteSnapshot route;
                            for (const ppp::string& segment : segments) {
                                std::size_t pos = segment.find('=');
                                if (pos == ppp::string::npos) {
                                    continue;
                                }

                                ppp::string key = segment.substr(0, pos);
                                ppp::string value = segment.substr(pos + 1);
                                if (key == "if") {
                                    route.InterfaceIndex = atoi(value.c_str());
                                }
                                else if (key == "metric") {
                                    route.Metric = atoi(value.c_str());
                                }
                                else if (key == "gw") {
                                    route.Gateway = value;
                                }
                            }

                            bool ok = RestoreDefaultRouteSnapshot(route);
                            restored |= ok;
                        }

                        if (!restored && state.OriginalDefaultRouteInterfaceIndex != -1) {
                            int metric = state.OriginalDefaultRouteMetric > 0 ? state.OriginalDefaultRouteMetric : 1;
                            if (state.OriginalDefaultRoute.empty()) {
                                ppp::win32::network::SetIPv6DefaultRoute(state.OriginalDefaultRouteInterfaceIndex, metric);
                            }
                            else {
                                ppp::win32::network::SetIPv6DefaultGateway(state.OriginalDefaultRouteInterfaceIndex, state.OriginalDefaultRoute, metric);
                            }
                        }
                    }
                }
            }
        }
    }
}
