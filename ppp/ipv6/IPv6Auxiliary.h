#pragma once

#include <ppp/stdafx.h>
#include <ppp/tap/ITap.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace ipv6 {
        namespace auxiliary {
            struct ClientContext {
                ppp::tap::ITap*                                               Tap = NULLPTR;
                int                                                           InterfaceIndex = -1;
                ppp::string                                                   InterfaceName;
            };

            struct ClientState {
                bool                                                          AddressApplied = false;
                bool                                                          DefaultRouteApplied = false;
                bool                                                          SubnetRouteApplied = false;
                bool                                                          DnsApplied = false;
                bool                                                          DefaultRouteWasPresent = false;
                int                                                           OriginalDefaultRouteInterfaceIndex = -1;
                int                                                           OriginalDefaultRouteMetric = -1;
                ppp::string                                                   Address;
                ppp::string                                                   DefaultRouteGateway;
                ppp::string                                                   SubnetRoutePrefix;
                int                                                           SubnetRoutePrefixLength = 0;
                ppp::string                                                   OriginalDefaultRouteInterface;
                ppp::vector<ppp::string>                                      DnsServers;
                ppp::vector<ppp::string>                                      OriginalDnsServers;
                ppp::string                                                   OriginalDnsConfiguration;
                ppp::string                                                   OriginalDefaultRoute;

                inline void                                                   Clear() noexcept {
                    AddressApplied = false;
                    DefaultRouteApplied = false;
                    SubnetRouteApplied = false;
                    DnsApplied = false;
                    DefaultRouteWasPresent = false;
                    OriginalDefaultRouteInterfaceIndex = -1;
                    OriginalDefaultRouteMetric = -1;
                    Address.clear();
                    DefaultRouteGateway.clear();
                    SubnetRoutePrefix.clear();
                    SubnetRoutePrefixLength = 0;
                    OriginalDefaultRouteInterface.clear();
                    DnsServers.clear();
                    OriginalDnsServers.clear();
                    OriginalDnsConfiguration.clear();
                    OriginalDefaultRoute.clear();
                }
            };

            bool                                                              PrepareServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic, const ppp::string& transit_ifname) noexcept;
            bool                                                              ClientSupportsManaged() noexcept;
            void                                                              CaptureClientOriginalState(const ClientContext& context, bool nat_mode, ClientState& state) noexcept;
            bool                                                              ApplyClientAddress(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool gua_mode, ClientState& state) noexcept;
            bool                                                              ApplyClientDefaultRoute(const ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept;
            bool                                                              ApplyClientSubnetRoute(const ClientContext& context, const boost::asio::ip::address& prefix, int prefix_length, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept;
            bool                                                              ApplyClientDns(const ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ClientState& state) noexcept;
            void                                                              RestoreClientConfiguration(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ClientState& state) noexcept;
        }
    }
}
