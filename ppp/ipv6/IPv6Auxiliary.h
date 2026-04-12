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
                bool                                                          PrefixRouteApplied = false;
                bool                                                          NetworkRouteApplied = false;
                bool                                                          DefaultRouteApplied = false;
                bool                                                          DnsApplied = false;
                bool                                                          DefaultRouteWasPresent = false;
                bool                                                          DefaultRouteAppliedByInterface = false;
                int                                                           OriginalDefaultRouteInterfaceIndex = -1;
                ppp::string                                                   Address;
                ppp::string                                                   DefaultRouteGateway;
                ppp::string                                                   OriginalDefaultRouteInterface;
                ppp::vector<ppp::string>                                      DnsServers;
                ppp::vector<ppp::string>                                      OriginalDnsServers;
                ppp::string                                                   OriginalDnsConfiguration;
                ppp::string                                                   OriginalDefaultRoute;

                inline void                                                   Clear() noexcept {
                    AddressApplied = false;
                    PrefixRouteApplied = false;
                    NetworkRouteApplied = false;
                    DefaultRouteApplied = false;
                    DnsApplied = false;
                    DefaultRouteWasPresent = false;
                    DefaultRouteAppliedByInterface = false;
                    OriginalDefaultRouteInterfaceIndex = -1;
                    Address.clear();
                    DefaultRouteGateway.clear();
                    OriginalDefaultRouteInterface.clear();
                    DnsServers.clear();
                    OriginalDnsServers.clear();
                    OriginalDnsConfiguration.clear();
                    OriginalDefaultRoute.clear();
                }
            };

            bool                                                              PrepareServerEnvironment(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration, const ppp::string& preferred_nic) noexcept;
            bool                                                              ClientSupportsManaged() noexcept;
            void                                                              CaptureClientOriginalState(const ClientContext& context, bool nat_mode, ClientState& state) noexcept;
            bool                                                              ApplyClientAddress(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool prefix_mode, ClientState& state) noexcept;
            bool                                                              ApplyClientDefaultRoute(const ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ClientState& state) noexcept;
            bool                                                              ApplyClientDns(const ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ClientState& state) noexcept;
            void                                                              RestoreClientConfiguration(const ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ClientState& state) noexcept;
        }
    }
}
