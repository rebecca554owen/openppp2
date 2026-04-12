#pragma once

#include <ppp/stdafx.h>
#include <ppp/ipv6/IPv6Auxiliary.h>

namespace ppp {
    namespace darwin {
        namespace ipv6 {
            namespace auxiliary {
                ppp::string     ComputeNetworkAddress(const boost::asio::ip::address_v6& address, int prefix_length) noexcept;
                void            ReadPrimaryDefaultRoute(ppp::string& interface_name, ppp::string& gateway) noexcept;
                bool            SetRoute(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept;
                bool            DeleteRoute(const ppp::string& ifrName, const ppp::string& addressIP, int prefix_length, const ppp::string& gw) noexcept;
                void            CaptureClientOriginalState(const ::ppp::ipv6::auxiliary::ClientContext& context, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept;
                bool            ApplyClientAddress(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool prefix_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept;
                bool            ApplyClientDefaultRoute(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& gateway, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept;
                bool            ApplyClientDns(const ::ppp::ipv6::auxiliary::ClientContext& context, const ppp::vector<ppp::string>& dns_servers, ::ppp::ipv6::auxiliary::ClientState& state) noexcept;
                void            RestoreClientConfiguration(const ::ppp::ipv6::auxiliary::ClientContext& context, const boost::asio::ip::address& address, int prefix_length, bool nat_mode, ::ppp::ipv6::auxiliary::ClientState& state) noexcept;
            }
        }
    }
}
