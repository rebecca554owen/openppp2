#pragma once

/**
 * @file DnsUdpRelay.h
 * @brief Legacy UDP DNS relay (socket protect + async receive).
 */

#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/dns/DnsWireValidation.h>
#include <ppp/stdafx.h>

namespace ppp {
    namespace coroutines {
        class YieldContext;
    }
}

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace dns {

                class DnsUdpRelay final {
                public:
                    static bool ShouldAcceptRelayResponse(
                        const boost::asio::ip::udp::endpoint& received_from,
                        const boost::asio::ip::udp::endpoint& expected_server,
                        const Byte* query,
                        int query_length,
                        const Byte* response,
                        int response_length) noexcept {

                        return received_from.address() == expected_server.address() &&
                            received_from.port() == expected_server.port() &&
                            ppp::dns::detail::IsDnsResponseForQuery(
                                query, static_cast<size_t>(query_length),
                                response, static_cast<size_t>(response_length));
                    }

                    static bool CanSpawn(
                        const DnsHostPorts& host,
                        const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                        return host.IsValid() && NULLPTR != exchanger;
                    }

                    static bool Spawn(
                        const DnsHostPorts& host,
                        const std::shared_ptr<VEthernetExchanger>& exchanger,
                        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const boost::asio::ip::address& serverIP,
                        const boost::asio::ip::address& destinationIP) noexcept;

                    static bool RunCoroutine(
                        const DnsHostPorts& host,
                        ppp::coroutines::YieldContext& y,
                        const std::shared_ptr<boost::asio::ip::udp::socket>& socket,
                        const std::shared_ptr<Byte>& buffer,
                        const boost::asio::ip::address& serverIP,
                        const std::shared_ptr<VEthernetExchanger>& exchanger,
                        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const std::shared_ptr<boost::asio::io_context>& context,
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destinationEP) noexcept;
                };

            }
        }
    }
}
