#pragma once

#include <boost/asio/ip/udp.hpp>
#include <memory>

#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>

namespace ppp {
    namespace coroutines {
        class YieldContext;
    }

    namespace app {
        namespace protocol {
            class VirtualEthernetPacket;
        }

        namespace client {
            class VEthernetExchanger;

            class ExchangerStaticEchoChannel {
            public:
                static bool IsValidServerPort(int serverPort) noexcept {
                    return serverPort > ppp::net::IPEndPoint::MinPort && serverPort <= ppp::net::IPEndPoint::MaxPort;
                }

                static bool AcceptsBalancePoolEndpoint(const boost::asio::ip::address& destinationIP) noexcept {
                    return destinationIP.is_v6();
                }

                void Bind(VEthernetExchanger* owner) noexcept;

                void StaticEchoClean() noexcept;
                bool StaticEchoAllocated() noexcept;
                bool StaticEchoSwapAsynchronousSocket() noexcept;
                bool StaticEchoGatewayServer(int ack_id) noexcept;
                bool StaticEchoAllocatedToRemoteExchanger(ppp::coroutines::YieldContext& y) noexcept;
                bool StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept;
                bool StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept;
                bool StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
                bool StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;

            private:
                VEthernetExchanger* owner_ = nullptr;
            };
        }
    }
}
