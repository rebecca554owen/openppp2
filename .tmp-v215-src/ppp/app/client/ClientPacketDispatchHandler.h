#pragma once

#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <memory>

namespace ppp::net::native { struct ip_hdr; }

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;
            class VEthernetExchanger;

            class ClientPacketDispatchHandler {
            public:
                void Bind(VEthernetNetworkSwitcher* owner) noexcept;

                bool OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept;
                bool OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept;
                bool OnPacketInput(const std::shared_ptr<ppp::net::packet::IPFrame>& packet) noexcept;
                bool ERORTE(int ack_id) noexcept;

            private:
                bool IsApprovedIPv6Packet(Byte* packet, int packet_length) noexcept;
                bool OnUdpPacketInput(const std::shared_ptr<ppp::net::packet::IPFrame>& packet) noexcept;
                bool OnIcmpPacketInput(const std::shared_ptr<ppp::net::packet::IPFrame>& packet) noexcept;
                bool RejectBlockedQuic(const std::shared_ptr<ppp::net::packet::IPFrame>& packet, const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept;
                bool ER(const std::shared_ptr<ppp::net::packet::IPFrame>& packet, const std::shared_ptr<ppp::net::packet::IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool TE(const std::shared_ptr<ppp::net::packet::IPFrame>& packet, const std::shared_ptr<ppp::net::packet::IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<ppp::net::packet::IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                bool EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<ppp::net::packet::IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

                VEthernetNetworkSwitcher* owner_ = nullptr;
            };
        }
    }
}
