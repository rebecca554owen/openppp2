#pragma once

#include <ppp/ipv6/IPv6Packet.h>

namespace ppp {
    namespace app {
        namespace server {
            using VirtualEthernetIPv6MinimalHeader = ::ppp::ipv6::PacketHeader;

            static inline bool ParseVirtualEthernetIPv6Header(ppp::Byte* packet, int packet_length, boost::asio::ip::address_v6& source, boost::asio::ip::address_v6& destination) noexcept {
                return ::ppp::ipv6::TryParsePacket(packet, packet_length, source, destination);
            }

            static inline unsigned short VirtualEthernetIPv6PseudoChecksum(unsigned char* payload, unsigned int proto_len, const boost::asio::ip::address_v6& source, const boost::asio::ip::address_v6& destination, unsigned int next_header) noexcept {
                return ::ppp::ipv6::ComputePseudoChecksum(payload, proto_len, source, destination, next_header);
            }
        }
    }
}
