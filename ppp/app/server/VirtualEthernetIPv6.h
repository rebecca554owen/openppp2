#pragma once

/**
 * @file VirtualEthernetIPv6.h
 * @brief Provides lightweight IPv6 parsing and checksum helpers for virtual ethernet server paths.
 * @author OPENPPP2 Team
 * @license GPL-3.0
 */

#include <ppp/ipv6/IPv6Packet.h>

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Alias of the minimal IPv6 fixed header used by virtual ethernet routines.
             */
            using VirtualEthernetIPv6MinimalHeader = ::ppp::ipv6::PacketHeader;

            /**
             * @brief Parses source and destination IPv6 addresses from a raw packet.
             * @param packet Raw packet bytes.
             * @param packet_length Packet length in bytes.
             * @param source Receives parsed source IPv6 address.
             * @param destination Receives parsed destination IPv6 address.
             * @return True when the packet is a valid IPv6 packet and addresses were extracted.
             */
            static inline bool ParseVirtualEthernetIPv6Header(ppp::Byte* packet, int packet_length, boost::asio::ip::address_v6& source, boost::asio::ip::address_v6& destination) noexcept {
                return ::ppp::ipv6::TryParsePacket(packet, packet_length, source, destination);
            }

            /**
             * @brief Computes IPv6 pseudo-header checksum for upper-layer payload.
             * @param payload Upper-layer payload buffer (for example ICMPv6 segment).
             * @param proto_len Upper-layer payload length.
             * @param source IPv6 source address.
             * @param destination IPv6 destination address.
             * @param next_header IPv6 next-header protocol number.
             * @return Calculated checksum in network byte order.
             */
            static inline unsigned short VirtualEthernetIPv6PseudoChecksum(unsigned char* payload, unsigned int proto_len, const boost::asio::ip::address_v6& source, const boost::asio::ip::address_v6& destination, unsigned int next_header) noexcept {
                return ::ppp::ipv6::ComputePseudoChecksum(payload, proto_len, source, destination, next_header);
            }
        }
    }
}
