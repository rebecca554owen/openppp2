#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/native/checksum.h>

namespace ppp {
    namespace ipv6 {
        static constexpr int             IPv6_HEADER_MIN_SIZE         = 40;   /* RFC 8200 - Fixed header size */
        static constexpr int             IPv6_ADDRESS_SIZE            = 16;   /* 128 bits / 8 */
        static constexpr int             IPv6_MAX_PREFIX_LENGTH       = 128;
        static constexpr int             IPv6_MIN_PREFIX_LENGTH       = 0;
        static constexpr int             IPv6_DEFAULT_PREFIX_LENGTH   = 64;
        static constexpr int             IPv6_DEFAULT_HOP_LIMIT       = 64;
        static constexpr unsigned char   IPv6_VERSION                 = 6;

        struct PacketHeader {
            ppp::Byte VersionTrafficClass;
            ppp::Byte TrafficClassFlow;
            ppp::UInt16 FlowLabelLow;
            ppp::UInt16 PayloadLength;
            ppp::Byte NextHeader;
            ppp::Byte HopLimit;
            ppp::Byte Source[16];
            ppp::Byte Destination[16];
        };

        static inline bool TryParsePacket(Byte* packet, int packet_length, boost::asio::ip::address_v6& source, boost::asio::ip::address_v6& destination, Byte* next_header = NULLPTR, int* payload_length = NULLPTR) noexcept {
            if (NULLPTR == packet || packet_length < IPv6_HEADER_MIN_SIZE) {
                return false;
            }

            PacketHeader* header = reinterpret_cast<PacketHeader*>(packet);
            if ((header->VersionTrafficClass >> 4) != IPv6_VERSION) {
                return false;
            }

            int body_length = ntohs(header->PayloadLength);
            if (body_length < 0 || packet_length < IPv6_HEADER_MIN_SIZE + body_length) {
                return false;
            }

            boost::asio::ip::address_v6::bytes_type source_bytes;
            boost::asio::ip::address_v6::bytes_type destination_bytes;
            memcpy(source_bytes.data(), header->Source, source_bytes.size());
            memcpy(destination_bytes.data(), header->Destination, destination_bytes.size());

            source = boost::asio::ip::address_v6(source_bytes);
            destination = boost::asio::ip::address_v6(destination_bytes);

            if (NULLPTR != next_header) {
                *next_header = header->NextHeader;
            }
            if (NULLPTR != payload_length) {
                *payload_length = body_length;
            }
            return true;
        }

        static inline unsigned short ComputePseudoChecksum(unsigned char* payload, unsigned int proto_len, const boost::asio::ip::address_v6& source, const boost::asio::ip::address_v6& destination, unsigned int next_header) noexcept {
            unsigned int acc = 0;
            boost::asio::ip::address_v6::bytes_type source_bytes = source.to_bytes();
            boost::asio::ip::address_v6::bytes_type destination_bytes = destination.to_bytes();

            acc += ppp::net::native::ip_standard_chksum(source_bytes.data(), static_cast<int>(source_bytes.size()));
            acc = ppp::net::native::FOLD_U32T(acc);
            acc += ppp::net::native::ip_standard_chksum(destination_bytes.data(), static_cast<int>(destination_bytes.size()));
            acc = ppp::net::native::FOLD_U32T(acc);
            return ppp::net::native::inet_cksum_pseudo_base(payload, next_header, proto_len, acc);
        }

        static inline boost::asio::ip::address_v6::bytes_type ComputeNetworkBytes(const boost::asio::ip::address_v6::bytes_type& address, int prefix_length) noexcept {
            boost::asio::ip::address_v6::bytes_type bytes = address;
            prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));

            int full_bytes = prefix_length / 8;
            int remainder_bits = prefix_length % 8;
            if (full_bytes < 16) {
                if (remainder_bits != 0) {
                    unsigned char mask = static_cast<unsigned char>(0xff << (8 - remainder_bits));
                    bytes[full_bytes] &= mask;
                    ++full_bytes;
                }

                for (int i = full_bytes; i < 16; ++i) {
                    bytes[i] = 0;
                }
            }

            return bytes;
        }

        static inline boost::asio::ip::address_v6 ComputeNetworkAddress(const boost::asio::ip::address_v6& address, int prefix_length) noexcept {
            return boost::asio::ip::address_v6(ComputeNetworkBytes(address.to_bytes(), prefix_length));
        }

        static inline bool PrefixMatch(const boost::asio::ip::address_v6& address, const boost::asio::ip::address_v6& prefix, int prefix_length) noexcept {
            prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
            boost::asio::ip::address_v6::bytes_type address_bytes = address.to_bytes();
            boost::asio::ip::address_v6::bytes_type prefix_bytes = prefix.to_bytes();

            int full_bytes = prefix_length / 8;
            int remainder_bits = prefix_length % 8;
            for (int i = 0; i < full_bytes; ++i) {
                if (address_bytes[i] != prefix_bytes[i]) {
                    return false;
                }
            }

            if (remainder_bits != 0 && full_bytes < 16) {
                unsigned char mask = static_cast<unsigned char>(0xff << (8 - remainder_bits));
                if ((address_bytes[full_bytes] & mask) != (prefix_bytes[full_bytes] & mask)) {
                    return false;
                }
            }

            return true;
        }
    }
}
