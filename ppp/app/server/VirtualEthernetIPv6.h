#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/native/checksum.h>

namespace ppp {
    namespace app {
        namespace server {
            struct VirtualEthernetIPv6MinimalHeader {
                ppp::Byte VersionTrafficClass;
                ppp::Byte TrafficClassFlow;
                ppp::UInt16 FlowLabelLow;
                ppp::UInt16 PayloadLength;
                ppp::Byte NextHeader;
                ppp::Byte HopLimit;
                ppp::Byte Source[16];
                ppp::Byte Destination[16];
            };

            static inline bool ParseVirtualEthernetIPv6Header(ppp::Byte* packet, int packet_length, boost::asio::ip::address_v6& source, boost::asio::ip::address_v6& destination) noexcept {
                if (NULLPTR == packet || packet_length < 40) {
                    return false;
                }

                VirtualEthernetIPv6MinimalHeader* header = reinterpret_cast<VirtualEthernetIPv6MinimalHeader*>(packet);
                if ((header->VersionTrafficClass >> 4) != 6) {
                    return false;
                }

                boost::asio::ip::address_v6::bytes_type source_bytes;
                boost::asio::ip::address_v6::bytes_type destination_bytes;
                memcpy(source_bytes.data(), header->Source, source_bytes.size());
                memcpy(destination_bytes.data(), header->Destination, destination_bytes.size());
                source = boost::asio::ip::address_v6(source_bytes);
                destination = boost::asio::ip::address_v6(destination_bytes);
                return true;
            }

            static inline unsigned short VirtualEthernetIPv6PseudoChecksum(unsigned char* payload, unsigned int proto_len, const boost::asio::ip::address_v6& source, const boost::asio::ip::address_v6& destination, unsigned int next_header) noexcept {
                unsigned int acc = 0;
                boost::asio::ip::address_v6::bytes_type source_bytes = source.to_bytes();
                boost::asio::ip::address_v6::bytes_type destination_bytes = destination.to_bytes();

                acc += ppp::net::native::ip_standard_chksum(source_bytes.data(), static_cast<int>(source_bytes.size()));
                acc = ppp::net::native::FOLD_U32T(acc);
                acc += ppp::net::native::ip_standard_chksum(destination_bytes.data(), static_cast<int>(destination_bytes.size()));
                acc = ppp::net::native::FOLD_U32T(acc);
                return ppp::net::native::inet_cksum_pseudo_base(payload, next_header, proto_len, acc);
            }
        }
    }
}
