#pragma once

#include <ppp/net/native/ip.h>

/// @file icmp.h
/// @brief ICMP message type enumeration and ICMP header layout (RFC 792).
///
/// All multi-byte fields inside `icmp_hdr` are in network byte order
/// (big-endian).  Use ntohs()/htons() when accessing `icmp_id` and
/// `icmp_seq` on little-endian hosts.

namespace ppp {
    namespace net {
        namespace native {
            /**
             * @brief ICMP message type values as defined by RFC 792.
             *
             * All fields are in network byte order (big-endian).
             * Use ntohs()/htons() for host-byte-order conversion.
             */
            enum IcmpType {
                ICMP_ER     = 0,  ///< Echo reply.
                ICMP_DUR    = 3,  ///< Destination unreachable.
                ICMP_SQ     = 4,  ///< Source quench (deprecated).
                ICMP_RD     = 5,  ///< Redirect.
                ICMP_ECHO   = 8,  ///< Echo request.
                ICMP_TE     = 11, ///< Time exceeded.
                ICMP_PP     = 12, ///< Parameter problem.
                ICMP_TS     = 13, ///< Timestamp request.
                ICMP_TSR    = 14, ///< Timestamp reply.
                ICMP_IRQ    = 15, ///< Information request (obsolete).
                ICMP_IR     = 16, ///< Information reply (obsolete).
                ICMP_AM     = 17, ///< Address mask request.
                ICMP_AMR    = 18, ///< Address mask reply.
            };

#pragma pack(push, 1)
            /// @brief ICMP header format (RFC 792).
            struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            icmp_hdr {                           // RFC 792(http://www.faqs.org/rfcs/rfc792.html)
            public:
                /// @brief ICMP type field.
                unsigned char           icmp_type;      // icmp service type, 8 echo request, 0 echo reply
                /// @brief ICMP code field.
                unsigned char           icmp_code;      // icmp header code
                /// @brief ICMP header checksum.
                unsigned short          icmp_chksum;    // icmp header chksum
                /// @brief Echo identifier.
                unsigned short          icmp_id;        // icmp packet identification
                /// @brief Echo sequence number.
                unsigned short          icmp_seq;       // icmp packet sequent

            public:
                /// @brief Parses and validates an ICMP header from an IP packet payload.
                /// @param iphdr Parsed IPv4 header associated with the packet.
                /// @param packet Pointer to the start of packet bytes.
                /// @param size Total packet size in bytes.
                /// @return Pointer to parsed ICMP header, or null on failure.
                static struct icmp_hdr* Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept;
            };
#pragma pack(pop)
        }
    }
}
