#pragma once

#include <ppp/net/native/ip.h>

/// @file icmp.h
/// @brief ICMP message types and ICMP header layout.

namespace ppp {
    namespace net {
        namespace native {
            /// @brief ICMP message type values.
            enum IcmpType {
                ICMP_ER     = 0,  /* echo reply */
                ICMP_DUR    = 3,  /* destination unreachable */
                ICMP_SQ     = 4,  /* source quench */
                ICMP_RD     = 5,  /* redirect */
                ICMP_ECHO   = 8,  /* echo */
                ICMP_TE     = 11, /* time exceeded */
                ICMP_PP     = 12, /* parameter problem */
                ICMP_TS     = 13, /* timestamp */
                ICMP_TSR    = 14, /* timestamp reply */
                ICMP_IRQ    = 15, /* information request */
                ICMP_IR     = 16, /* information reply */
                ICMP_AM     = 17, /* address mask request */
                ICMP_AMR    = 18, /* address mask reply */
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
