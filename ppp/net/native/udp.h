#pragma once

/**
 * @file udp.h
 * @brief Defines the native IPv4 UDP header layout (RFC 768) and parser.
 *
 * All multi-byte fields inside `udp_hdr` are stored in network byte order
 * (big-endian).  Use ntohs()/htons() for host-byte-order access.
 */

#include <memory>
#include <vector>

#include <ppp/net/native/ip.h>

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1)
            /**
             * @brief IPv4 UDP datagram header (RFC 768).
             *
             * All fields are in network byte order (big-endian).
             * Use ntohs()/htons() for host-byte-order conversion.
             * The packed attribute ensures no compiler-inserted padding.
             */
            struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            udp_hdr {
            public:
                /** @brief Source UDP port in network byte order. */
                unsigned short                  src;
                /** @brief Destination UDP port in network byte order. */
                unsigned short                  dest;  /* src/dest UDP ports */
                /** @brief UDP datagram length in bytes, in network byte order. */
                unsigned short                  len;
                /** @brief UDP checksum in network byte order. */
                unsigned short                  chksum;

            public:
                /**
                 * @brief Parses a UDP header from an IPv4 packet payload.
                 * @param iphdr Parsed IPv4 header associated with @p packet.
                 * @param packet Pointer to the full packet buffer.
                 * @param size Packet size in bytes.
                 * @return Pointer to a valid UDP header on success, otherwise nullptr.
                 */
                static struct udp_hdr*          Parse(struct ip_hdr* iphdr, const void* packet, int size) noexcept;
            };
#pragma pack(pop)
        }
    }
}
