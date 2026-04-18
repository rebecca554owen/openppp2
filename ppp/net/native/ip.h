#pragma once

#include <stdio.h>
#include <stdint.h>

/// @file ip.h
/// @brief IPv4 header structure, protocol constants, and helper utilities.

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1)
            /// @brief IPv4 packet header and utility helpers.
            struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            ip_hdr {
            public:
                /// @brief Fragmentation and offset flags used in the IPv4 header.
                enum Flags {
                    IP_RF                                                   = 0x8000,            /* reserved fragment flag */
                    IP_DF                                                   = 0x4000,            /* dont fragment flag */
                    IP_MF                                                   = 0x2000,            /* more fragments flag */
                    IP_OFFMASK                                              = 0x1fff,            /* mask for fragmenting bits */
                };

            public:
                 /// @brief Combined IPv4 version (high nibble) and header length (low nibble).
                 /* version / header length / type of service */
                 unsigned char                                              v_hl;
                 /// @brief Type of service / DSCP and ECN bits.
                 /* type of service */
                 unsigned char                                              tos;
                 /// @brief Total IPv4 packet length in bytes.
                 /* total length */
                 unsigned short                                             len;
                 /// @brief Datagram identification value.
                 /* identification */
                 unsigned short                                             id;
                 /// @brief Fragment flags and fragment offset.
                 /* fragment offset field */                                
                 unsigned short                                             flags;
                 /// @brief Time-to-live value.
                 /* time to live */
                 unsigned char                                              ttl;
                 /// @brief Encapsulated upper-layer protocol number.
                 /* protocol */
                 unsigned char                                              proto;
                 /// @brief IPv4 header checksum.
                 /* checksum */
                 unsigned short                                             chksum;
                 /// @brief Source IPv4 address.
                 /* source and destination IP addresses */
                 unsigned int                                               src;
                 union {
                    /// @brief Destination IPv4 address.
                    unsigned int                                            dst;
                    /// @brief Alias for destination IPv4 address.
                    unsigned int                                            dest;
                 };

            public:
                /// @brief Extracts IPv4 version from @p v_hl.
                /// @param hdr IPv4 header pointer.
                /// @return IPv4 version value.
                static int                                                  IPH_V(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->v_hl >> 4);      
                }       
                /// @brief Extracts IPv4 header length in 32-bit words from @p v_hl.
                /// @param hdr IPv4 header pointer.
                /// @return Header length in 32-bit words.
                static int                                                  IPH_HL(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->v_hl & 0x0f);        
                }       
                /// @brief Extracts protocol field as an unsigned byte value.
                /// @param hdr IPv4 header pointer.
                /// @return Protocol number.
                static int                                                  IPH_PROTO(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->proto & 0xff);       
                }       
                /// @brief Returns raw fragment flags/offset field.
                /// @param hdr IPv4 header pointer.
                /// @return Fragmentation field value.
                static int                                                  IPH_OFFSET(struct ip_hdr* hdr) noexcept {
                    return (hdr)->flags;        
                }       
                /// @brief Extracts TTL field as an unsigned byte value.
                /// @param hdr IPv4 header pointer.
                /// @return TTL value.
                static int                                                  IPH_TTL(struct ip_hdr* hdr) noexcept {
                    return ((hdr)->ttl & 0xff);
                }

            public:
                /// @brief Clamps an MTU value to protocol-safe bounds.
                /// @param mtu Input MTU candidate.
                /// @param v4_or_v6 true for IPv4 bounds; false for IPv6 bounds.
                /// @return Bounded MTU value.
                static int                                                  Mtu(int mtu, bool v4_or_v6) noexcept {
                    static constexpr int MTU_V4_MIN = 68;
                    static constexpr int MTU_V6_MIN = 1280;

                    if (mtu > ip_hdr::MTU) {
                        mtu = ip_hdr::MTU;
                    }
                    elif(v4_or_v6) {
                        if (mtu < MTU_V4_MIN) {
                            mtu = MTU_V4_MIN;
                        }
                    }
                    elif(mtu < MTU_V6_MIN) {
                        mtu = MTU_V6_MIN;
                    }

                    return mtu;
                }
                /// @brief Computes maximum segment size from bounded MTU.
                /// @param mtu Input MTU candidate.
                /// @param v4_or_v6 true for IPv4 overhead; false for IPv6 overhead.
                /// @return MSS value after IP header deduction.
                static int                                                  Mss(int mtu, bool v4_or_v6) noexcept {
                    mtu = ip_hdr::Mtu(mtu, v4_or_v6);
                    if (v4_or_v6) {
                        return mtu - (ip_hdr::IP_HLEN << 0);
                    }
                    else {
                        return mtu - (ip_hdr::IP_HLEN << 1);
                    }
                }

            public:
                /// @brief Parses an IPv4 header from raw packet bytes.
                /// @param packet Pointer to packet bytes.
                /// @param size [in/out] Packet size on input; remaining size after parse on output.
                /// @return Parsed IPv4 header pointer, or null on failure.
                static struct ip_hdr*                                       Parse(const void* packet, int& size) noexcept;
                /// @brief Generates a new IPv4 identification value.
                /// @return Monotonic or pseudo-random IPv4 ID.
                static unsigned short                                       NewId() noexcept;

            public:
                /// @brief Default IPv4 header length in bytes.
                static const int                                            IP_HLEN;
                /// @brief Default IPv4 time-to-live value.
                static const unsigned char                                  IP_DFT_TTL;

            public:
                /// @brief IPv4 protocol version number.
                static constexpr unsigned char                              IP_VER                  = 4;
                /// @brief IPv4 wildcard address value.
                static constexpr unsigned int                               IP_ADDR_ANY_VALUE       = INADDR_ANY;
                /// @brief IPv4 broadcast address value.
                static constexpr unsigned int                               IP_ADDR_BROADCAST_VALUE = INADDR_BROADCAST;
                /// @brief Default routine TOS mode.
                static constexpr int                                        TOS_ROUTIN_MODE         = 0;
                /// @brief IP-in-IP protocol number.
                static constexpr unsigned char                              IP_PROTO_IP             = 0;
                /// @brief ICMP protocol number.
                static constexpr unsigned char                              IP_PROTO_ICMP           = 1;
                /// @brief UDP protocol number.
                static constexpr unsigned char                              IP_PROTO_UDP            = 17;
                /// @brief TCP protocol number.
                static constexpr unsigned char                              IP_PROTO_TCP            = 6;
                /// @brief Default Ethernet MTU for IPv4 payload.
                static constexpr int                                        MTU                     = 1500;
            };
#pragma pack(pop)
        }
    }
}
