#pragma once

#include <ppp/stdafx.h>

/**
 * @file eth.h
 * @brief Ethernet MAC address and Ethernet II frame header definitions.
 *
 * All structures use `#pragma pack(push, 1)` / `__attribute__((packed))` to
 * eliminate compiler-inserted padding, so they can be cast directly onto
 * raw network buffers.  Multi-byte fields (e.g. `eth_hdr::type`) are stored
 * in network byte order (big-endian); use ntohs()/htons() when comparing
 * or assigning on little-endian hosts.
 */

namespace ppp {
    namespace net {
        namespace native {
#pragma pack(push, 1) 
            /// @brief Represents a 48-bit Ethernet MAC address.
            struct 
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            eth_addr {
            public:
                /// @brief Number of bytes in a hardware MAC address.
                static const int    ETH_HWADDR_LEN  = 6;

            public:
                union {
                    /// @brief Raw MAC address bytes in network order.
                    uint8_t         s_data[ETH_HWADDR_LEN];
                    struct {
                        /// @brief Low 32 bits for compact zero-check operations.
                        uint32_t    dw;
                        /// @brief High 16 bits for compact zero-check operations.
                        uint16_t    w;
                    }               s_zero;
                };

            public:
                /// @brief Parses a MAC address string into binary form.
                /// @param mac_string Input MAC string, e.g. "aa:bb:cc:dd:ee:ff".
                /// @param mac Output parsed MAC address.
                /// @return true if parsing succeeds; otherwise false.
                bool                TryParse(const char* mac_string, struct eth_addr& mac) noexcept;
                /// @brief Converts this MAC address to a canonical string form.
                /// @return MAC address string.
                ppp::string         ToString() noexcept;
                /// @brief Converts a MAC address to a canonical string form.
                /// @param mac MAC address to convert.
                /// @return MAC address string.
                static ppp::string  ToString(const struct eth_addr& mac) noexcept;
                /// @brief Converts raw bytes to a MAC address string.
                /// @param data Pointer to raw bytes.
                /// @param size Available byte count in @p data.
                /// @return MAC address string, or empty string on invalid input.
                static ppp::string  BytesToMacAddress(const void* data, int size) noexcept;
            };

            /**
             * @brief Ethernet II frame header (IEEE 802.3).
             *
             * Immediately follows the preamble/SFD on the wire.  The @ref type
             * field identifies the encapsulated payload protocol and is stored in
             * network byte order; use ntohs() before comparing against the
             * ETHTYPE_* constants on little-endian platforms.
             */
            struct 
#if !defined(_WIN32)
                __attribute__((packed)) 
#endif
            eth_hdr {
            public:
                /// @brief Destination MAC address.
                eth_addr            dest;
                /// @brief Source MAC address.
                eth_addr            src;
                /// @brief EtherType value in network byte order.
                UInt16              type;

            public:
                /// @brief EtherType for IPv4 payload.
                static const int    ETHTYPE_IP      = 0x0800U;
                /// @brief EtherType for ARP payload.
                static const int    ETHTYPE_ARP     = 0x0806U;
            };
#pragma pack(pop) 
        }
    }
}
