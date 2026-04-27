#pragma once

/**
 * @file checksum.h
 * @brief DNS parsing helpers, bit utilities, and Internet checksum primitives.
 */

#include <ppp/stdafx.h>

// Platform-specific networking headers for socket address structures and byte order.
#if _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>   // Linux: defines ntohs, htons, etc.
#include <arpa/inet.h>    // MacOS / Darwin: provides inet_ntoa, etc.
#endif

namespace ppp {
    namespace net {
        namespace native {
            /**
             * @brief DNS packet parsing utilities.
             */
            namespace dns {

                // -----------------------------------------------------------------------
                // DNS Header Structure (packed, network byte order)
                // According to RFC 1035, section 4.1.1
                // -----------------------------------------------------------------------
#pragma pack(push, 1)
                struct
#if defined(__GNUC__) || defined(__clang__)
                    __attribute__((packed))     // GCC/Clang: ensure no padding between fields
#endif
                    dns_hdr{
                        uint16_t usTransID;         ///< Transaction ID: matches query with response
                        uint16_t usFlags;           ///< Flags: QR, OPCODE, AA, TC, RD, RA, Z, RCODE
                        uint16_t usQuestionCount;   ///< Number of entries in the question section (QDCOUNT)
                        uint16_t usAnswerCount;     ///< Number of resource records in the answer section (ANCOUNT)
                        uint16_t usAuthorityCount;  ///< Number of NS records in the authority section (NSCOUNT)
                        uint16_t usAdditionalCount; ///< Number of resource records in the additional section (ARCOUNT)
                };
#pragma pack(pop)

                // -----------------------------------------------------------------------
                // DNS Protocol Constants (RFC 1035)
                // -----------------------------------------------------------------------

                /// @brief Maximum length of a domain name in wire format (RFC 1035: 255 octets).
                static constexpr int MAX_DOMAINNAME_LEN = 255;

                /// @brief Standard DNS server port (53).
                static constexpr int DNS_PORT = PPP_DNS_SYS_PORT;

                /// @brief Size of the QTYPE / TYPE field in bytes.
                static constexpr int DNS_TYPE_SIZE = 2;

                /// @brief Size of the QCLASS / CLASS field in bytes.
                static constexpr int DNS_CLASS_SIZE = 2;

                /// @brief Size of the TTL field in resource records (seconds).
                static constexpr int DNS_TTL_SIZE = 4;

                /// @brief Size of the RDLENGTH field in resource records.
                static constexpr int DNS_DATALEN_SIZE = 2;

                /// @brief Record type A: IPv4 address.
                static constexpr int DNS_TYPE_A = 0x0001;

                /// @brief Record type AAAA: IPv6 address.
                static constexpr int DNS_TYPE_AAAA = 0x001c;

                /// @brief Record type CNAME: canonical name (alias).
                static constexpr int DNS_TYPE_CNAME = 0x0005;

                /// @brief Class IN: the Internet.
                static constexpr int DNS_CLASS_IN = 0x0001;

                /// @brief Maximum safe size for a DNS packet header plus a typical query.
                static constexpr int DNS_PACKET_MAX_SIZE = (sizeof(struct dns_hdr) + MAX_DOMAINNAME_LEN + DNS_TYPE_SIZE + DNS_CLASS_SIZE);

                // -----------------------------------------------------------------------
                // Public DNS Query Extraction Functions
                // -----------------------------------------------------------------------

                /// @brief Extract the query domain name from a DNS packet using default filters.
                ///        Accepts only standard queries (QR=0, OPCODE=0). No further filtering.
                /// @param szPacketStartPos  Pointer to the beginning of the DNS packet.
                /// @param nPacketLength     Total length of the packet in bytes.
                /// @return Decoded domain name as a string, or empty string on failure.
                ppp::string ExtractHost(
                    const Byte* szPacketStartPos,
                    int nPacketLength) noexcept;

                /// @brief Extract domain name using a custom header predicate.
                ///        The second predicate (on name/type/class) accepts everything.
                /// @param szPacketStartPos  Pointer to the DNS packet.
                /// @param nPacketLength     Packet length.
                /// @param fPredicateB       Predicate that receives the DNS header; return true to continue.
                /// @return Decoded domain name, or empty string if predicate rejects or parsing fails.
                ppp::string ExtractHostX(
                    const Byte* szPacketStartPos,
                    int nPacketLength,
                    const ppp::function<bool(dns_hdr*)>& fPredicateB) noexcept;

                /// @brief Extract domain name using a custom extended predicate (header + name + type + class).
                ///        The header predicate uses default filtering (standard query only).
                /// @param szPacketStartPos  Pointer to the DNS packet.
                /// @param nPacketLength     Packet length.
                /// @param fPredicateE       Predicate that receives header, domain name, QTYPE, QCLASS.
                /// @return Decoded domain name, or empty string if predicate rejects or parsing fails.
                ppp::string ExtractHostY(
                    const Byte* szPacketStartPos,
                    int nPacketLength,
                    const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>& fPredicateE) noexcept;

                /// @brief Most flexible extraction: both predicates can be customized.
                /// @param szPacketStartPos  Pointer to the DNS packet.
                /// @param nPacketLength     Packet length.
                /// @param fPredicateB       Predicate on DNS header.
                /// @param fPredicateE       Predicate on (header, name, QTYPE, QCLASS).
                /// @return Decoded domain name, or empty string on rejection or error.
                ppp::string ExtractHostZ(
                    const Byte* szPacketStartPos,
                    int nPacketLength,
                    const ppp::function<bool(dns_hdr*)>& fPredicateB,
                    const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>& fPredicateE) noexcept;

            } // namespace dns

            // -----------------------------------------------------------------------
            // Bit Manipulation Utilities
            // -----------------------------------------------------------------------

            /// @brief Extract a field of 'length' bits from byte 'b', starting at 'offset' (0=LSB).
            /// @param b       Input byte.
            /// @param offset  Bit offset (0..7).
            /// @param length  Number of bits to extract (1..8).
            /// @return Extracted value, right-aligned.
            inline Byte GetBitValueAt(Byte b, Byte offset, Byte length) noexcept {
                return (Byte)((b >> offset) & ~(0xff << length));
            }

            /// @brief Extract a single bit from byte 'b' at given offset.
            /// @param b       Input byte.
            /// @param offset  Bit offset (0..7).
            /// @return 1 or 0.
            inline Byte GetBitValueAt(Byte b, Byte offset) noexcept {
                return GetBitValueAt(b, offset, 1);
            }

            /// @brief Set a field of 'length' bits in byte 'b' to 'value' (right-aligned).
            /// @param b       Original byte.
            /// @param offset  Bit offset where the field starts.
            /// @param length  Number of bits in the field.
            /// @param value   New value for the field (only low 'length' bits are used).
            /// @return Modified byte.
            inline Byte SetBitValueAt(Byte b, Byte offset, Byte length, Byte value) noexcept {
                int mask = ~(0xff << length);
                value = (Byte)(value & mask);
                return (Byte)((value << offset) | (b & ~(mask << offset)));
            }

            /// @brief Set a single bit in byte 'b' at given offset to 0 or 1.
            /// @param b       Original byte.
            /// @param offset  Bit offset.
            /// @param value   0 or 1.
            /// @return Modified byte.
            inline Byte SetBitValueAt(Byte b, Byte offset, Byte value) noexcept {
                return SetBitValueAt(b, offset, 1, value);
            }

            // -----------------------------------------------------------------------
            // Checksum Functions (used for IP, TCP, UDP, ICMP)
            // -----------------------------------------------------------------------

            /// @brief Standard Internet checksum (one's complement of the 16-bit sum).
            /// @param dataptr  Pointer to data buffer.
            /// @param len      Length in bytes.
            /// @return The 16-bit checksum (in network byte order).
            unsigned short ip_standard_chksum(void* dataptr, int len) noexcept;

            /// @brief Convenience wrapper: returns the one's complement (Internet checksum).
            inline unsigned short inet_chksum(void* dataptr, int len) noexcept {
                return (unsigned short)~ip_standard_chksum(dataptr, len);
            }

            /// @brief Fold a 32-bit value to 16 bits by adding the upper and lower halves.
            /// @param u  32-bit unsigned integer.
            /// @return  Folded 32-bit value (still may need further folding).
            inline unsigned int FOLD_U32T(unsigned int u) noexcept {
                return ((unsigned int)(((u) >> 16) + ((u) & 0x0000ffffUL)));
            }

            /// @brief Swap the two bytes of a 16-bit word (endian conversion).
            /// @param w  Input word (as unsigned int, only low 16 bits used).
            /// @return  Byte-swapped value.
            inline unsigned int SWAP_BYTES_IN_WORD(unsigned int w) noexcept {
                return (((w) & 0xff) << 8) | (((w) & 0xff00) >> 8);
            }

            /// @brief Pseudo-header checksum for TCP/UDP (base part, without IP addresses).
            /// @param payload    Pointer to the transport layer segment.
            /// @param proto      Protocol number (IPPROTO_TCP or IPPROTO_UDP).
            /// @param proto_len  Length of the transport segment (including header).
            /// @param acc        Initial accumulator (already containing IP addresses).
            /// @return The final 16-bit checksum (one's complement).
            inline unsigned short inet_cksum_pseudo_base(unsigned char* payload,
                unsigned int proto,
                unsigned int proto_len,
                unsigned int acc) noexcept {
                bool swapped = false;
                acc += ip_standard_chksum(payload, (int)proto_len);
                acc = FOLD_U32T(acc);

                if (proto_len % 2 != 0) {
                    swapped = !swapped;
                    acc = SWAP_BYTES_IN_WORD(acc);
                }

                if (swapped) {
                    acc = SWAP_BYTES_IN_WORD(acc);
                }

                acc += htons((unsigned short)proto);
                acc += htons((unsigned short)proto_len);

                acc = FOLD_U32T(acc);
                acc = FOLD_U32T(acc);

                return (unsigned short)~(acc & 0xffffUL);
            }

            /// @brief Full pseudo-header checksum for TCP/UDP including source/dest IP.
            /// @param payload    Pointer to the transport layer segment.
            /// @param proto      Protocol number.
            /// @param proto_len  Length of the transport segment.
            /// @param src        Source IPv4 address (network byte order).
            /// @param dest       Destination IPv4 address (network byte order).
            /// @return The 16-bit Internet checksum.
            inline unsigned short inet_chksum_pseudo(unsigned char* payload,
                unsigned int proto,
                unsigned int proto_len,
                unsigned int src,
                unsigned int dest) noexcept {
                unsigned int acc;
                unsigned int addr;

                // Add source and destination IP addresses (split into 16-bit halves).
                addr = src;
                acc = (addr & 0xffff);
                acc = (acc + ((addr >> 16) & 0xffff));
                addr = dest;
                acc = (acc + (addr & 0xffff));
                acc = (acc + ((addr >> 16) & 0xffff));

                // Fold down to 16 bits.
                acc = FOLD_U32T(acc);
                acc = FOLD_U32T(acc);

                return inet_cksum_pseudo_base(payload, proto, proto_len, acc);
            }

        } // namespace native
    } // namespace net
} // namespace ppp
