// =======================================================================================
// Module: DNS (Domain Name System) packet query name extraction.
// 
// This module provides safe, crash‑resistant parsing of DNS query packets.
// It implements RFC 1035 name decompression with full bounds checking and
// recursion depth limiting to withstand malicious or malformed packets.
// 
// All public functions are re‑entrant, exception‑neutral, and produce no
// undefined behavior even when presented with arbitrary byte sequences.
// =======================================================================================

#include <ppp/stdafx.h>
#include <ppp/net/native/checksum.h>

#include <cstring>      // std::memcpy, std::strlen
#include <memory>       // std::shared_ptr
#include <new>          // std::bad_alloc

namespace ppp {
    namespace net {
        namespace native {
            namespace dns {

                // ---------------------------------------------------------------------------------------
                // Constants (RFC 1035 and safety limits)
                // ---------------------------------------------------------------------------------------
                /// @brief Buffer size needed to hold the decoded dot‑separated name + null terminator.
                static constexpr int MAX_DOMAINNAME_LEN_STR = MAX_DOMAINNAME_LEN + 1;

                /// @brief Maximum recursion depth when following DNS compression pointers.
                ///        Prevents stack overflow from malicious cycles or deeply nested pointers.
                static constexpr int DNS_MAX_RECURSION_DEPTH = 256;

                /// @brief Maximum length of a single DNS label (RFC 1035: 63 octets).
                static constexpr uint8_t DNS_MAX_LABEL_LEN = 63;

                // ---------------------------------------------------------------------------------------
                // Safe DNS name decompressor (recursive with depth limit)
                // ---------------------------------------------------------------------------------------

                /// @brief Decodes a DNS domain name from its wire format, supporting compression.
                /// @param szEncodedStr      Pointer to the encoded name inside the DNS packet.
                /// @param pusEncodedStrLen  [out] Number of wire octets consumed from the encoded name.
                /// @param szDotStr          Output buffer for the decoded dot‑separated name.
                /// @param nDotStrSize       Size of the output buffer (including null terminator).
                /// @param szPacketStartPos  Start of the whole DNS packet (for compression jumps).
                /// @param szPacketEndPos    One‑past‑last byte of the DNS packet.
                /// @param ppDecodePos       [in/out] Current parsing pointer (updated after name).
                /// @param depth             Current recursion depth (0 on initial call).
                /// @return true if decoding succeeded, false on any error (bounds, truncation, cycle).
                static bool ExtractNameEx(char* szEncodedStr,
                    uint16_t*                   pusEncodedStrLen,
                    char*                       szDotStr,
                    uint16_t                    nDotStrSize,
                    char*                       szPacketStartPos,
                    char*                       szPacketEndPos,
                    char**                      ppDecodePos,
                    int                         depth) noexcept
                {
                    // Guard against excessive recursion (malicious compression loops or deep nesting).
                    if (depth > DNS_MAX_RECURSION_DEPTH) {
                        return false;
                    }

                    // Validate mandatory pointers and ensure the encoded name lies inside the packet.
                    if (NULLPTR == szEncodedStr || NULLPTR == pusEncodedStrLen ||
                        NULLPTR == szDotStr || NULLPTR == ppDecodePos ||
                        szEncodedStr < szPacketStartPos || szEncodedStr >= szPacketEndPos) {
                        return false;
                    }

                    char*& pDecodePos = *ppDecodePos;
                    pDecodePos = szEncodedStr;

                    size_t plainStrLen = 0;          // Number of characters written into szDotStr (excluding null)
                    uint8_t nLabelDataLen = 0;       // Length of the current label (0..63)
                    *pusEncodedStrLen = 0;            // Total wire bytes consumed

                    // Process labels until we hit the terminating zero (end of name).
                    for (;;) {
                        // Ensure we never read past the packet boundary before accessing the label length.
                        if (pDecodePos >= szPacketEndPos) {
                            return false;
                        }

                        nLabelDataLen = static_cast<uint8_t>(*pDecodePos);
                        if (nLabelDataLen == 0x00) {
                            // Reached the terminating zero byte that marks the end of the name.
                            ++pDecodePos;                       // Consume the zero octet.
                            if (plainStrLen > 0) {
                                szDotStr[plainStrLen - 1] = '\0';   // Replace the last dot with null terminator.
                            } else {
                                *szDotStr = '\0';                    // Empty name (root domain) – rare but possible.
                            }
                            
                            *pusEncodedStrLen += 1;             // Account for the terminating zero.
                            return true;
                        }

                        // Distinguish between normal label (0xxxxxxx) and compression pointer (11xxxxxx)
                        if ((nLabelDataLen & 0xC0) == 0) {
                            // ----- Normal label (length octet followed by 'length' data octets) -----

                            // RFC 1035: label length must be between 1 and 63 inclusive.
                            // Length 0 is illegal here because the terminator is handled above.
                            if (nLabelDataLen == 0 || nLabelDataLen > DNS_MAX_LABEL_LEN) {
                                return false;
                            }

                            // Check if the label fits into the output buffer.
                            // +1 accounts for the dot that will be appended after the label.
                            // Use size_t to avoid unsigned integer overflow.
                            if (plainStrLen + static_cast<size_t>(nLabelDataLen) + 1 > static_cast<size_t>(nDotStrSize)) {
                                return false;
                            }

                            // Ensure the entire label data is within the packet bounds (exact boundary allowed).
                            if (pDecodePos + 1 + nLabelDataLen > szPacketEndPos) {
                                return false;
                            }

                            // Copy the label characters (not including the length octet).
                            std::memcpy(szDotStr + plainStrLen, pDecodePos + 1, nLabelDataLen);

                            // Append a dot separator (will be overwritten for the last label).
                            std::memcpy(szDotStr + plainStrLen + nLabelDataLen, ".", 1);

                            // Advance pointers and update lengths.
                            pDecodePos += 1 + nLabelDataLen;
                            plainStrLen += nLabelDataLen + 1;
                            *pusEncodedStrLen += 1 + nLabelDataLen;
                        } else {
                            // ----- Compression pointer (two‑byte sequence: 11 followed by 14‑bit offset) -----
                            // The first two bits are 11; the remaining 14 bits specify an offset from
                            // the start of the packet to another location where the name continues.

                            if (NULLPTR == szPacketStartPos) {
                                return false;
                            }

                            // The pointer occupies 2 bytes; verify they are present.
                            if (pDecodePos + 2 > szPacketEndPos) {
                                return false;
                            }

                            // Read the pointer value safely (no unaligned access).
                            uint16_t usJumpPos = ((pDecodePos[0] & 0x3F) << 8) | static_cast<uint8_t>(pDecodePos[1]);

                            // Validate the offset: it must point to a position within the packet.
                            // Use uintptr_t to avoid signed overflow in pointer arithmetic.
                            uintptr_t packet_len = static_cast<uintptr_t>(szPacketEndPos - szPacketStartPos);
                            if (static_cast<uintptr_t>(usJumpPos) >= packet_len) {
                                return false;   // Jump target is outside the packet → malformed.
                            }

                            // Recursively decode the name starting at the jump position.
                            // The recursive call must NOT change our own pDecodePos.
                            uint16_t nEncodeStrLen = 0;   // Not used directly, but required for API.
                            char* jumpDecodePos = NULLPTR;   // Temporary pointer for the recursive call.
                            if (!ExtractNameEx(szPacketStartPos + usJumpPos,
                                &nEncodeStrLen,
                                szDotStr + plainStrLen,
                                static_cast<uint16_t>(nDotStrSize - plainStrLen),
                                szPacketStartPos,
                                szPacketEndPos,
                                &jumpDecodePos,
                                depth + 1)) {
                                return false;
                            }

                            // Compression pointer consumes exactly 2 bytes in the wire format.
                            // Advance the outer decode position past the pointer.
                            pDecodePos += 2;
                            *pusEncodedStrLen += 2;

                            // The name is fully resolved; we are done (no trailing zero after pointer).
                            return true;
                        }
                    }
                }

                // ---------------------------------------------------------------------------------------
                // Legacy compatibility wrapper (ExtractName) using the new safe implementation.
                // ---------------------------------------------------------------------------------------
                static bool ExtractName(char*                                               szEncodedStr,
                    uint16_t*                                                               pusEncodedStrLen,
                    char*                                                                   szDotStr,
                    uint16_t                                                                nDotStrSize,
                    char*                                                                   szPacketStartPos,
                    char*                                                                   szPacketEndPos,
                    char**                                                                  ppDecodePos) noexcept
                {
                    return ExtractNameEx(szEncodedStr, pusEncodedStrLen, szDotStr, nDotStrSize,
                        szPacketStartPos, szPacketEndPos, ppDecodePos, 0);
                }

                // ---------------------------------------------------------------------------------------
                // Public API: ExtractHostZ – most flexible version with two user‑provided predicates.
                // ---------------------------------------------------------------------------------------

                /// @brief Extracts the query domain name from a DNS packet.
                /// @param szPacketStartPos  Pointer to the beginning of the DNS packet.
                /// @param nPacketLength     Total length of the packet in bytes.
                /// @param fPredicateB       Predicate applied to the DNS header (e.g., check QR bit, QTYPE).
                /// @param fPredicateE       Predicate applied to the extracted name, QTYPE, QCLASS.
                /// @return The decoded domain name as a string, or empty string on failure.
                ppp::string ExtractHostZ(const Byte*                                        szPacketStartPos,
                    int                                                                     nPacketLength,
                    const ppp::function<bool(dns_hdr*)>&                                    fPredicateB,
                    const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>&  fPredicateE) noexcept
                {
                    // Validate that predicates are callable.
                    if (!fPredicateB || !fPredicateE) {
                        return ppp::string();
                    }

                    // Basic integrity: the packet must contain at least a DNS header.
                    if (NULLPTR == szPacketStartPos || nPacketLength < static_cast<int>(sizeof(dns_hdr))) {
                        return ppp::string();
                    }

                    dns_hdr* pDNSHeader = const_cast<dns_hdr*>(reinterpret_cast<const dns_hdr*>(szPacketStartPos));

                    // Apply the first predicate (usually checks for query type and record class).
                    if (!fPredicateB(pDNSHeader)) {
                        return ppp::string();
                    }

                    // The question section must contain at least one query.
                    int nQuestionCount = ntohs(pDNSHeader->usQuestionCount);
                    if (nQuestionCount < 1) {
                        return ppp::string();
                    }

                    // Allocate a temporary buffer for decoding the domain name.
                    std::shared_ptr<Byte> pioBuffers;
                    try {
                        pioBuffers = make_shared_alloc<Byte>(MAX_DOMAINNAME_LEN_STR);
                        if (NULLPTR == pioBuffers) {
                            return ppp::string();   // Allocation failure.
                        }
                    } catch (const std::bad_alloc&) {
                        return ppp::string();       // Exception safety: return empty on allocation failure.
                    }

                    uint16_t pusEncodedStrLen = 0;
                    char* pDecodePos = NULLPTR;
                    char* szDomainDotStr = reinterpret_cast<char*>(pioBuffers.get());
                    char* packetStart = reinterpret_cast<char*>(const_cast<Byte*>(szPacketStartPos));
                    char* packetEnd = packetStart + nPacketLength;

                    // The encoded name starts immediately after the DNS header.
                    if (!ExtractNameEx(reinterpret_cast<char*>(pDNSHeader + 1),
                        &pusEncodedStrLen,
                        szDomainDotStr,
                        static_cast<uint16_t>(MAX_DOMAINNAME_LEN_STR),
                        packetStart,
                        packetEnd,
                        &pDecodePos,
                        0)) {
                        return ppp::string();
                    }

                    // The decoded string is null-terminated; get its length safely.
                    size_t domainLen = std::strlen(szDomainDotStr);
                    if (domainLen == 0) {
                        return ppp::string();   // Empty domain name.
                    }

                    // After the name, the question section contains QTYPE (2 bytes) and QCLASS (2 bytes).
                    // Ensure we have at least 4 bytes remaining.
                    if (pDecodePos + 4 > packetEnd) {
                        return ppp::string();   // Packet truncated before the type/class fields.
                    }

                    // Extract QTYPE and QCLASS (network byte order → host byte order).
                    uint16_t usQueriesType = (static_cast<uint8_t>(pDecodePos[0]) << 8) | static_cast<uint8_t>(pDecodePos[1]);
                    uint16_t usQueriesClass = (static_cast<uint8_t>(pDecodePos[2]) << 8) | static_cast<uint8_t>(pDecodePos[3]);

                    // Construct the result string using the actual decoded length.
                    ppp::string strDomainStr(szDomainDotStr, domainLen);

                    // Apply the second predicate (e.g., filter by QTYPE or QCLASS).
                    if (!fPredicateE(pDNSHeader, strDomainStr, usQueriesType, usQueriesClass)) {
                        return ppp::string();
                    }

                    return strDomainStr;
                }

                // ---------------------------------------------------------------------------------------
                // Public API: ExtractHostY – uses default first predicate, custom second predicate.
                // ---------------------------------------------------------------------------------------
                ppp::string ExtractHostY(const Byte*                                        szPacketStartPos,
                    int                                                                     nPacketLength,
                    const ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)>&  fPredicateE) noexcept
                {
                    // Default first predicate: accept only standard DNS queries (QR=0, OPCODE=0).
                    ppp::function<bool(dns_hdr*)> fPredicateB = 
                        [](dns_hdr* h) noexcept -> bool {
                            uint16_t usFlags = ntohs(h->usFlags);
                            // QR bit (0x8000) must be 0 → query, not response.
                            // OPCODE field (0x7800) must be 0 → standard query.
                            return (usFlags & 0x8000) == 0 && (usFlags & 0x7800) == 0;
                        };
                    return ExtractHostZ(szPacketStartPos, nPacketLength, fPredicateB, fPredicateE);
                }

                // ---------------------------------------------------------------------------------------
                // Public API: ExtractHostX – uses custom first predicate, default second predicate.
                // ---------------------------------------------------------------------------------------
                ppp::string ExtractHostX(const Byte*        szPacketStartPos,
                    int                                     nPacketLength,
                    const ppp::function<bool(dns_hdr*)>&    fPredicateB) noexcept
                {
                    // Default second predicate: accept any extracted name unconditionally.
                    ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)> fPredicateE =
                        [](dns_hdr*, ppp::string&, uint16_t, uint16_t) noexcept -> bool {
                            return true;
                        };
                    return ExtractHostZ(szPacketStartPos, nPacketLength, fPredicateB, fPredicateE);
                }

                // ---------------------------------------------------------------------------------------
                // Public API: ExtractHost – simplest version, using both default predicates.
                // ---------------------------------------------------------------------------------------
                ppp::string ExtractHost(const Byte* szPacketStartPos, int nPacketLength) noexcept
                {
                    // Default first predicate: standard query (QR=0, OPCODE=0).
                    ppp::function<bool(dns_hdr*)> fPredicateB = 
                        [](dns_hdr* h) noexcept -> bool {
                            uint16_t usFlags = ntohs(h->usFlags);
                            return (usFlags & 0x8000) == 0 && (usFlags & 0x7800) == 0;
                        };

                    // Default second predicate: accept all.
                    ppp::function<bool(dns_hdr*, ppp::string&, uint16_t, uint16_t)> fPredicateE =
                        [](dns_hdr*, ppp::string&, uint16_t, uint16_t) noexcept -> bool {
                            return true;
                        };
                    return ExtractHostZ(szPacketStartPos, nPacketLength, fPredicateB, fPredicateE);
                }

            } // namespace dns
        } // namespace native
    } // namespace net
} // namespace ppp