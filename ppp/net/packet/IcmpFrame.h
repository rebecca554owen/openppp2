#pragma once

/**
 * @file IcmpFrame.h
 * @brief Declares ICMP packet abstraction and conversion helpers.
 *
 * @ref ppp::net::packet::IcmpFrame models the ICMP header and payload as they
 * exist within an IPv4 datagram.  All multi-byte fields follow **network byte
 * order** (big-endian) as they appear on the wire; callers must apply ntohl/ntohs
 * when performing numeric comparisons.
 *
 * Typical usage patterns
 * ----------------------
 * Parsing (inbound path):
 * @code
 *   auto ip_frame  = IPFrame::Parse(allocator, raw, raw_len);
 *   auto icmp_frame = IcmpFrame::Parse(ip_frame.get());
 * @endcode
 *
 * Generation (outbound path, e.g. building an echo reply):
 * @code
 *   IcmpFrame icmp;
 *   icmp.Type           = IcmpType::ICMP_ECHOREPLY;
 *   icmp.Identification = request->Identification;
 *   icmp.Sequence       = request->Sequence;
 *   icmp.Source         = request->Destination;
 *   icmp.Destination    = request->Source;
 *   auto ip_frame       = IcmpFrame::ToIp(allocator, &icmp);
 * @endcode
 *
 * @note  ICMP checksum calculation is performed internally by @ref ToIp; callers
 *        do not need to set or verify the checksum field.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            /**
             * @brief ICMP message type alias sourced from the native ICMP header definitions.
             *
             * Enumerates standard ICMP types (ECHO, ECHOREPLY, DEST_UNREACH, TIME_EXCEEDED, …)
             * as defined in @ref ppp::net::native::IcmpType.
             */
            typedef ppp::net::native::IcmpType                  IcmpType;

            class IPFrame;
            class BufferSegment;

            /**
             * @brief Represents a parsed ICMP message with endpoint and payload information.
             *
             * Structure layout:
             *   Type            = IcmpType,                       ///< ICMP message type
             *   Code            = Byte,                           ///< ICMP sub-code
             *   Identification  = UInt16,                         ///< Echo request/reply identifier
             *   Sequence        = UInt16,                         ///< Echo request/reply sequence
             *   Source          = UInt32,                         ///< IPv4 source address (network order)
             *   Destination     = UInt32,                         ///< IPv4 destination address (network order)
             *   Ttl             = Byte,                           ///< Time to live from enclosing IP header
             *   AddressesFamily = AddressFamily,                  ///< Address family (InterNetwork)
             *   Payload         = std::shared_ptr<BufferSegment>  ///< ICMP data following fixed header
             *
             * @note  @ref Source and @ref Destination are in **network byte order**, consistent
             *        with @ref IPFrame::Source and @ref IPFrame::Destination.
             */
            class IcmpFrame final {
            public:
                /** @brief ICMP message type (e.g. ICMP_ECHO = 8, ICMP_ECHOREPLY = 0). */
                IcmpType                                        Type;
                /** @brief ICMP message code; typically 0 for echo and echo-reply messages. */
                Byte                                            Code;
                /**
                 * @brief Echo request/reply identifier field.
                 *
                 * Used to correlate echo replies with their originating requests.
                 * Stored in **network byte order**.
                 */
                UInt16                                          Identification;
                /**
                 * @brief Echo request/reply sequence number.
                 *
                 * Incremented for each successive ping probe from the same source.
                 * Stored in **network byte order**.
                 */
                UInt16                                          Sequence;
                /** @brief IPv4 source address in **network byte order**. */
                UInt32                                          Source;
                /** @brief IPv4 destination address in **network byte order**. */
                UInt32                                          Destination;
                /** @brief IP Time-To-Live copied from the enclosing IPv4 header. */
                Byte                                            Ttl;
                /** @brief Address family; always @ref AddressFamily::InterNetwork for ICMP. */
                AddressFamily                                   AddressesFamily;
                /**
                 * @brief ICMP payload following the 8-byte fixed ICMP header.
                 *
                 * For echo messages this contains the ping data sent by the originator.
                 * For error messages (Destination Unreachable, Time Exceeded) this contains
                 * the original IP header plus the first 8 bytes of the original datagram.
                 * NULLPTR when no payload is present.
                 */
                std::shared_ptr<BufferSegment>                  Payload;

            public:
                /**
                 * @brief Initializes an ICMP echo-request frame with IPv4 defaults.
                 *
                 * Default values:
                 * - @ref Type = ICMP_ECHO (8).
                 * - @ref Code = 0.
                 * - @ref Identification / @ref Sequence = 0 (caller must set).
                 * - @ref Ttl = @ref IPFrame::DefaultTtl.
                 * - @ref AddressesFamily = InterNetwork.
                 */
                IcmpFrame() noexcept
                    : Type(IcmpType::ICMP_ECHO)
                    , Code(0)
                    , Identification(0)
                    , Sequence(0)
                    , Source(0)
                    , Destination(0)
                    , Ttl(IPFrame::DefaultTtl)
                    , AddressesFamily(AddressFamily::InterNetwork) {
                }

            public:
                /**
                 * @brief Converts an ICMP frame pointer to an enclosing IPv4 packet frame.
                 *
                 * Static convenience overload that null-checks @p frame before dispatching
                 * to the member @ref ToIp overload.
                 *
                 * @param allocator  Allocator for the generated packet buffer.
                 * @param frame      Source ICMP frame pointer; NULLPTR returns NULLPTR.
                 * @return           Newly constructed @ref IPFrame on success; NULLPTR on failure.
                 */
                static std::shared_ptr<IPFrame>                 ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const IcmpFrame* frame) {
                    if (NULLPTR == frame) {
                        return NULLPTR;
                    }

                    IcmpFrame* packet = constantof(frame);
                    return packet->ToIp(allocator);
                }

                /**
                 * @brief Converts this ICMP frame into an enclosing IPv4 packet frame.
                 *
                 * Fills the IPv4 header from this frame's @ref Source, @ref Destination,
                 * @ref Ttl, and @ref AddressesFamily fields, then appends the serialized
                 * ICMP message (with computed checksum) as the payload.
                 *
                 * @param allocator  Allocator for the generated packet buffer.
                 * @return           Shared @ref IPFrame containing the complete ICMP datagram;
                 *                   NULLPTR on allocation failure.
                 */
                std::shared_ptr<IPFrame>                        ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator);

                /**
                 * @brief Parses an ICMP frame from an enclosing IPv4 packet.
                 *
                 * Extracts the ICMP type, code, identification, sequence, and payload from
                 * @p frame's payload buffer.  The ICMP checksum is verified; frames with
                 * invalid checksums are rejected.
                 *
                 * @param frame  Source IPv4 frame whose protocol type must be IPPROTO_ICMP.
                 * @return       Shared @ref IcmpFrame on success; NULLPTR if @p frame is null,
                 *               protocol mismatch, or checksum validation fails.
                 */
                static std::shared_ptr<IcmpFrame>               Parse(const IPFrame* frame) noexcept;
            };
        }
    }
}
