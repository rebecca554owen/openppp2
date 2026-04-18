#pragma once

/**
 * @file IcmpFrame.h
 * @brief Declares ICMP packet abstraction and conversion helpers.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            typedef ppp::net::native::IcmpType                  IcmpType;

            class IPFrame;
            class BufferSegment;

            class IcmpFrame final {
            public:
                /** @brief ICMP message type. */
                IcmpType                                        Type;
                /** @brief ICMP message code. */
                Byte                                            Code;
                /** @brief Echo/request identifier field. */
                UInt16                                          Identification;
                /** @brief Echo/request sequence field. */
                UInt16                                          Sequence;
                /** @brief IPv4 source address. */
                UInt32                                          Source;
                /** @brief IPv4 destination address. */
                UInt32                                          Destination;
                /** @brief IPv4 time-to-live value. */
                Byte                                            Ttl;
                /** @brief Address family of this frame. */
                AddressFamily                                   AddressesFamily;
                /** @brief ICMP payload following the fixed header. */
                std::shared_ptr<BufferSegment>                  Payload;

            public:
                /** @brief Initializes an ICMP echo frame with IPv4 defaults. */
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
                 * @brief Converts an ICMP frame into an IP frame.
                 * @param allocator Buffer allocator used for packet construction.
                 * @param frame Source ICMP frame.
                 * @return Newly created IP frame, or nullptr on failure.
                 */
                static std::shared_ptr<IPFrame>                 ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const IcmpFrame* frame) {
                    if (NULLPTR == frame) {
                        return NULLPTR;
                    }

                    IcmpFrame* packet = constantof(frame);
                    return packet->ToIp(allocator);
                }
                /**
                 * @brief Converts this ICMP frame into an IPv4 packet frame.
                 * @param allocator Buffer allocator used for packet construction.
                 * @return Newly created IP frame, or nullptr on failure.
                 */
                std::shared_ptr<IPFrame>                        ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator);
                /**
                 * @brief Parses an ICMP frame from an IP packet.
                 * @param frame Source IP frame.
                 * @return Parsed ICMP frame, or nullptr if parsing fails.
                 */
                static std::shared_ptr<IcmpFrame>               Parse(const IPFrame* frame) noexcept;
            };
        }
    }
}
