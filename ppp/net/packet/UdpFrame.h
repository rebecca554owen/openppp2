#pragma once

/**
 * @file UdpFrame.h
 * @brief UDP packet model and UDP/IPv4 conversion helpers.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>

namespace ppp {
    namespace net {
        namespace packet {
            class IPFrame;
            class BufferSegment;

            /**
             * @brief Represents a UDP datagram with endpoint metadata.
             */
            class UdpFrame final {
            public:
                /** @brief UDP source endpoint. */
                IPEndPoint                                      Source;
                /** @brief UDP destination endpoint. */
                IPEndPoint                                      Destination;
                /** @brief Address family used by this datagram. */
                AddressFamily                                   AddressesFamily;
                /** @brief TTL propagated to generated IP packet. */
                Byte                                            Ttl;
                /** @brief UDP payload bytes. */
                std::shared_ptr<BufferSegment>                  Payload;

            public:
                UdpFrame() noexcept
                    : AddressesFamily(AddressFamily::InterNetwork)
                    , Ttl(IPFrame::DefaultTtl) {
                }

            public:
                /**
                 * @brief Converts a UDP frame pointer to an IPv4 frame.
                 * @param allocator Buffer allocator for generated packet bytes.
                 * @param frame Source UDP frame pointer.
                 * @return IPv4 frame on success; otherwise null.
                 */
                static std::shared_ptr<IPFrame>                 ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const UdpFrame* frame) {
                    if (NULLPTR == frame) {
                        return NULLPTR;
                    }

                    UdpFrame* packet = constantof(frame);
                    return packet->ToIp(allocator);
                }
                /**
                 * @brief Converts this UDP frame to an IPv4 packet.
                 * @param allocator Buffer allocator for generated packet bytes.
                 * @return IPv4 frame on success; otherwise null.
                 */
                std::shared_ptr<IPFrame>                        ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator);
                /**
                 * @brief Parses an IPv4 frame as a UDP datagram.
                 * @param frame Source IPv4 frame pointer.
                 * @return Parsed UDP frame on success; otherwise null.
                 */
                static std::shared_ptr<UdpFrame>                Parse(const IPFrame* frame) noexcept;
            };
        }
    }
}
