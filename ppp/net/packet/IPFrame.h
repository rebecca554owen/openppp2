#pragma once

/**
 * @file IPFrame.h
 * @brief IPv4 frame model, serialization, parsing, and fragmentation helpers.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace net {
        namespace packet {
            /** @brief Alias for IPv4 header flags field. */
            typedef ppp::net::native::ip_hdr::Flags                     IPFlags;

            /**
             * @brief Owns a shared byte buffer and its valid length.
             */
            class BufferSegment final {
            public:
                /** @brief Shared pointer to the underlying byte storage. */
                std::shared_ptr<Byte>                                   Buffer;
                /** @brief Number of valid bytes in @ref Buffer. */
                int                                                     Length = 0;

            public:
                BufferSegment() noexcept : Length(0) {}
                BufferSegment(const std::shared_ptr<Byte>& buffer, int length) noexcept
                    : Buffer(buffer)
                    , Length(buffer ? std::max<int>(0, length) : 0) {

                }
            };

            /**
             * @brief Represents an IPv4 packet with header fields and payload segments.
             */
            class IPFrame final {
            public:
                typedef std::shared_ptr<IPFrame>                        IPFramePtr;

            public:
                /** @brief Address family of this packet. */
                AddressFamily                                           AddressesFamily;
                /** @brief Destination IPv4 address in network byte order. */
                UInt32                                                  Destination;
                /** @brief Source IPv4 address in network byte order. */
                UInt32                                                  Source;
                /** @brief Time to live field. */
                Byte                                                    Ttl;
                /** @brief IPv4 identification field. */
                UInt16                                                  Id;
                /** @brief Type of service field. */
                Byte                                                    Tos;
                /** @brief Encapsulated protocol identifier. */
                Byte                                                    ProtocolType;
                /** @brief Fragmentation flags and offset bits. */
                IPFlags                                                 Flags;
                /** @brief Payload segment (transport header + data). */
                std::shared_ptr<BufferSegment>                          Payload;
                /** @brief Optional IPv4 options segment. */
                std::shared_ptr<BufferSegment>                          Options;

            public:
                IPFrame() noexcept
                    : AddressesFamily(AddressFamily::InterNetwork)
                    , Destination(0)
                    , Source(0)
                    , Ttl(IPFrame::DefaultTtl)
                    , Id(0)
                    , Tos(ppp::net::Socket::IsDefaultFlashTypeOfService() ? DefaultFlashTypeOfService() : 0)
                    , ProtocolType(0)
                    , Flags(IPFlags::IP_DF) {

                }

            public:
                /**
                 * @brief Gets fragment byte offset extracted from @ref Flags.
                 * @return Fragment offset in bytes.
                 */
                int                                                     GetFragmentOffset() noexcept {
                    int offset = (UInt16)this->Flags;
                    offset = ((UInt16)(offset << 3)) >> 3;
                    offset <<= 3;
                    return offset;
                }
                /**
                 * @brief Sets fragment byte offset into @ref Flags.
                 * @param value Fragment offset in bytes.
                 */
                void                                                    SetFragmentOffset(int value) noexcept {
                    int flags = (int)this->Flags >> 13;
                    flags = flags << 13 | value >> 3;
                    this->Flags = (IPFlags)flags;
                }
                /**
                 * @brief Checks whether payload content is absent.
                 * @return true when payload buffer is null or empty.
                 */
                bool                                                    IsEmpty() noexcept {
                    std::shared_ptr<BufferSegment> payload = Payload;
                    if (NULLPTR == payload) {
                        return true;
                    }

                    std::shared_ptr<Byte> buffer = payload->Buffer;
                    return NULLPTR == buffer || payload->Length < 1;
                }
                /** @brief Returns default flash TOS value used by this project. */
                static int                                              DefaultFlashTypeOfService() noexcept { return 0x68; }
                /**
                 * @brief Applies the default flash TOS to a frame when pointer is valid.
                 * @param packet Target frame pointer.
                 */
                static void                                             DefaultFlashTypeOfService(const IPFrame* packet) noexcept { 
                    if (NULLPTR != packet) {
                        IPFrame* frame = constantof(packet);
                        frame->Tos = DefaultFlashTypeOfService();
                    }
                }
                
            public:     
                /**
                 * @brief Serializes this frame into contiguous bytes.
                 * @param allocator Buffer allocator used for output storage.
                 * @return Serialized frame buffer segment.
                 */
                std::shared_ptr<BufferSegment>                          ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                /**
                 * @brief Serializes a frame pointer into contiguous bytes.
                 * @param allocator Buffer allocator used for output storage.
                 * @param packet Source frame pointer.
                 * @return Serialized frame buffer segment.
                 */
                static std::shared_ptr<BufferSegment>                   ToArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const IPFrame* packet) noexcept {
                    if (NULLPTR == packet) {
                        return NULLPTR;
                    }

                    IPFrame* frame = constantof(packet);
                    return frame->ToArray(allocator);
                }

            public:
                /**
                 * @brief Calculates total serialized frame size.
                 * @return Packet length in bytes.
                 */
                int                                                     SizeOf() noexcept;
                /**
                 * @brief Calculates serialized size for a frame pointer.
                 * @param packet Source frame pointer.
                 * @return Packet length in bytes, or bitwise-not zero on null.
                 */
                static int                                              SizeOf(const IPFrame* packet) noexcept {
                    if (NULLPTR == packet) {
                        return ~0;
                    }

                    IPFrame* frame = constantof(packet);
                    return frame->SizeOf();
                }

            public:
                /**
                 * @brief Parses raw bytes into an IPv4 frame object.
                 * @param allocator Buffer allocator used for copied segments.
                 * @param packet Raw packet pointer.
                 * @param size Raw packet size in bytes.
                 * @return Parsed frame on success; otherwise null.
                 */
                static std::shared_ptr<IPFrame>                         Parse(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* packet, int size) noexcept;
                
            public:
                /** @brief Generates a new IPv4 identification value. */
                static UInt16                                           NewId() noexcept { return ppp::net::native::ip_hdr::NewId(); }
                /**
                 * @brief Splits a frame into MTU-compatible IPv4 fragments.
                 * @param out Receives output fragment frames.
                 * @param packet Source frame.
                 * @return Number of generated fragments.
                 */
                static int                                              Subpackages(ppp::vector<IPFramePtr>& out, const IPFramePtr& packet) noexcept;

            public:
                /** @brief Default TTL value used for newly created frames. */
                static const unsigned char&                             DefaultTtl;
            };
        }
    }
}
