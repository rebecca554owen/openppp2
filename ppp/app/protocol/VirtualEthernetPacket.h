#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>

namespace ppp 
{
    namespace app 
    {
        namespace protocol 
        {
            // Represents a virtual Ethernet packet that can be packed/unpacked for UDP transmission.
            struct VirtualEthernetPacket final
            {
            public:
                std::shared_ptr<ppp::Byte>                                          Payload;             // Encrypted or plain payload data
                int32_t                                                             Length = 0;          // Length of payload in bytes
                int32_t                                                             Protocol = 0;        // IP protocol type (IP_PROTO_UDP or IP_PROTO_IP)
                int32_t                                                             Id = 0;              // Session identifier (positive for UDP, negative for IP)
                uint32_t                                                            SourceIP = 0;        // Source IPv4 address (host order)
                uint16_t                                                            SourcePort = 0;      // Source port (host order)
                uint32_t                                                            DestinationIP = 0;   // Destination IPv4 address (host order)
                uint32_t                                                            DestinationPort = 0; // Destination port (host order)

            public:
                // Functor type to obtain a ciphertext instance for a given session ID.
                typedef ppp::function<
                    std::shared_ptr<ppp::cryptography::Ciphertext>(int session_id)> SessionCiphertext;

            public:
                // Extracts an ICMP frame from the packet (if protocol is IP).
                std::shared_ptr<ppp::net::packet::IcmpFrame>                        GetIcmpPacket(
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    std::shared_ptr<ppp::net::packet::IPFrame>&                     packet) noexcept;

                // Extracts an IP frame from the packet (if protocol is IP).
                std::shared_ptr<ppp::net::packet::IPFrame>                          GetIPPacket(
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator) noexcept;

                // Extracts a UDP frame from the packet (if protocol is UDP).
                std::shared_ptr<ppp::net::packet::UdpFrame>                         GetUdpPacket() noexcept;

            public:
                // Packs an IP frame into a virtual Ethernet packet.
                static std::shared_ptr<ppp::Byte>                                   Pack(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    int                                                             session_id,
                    const ppp::net::packet::IPFrame*                                packet,
                    int&                                                            out) noexcept;

                // Packs raw UDP payload into a virtual Ethernet packet.
                static std::shared_ptr<ppp::Byte>                                   Pack(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    int                                                             session_id,
                    uint32_t                                                        source_ip,
                    int                                                             source_port,
                    uint32_t                                                        destination_ip,
                    int                                                             destination_port,
                    const void*                                                     payload,
                    int                                                             payload_length,
                    int&                                                            out) noexcept;

                // Unpacks a raw buffer into a VirtualEthernetPacket structure.
                static std::shared_ptr<VirtualEthernetPacket>                       Unpack(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    const void*                                                     packet,
                    int                                                             packet_length) noexcept;

            public:
                // Generates protocol and transport ciphertexts for a given session ID.
                static void                                                         Ciphertext(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const Int128&                                                   guid,
                    const Int128&                                                   fsid,
                    int                                                             id,
                    std::shared_ptr<ppp::cryptography::Ciphertext>&                 protocol,
                    std::shared_ptr<ppp::cryptography::Ciphertext>&                 transport) noexcept;

            public:
                // Fills the payload of an IP frame with random printable characters (default length 1..128).
                static bool                                                         FillBytesToPayload(ppp::net::packet::IPFrame* frame) noexcept {
                    return FillBytesToPayload(frame, 1, 128);
                }
                
                // Fills the payload of an IP frame with random printable characters of random length between min and max.
                static bool                                                         FillBytesToPayload(ppp::net::packet::IPFrame* frame, int min, int max) noexcept;

                // Opens a UDP socket bound to the specified address and port, falling back to ANY address.
                static bool                                                         OpenDatagramSocket(
                    boost::asio::ip::udp::socket&                                   socket,
                    const boost::asio::ip::address&                                 address,
                    int                                                             port,
                    const boost::asio::ip::udp::endpoint&                           sourceEP) noexcept;

            private:
                // Internal unpack implementation without allocation.
                static bool                                                         UnpackBy(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    const void*                                                     packet,
                    int                                                             packet_length,
                    VirtualEthernetPacket&                                          out) noexcept;

                // Internal pack implementation with origin ID.
                static std::shared_ptr<ppp::Byte>                                   PackBy(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    int                                                             origin_id,
                    int                                                             session_id,
                    uint32_t                                                        source_ip,
                    int                                                             source_port,
                    uint32_t                                                        destination_ip,
                    int                                                             destination_port,
                    const void*                                                     payload,
                    int                                                             payload_length,
                    int&                                                            out) noexcept;
            };
        }
    }
}