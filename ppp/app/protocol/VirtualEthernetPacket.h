#pragma once

/**
 * @file VirtualEthernetPacket.h
 * @brief Defines the virtual Ethernet packet model and pack/unpack helpers.
 * @author ("OPENPPP2 Team")
 * @license ("GPL-3.0")
 */

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
            /**
             * @brief Represents a virtual Ethernet packet for tunnel transport.
             */
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
                /**
                 * @brief Ciphertext resolver callback type.
                 */
                typedef ppp::function<
                    std::shared_ptr<ppp::cryptography::Ciphertext>(int session_id)> SessionCiphertext;

            public:
                /**
                 * @brief Parses the payload as ICMP from an IP virtual packet.
                 * @param allocator Buffer allocator used by packet parser.
                 * @param packet Receives the parsed IP frame on success.
                 * @return Parsed ICMP frame, or null if protocol/type mismatch.
                 * @note Valid only when `Protocol` is `IP_PROTO_IP` and inner protocol is ICMP.
                 */
                std::shared_ptr<ppp::net::packet::IcmpFrame>                        GetIcmpPacket(
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    std::shared_ptr<ppp::net::packet::IPFrame>&                     packet) noexcept;

                /**
                 * @brief Parses the payload as an IP frame.
                 * @param allocator Buffer allocator used by packet parser.
                 * @return Parsed IP frame, or null when this packet is not an IP virtual packet.
                 * @note Uses the internal pseudo header fields plus payload to reconstruct an IPFrame.
                 */
                std::shared_ptr<ppp::net::packet::IPFrame>                          GetIPPacket(
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator) noexcept;

                /**
                 * @brief Parses the payload as a UDP frame.
                 * @return Parsed UDP frame, or null when protocol is not UDP.
                 * @note The returned frame is represented as IPv4 endpoint based data.
                 */
                std::shared_ptr<ppp::net::packet::UdpFrame>                         GetUdpPacket() noexcept;

            public:
                /**
                 * @brief Packs an IP frame into a virtual Ethernet transport packet.
                 * @param configuration Runtime configuration.
                 * @param allocator Buffer allocator used for intermediate buffers.
                 * @param protocol Protocol-layer ciphertext resolver.
                 * @param transport Transport-layer ciphertext resolver.
                 * @param session_id Positive session identifier.
                 * @param packet Source IP frame to pack.
                 * @param out Receives resulting encoded packet size.
                 * @return Encoded packet buffer, or null on failure.
                 * @note This overload marks packet type as IP internally.
                 */
                static std::shared_ptr<ppp::Byte>                                   Pack(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    int                                                             session_id,
                    const ppp::net::packet::IPFrame*                                packet,
                    int&                                                            out) noexcept;

                /**
                 * @brief Packs raw UDP payload into a virtual Ethernet transport packet.
                 * @param configuration Runtime configuration.
                 * @param allocator Buffer allocator used for intermediate buffers.
                 * @param protocol Protocol-layer ciphertext resolver.
                 * @param transport Transport-layer ciphertext resolver.
                 * @param session_id Positive session identifier.
                 * @param source_ip Source IPv4 address in host order.
                 * @param source_port Source UDP port in host order.
                 * @param destination_ip Destination IPv4 address in host order.
                 * @param destination_port Destination UDP port in host order.
                 * @param payload Raw payload bytes.
                 * @param payload_length Raw payload length.
                 * @param out Receives resulting encoded packet size.
                 * @return Encoded packet buffer, or null on failure.
                 * @note This overload keeps packet type as UDP.
                 */
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

                /**
                 * @brief Unpacks a transport packet into a VirtualEthernetPacket object.
                 * @param configuration Runtime configuration.
                 * @param allocator Buffer allocator used for decoded payload.
                 * @param protocol Protocol-layer ciphertext resolver.
                 * @param transport Transport-layer ciphertext resolver.
                 * @param packet Raw encoded packet bytes.
                 * @param packet_length Raw encoded packet length.
                 * @return Parsed packet object, or null on decode/validation failure.
                 * @note This helper allocates the output object and delegates to `UnpackBy`.
                 */
                static std::shared_ptr<VirtualEthernetPacket>                       Unpack(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    const void*                                                     packet,
                    int                                                             packet_length) noexcept;

            public:
                /**
                 * @brief Builds protocol and transport ciphertext instances for a session.
                 * @param configuration Runtime configuration.
                 * @param guid Device/session GUID.
                 * @param fsid Forward-session identifier.
                 * @param id Session identifier used in IV derivation.
                 * @param protocol Receives protocol-layer ciphertext object.
                 * @param transport Receives transport-layer ciphertext object.
                 * @return void.
                 * @note Outputs are set to null when encryption is disabled or creation fails.
                 */
                static void                                                         Ciphertext(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const Int128&                                                   guid,
                    const Int128&                                                   fsid,
                    int                                                             id,
                    std::shared_ptr<ppp::cryptography::Ciphertext>&                 protocol,
                    std::shared_ptr<ppp::cryptography::Ciphertext>&                 transport) noexcept;

            public:
                /**
                 * @brief Fills an IP frame payload with random printable bytes.
                 * @param frame Target IP frame.
                 * @return True on success, false on invalid input/allocation failure.
                 * @note Uses default random payload length range `[1, 128]`.
                 */
                static bool                                                         FillBytesToPayload(ppp::net::packet::IPFrame* frame) noexcept {
                    return FillBytesToPayload(frame, 1, 128);
                }
                
                /**
                 * @brief Fills an IP frame payload with random printable bytes.
                 * @param frame Target IP frame.
                 * @param min Minimum random payload length.
                 * @param max Maximum random payload length.
                 * @return True on success, false on invalid arguments/allocation failure.
                 * @note Generated bytes are in printable ASCII range `0x20..0x7e`.
                 */
                static bool                                                         FillBytesToPayload(ppp::net::packet::IPFrame* frame, int min, int max) noexcept;

                /**
                 * @brief Opens a UDP socket for a target address/port with protocol fallback.
                 * @param socket Socket object to open/bind.
                 * @param address Preferred bind address.
                 * @param port Local bind port.
                 * @param sourceEP Reference endpoint used to infer protocol fallback.
                 * @return True if socket open/bind succeeds; otherwise false.
                 * @note Falls back to IPv4/IPv6 ANY address when direct bind fails.
                 */
                static bool                                                         OpenDatagramSocket(
                    boost::asio::ip::udp::socket&                                   socket,
                    const boost::asio::ip::address&                                 address,
                    int                                                             port,
                    const boost::asio::ip::udp::endpoint&                           sourceEP) noexcept;

            private:
                /**
                 * @brief Decodes a transport packet into an existing output object.
                 * @param configuration Runtime configuration.
                 * @param allocator Buffer allocator used for decoded data.
                 * @param protocol Protocol-layer ciphertext resolver.
                 * @param transport Transport-layer ciphertext resolver.
                 * @param packet Raw encoded packet bytes.
                 * @param packet_length Raw encoded packet length.
                 * @param out Receives decoded packet fields on success.
                 * @return True on success, otherwise false.
                 * @note Internal helper used by public `Unpack`.
                 */
                static bool                                                         UnpackBy(
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                    const SessionCiphertext&                                        protocol,
                    const SessionCiphertext&                                        transport,
                    const void*                                                     packet,
                    int                                                             packet_length,
                    VirtualEthernetPacket&                                          out) noexcept;

                /**
                 * @brief Encodes packet payload with explicit origin/session identifier split.
                 * @param configuration Runtime configuration.
                 * @param allocator Buffer allocator used for intermediate buffers.
                 * @param protocol Protocol-layer ciphertext resolver.
                 * @param transport Transport-layer ciphertext resolver.
                 * @param origin_id Session identifier used to resolve ciphers.
                 * @param session_id Session identifier encoded into packet header.
                 * @param source_ip Source IPv4 address in host order.
                 * @param source_port Source UDP port in host order.
                 * @param destination_ip Destination IPv4 address in host order.
                 * @param destination_port Destination UDP port in host order.
                 * @param payload Raw payload bytes.
                 * @param payload_length Raw payload length.
                 * @param out Receives resulting encoded packet size.
                 * @return Encoded packet buffer, or null on failure.
                 * @note Internal helper used by both public `Pack` overloads.
                 */
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
