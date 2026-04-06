#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/checksum.h>
#include <ppp/cryptography/ssea.h>

namespace ppp
{
    namespace app
    {
        namespace protocol
        {
#pragma pack(push, 1)
            // Posedo structure for IP packet header (source/destination IP and port).
            typedef struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed))
#endif
            {
                uint32_t    source_ip;          // Source IPv4 address (network order)
                uint16_t    source_port;        // Source port (network order)
                uint32_t    destination_ip;     // Destination IPv4 address (network order)
                uint16_t    destination_port;   // Destination port (network order)
            } PACKET_IP_PACKET_POSEDO;

            // Main virtual Ethernet packet header.
            typedef struct
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed))
#endif
            {
                uint32_t                mask_id;            // Random mask ID for obfuscation
                uint8_t                 header_length;      // Obfuscated header length (actual length derived via mapping)
                int32_t                 session_id;         // Session ID (positive for UDP, negative for IP)
                uint16_t                checksum;           // Checksum covering header + encrypted payload
                PACKET_IP_PACKET_POSEDO posedo;             // Posedo IP header fields
            } PACKET_HEADER;
#pragma pack(pop)

            typedef ppp::net::IPEndPoint                                        IPEndPoint;
            typedef ppp::net::Socket                                            Socket;

            // Computes the actual header length from the stored obfuscated value using a linear congruential mapping.
            // N: stored header_length, kf: per-packet random key factor.
            // Returns the real header length (always sizeof(PACKET_HEADER) in practice).
            static int STATIC_header_length(const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                                            int N, int kf) noexcept {
                // Obtain the modulus value from configuration (expected to be between 128 and 256).
                const int VEP_HEADER_MSS_MOD = configuration->Lcgmod(ppp::configurations::AppConfiguration::LCGMOD_TYPE_STATIC);

                // Protect against division by zero (should not happen in production).
                if (VEP_HEADER_MSS_MOD == 0) {
                    return sizeof(PACKET_HEADER); // Fallback to safe value.
                }

                const int KF_MOD = abs(kf % VEP_HEADER_MSS_MOD);

                // Mapping: (N - KF_MOD + MOD) % MOD  (inverse of packing mapping)
                return (N - KF_MOD + VEP_HEADER_MSS_MOD) % VEP_HEADER_MSS_MOD;
            }

            // Internal unpack routine after header has been decrypted and de-obfuscated.
            static bool STATIC_Unpack(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           transport,
                PACKET_HEADER*                                                  h,
                int                                                             proto,
                int                                                             session_id,
                int                                                             packet_length,
                VirtualEthernetPacket&                                          out) noexcept
            {
                // Session ID must be non-zero.
                if (session_id == 0) {
                    return false;
                }

                // Validate checksum: store original, zero it, compute, compare.
                uint16_t x_checksum = h->checksum;
                h->checksum = 0;

                uint16_t y_checksum = ppp::net::native::inet_chksum(h, packet_length);
                h->checksum = x_checksum;
                
                if (x_checksum != y_checksum) {
                    return false;
                }

                // Decrypt payload if transport ciphertext is provided.
                std::shared_ptr<ppp::Byte> payload;
                int payload_length = packet_length - sizeof(PACKET_HEADER);
                if (NULLPTR != transport) {
                    payload = transport->Decrypt(allocator, (ppp::Byte*)(h + 1), payload_length, payload_length);
                    if (NULLPTR == payload) {
                        return false;
                    }
                } else {
                    // No encryption: copy payload as-is.
                    payload = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, payload_length);
                    if (NULLPTR == payload) {
                        return false;
                    }

                    memcpy(payload.get(), h + 1, payload_length);
                }

                // Fill output structure.
                out.Id              = session_id;
                out.Payload         = payload;
                out.Length          = payload_length;
                out.Protocol        = proto;
                out.SourceIP        = h->posedo.source_ip;
                out.SourcePort      = ntohs(h->posedo.source_port);
                out.DestinationIP   = h->posedo.destination_ip;
                out.DestinationPort = ntohs(h->posedo.destination_port);

                // For non-UDP protocols, accept any IP/port.
                if (proto != ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    return true;
                }

                // UDP specific validation: destination and source must be valid.
                if (out.DestinationIP == IPEndPoint::NoneAddress || out.DestinationIP == IPEndPoint::AnyAddress) {
                    return false;
                }

                if (out.DestinationPort <= IPEndPoint::MinPort || out.DestinationPort > IPEndPoint::MaxPort) {
                    return false;
                }

                if (out.SourceIP == IPEndPoint::NoneAddress || out.SourceIP == IPEndPoint::AnyAddress) {
                    return false;
                }

                if (out.SourcePort <= IPEndPoint::MinPort || out.SourcePort > IPEndPoint::MaxPort) {
                    return false;
                }

                return true;
            }

            // Public unpack entry point.
            bool VirtualEthernetPacket::UnpackBy(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                const void*                                                     packet,
                int                                                             packet_length,
                VirtualEthernetPacket&                                          out) noexcept
            {
                // Basic length validation.
                if (NULLPTR == packet || packet_length <= sizeof(PACKET_HEADER)) {
                    return false;
                }

                // First layer: delta decoding (decompression / obfuscation removal).
                std::shared_ptr<ppp::Byte> output;
                packet_length = ppp::cryptography::ssea::delta_decode(allocator, packet, packet_length,
                                                                      configuration->key.kf, output);
                if (NULLPTR == output || packet_length <= sizeof(PACKET_HEADER)) {
                    return false;
                }

                packet = output.get();

                // Access header.
                ppp::Byte* p = (ppp::Byte*)packet;
                PACKET_HEADER* h = (PACKET_HEADER*)p;
                if (h->mask_id == 0) {
                    return false;
                }

                // Compute per-packet key factor from mask_id and global key.
                int kf = ppp::cryptography::ssea::random_next(configuration->key.kf * h->mask_id);

                // Derive actual header length from stored obfuscated value.
                int header_length = (ppp::Byte)STATIC_header_length(configuration, h->header_length, kf);
                if (header_length < sizeof(PACKET_HEADER)) {
                    return false;
                }

                // Reverse XOR masking on the session_id field and following bytes.
                ppp::Byte* x = p + offsetof(PACKET_HEADER, session_id);
                ppp::Byte* y = p + packet_length;
                ppp::cryptography::ssea::masked_xor_random_next(x, y, kf);

                // Reverse shuffle on the session_id field and following bytes.
                ppp::cryptography::ssea::unshuffle_data(reinterpret_cast<char*>(&h->session_id),
                                                        packet_length - offsetof(PACKET_HEADER, session_id), kf);

                // Determine protocol type based on sign of session_id.
                int32_t session_id = htonl(h->session_id) ^ kf;
                int proto = ppp::net::native::ip_hdr::IP_PROTO_UDP;
                if (session_id < 0) {
                    session_id = ~session_id;   // Absolute value for IP packets.
                    proto = ppp::net::native::ip_hdr::IP_PROTO_IP;
                }

                // Obtain ciphertext instances for the session.
                std::shared_ptr<ppp::cryptography::Ciphertext> transport_ciphertext = transport ? transport(session_id) : NULLPTR;
                std::shared_ptr<ppp::cryptography::Ciphertext> protocol_ciphertext = protocol ? protocol(session_id) : NULLPTR;

                // If both protocol and transport ciphertexts are available, decrypt the header section.
                if (NULLPTR != protocol_ciphertext && NULLPTR != transport_ciphertext) {
                    int header_length_raw = sizeof(PACKET_HEADER) - offsetof(PACKET_HEADER, checksum);
                    int header_length_new;
                    std::shared_ptr<Byte> header_body = protocol_ciphertext->Decrypt(allocator,
                                        reinterpret_cast<ppp::Byte*>(&h->checksum), header_length_raw, header_length_new);
                    if (NULLPTR == header_body) {
                        return false;
                    }

                    // If decrypted length matches original, replace in-place.
                    if (header_length_new == header_length_raw) {
                        memcpy(reinterpret_cast<ppp::Byte*>(&h->checksum), header_body.get(), header_length_new);
                    } else {
                        // Otherwise rebuild the entire packet with new header layout.
                        ppp::io::MemoryStream ms;
                        ms.Write(h, 0, offsetof(PACKET_HEADER, checksum));
                        ms.Write(header_body.get(), 0, header_length_new);
                        ms.Write((Byte*)h + header_length, 0, packet_length - header_length);

                        std::shared_ptr<ppp::Byte> buf = ms.GetBuffer();
                        packet_length = ms.GetPosition();

                        h = (PACKET_HEADER*)buf.get();

                        // Recompute obfuscated header length for consistency.
                        h->header_length = (ppp::Byte)STATIC_header_length(configuration, sizeof(PACKET_HEADER), kf);

                        // Continue unpack with reconstructed packet.
                        return STATIC_Unpack(allocator, transport_ciphertext, h, proto, session_id, packet_length, out);
                    }
                } else {
                    // No protocol encryption; fall through.
                    protocol_ciphertext  = NULLPTR;
                    transport_ciphertext = NULLPTR;
                }

                // Final unpack with possibly modified header.
                return STATIC_Unpack(allocator, transport_ciphertext, h, proto, session_id, packet_length, out);
            }

            // Internal packing routine.
            static std::shared_ptr<ppp::Byte> STATIC_Pack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const std::shared_ptr<ppp::cryptography::Ciphertext>&           protocol,
                PACKET_HEADER*                                                  h,
                const void*                                                     payload,
                int                                                             payload_length,
                int                                                             message_length,
                int&                                                            out) noexcept
            {
                // Compute per-packet key factor.
                const int kf = ppp::cryptography::ssea::random_next(configuration->key.kf * h->mask_id);
                const int VEP_HEADER_MSS_MOD = configuration->Lcgmod(ppp::configurations::AppConfiguration::LCGMOD_TYPE_STATIC);

                // Defensive check: modulus should not be zero.
                if (VEP_HEADER_MSS_MOD == 0) {
                    out = 0;
                    return NULLPTR;
                }
                const int KF_MOD = abs(kf % VEP_HEADER_MSS_MOD);

                // Set obfuscated header length.
                h->header_length = (Byte)((sizeof(PACKET_HEADER) + KF_MOD) % VEP_HEADER_MSS_MOD);

                // Obfuscate session_id.
                h->session_id = htonl(h->session_id ^ kf);

                // Copy payload after header.
                memcpy(h + 1, payload, payload_length);

                // Compute checksum over header + payload (payload may be transport-encrypted).
                h->checksum = ppp::net::native::inet_chksum(h, message_length);

                std::shared_ptr<ppp::Byte> buf;
                std::shared_ptr<ppp::Byte> output;

                // If protocol encryption is enabled, encrypt the trailing part of the header.
                if (NULLPTR != protocol) {
                    int header_length_raw = sizeof(PACKET_HEADER) - offsetof(PACKET_HEADER, checksum);
                    int header_length_new = 0;
                    std::shared_ptr<Byte> header_body = protocol->Encrypt(allocator,
                                        reinterpret_cast<ppp::Byte*>(&h->checksum), header_length_raw, header_length_new);
                    if (NULLPTR == header_body) {
                        out = 0;
                        return NULLPTR;
                    }

                    if (header_length_raw == header_length_new) {
                        // Replace in-place.
                        memcpy(reinterpret_cast<ppp::Byte*>(&h->checksum), header_body.get(), header_length_new);
                    } else {
                        // Rebuild packet with new header layout.
                        ppp::io::MemoryStream ms;
                        ms.Write(h, 0, offsetof(PACKET_HEADER, checksum));
                        ms.Write(header_body.get(), 0, header_length_new);
                        ms.Write(h + 1, 0, payload_length);

                        message_length = ms.GetPosition();
                        buf = ms.GetBuffer();

                        h = (PACKET_HEADER*)buf.get();

                        // Recompute obfuscated header length.
                        h->header_length = (Byte)((header_length_new + offsetof(PACKET_HEADER, checksum) + KF_MOD) % VEP_HEADER_MSS_MOD);
                    }
                }

                // Apply shuffle and XOR masking to the session_id and following data.
                ppp::cryptography::ssea::shuffle_data(reinterpret_cast<char*>(&h->session_id),
                                                      message_length - offsetof(PACKET_HEADER, session_id), kf);
                Byte* p = reinterpret_cast<Byte*>(h);
                Byte* x = p + offsetof(PACKET_HEADER, session_id);
                Byte* y = p + message_length;
                ppp::cryptography::ssea::masked_xor_random_next(x, y, kf);

                // Final delta encoding before transmission.
                out = ppp::cryptography::ssea::delta_encode(allocator, h, message_length, configuration->key.kf, output);
                return output;
            }

            // Public pack entry point (with origin ID).
            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::PackBy(
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
                int&                                                            out) noexcept
            {
                out = 0;
                // Validate inputs.
                if (NULLPTR == payload || payload_length < 1 || origin_id == 0) {
                    return NULLPTR;
                }

                // Obtain ciphertext instances for the given origin_id.
                std::shared_ptr<ppp::cryptography::Ciphertext> protocol_ciphertext = protocol ? protocol(origin_id) : NULLPTR;
                std::shared_ptr<ppp::cryptography::Ciphertext> transport_ciphertext = transport ? transport(origin_id) : NULLPTR;
                if (NULLPTR == protocol_ciphertext || NULLPTR == transport_ciphertext) {
                    protocol_ciphertext  = NULLPTR;
                    transport_ciphertext = NULLPTR;
                }

                // Encrypt payload with transport ciphertext if available.
                std::shared_ptr<ppp::Byte> payload_managed;
                if (NULLPTR != transport_ciphertext) {
                    payload_managed = transport_ciphertext->Encrypt(allocator, (ppp::Byte*)payload, payload_length, payload_length);
                    if (NULLPTR == payload_managed) {
                        return NULLPTR;
                    }
                    payload = payload_managed.get();
                }

                // Allocate buffer for full packet (header + payload).
                int message_length = sizeof(PACKET_HEADER) + payload_length;
                std::shared_ptr<ppp::Byte> messages = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_length);
                if (NULLPTR == messages) {
                    return NULLPTR;
                }

                // Fill header fields.
                PACKET_HEADER* h = reinterpret_cast<PACKET_HEADER*>(messages.get());
                h->checksum                = 0;
                h->header_length           = 0;
                h->session_id              = session_id;
                h->posedo.source_ip        = source_ip;
                h->posedo.source_port      = htons(source_port);
                h->posedo.destination_ip   = destination_ip;
                h->posedo.destination_port = htons(destination_port);

                // Generate a non-zero random mask_id.
                do {
                    h->mask_id = ppp::RandomNext(0, UINT8_MAX) << 24 |
                                 ppp::RandomNext(0, UINT8_MAX) << 16 |
                                 ppp::RandomNext(0, UINT8_MAX) << 8  |
                                 ppp::RandomNext(0, UINT8_MAX);
                } while (h->mask_id == 0);

                // Call static pack routine.
                return STATIC_Pack(configuration, allocator, protocol_ciphertext, h, payload, payload_length, message_length, out);
            }

            // Helper to allocate and unpack into a new VirtualEthernetPacket object.
            std::shared_ptr<VirtualEthernetPacket> VirtualEthernetPacket::Unpack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                const void*                                                     packet,
                int                                                             packet_length) noexcept
            {
                std::shared_ptr<VirtualEthernetPacket> result = ppp::make_shared_object<VirtualEthernetPacket>();
                if (NULLPTR == result) {
                    return NULLPTR;
                }

                return UnpackBy(configuration, allocator, protocol, transport, packet, packet_length, *result) ? result : NULLPTR;
            }

            // Convert IP protocol packet to an IPFrame.
            std::shared_ptr<ppp::net::packet::IPFrame> VirtualEthernetPacket::GetIPPacket(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator) noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    return NULLPTR;
                }

                // Reconstruct posedo header and payload.
                PACKET_IP_PACKET_POSEDO posedo;
                posedo.source_ip        = SourceIP;
                posedo.source_port      = SourcePort;
                posedo.destination_ip   = DestinationIP;
                posedo.destination_port = DestinationPort;

                ppp::io::MemoryStream ms;
                ms.Write(&posedo, 0, sizeof(posedo));
                ms.Write(Payload.get(), 0, Length);

                std::shared_ptr<ppp::Byte> buffer = ms.GetBuffer();
                return ppp::net::packet::IPFrame::Parse(allocator, buffer.get(), ms.GetPosition());
            }

            // Extract ICMP packet from this virtual Ethernet packet.
            std::shared_ptr<ppp::net::packet::IcmpFrame> VirtualEthernetPacket::GetIcmpPacket(
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                std::shared_ptr<ppp::net::packet::IPFrame>&                     packet) noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    return NULLPTR;
                }

                packet = GetIPPacket(allocator);
                if (NULLPTR == packet) {
                    return NULLPTR;
                }

                if (packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return NULLPTR;
                }

                return ppp::net::packet::IcmpFrame::Parse(packet.get());
            }

            // Extract UDP packet from this virtual Ethernet packet.
            std::shared_ptr<ppp::net::packet::UdpFrame> VirtualEthernetPacket::GetUdpPacket() noexcept
            {
                if (Protocol != ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::net::packet::UdpFrame> packet = ppp::make_shared_object<ppp::net::packet::UdpFrame>();
                if (NULLPTR == packet) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::net::packet::BufferSegment> payload = ppp::make_shared_object<ppp::net::packet::BufferSegment>(Payload, Length);
                if (NULLPTR == payload) {
                    return NULLPTR;
                }

                packet->AddressesFamily = ppp::net::AddressFamily::InterNetwork;
                packet->Source          = IPEndPoint(SourceIP, SourcePort);
                packet->Destination     = IPEndPoint(DestinationIP, DestinationPort);
                packet->Payload         = payload;
                return packet;
            }

            // Public pack overload for UDP raw data.
            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::Pack(
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
                int&                                                            out) noexcept
            {
                // Session ID must be positive for UDP.
                if (session_id < 1) {
                    return NULLPTR;
                }

                // Validate destination.
                if (destination_ip == IPEndPoint::NoneAddress || destination_ip == IPEndPoint::AnyAddress) {
                    return NULLPTR;
                }

                if (destination_port <= IPEndPoint::MinPort || destination_port > IPEndPoint::MaxPort) {
                    return NULLPTR;
                }

                if (source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    return NULLPTR;
                }
                
                return PackBy(configuration, allocator, protocol, transport, session_id, session_id,
                             source_ip, source_port, destination_ip, destination_port,
                             payload, payload_length, out);
            }

            // Public pack overload for IP frame.
            std::shared_ptr<ppp::Byte> VirtualEthernetPacket::Pack(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const std::shared_ptr<ppp::threading::BufferswapAllocator>&     allocator,
                const SessionCiphertext&                                        protocol,
                const SessionCiphertext&                                        transport,
                int                                                             session_id,
                const ppp::net::packet::IPFrame*                                packet,
                int&                                                            out) noexcept
            {
                if (NULLPTR == packet || session_id < 1) {
                    return NULLPTR;
                }

                // Only ICMP, UDP, TCP are allowed.
                if (packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP &&
                    packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_UDP &&
                    packet->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_TCP) {
                    return NULLPTR;
                }

                // Convert IP frame to raw buffer.
                std::shared_ptr<ppp::net::packet::BufferSegment> packet_buffers = constantof(packet)->ToArray(allocator);
                if (NULLPTR == packet_buffers) {
                    return NULLPTR;
                }

                // The buffer starts with PACKET_IP_PACKET_POSEDO followed by payload.
                PACKET_IP_PACKET_POSEDO* posedo = (PACKET_IP_PACKET_POSEDO*)packet_buffers->Buffer.get();
                return PackBy(configuration, allocator, protocol, transport, session_id, ~session_id,
                              posedo->source_ip, posedo->source_port,
                              posedo->destination_ip, posedo->destination_port,
                              posedo + 1, packet_buffers->Length - sizeof(PACKET_IP_PACKET_POSEDO), out);
            }

            // Open a UDP socket with fallback to ANY address.
            bool VirtualEthernetPacket::OpenDatagramSocket(boost::asio::ip::udp::socket&            socket,
                                                           const boost::asio::ip::address&          address,
                                                           int                                      port,
                                                           const boost::asio::ip::udp::endpoint&    sourceEP) noexcept
            {
                bool ok = false;
                if (address.is_v4() || address.is_v6()) {
                    ok = Socket::OpenSocket(socket, address, port);
                    if (ok) {
                        return true;
                    }

                    ok = Socket::Closesocket(socket);
                    if (!ok) {
                        return false;
                    }

                    goto opensocket_by_protocol;
                }

            opensocket_by_protocol:
                if (sourceEP.protocol() == boost::asio::ip::udp::v4()) {
                    ok = Socket::OpenSocket(socket, boost::asio::ip::address_v4::any(), port);
                } else {
                    ok = Socket::OpenSocket(socket, boost::asio::ip::address_v6::any(), port);
                }
                
                return ok;
            }

            // Fill IP frame payload with random printable characters.
            bool VirtualEthernetPacket::FillBytesToPayload(ppp::net::packet::IPFrame* frame, int min, int max) noexcept
            {
                if (NULLPTR == frame) {
                    return false;
                }

                if (min < 1 || max < 1 || min > max) {
                    return false;
                }

                int payload_length = RandomNext(min, max);
                if (payload_length < 1) {
                    return false;
                }

                auto payload = make_shared_object<ppp::net::packet::BufferSegment>();
                if (NULLPTR == payload) {
                    return false;
                }

                std::shared_ptr<Byte> buffer = make_shared_alloc<Byte>(payload_length);
                if (NULLPTR == buffer) {
                    return false;
                }

                Byte* p = buffer.get();
                for (int i = 0; i < payload_length; i++) {
                    *p++ = RandomNext(0x20, 0x7e); // Printable ASCII range
                }

                frame->Payload  = payload;
                payload->Buffer = buffer;
                payload->Length = payload_length;
                return true;
            }

            // Generate ciphertext instances for protocol and transport layers.
            void VirtualEthernetPacket::Ciphertext(
                const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                const Int128&                                                   guid,
                const Int128&                                                   fsid,
                int                                                             id,
                std::shared_ptr<ppp::cryptography::Ciphertext>&                 protocol,
                std::shared_ptr<ppp::cryptography::Ciphertext>&                 transport) noexcept
            {
                protocol  = NULLPTR;
                transport = NULLPTR;
                if (ppp::configurations::extensions::IsHaveCiphertext(configuration.get())) {
                    ppp::string ivv_string = stl::to_string<ppp::string>(guid, 32) + "/" +
                                             stl::to_string<ppp::string>(fsid, 32) + "\\" +
                                             stl::to_string<ppp::string>(id, 32) + ";";
                    protocol  = make_shared_object<ppp::cryptography::Ciphertext>(configuration->key.protocol,
                                                                                   configuration->key.protocol_key + ivv_string);
                    transport = make_shared_object<ppp::cryptography::Ciphertext>(configuration->key.transport,
                                                                                   configuration->key.transport_key + ivv_string);
                    if (NULLPTR == protocol || NULLPTR == transport) {
                        protocol  = NULLPTR;
                        transport = NULLPTR;
                    }
                }
            }
        }
    }
}