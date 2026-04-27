#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file IcmpFrame.cpp
 * @brief Implements ICMP frame serialization and parsing helpers.
 */

using namespace ppp::net::native;

namespace ppp {
    namespace net {
        namespace packet {
            /**
             * @brief Builds an IPv4 ICMP packet from this frame.
             * @param allocator Buffer allocator used for packet memory.
             * @return Serialized IP frame, or nullptr when validation/allocation fails.
             * @throws std::runtime_error Thrown for unsupported address families.
             */
            std::shared_ptr<IPFrame> IcmpFrame::ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) {
                if (AddressFamily::InterNetwork != this->AddressesFamily) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressFamilyMismatch);
                    throw std::runtime_error("ICMP frames of this address family type are not supported.");
                }

                int payload_size = 0;
                std::shared_ptr<BufferSegment> payload = this->Payload;
                if (NULLPTR != payload) {
                    if (0 > payload->Length || (0 < payload->Length && NULLPTR == payload->Buffer)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, std::shared_ptr<IPFrame>());
                    }

                    payload_size += payload->Length;
                }

                int hdr_bytes_len = sizeof(struct icmp_hdr);
                int packet_size = hdr_bytes_len + payload_size;
                std::shared_ptr<Byte> packet_data = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_size);
                if (NULLPTR == packet_data) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, std::shared_ptr<IPFrame>());
                }

                struct icmp_hdr* icmphdr = (struct icmp_hdr*)packet_data.get();
                icmphdr->icmp_type = this->Type;
                icmphdr->icmp_code = this->Code;
                icmphdr->icmp_id = ntohs(this->Identification);
                icmphdr->icmp_seq = ntohs(this->Sequence);
                icmphdr->icmp_chksum = 0;

                if (0 < payload_size) {
                    memcpy((char*)icmphdr + hdr_bytes_len, payload->Buffer.get(), payload_size);
                }

                /** Recompute checksum after header and payload are finalized. */
                icmphdr->icmp_chksum = inet_chksum(icmphdr, packet_size);
                if (0 == icmphdr->icmp_chksum) {
                    icmphdr->icmp_chksum = 0xffff;
                }

                std::shared_ptr<IPFrame> packet = make_shared_object<IPFrame>();
                if (NULLPTR == packet) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, std::shared_ptr<IPFrame>());
                }

                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(packet_data, packet_size);
                if (NULLPTR == packet_payload) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed, std::shared_ptr<IPFrame>());
                }
                
                packet->ProtocolType = ip_hdr::IP_PROTO_ICMP;
                packet->Source = this->Source;
                packet->Destination = this->Destination;
                packet->Ttl = this->Ttl;
                packet->Payload = packet_payload;
                return packet;
            }

            /**
             * @brief Parses an ICMP frame from an IPv4 packet payload.
             * @param frame Source IP frame that should carry ICMP data.
             * @return Parsed ICMP frame, or nullptr on validation/parsing failure.
             */
            std::shared_ptr<IcmpFrame> IcmpFrame::Parse(const IPFrame* frame) noexcept {
                if (NULLPTR == frame || ip_hdr::IP_PROTO_ICMP != frame->ProtocolType) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid, std::shared_ptr<IcmpFrame>());
                }

                std::shared_ptr<BufferSegment> messages = frame->Payload;
                if (NULLPTR == messages || 0 >= messages->Length) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed, std::shared_ptr<IcmpFrame>());
                }

                if (sizeof(struct icmp_hdr) > messages->Length) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed, std::shared_ptr<IcmpFrame>());
                }

                struct icmp_hdr* icmphdr = (struct icmp_hdr*)messages->Buffer.get();
                if (NULLPTR == icmphdr) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed, std::shared_ptr<IcmpFrame>());
                }

#if defined(PACKET_CHECKSUM)
                /** Validate checksum when runtime checksum verification is enabled. */
                if (icmphdr->icmp_chksum != 0) {
                    UInt16 cksum = inet_chksum(icmphdr, messages->Length);
                    if (0 != cksum) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed, std::shared_ptr<IcmpFrame>());
                    }
                }
#endif

                int hdr_bytes_len = sizeof(struct icmp_hdr);
                int payload_size = messages->Length - hdr_bytes_len;
                if (0 > payload_size) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed, std::shared_ptr<IcmpFrame>());
                }

                std::shared_ptr<IcmpFrame> packet = make_shared_object<IcmpFrame>();
                if (NULLPTR == packet) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, std::shared_ptr<IcmpFrame>());
                }
                
                packet->Type = (IcmpType)icmphdr->icmp_type;
                packet->Code = icmphdr->icmp_code;
                packet->Identification = ntohs(icmphdr->icmp_id);
                packet->Sequence = ntohs(icmphdr->icmp_seq);
                packet->Ttl = frame->Ttl;
                packet->Destination = frame->Destination;
                packet->Source = frame->Source;
                packet->AddressesFamily = frame->AddressesFamily;

                std::shared_ptr<Byte> buffer = messages->Buffer;
                std::shared_ptr<BufferSegment> packet_payload = 
                    make_shared_object<BufferSegment>(wrap_shared_pointer(buffer.get() + hdr_bytes_len, buffer), payload_size);
                if (NULLPTR == packet_payload) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed, std::shared_ptr<IcmpFrame>());
                }

                packet->Payload = packet_payload;
                return packet;
            }
        }
    }
}
