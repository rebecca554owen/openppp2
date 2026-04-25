#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file UdpFrame.cpp
 * @brief Implements UDP frame parsing and IPv4 encapsulation.
 */

using namespace ppp::net::native;

namespace ppp {
    namespace net {
        namespace packet {
            /**
             * @brief Encapsulates this UDP frame into an IPv4 packet.
             * @param allocator Buffer allocator for temporary and payload storage.
             * @return Generated IPv4 frame, or null on validation/allocation failure.
             * @throws std::runtime_error When address family is unsupported.
             */
            std::shared_ptr<IPFrame> UdpFrame::ToIp(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) {
                if (this->AddressesFamily != AddressFamily::InterNetwork) {
                    throw std::runtime_error("UDP frames of this address family type are not supported.");
                }

                std::shared_ptr<BufferSegment> payload = this->Payload;
                if (NULLPTR == payload || NULLPTR == payload->Buffer) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                int payload_size = payload->Length;
                if (payload_size <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                int payload_offset = sizeof(udp_hdr);
                int message_size_ = payload_offset + payload_size;

                std::shared_ptr<Byte> message_ = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, message_size_);
                if (NULLPTR == message_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }
                else {
                    memcpy(message_.get() + payload_offset, payload->Buffer.get(), payload_size);
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)message_.get();
                udphdr->src = ntohs(this->Source.Port);
                udphdr->dest = ntohs(this->Destination.Port);
                udphdr->len = ntohs(message_size_);
                udphdr->chksum = 0;

                UInt16 pseudo_checksum = inet_chksum_pseudo(message_.get(),
                    ip_hdr::IP_PROTO_UDP,
                    message_size_,
                    this->Source.GetAddress(),
                    this->Destination.GetAddress());
                /** @note UDP checksum of zero is represented as 0xFFFF on the wire. */
                if (pseudo_checksum == 0) {
                    pseudo_checksum = 0xffff;
                }

                udphdr->chksum = pseudo_checksum;

                std::shared_ptr<IPFrame> packet = make_shared_object<IPFrame>();
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                packet->ProtocolType = ip_hdr::IP_PROTO_UDP;
                packet->Source = this->Source.GetAddress();
                packet->Destination = this->Destination.GetAddress();
                packet->Ttl = this->Ttl;
                packet->Flags = (IPFlags)0x00;
                packet->Tos = ppp::net::Socket::IsDefaultFlashTypeOfService() ? IPFrame::DefaultFlashTypeOfService() : 0x04;

                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(message_, message_size_);
                if (NULLPTR == packet_payload) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }
                
                packet->Payload = packet_payload;
                return packet;
            }

            /**
             * @brief Parses a UDP datagram from an IPv4 payload.
             * @param frame Source IPv4 frame.
             * @return Parsed UDP frame or null if validation fails.
             */
            std::shared_ptr<UdpFrame> UdpFrame::Parse(const IPFrame* frame) noexcept {
                if (NULLPTR == frame) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                std::shared_ptr<BufferSegment> messages = frame->Payload;
                if (NULLPTR == messages || messages->Length <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                if (messages->Length < sizeof(struct udp_hdr)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                struct udp_hdr* udphdr = (struct udp_hdr*)messages->Buffer.get();
                if (NULLPTR == udphdr) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                if (messages->Length != ntohs(udphdr->len)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                int offset = sizeof(struct udp_hdr);
                int payload_len = messages->Length - offset;
                if (payload_len <= 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

#if defined(PACKET_CHECKSUM)
                /** @details Validate checksum only when checksum checks are enabled. */
                if (udphdr->chksum != 0) {
                    UInt32 pseudo_checksum = inet_chksum_pseudo((unsigned char*)udphdr,
                        ip_hdr::IP_PROTO_UDP,
                        messages->Length,
                        frame->Source,
                        frame->Destination);
                    if (pseudo_checksum != 0) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                        return NULLPTR;
                    }
                }
#endif

                std::shared_ptr<UdpFrame> packet = make_shared_object<UdpFrame>();
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }
                
                packet->AddressesFamily = AddressFamily::InterNetwork;
                packet->Ttl = frame->Ttl;
                packet->Source = IPEndPoint(frame->Source, ntohs(udphdr->src));
                packet->Destination = IPEndPoint(frame->Destination, ntohs(udphdr->dest));

                std::shared_ptr<Byte> buffer = messages->Buffer;
                std::shared_ptr<BufferSegment> packet_payload = make_shared_object<BufferSegment>(
                    wrap_shared_pointer(buffer.get() + offset, buffer), payload_len);

                if (NULLPTR == packet_payload) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
                    return NULLPTR;
                }

                packet->Payload = packet_payload;
                return packet;
            }
        }
    }
}
