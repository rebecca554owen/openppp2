#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetHttpProxyConnection.h>
#include <ppp/IDisposable.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include <ppp/io/File.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>
#include <ppp/ipv6/IPv6Packet.h>

#include <ppp/net/asio/vdns.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/net/asio/InternetControlMessageProtocol.h>

#include <chrono>

#if defined(_ANDROID)
#include <android/log.h>
#endif

/**
 * @file VEthernetNetworkSwitcher.cpp
 * @brief Client-side virtual Ethernet network switcher implementation.
 * @details Licensed under GPL-3.0.
 */

#if defined(_WIN32)
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#endif
#endif


/** @brief Returns whether current platform supports managed IPv6 operations. */
static bool ClientSupportsManagedIPv6() noexcept {
#if defined(_WIN32) || defined(_LINUX) || defined(_MACOS)
    return true;
#else
    return false;
#endif
}

/** @brief Validates whether extensions describe an applicable managed IPv6 assignment. */
static bool HasManagedIPv6Assignment(const ppp::app::protocol::VirtualEthernetInformationExtensions& extensions) noexcept {
    bool status_ok = extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_Applied ||
        extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned ||
        extensions.IPv6StatusCode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Status_ClientRequested;

    return status_ok &&
        (extensions.AssignedIPv6Mode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
        extensions.AssignedIPv6Mode == ppp::app::protocol::VirtualEthernetInformationExtensions::IPv6Mode_Gua) &&
        extensions.AssignedIPv6AddressPrefixLength == ppp::ipv6::IPv6_MAX_PREFIX_LENGTH &&
        extensions.AssignedIPv6Address.is_v6() &&
        !extensions.AssignedIPv6Address.is_unspecified() &&
        !extensions.AssignedIPv6Address.is_multicast() &&
        !extensions.AssignedIPv6Address.is_loopback();
}

/** @brief Compares two managed IPv6 assignment snapshots for equality. */
static bool SameManagedIPv6Configuration(
    const ppp::app::protocol::VirtualEthernetInformationExtensions& left,
    const ppp::app::protocol::VirtualEthernetInformationExtensions& right) noexcept {

    return left.AssignedIPv6Mode == right.AssignedIPv6Mode &&
        left.AssignedIPv6AddressPrefixLength == right.AssignedIPv6AddressPrefixLength &&
        left.AssignedIPv6Flags == right.AssignedIPv6Flags &&
        left.AssignedIPv6Address == right.AssignedIPv6Address &&
        left.AssignedIPv6Gateway == right.AssignedIPv6Gateway &&
        left.AssignedIPv6RoutePrefix == right.AssignedIPv6RoutePrefix &&
        left.AssignedIPv6RoutePrefixLength == right.AssignedIPv6RoutePrefixLength &&
        left.AssignedIPv6Dns1 == right.AssignedIPv6Dns1 &&
        left.AssignedIPv6Dns2 == right.AssignedIPv6Dns2;
}

using ppp::auxiliary::StringAuxiliary;
using ppp::collections::Dictionary;
using ppp::threading::Timer;
using ppp::threading::Executors;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::net::Ipep;
using ppp::net::native::ip_hdr;
using ppp::net::native::udp_hdr;
using ppp::net::native::icmp_hdr;
using ppp::net::packet::IPFlags;
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;
using ppp::net::packet::IcmpFrame;
using ppp::net::packet::IcmpType;
using ppp::net::packet::BufferSegment;
using ppp::transmissions::ITransmission;
using ppp::telemetry::Level;

/**
 * @brief Converts AppConfiguration::DnsServerEntry to dns::ServerEntry.
 *
 * @param ce  Configuration-layer DNS server entry.
 * @return Resolver-layer server entry with protocol, address, hostname, and url populated.
 */
static ppp::dns::ServerEntry DnsServerEntryToResolverEntry(
    const ppp::configurations::AppConfiguration::DnsServerEntry& ce) noexcept {

    ppp::dns::ServerEntry se;
    ppp::string proto = ToLower(ce.protocol);
    if (proto == "doh") {
        se.protocol = ppp::dns::Protocol::DoH;
    } else if (proto == "dot") {
        se.protocol = ppp::dns::Protocol::DoT;
    } else if (proto == "tcp") {
        se.protocol = ppp::dns::Protocol::TCP;
    } else {
        se.protocol = ppp::dns::Protocol::UDP;
    }
    se.url      = ce.url;
    se.hostname = ce.hostname;
    se.address  = ce.address;
    for (const auto& b : ce.bootstrap) {
        boost::system::error_code ec;
        boost::asio::ip::address addr = ppp::StringToAddress(b.data(), ec);
        if (!ec && !addr.is_unspecified()) {
            se.bootstrap_ips.push_back(addr);
        }
    }
    return se;
}

/**
 * @brief Builds a dns::ServerEntry vector from AppConfiguration::DnsServerEntry list.
 */
static ppp::vector<ppp::dns::ServerEntry> BuildResolverEntries(
    const ppp::vector<ppp::configurations::AppConfiguration::DnsServerEntry>& config_entries) noexcept {

    ppp::vector<ppp::dns::ServerEntry> result;
    result.reserve(config_entries.size());
    for (const auto& ce : config_entries) {
        result.emplace_back(DnsServerEntryToResolverEntry(ce));
    }
    return result;
}

/**
 * @brief Parses a STUN candidate string ("ip:port" or "hostname:port") into StunCandidate.
 *
 * Only IP-literal candidates are accepted (returns false for hostnames to
 * avoid blocking DNS resolution at config time).
 */
static bool ParseStunCandidate(const ppp::string& s, ppp::dns::StunCandidate& out) noexcept {
    ppp::string text = ATrim(s);
    if (text.empty()) {
        return false;
    }

    int port = 3478;
    ppp::string host;

    std::size_t colon = text.rfind(':');
    if (colon != ppp::string::npos && colon > 0) {
        host = text.substr(0, colon);
        ppp::string port_str = text.substr(colon + 1);
        int p = atoi(port_str.data());
        if (p > 0 && p <= 65535) {
            port = p;
        }
    } else {
        host = text;
    }

    boost::system::error_code ec;
    boost::asio::ip::address ip = ppp::StringToAddress(host.data(), ec);
    if (ec || ip.is_unspecified()) {
        return false;
    }

    out.ip   = ip;
    out.port = port;
    return true;
}

namespace ppp {
    namespace app {
        namespace client {
            /** @brief Constructs network switcher and initializes baseline state flags. */
            VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
                : VEthernet(context, lwip, vnet, mta)
                , configuration_(configuration)
                , icmppackets_aid_(0) {

#if !defined(_ANDROID) && !defined(_IPHONE)
                route_added_     = false;
#if defined(_LINUX)
                protect_mode_    = false;
#endif
#endif
                static_mode_     = false;
                block_quic_      = false;
                icmppackets_aid_ = RandomNext();
            }

            /** @brief Finalizes network switcher on destruction. */
            VEthernetNetworkSwitcher::~VEthernetNetworkSwitcher() noexcept {
                Finalize();
            }

            /** @brief Initializes network interface snapshot defaults. */
            VEthernetNetworkSwitcher::NetworkInterface::NetworkInterface() noexcept
                : Index(-1) {

            }

            /** @brief Creates concrete TCP/IP stack implementation for VEthernet. */
            std::shared_ptr<ppp::ethernet::VNetstack> VEthernetNetworkSwitcher::NewNetstack() noexcept {
                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetNetworkTcpipStack>(self);
            }

            /** @brief Performs periodic tick maintenance for QoS, exchanger, and timers. */
            bool VEthernetNetworkSwitcher::OnTick(uint64_t now) noexcept {
                if (!VEthernet::OnTick(now)) {
                    return false;
                }

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULLPTR != qos) {
                    qos->Update(now);
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR != exchanger) {
                    exchanger->Update();
                }

                std::shared_ptr<IForwarding> forwarding = forwarding_;
                if (NULLPTR != forwarding) {
                    forwarding->Update(now);
                }

                ppp::vector<int> releases_icmppackets;
                for (;;) {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    for (auto&& kv : icmppackets_) {
                        const VEthernetIcmpPacket& icmppacket = kv.second;
                        if (icmppacket.datetime > now) {
                            continue;
                        }

                        releases_icmppackets.emplace_back(kv.first);
                    }

                    for (int ack_id : releases_icmppackets) {
                        ppp::collections::Dictionary::RemoveValueByKey(icmppackets_, ack_id);
                    }

                    break;
                }

                VEthernetTickEventHandler tick_event = TickEvent;
                if (tick_event) {
                    tick_event(this, now);
                }

                return true;
            }

            /** @brief Handles native IPv4 packet input and forwards eligible NAT traffic. */
            bool VEthernetNetworkSwitcher::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept {
                if (!vnet) {
                    return false;
                }

                if (proto != ppp::net::native::ip_hdr::IP_PROTO_TCP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_UDP &&
                    proto != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                uint32_t destination = packet->dest;
                if (destination == tap->IPAddress || packet->src != tap->IPAddress) {
                    return false;
                }

                uint32_t gw = tap->GatewayServer;
                uint32_t mask = tap->SubmaskAddress;
                if (IPAddressIsGatewayServer(destination, gw, mask)) {
                    return false;
                }

                if (destination != ppp::net::native::ip_hdr::IP_ADDR_BROADCAST_VALUE) {
                    if ((destination & mask) != (gw & mask)) {
                        return false;
                    }
                }

                exchanger->Nat(packet, packet_length);
                return true;
            }

            /** @brief Handles raw IPv6 packet input and forwards approved traffic. */
            bool VEthernetNetworkSwitcher::OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept {
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    return false;
                }


                if (!IsApprovedIPv6Packet(packet, packet_length)) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    return false;
                }

                app::protocol::ClampTcpMssIPv6(packet, packet_length, app::protocol::ComputeDynamicTcpMss(false, app::protocol::kVEthernetTunnelOverhead));

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                exchanger->Nat(packet, packet_length);
                return true;
            }

            /** @brief Validates IPv6 packet source and destination against assigned policy. */
            bool VEthernetNetworkSwitcher::IsApprovedIPv6Packet(Byte* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < ppp::ipv6::IPv6_HEADER_MIN_SIZE) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    return false;
                }

                boost::asio::ip::address_v6::bytes_type src_bytes = source.to_bytes();
                if (src_bytes[0] == 0xfe && (src_bytes[1] & 0xc0) == 0x80) {
                    return false;
                }

                if (destination.is_unspecified() || destination.is_loopback() || destination.is_multicast()) {
                    return false;
                }

                const VirtualEthernetInformationExtensions& approved = information_extensions_;
                bool valid_mode = approved.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
                    approved.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                if (!ipv6_applied_ || !valid_mode || approved.AssignedIPv6AddressPrefixLength != ppp::ipv6::IPv6_MAX_PREFIX_LENGTH || !approved.AssignedIPv6Address.is_v6()) {
                    return false;
                }

                if (source != approved.AssignedIPv6Address.to_v6()) {
                    return false;
                }

                return true;
            }

            /** @brief Routes parsed IP frame to protocol-specific handlers. */
            bool VEthernetNetworkSwitcher::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                if (packet->ProtocolType == ip_hdr::IP_PROTO_UDP) {
                    return OnUdpPacketInput(packet);
                }
                elif(packet->ProtocolType == ip_hdr::IP_PROTO_ICMP) {
                    return OnIcmpPacketInput(packet);
                }
                else {
                    return false;
                }
            }

            /** @brief Handles UDP frame forwarding, DNS redirect, and static mode paths. */
            bool VEthernetNetworkSwitcher::OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<UdpFrame> frame = UdpFrame::Parse(packet.get());
                if (NULLPTR == frame) {
                    return false;
                }

                const std::shared_ptr<BufferSegment>& messages = frame->Payload;
                if (NULLPTR == messages) {
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                // Check whether dns resolution packets need to be redirected.
                int destinationPort = frame->Destination.Port;
                if (destinationPort == PPP_DNS_SYS_PORT) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2",
                        "dns_redirect udp53 input src_port=%d dst_port=%d payload=%d dst=%s",
                        (int)frame->Source.Port,
                        (int)frame->Destination.Port,
                        NULLPTR != messages ? (int)messages->Length : -1,
                        Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    if (RedirectDnsServer(exchanger, packet, frame, messages)) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect udp53 handled");
#endif
                        return true;
                    }
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect udp53 passthrough");
#endif
                }

                // If the current need to prohibit the transfer of QUIC IETF control protocol traffic,
                // then the outgoing traffic sent to the 443 two ports through the UDP protocol can be directly discarded,
                // simple and rough processing, if the remote sensing of all UDP port traffic,
                // it will produce unnecessary burden and overhead on the performance of the program itself.
                if (block_quic_ && destinationPort == PPP_HTTPS_SYS_PORT) {
                    return false;
                }

                // If the VPN uses static transmission mode, ensure that the link is link ready.
                if (static_mode_) {
                    auto& static_ = configuration_->udp.static_;
                    if (static_.quic && destinationPort == PPP_HTTPS_SYS_PORT) {
                        if (exchanger->StaticEchoAllocated()) {
                            return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                        }
                    }
                    elif(static_.dns && destinationPort == PPP_DNS_SYS_PORT) {
                        if (exchanger->StaticEchoAllocated()) {
                            return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                        }
                    }
                    elif(exchanger->StaticEchoAllocated()) {
                        return exchanger->StaticEchoPacketToRemoteExchanger(frame);
                    }
                }

                boost::asio::ip::udp::endpoint sourceEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                boost::asio::ip::udp::endpoint destinationEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Destination);
                return exchanger->SendTo(sourceEP, destinationEP, messages->Buffer.get(), messages->Length);
            }

            /** @brief Sends ICMP Echo Reply generated from tracked packet context. */
            bool VEthernetNetworkSwitcher::ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::ER(packet, frame, ttl, allocator);
                if (NULLPTR == reply) {
                    return false;
                }
                else {
                    return Output(reply.get());
                }
            }

            /** @brief Sends ICMP Time Exceeded generated from tracked packet context. */
            bool VEthernetNetworkSwitcher::TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<IPFrame> reply = ppp::net::asio::InternetControlMessageProtocol::TE(packet, frame, source, allocator);
                if (NULLPTR == reply) {
                    return false;
                }
                else {
                    return Output(reply.get());
                }
            }

            /** @brief Resolves ACK identifier and emits appropriate ICMP response packet. */
            bool VEthernetNetworkSwitcher::ERORTE(int ack_id) noexcept {
                std::shared_ptr<IPFrame> packet;
                if (ack_id != 0) {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    bool ok = Dictionary::RemoveValueByKey(icmppackets_, ack_id, packet,
                        [](VEthernetIcmpPacket& value) noexcept {
                            return value.packet;
                        });
                    if (!ok) {
                        return false;
                    }
                }

                if (NULLPTR == packet) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
                if (NULLPTR == frame) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                if (IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
                    int ttl = std::max<int>(1, static_cast<int>(frame->Ttl) - 1);
                    return ER(packet, frame, ttl, allocator);
                }
                else {
                    return TE(packet, frame, tap->GatewayServer, allocator);
                }
            }

            /** @brief Processes ICMP input and dispatches to gateway/other echo paths. */
            bool VEthernetNetworkSwitcher::OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                std::shared_ptr<IcmpFrame> frame = IcmpFrame::Parse(packet.get());
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_input dst=%s ttl=%d type=%d code=%d frame=%p",
                    Ipep::ToAddress(packet->Destination).to_string().c_str(),
                    packet->Ttl,
                    NULLPTR != frame ? (int)frame->Type : -1,
                    NULLPTR != frame ? (int)frame->Code : -1,
                    (void*)frame.get());
#endif
                if (NULLPTR == frame || frame->Ttl == 0) {
                    return false;
                }
                elif(IPAddressIsGatewayServer(frame->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_gateway dst=%s", Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                elif(frame->Ttl == 1) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_ttl1 dst=%s", Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return EchoGatewayServer(exchanger, packet, allocator);
                }
                else {
                    int ttl = std::max<int>(0, static_cast<int>(packet->Ttl) - 1);
                    if (packet->Ttl < 1) {
                        return false;
                    }

                    frame->Ttl = ttl;
                    packet->Ttl = ttl;

#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_other dst=%s ttl=%d", Ipep::ToAddress(packet->Destination).to_string().c_str(), ttl);
#endif
                    return EchoOtherServer(exchanger, packet, allocator);
                }
            }

            /** @brief Forwards ICMP packet to non-gateway destination through exchanger.
             *
             *  Fallback strategy: when static echo is available, try it first for the
             *  low-latency path.  Regardless of the static-echo result, also send via
             *  the standard PacketAction_ECHO channel so the server's ICMP echo-reply
             *  machinery always gets a chance to respond.  The server de-duplicates
             *  repeated echo requests natively, so the extra probe is harmless.
             */
            bool VEthernetNetworkSwitcher::EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                if (NULLPTR == exchanger) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                std::shared_ptr<BufferSegment> messages = IPFrame::ToArray(allocator, packet.get());
                if (NULLPTR == messages) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "icmp_other to_array failed dst=%s",
                        Ipep::ToAddress(packet->Destination).to_string().c_str());
#endif
                    return false;
                }

                auto& static_ = configuration_->udp.static_;
                if ((static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                    bool se_ok = exchanger->StaticEchoPacketToRemoteExchanger(packet.get());
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_other static_echo dst=%s ok=%d",
                        Ipep::ToAddress(packet->Destination).to_string().c_str(), (int)se_ok);
#endif
                }

                bool ok = exchanger->Echo(messages->Buffer.get(), messages->Length);
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_other echo dst=%s ok=%d",
                    Ipep::ToAddress(packet->Destination).to_string().c_str(), (int)ok);
#endif
                return ok;
            }

            /** @brief Tracks ICMP packet by ACK ID and triggers remote gateway echo flow. */
            bool VEthernetNetworkSwitcher::EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                static constexpr int max_icmp_packets_aid = (1 << 24) - 1;

                if (NULLPTR == exchanger) {
                    return false;
                }

                int ack_id = 0;
                /** @brief Allocates a unique ACK ID and stores packet until callback/timeout. */
                for (SynchronizedObjectScope scope(GetSynchronizedObject());;) {
                    if (IsDisposed()) {
                        return false;
                    }

                    VEthernetIcmpPacket e = { Executors::GetTickCount() + ppp::net::asio::InternetControlMessageProtocol::MAX_ICMP_TIMEOUT, packet };
                    bool static_exchange = false;

                    for (int i = 0; i < UINT16_MAX; i++) {
                        ack_id = ++icmppackets_aid_;
                        if (ack_id < 1) {
                            icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ack_id > max_icmp_packets_aid) {
                            icmppackets_aid_ = 0;
                            continue;
                        }

                        if (ppp::collections::Dictionary::ContainsKey(icmppackets_, ack_id)) {
                            continue;
                        }

                        if (!ppp::collections::Dictionary::TryAdd(icmppackets_, ack_id, e)) {
                            return false;
                        }

                        auto& static_ = configuration_->udp.static_;
                        if ((static_mode_ && static_.icmp) && exchanger->StaticEchoAllocated()) {
                            static_exchange = true;
                            break;
                        }
                        elif(exchanger->Echo(ack_id)) {
#if defined(_ANDROID)
                            __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_gateway echo ack_id=%d ok=1", ack_id);
#endif
                            return true;
                        }

                        ppp::collections::Dictionary::TryRemove(icmppackets_, ack_id);
                        return false;
                    }

                    if (static_exchange) {
                        break;
                    }

                    return false;
                }

                bool ok = exchanger->StaticEchoGatewayServer(ack_id);
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "icmp_gateway static_echo ack_id=%d ok=%d", ack_id, (int)ok);
#endif
                if (ok) {
                    return true;
                }
                else {
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    ppp::collections::Dictionary::TryRemove(icmppackets_, ack_id);
                    return false;
                }
            }

            /** @brief Dispatches switcher finalization and then disposes base VEthernet. */
            void VEthernetNetworkSwitcher::Dispose() noexcept {
                auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::dispatch(*context,
                    [self, this, context]() noexcept {
                        Finalize();
                    });
                ppp::telemetry::Log(Level::kInfo, "client", "TUN detached");
                VEthernet::Dispose();
            }

            /** @brief Releases objects, packets, and timeout handlers. */
            void VEthernetNetworkSwitcher::Finalize() noexcept {
                ReleaseAllObjects();
                ReleaseAllPackets();
                ReleaseAllTimeouts();
            }

            /** @brief Clears all tracked ICMP packet records. */
            void VEthernetNetworkSwitcher::ReleaseAllPackets() noexcept {
                // Clear all ICMP packet container.
                SynchronizedObjectScope scope(GetSynchronizedObject());
                icmppackets_.clear();
            }

            /** @brief Releases all registered timeout callbacks. */
            void VEthernetNetworkSwitcher::ReleaseAllTimeouts() noexcept {
                TimeoutEventHandlerTable timeouts; {
                    // Clear all ICMP packet container.
                    SynchronizedObjectScope scope(GetSynchronizedObject());
                    timeouts = std::move(timeouts_);
                    timeouts_.clear();
                }

                // Release all timeout callbacks.
                Timer::ReleaseAllTimeouts(timeouts);
            }

#if defined(_ANDROID) || defined(_IPHONE)
            /** @brief Stores bypass IP list text used by mobile route setup. */
            void VEthernetNetworkSwitcher::SetBypassIpList(ppp::string&& bypass_ip_list) noexcept {
                bypass_ip_list_ = std::move(bypass_ip_list);
            }
#endif

            /** @brief Creates QoS controller with configured bandwidth policy. */
            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::NewQoS() noexcept {
                int64_t bandwidth = std::max<int64_t>(0, configuration_->client.bandwidth);
                if (bandwidth < 0) {
                    bandwidth *= (1024 >> 3); /* Kbps. */
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                return make_shared_object<ppp::transmissions::ITransmissionQoS>(context, bandwidth);
            }

            /** @brief Creates exchanger instance using configured client GUID. */
            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::NewExchanger() noexcept {
                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                auto guid = StringAuxiliary::GuidStringToInt128(configuration->client.guid);
                if (guid == 0) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionIdInvalid, std::shared_ptr<VEthernetExchanger>(NULLPTR));
                }

                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VEthernetNetworkSwitcher>(my);
                return make_shared_object<VEthernetExchanger>(self, configuration, GetContext(), guid);
            }

            /** @brief Creates HTTP proxy switcher bound to exchanger. */
            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr(NULLPTR));
                }
                else {
                    return make_shared_object<VEthernetHttpProxySwitcher>(exchanger);
                }
            }

            /** @brief Creates SOCKS proxy switcher bound to exchanger. */
            VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {
                if (NULLPTR == exchanger) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr(NULLPTR));
                }
                else {
                    return make_shared_object<VEthernetSocksProxySwitcher>(exchanger);
                }
            }

            /** @brief Returns buffer allocator from runtime configuration. */
            std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetNetworkSwitcher::GetBufferAllocator() noexcept {
                return configuration_->GetBufferAllocator();
            }

            /** @brief Converts UDP payload to IP frame and emits it to local output. */
            bool VEthernetNetworkSwitcher::DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return false;
                }

                if (IsDisposed()) {
                    return false;
                }

                boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                boost::asio::ip::address address = remoteEP.address();
                if (address.is_v4()) {
                    std::shared_ptr<BufferSegment> messages = make_shared_object<BufferSegment>();
                    if (NULLPTR == messages) {
                        return false;
                    }

                    messages->Buffer = wrap_shared_pointer(reinterpret_cast<Byte*>(packet));
                    messages->Length = packet_size;

                    std::shared_ptr<UdpFrame> frame = make_shared_object<UdpFrame>();
                    if (NULLPTR == frame) {
                        return false;
                    }

                    frame->AddressesFamily = AddressFamily::InterNetwork;
                    frame->Source = IPEndPoint::ToEndPoint(remoteEP);
                    frame->Destination = IPEndPoint::ToEndPoint(sourceEP);
                    frame->Payload = messages;

                    if (caching && configuration_->udp.dns.cache) {
                        int destinationPort = destinationEP.port();
                        if (destinationPort == PPP_DNS_SYS_PORT) {
                            ppp::net::asio::vdns::AddCache((Byte*)packet, packet_size);
                        }
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
                    std::shared_ptr<IPFrame> ip = UdpFrame::ToIp(allocator, frame.get());
                    return Output(ip.get());
                }

                return false;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            /** @brief Applies managed IPv6 address, route, and DNS configuration. */
            bool VEthernetNetworkSwitcher::ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept {
                if (!ClientSupportsManagedIPv6()) {
                    return false;
                }

                if (ipv6_applied_) {
                    return false;
                }

                auto tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                auto tun_ni = tun_ni_;
                if (NULLPTR == tun_ni) {
                    return false;
                }

                ppp::telemetry::SpanScope span("client.ipv6.apply");
                struct ScopedIPv6ApplyHistogram final {
                    std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                    ~ScopedIPv6ApplyHistogram() noexcept {
                        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                        ppp::telemetry::Histogram("client.ipv6.apply.us", elapsed);
                    }
                } ipv6_apply_histogram;


                bool nat_mode = extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66;
                bool gua_mode = extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                if (!nat_mode && !gua_mode) {
                    return false;
                }

                if (extensions.AssignedIPv6AddressPrefixLength != ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                    return false;
                }

                if (!extensions.AssignedIPv6Address.is_v6()) {
                    return false;
                }

                bool applied = true;
                bool attempted = false;
                ipv6_state_.Clear();

                ppp::ipv6::auxiliary::ClientContext ipv6_context;
                ipv6_context.Tap = tap.get();
                ipv6_context.InterfaceIndex = tun_ni->Index;
                ipv6_context.InterfaceName = tun_ni->Name;

                int prefix = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH + 1, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, (int)extensions.AssignedIPv6AddressPrefixLength));
                if (prefix < 1) {
                    prefix = 64;
                }

                ppp::ipv6::auxiliary::CaptureClientOriginalState(ipv6_context, nat_mode, ipv6_state_);

                if (extensions.AssignedIPv6Address.is_v6()) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientAddress(ipv6_context, extensions.AssignedIPv6Address, prefix, gua_mode, ipv6_state_);
                }

                if (extensions.AssignedIPv6Gateway.is_v6() || nat_mode) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientDefaultRoute(ipv6_context, extensions.AssignedIPv6Gateway, nat_mode, ipv6_state_);
                }

                if (nat_mode && extensions.AssignedIPv6RoutePrefix.is_v6() &&
                    extensions.AssignedIPv6RoutePrefixLength > 0 &&
                    extensions.AssignedIPv6RoutePrefixLength < ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientSubnetRoute(
                        ipv6_context,
                        extensions.AssignedIPv6RoutePrefix,
                        extensions.AssignedIPv6RoutePrefixLength,
                        extensions.AssignedIPv6Gateway,
                        nat_mode,
                        ipv6_state_);
                }

                ppp::vector<ppp::string> dns_servers;
                if (extensions.AssignedIPv6Dns1.is_v6()) {
                    std::string dns1_std = extensions.AssignedIPv6Dns1.to_string();
                    dns_servers.emplace_back(dns1_std.data(), dns1_std.size());
                }
                if (extensions.AssignedIPv6Dns2.is_v6()) {
                    std::string dns2_std = extensions.AssignedIPv6Dns2.to_string();
                    dns_servers.emplace_back(dns2_std.data(), dns2_std.size());
                }

                if (!dns_servers.empty()) {
                    attempted = true;
                    applied &= ppp::ipv6::auxiliary::ApplyClientDns(ipv6_context, dns_servers, ipv6_state_);
                }

                applied &= attempted;

                if (applied) {
                    ipv6_applied_      = true;
                    // Memoize the successfully-applied address so that SendRequestedIPv6Configuration()
                    // can use it as a sticky hint on reconnect to re-request the same address when the
                    // user has not configured an explicit RequestedIPv6() preference.
                    last_assigned_ipv6_ = extensions.AssignedIPv6Address;
                    ppp::telemetry::Log(Level::kDebug, "client", "IPv6 applied");
                    ppp::telemetry::Count("client.ipv6.apply", 1);
                }
                else {
                    ppp::ipv6::auxiliary::RestoreClientConfiguration(ipv6_context, extensions.AssignedIPv6Address, prefix, nat_mode, ipv6_state_);
                    ipv6_state_.Clear();
                }

                return applied;
            }

            /** @brief Restores previous IPv6 configuration captured before apply. */
            void VEthernetNetworkSwitcher::RestoreAssignedIPv6() noexcept {
                ppp::telemetry::SpanScope span("client.ipv6.restore");
                if (!ipv6_applied_) {
                    return;
                }

                ppp::telemetry::Log(Level::kDebug, "client", "IPv6 removed");

                auto tap = GetTap();
                if (NULLPTR == tap) {
                    ipv6_applied_ = false;
                    return;
                }

                auto tun_ni = tun_ni_;
                if (NULLPTR == tun_ni) {
                    ipv6_applied_ = false;
                    return;
                }

                int prefix = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH + 1, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, (int)information_extensions_.AssignedIPv6AddressPrefixLength));
                if (prefix < 1) {
                    prefix = 64;
                }

                ppp::ipv6::auxiliary::ClientContext ipv6_context;
                ipv6_context.Tap = tap.get();
                ipv6_context.InterfaceIndex = tun_ni->Index;
                ipv6_context.InterfaceName = tun_ni->Name;

                bool nat_mode = information_extensions_.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66;
                auto started_at = std::chrono::steady_clock::now();
                ppp::ipv6::auxiliary::RestoreClientConfiguration(ipv6_context, information_extensions_.AssignedIPv6Address, prefix, nat_mode, ipv6_state_);
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("client.ipv6.restore.us", elapsed);

                ipv6_applied_ = false;
                ipv6_state_.Clear();
            }

#endif

            /** @brief Adapts base information callback to extension-aware overload. */
            bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>& info) noexcept {
                VirtualEthernetInformationExtensions extensions;
                extensions.Clear();
                return OnInformation(info, extensions);
            }

            /** @brief Updates runtime state from server information and extensions. */
            bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>& info, const VirtualEthernetInformationExtensions& extensions) noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }


#if !defined(_ANDROID) && !defined(_IPHONE)
                bool previous_assignment = HasManagedIPv6Assignment(information_extensions_);
                bool current_assignment = HasManagedIPv6Assignment(extensions);
                if (ipv6_applied_ && (!previous_assignment || !current_assignment || !SameManagedIPv6Configuration(information_extensions_, extensions))) {
                    RestoreAssignedIPv6();
                }

                information_extensions_ = extensions;

                // Propagate the server-observed ClientExitIP into DnsResolver so that
                // ECS injection can use it as the fallback source address when no
                // override_ip is configured.
                if (NULLPTR != dns_resolver_ && !extensions.ClientExitIP.is_unspecified()) {
                    dns_resolver_->SetExitIP(extensions.ClientExitIP);
                }

                bool valid_ipv6_assignment = HasManagedIPv6Assignment(extensions);

                /**
                 * @brief Tell the DNS resolver whether AAAA records may safely be
                 *        propagated to local applications. We allow them only when
                 *        the server has actually assigned a usable IPv6 address;
                 *        otherwise AAAA queries are answered with empty NOERROR to
                 *        avoid 30+ second IPv6-first connect stalls.
                 */
                if (NULLPTR != dns_resolver_) {
                    dns_resolver_->SetAllowIPv6Response(valid_ipv6_assignment);
                }

                if (!valid_ipv6_assignment && ipv6_applied_) {
                    RestoreAssignedIPv6();
                }

                if (valid_ipv6_assignment) {
                    if (!ClientSupportsManagedIPv6()) {
                    }
                    elif (extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Nat66 &&
                        extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Gua) {
                    }
                    elif (!ipv6_applied_) {
                        ApplyAssignedIPv6(extensions);
                    }
                }
#else
                information_extensions_ = extensions;

                // Propagate ClientExitIP for ECS on mobile platforms as well.
                if (NULLPTR != dns_resolver_ && !extensions.ClientExitIP.is_unspecified()) {
                    dns_resolver_->SetExitIP(extensions.ClientExitIP);
                }

                // Mirror desktop behaviour: enable AAAA propagation only when the
                // server has assigned a usable IPv6 address. The mobile data plane
                // does not currently apply the assignment, but the gating policy
                // should remain consistent so AAAA queries do not stall connect().
                if (NULLPTR != dns_resolver_) {
                    dns_resolver_->SetAllowIPv6Response(HasManagedIPv6Assignment(extensions));
                }
#endif

                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = qos_;
                if (NULLPTR != qos) {
                    int64_t bandwidth = static_cast<int64_t>(info->BandwidthQoS) * (1024 >> 3); /* Kbps. */
                    qos->SetBandwidth(bandwidth);
                }

                // If the user still has the remaining incoming/outgoing traffic and the expiration time is not reached,
                // The VPN link is regarded as successful. Otherwise, the VPN link needs to be disconnected.
                if (info->Valid()) {
                    return true;
                }

                // If the VPN link needs to be disconnected, the client requires the active end, and the server forcibly disconnects.
                // This prevents you from bypassing the disconnection problem by modifying the code of the client switch.
                std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->GetTransmission();
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                return false;
            }

#if defined(_WIN32)
            /** @brief Creates Windows PaperAirplane controller bound to exchanger. */
            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::NewPaperAirplaneController() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = GetExchanger();
                if (NULLPTR == exchanger) {
                    return NULLPTR;
                }
                else {
                    return make_shared_object<PaperAirplaneController>(exchanger);
                }
            }
#elif defined(_LINUX)
            /** @brief Creates Linux protector network instance for socket protection. */
            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::NewProtectorNetwork() noexcept {
#if defined(_ANDROID)
                // Embedding the so framework into the Android platform does not use sendfd/recvfd unix to share fd across processes,
                // So you cannot pass in network cards or unix path names.
                ppp::string dev;
                return make_shared_object<ProtectorNetwork>(dev);
#else
                std::shared_ptr<NetworkInterface> ni = GetUnderlyingNetworkInterface();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

                return make_shared_object<ProtectorNetwork>(ni->Name);
#endif
            }
#endif

            /** @brief Retrieves latest information snapshot from exchanger. */
            std::shared_ptr<VEthernetNetworkSwitcher::VirtualEthernetInformation> VEthernetNetworkSwitcher::GetInformation() noexcept {
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return NULLPTR;
                }

                return exchanger->GetInformation();
            }

            /** @brief Creates transmission statistics collector instance. */
            VEthernetNetworkSwitcher::ITransmissionStatisticsPtr VEthernetNetworkSwitcher::NewStatistics() noexcept {
                return make_shared_object<ITransmissionStatistics>();
            }

#if defined(_WIN32)
            /** @brief Builds switcher network-interface snapshot from Windows adapter details. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetNetworkInterface(const ppp::win32::network::AdapterInterfacePtr& ai, const ppp::win32::network::NetworkInterfacePtr& ni) noexcept {
                if (NULLPTR == ai || NULLPTR == ni) {
                    return NULLPTR;
                }

                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> result = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                if (NULLPTR == result) {
                    return NULLPTR;
                }

                boost::system::error_code ec;
                result->Id = ni->Guid;
                result->Index = ai->IfIndex;
                result->Name = ni->ConnectionId;
                result->Description = ni->Description;
                Ipep::StringsTransformToAddresses(ni->DnsAddresses, result->DnsAddresses);

                result->IPAddress = StringToAddress(ai->Address.data(), ec);
                result->SubmaskAddress = StringToAddress(ai->Mask.data(), ec);
                result->GatewayServer = StringToAddress(ai->GatewayServer.data(), ec);
                return result;
            }

            /** @brief Resolves Windows network-interface snapshot by adapter interface. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetNetworkInterface(const ppp::win32::network::AdapterInterfacePtr& ai) noexcept {
                if (NULLPTR == ai) {
                    return NULLPTR;
                }

                auto ni = ppp::win32::network::GetNetworkInterfaceByInterfaceIndex(ai->IfIndex);
                return Windows_GetNetworkInterface(ai, ni);
            }

            /** @brief Gets Windows TAP-side network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetTapNetworkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULLPTR;
                }

                ppp::vector<ppp::win32::network::AdapterInterfacePtr> interfaces;
                if (ppp::win32::network::GetAllAdapterInterfaces(interfaces)) {
                    for (auto&& ai : interfaces) {
                        if (ai->IfIndex == interface_index) {
                            return Windows_GetNetworkInterface(ai);
                        }
                    }
                }

                return NULLPTR;
            }

            /** @brief Gets Windows underlying physical network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Windows_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap, const ppp::string& nic) noexcept {
                auto [ai, ni] = ppp::win32::network::GetUnderlyingNetowrkInterface2(tap->GetId(), nic);
                return Windows_GetNetworkInterface(ai, ni);
            }
#elif !defined(_ANDROID) && !defined(_IPHONE)
            class UnixNetworkInterface final : public VEthernetNetworkSwitcher::NetworkInterface {
            public:
                ppp::string DnsResolveConfiguration;

            public:
                /** @brief Restores Unix DNS resolver configuration from captured state. */
                static bool SetDnsResolveConfiguration(const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>& underlying_ni) noexcept {
                    if (NULLPTR == underlying_ni) {
                        return false;
                    }

                    UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get());
                    if (NULLPTR == ni) {
                        return false;
                    }

                    return ppp::unix__::UnixAfx::SetDnsResolveConfiguration(ni->DnsResolveConfiguration);
                }
            };

#if defined(_LINUX)
            static ppp::function<ppp::string(ppp::net::native::RouteEntry&)> Linux_GetNetworkInterfaceName(
                const std::shared_ptr<ppp::tap::ITap>&                              tap_if,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>&  tap_ni,
                const std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface>&  underlying_ni,
                ppp::unordered_map<uint32_t, ppp::string>&                          nics) noexcept {

                auto f =
                    [tap_if, tap_ni, underlying_ni, &nics](ppp::net::native::RouteEntry& entry) noexcept {
                        if (entry.NextHop == tap_if->GatewayServer) {
                            return tap_ni->Name;
                        }

                        ppp::string nic;
                        if (Dictionary::TryGetValue(nics, entry.NextHop, nic)) {
                            if (!nic.empty()) {
                                return nic;
                            }
                        }

                        return underlying_ni->Name;
                    };
                return f;
            }
#endif

            /** @brief Gets Unix TAP/TUN-side network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Unix_GetTapNetworkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap) noexcept {
                int interface_index = tap->GetInterfaceIndex();
                if (interface_index == -1) {
                    return NULLPTR;
                }

                int dev_handle = (int)reinterpret_cast<std::intptr_t>(tap->GetHandle());
                if (dev_handle == -1) {
                    return NULLPTR;
                }

                ppp::string interface_name;
#if defined(_MACOS)
                if (!ppp::darwin::tun::utun_get_if_name(dev_handle, interface_name)) {
                    return NULLPTR;
                }
#else
                if (!ppp::tap::TapLinux::GetInterfaceName(dev_handle, interface_name)) {
                    return NULLPTR;
                }
#endif

                std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni = make_shared_object<VEthernetNetworkSwitcher::NetworkInterface>();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

                ni->Index = interface_index;
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->GatewayServer, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->IPAddress, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(tap->SubmaskAddress, IPEndPoint::MinPort)).address();

#if defined(_MACOS)
                ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                if (NULLPTR != darwin_tap) {
                    ni->DnsAddresses = darwin_tap->GetDnsAddresses();
                }
#else
                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);

                if (NULLPTR != linux_tap) {
                    ni->DnsAddresses = linux_tap->GetDnsAddresses();
                }
#endif
                return ni;
            }

            /** @brief Gets Unix underlying physical network-interface snapshot. */
            static std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> Unix_GetUnderlyingNetowrkInterface(const std::shared_ptr<VEthernetNetworkSwitcher::ITap>& tap, const ppp::string& nic) noexcept {
                std::shared_ptr<UnixNetworkInterface> ni = make_shared_object<UnixNetworkInterface>();
                if (NULLPTR == ni) {
                    return NULLPTR;
                }

#if defined(_MACOS)
                using NetworkInterface = ppp::tap::TapDarwin::NetworkInterface;

                ppp::vector<NetworkInterface::Ptr> network_interfaces;
                if (!ppp::tap::TapDarwin::GetAllNetworkInterfaces(network_interfaces)) {
                    return NULLPTR;
                }

                NetworkInterface::Ptr network_interface = ppp::tap::TapDarwin::GetPreferredNetworkInterface2(network_interfaces, nic);
                if (NULLPTR == network_interface) {
                    return NULLPTR;
                }

                ni->Index = network_interface->Index;
                ni->Name = network_interface->Name;

                struct {
                    boost::asio::ip::address* address;
                    ppp::string* address_string;
                } addresses[] = {{&ni->GatewayServer, &network_interface->GatewayServer},
                    {&ni->IPAddress, &network_interface->IPAddress}, {&ni->SubmaskAddress, &network_interface->SubnetmaskAddress}};

                for (int i = 0; i < arraysizeof(addresses); i++) {
                    auto& r = addresses[i];
                    ppp::string* address_string = r.address_string;
                    if (address_string->empty()) {
                        continue;
                    }

                    boost::system::error_code ec;
                    *r.address = StringToAddress(address_string->data(), ec);
                    if (ec) {
                        return NULLPTR;
                    }
                }

                ni->DefaultRoutes = std::move(network_interface->GatewayAddresses);
#else
                ppp::string interface_name;
                ppp::UInt32 ip, gw, mask;
                if (!ppp::tap::TapLinux::GetPreferredNetworkInterface(interface_name, ip, mask, gw, nic)) {
                    return NULLPTR;
                }

                ni->Id = ppp::tap::TapLinux::GetDeviceId(interface_name);
                ni->Index = ppp::tap::TapLinux::GetInterfaceIndex(interface_name);
                ni->Name = interface_name;
                ni->GatewayServer = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(gw, IPEndPoint::MinPort)).address();
                ni->IPAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(ip, IPEndPoint::MinPort)).address();
                ni->SubmaskAddress = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint(mask, IPEndPoint::MinPort)).address();
#endif

                ni->DnsResolveConfiguration = ppp::unix__::UnixAfx::GetDnsResolveConfiguration();
                ppp::unix__::UnixAfx::GetDnsAddresses(ni->DnsResolveConfiguration, ni->DnsAddresses);
                return ni;
            }
#endif

            /** @brief Enables or disables outbound QUIC blocking policy. */
            bool VEthernetNetworkSwitcher::BlockQUIC(bool value) noexcept {
                // Set the status of the current VPN client switcher that needs to block QUIC traffic flags.
                block_quic_ = value;
                return true;
            }

#if defined(_WIN32)
            /** @brief Applies local HTTP proxy endpoint to Windows system settings. */
            bool VEthernetNetworkSwitcher::SetHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to set the system HTTP proxy environment.
                auto http_proxy = GetHttpProxy();
                if (NULLPTR == http_proxy) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::tcp::endpoint localEP = http_proxy->GetLocalEndPoint();
                int localPort = localEP.port();
                if (localPort <= IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                    return ClearHttpProxyToSystemEnv();
                }

                boost::asio::ip::address localIP = localEP.address();
                if (IPEndPoint::IsInvalid(localIP)) {
                    localIP = boost::asio::ip::address_v4::loopback();
                }

                ppp::string server = ppp::net::Ipep::ToAddressString<ppp::string>(localIP) + ":" + stl::to_string<ppp::string>(localPort);
                ppp::string pac;
                bool bok = ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, true) &&
                    ppp::net::proxies::HttpProxy::SetSystemProxy(server) &&
                    ppp::net::proxies::HttpProxy::RefreshSystemProxy();
                if (!bok) {
                    return ClearHttpProxyToSystemEnv();
                }

                return bok;
            }

            /** @brief Clears Windows system HTTP proxy settings managed by switcher. */
            bool VEthernetNetworkSwitcher::ClearHttpProxyToSystemEnv() noexcept {
                // Windows platform uses the system's Internet function library to clear the system HTTP proxy environment.
                ppp::string server;
                ppp::string pac;
                return ppp::net::proxies::HttpProxy::SetSystemProxy(server, pac, false);
            }
#endif

#if defined(_ANDROID) || defined(_IPHONE)
            /** @brief Builds mobile-side route table including bypass and DNS exceptions. */
            bool VEthernetNetworkSwitcher::AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept {
                RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                if (NULLPTR == rib)  {
                    return false;
                }

                // Android requires the VPN to manage the routing table itself because it is a default gateway hybrid architecture.
                rib_ = rib;

                // Set up VPN subnet ip route.
                uint32_t cidr = ntohl(tap->SubmaskAddress);
                cidr = cidr & ntohl(tap->IPAddress);
                cidr = htonl(cidr);
                rib->AddRoute(cidr, IPEndPoint::NetmaskToPrefix(tap->SubmaskAddress), tap->GatewayServer);

                // Why does Android/APPLE-IOS load routing table information?
                // This is to implement the IP diversion function of the HTTP proxy to prevent all traffic from going to the VPN server,
                // Because there are some scenarios that do not want to go through the VPN server.
                if (ppp::string bypass_ip_list = std::move(bypass_ip_list_); bypass_ip_list.size() > 0) {
                    // IP address of the virtual network card is used here to make it inconsistent with the condition of determining
                    // The next hop gateway of the route in the IsBypassIpAddress function.
                    bool bypass_loaded = rib->AddAllRoutes(bypass_ip_list, IPEndPoint::LoopbackAddress);
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2", "bypass_ip_list load len=%d ok=%d",
                        (int)bypass_ip_list.size(), bypass_loaded ? 1 : 0);
#endif
                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                }

                // Add dns route set rules.
                uint32_t gws[] = {tap->GatewayServer, IPEndPoint::LoopbackAddress};
                ppp::unordered_set<uint32_t> dns_serverss_[2];
                for (auto&& dns_rules : dns_ruless_) {
                    for (auto& [_, r] : dns_rules) {
                        boost::asio::ip::address server = r->Server;
                        if (!server.is_v4()) {
                            continue;
                        }

                        uint32_t ip = htonl(server.to_v4().to_uint());
                        if (r->Nic) {
                            dns_serverss_[1].emplace(ip);
                        }
                        else {
                            dns_serverss_[0].emplace(ip);
                        }
                    }
                }

                // Compare two lists and remove duplicate ip addresses that appear in both lists.
                ppp::collections::Dictionary::DeduplicationList(dns_serverss_[1], dns_serverss_[0]);
                for (int i = 0; i < arraysizeof(gws); i++) {
                    uint32_t gw = gws[i];
                    for (auto& ip : dns_serverss_[i]) {
                        rib->AddRoute(ip, 32, gw);
                    }
                }

                // Add VPN remote server to IPList bypass route table iplist.
                return AddRemoteEndPointToIPList(Ipep::ToAddress(IPEndPoint::LoopbackAddress));
            }
#endif

            /** @brief Creates and configures static-mode aggligator instance. */
            bool VEthernetNetworkSwitcher::PreparedAggregator() noexcept {
                std::shared_ptr<boost::asio::io_context> context = ppp::threading::Executors::GetDefault();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                std::shared_ptr<Byte> buffer = ppp::threading::Executors::GetCachedBuffer(context);
                if (NULLPTR == buffer) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                }

                std::shared_ptr<aggligator::aggligator> aggligator =
                    make_shared_object<aggligator::aggligator>(*context, buffer, PPP_BUFFER_SIZE, PPP_AGGLIGATOR_CONGESTIONS);
                if (NULLPTR == aggligator) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                aggligator_ = aggligator;
#if defined(_LINUX)
                aggligator->ProtectorNetwork = GetProtectorNetwork();
#endif
                aggligator->AppConfiguration = configuration_;
                aggligator->BufferswapAllocator = configuration_->GetBufferAllocator();
                return true;
            }

            /** @brief Initializes switcher runtime components and opens all services. */
            bool VEthernetNetworkSwitcher::Open(const std::shared_ptr<ITap>& tap) noexcept {
                ppp::telemetry::SpanScope span("client.connect");
                struct ScopedConnectHistogram final {
                    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

                    ~ScopedConnectHistogram() noexcept {
                        int64_t elapsed = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                        ppp::telemetry::Histogram("client.connect.us", elapsed);
                    }
                } connect_histogram;

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Get and retrieve the current underlying Ethernet interface information!
#if defined(_WIN32)
                underlying_ni_ = Windows_GetUnderlyingNetowrkInterface(tap, preferred_nic_);
#else
                underlying_ni_ = Unix_GetUnderlyingNetowrkInterface(tap, preferred_nic_);
#endif

                // The physical hosting network interface required for the VPN overlap network is not allowed to construct and turn on the VPN service.
                if (auto underlying_ni = underlying_ni_; NULLPTR != underlying_ni) {
                    boost::asio::ip::address& ngw = preferred_ngw_;
                    if (!IPEndPoint::IsInvalid(ngw)) {
                        underlying_ni->GatewayServer = ngw;
                    }
                }
                else {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                // Compatibility by all means try to check and fix the gateway route of the physical network card once,
                // Otherwise there will be no network with all kinds of chain problems!
                FixUnderlyingNgw();
#endif
                // Construction of VEtherent virtual Ethernet switcher processing framework.
                /** @brief Creates base VEthernet framework before higher-level services. */
                if (!VEthernet::Open(tap)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                }

                ppp::telemetry::Log(Level::kInfo, "client", "TUN attached");
                ppp::telemetry::Count("client.tun.attach", 1);

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_WIN32)
                // Get network interface information for TAP-Windows virtual Ethernet devices!
                tun_ni_ = Windows_GetTapNetworkInterface(tap);
#else
                // Get network interface information for Linux tun/tap virtual Ethernet devices!
                tun_ni_ = Unix_GetTapNetworkInterface(tap);
#endif

                // The vEthernet network switcher cannot be opened when the virtual network adapter device interface for the VPN startup link cannot be found!
                if (NULLPTR == tun_ni_) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                }
#endif

                // Initial a new network statistics.
                statistics_ = NewStatistics();

                // Instantiate the local QoS throughput speed control module!
                std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = NewQoS();
                if (NULLPTR == qos) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                }

#if defined(_LINUX)
                // This section describes how to instantiate the physical network instance protector required by ppp to
                // Prevent VPN virtual switcher crashes caused by IP route loopback.
                ProtectorNetworkPtr protector_network;
#if defined(_ANDROID)
                protector_network = NewProtectorNetwork();
                if (NULLPTR == protector_network) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                }
#else
                if (protect_mode_) {
                    protector_network = NewProtectorNetwork();
                }
#endif
#endif
                // Instantiate and open the internal virtual Ethernet switch that needs to be switcher to the remote.
                std::shared_ptr<VEthernetExchanger> exchanger = NewExchanger();
                if (NULLPTR == exchanger) {
                    return false;
                }
                elif(!exchanger->Open()) {
                    IDisposable::DisposeReferences(qos, exchanger);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                }

                // Enable the local HTTP PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetHttpProxySwitcherPtr http_proxy = NewHttpProxy(exchanger);
                if (NULLPTR == http_proxy) {
                    return false;
                }
                elif(http_proxy->Open()) {
                    http_proxy_ = std::move(http_proxy);
                }
                else {
                    http_proxy->Dispose();
                    http_proxy.reset();
                }

                // Enable the local SOCKS PROXY server middleware to provide proxy services directly by the VPN.
                VEthernetSocksProxySwitcherPtr socks_proxy = NewSocksProxy(exchanger);
                if (NULLPTR == socks_proxy) {
                    return false;
                }
                elif(socks_proxy->Open()) {
                    socks_proxy_ = std::move(socks_proxy);
                }
                else {
                    socks_proxy->Dispose();
                    socks_proxy.reset();
                }

                // Mounts the various service objects created and opened by the current constructor.
                qos_             = std::move(qos);
                exchanger_       = std::move(exchanger);

#if defined(_LINUX)
                protect_network_ = std::move(protector_network);
#endif

                // Create the multi-protocol DNS resolver for provider-based rules.
                // The resolver is used when dns-rules.txt contains provider short names
                // (e.g. "doh.pub", "cloudflare") instead of raw IP addresses.
                {
                    std::shared_ptr<boost::asio::io_context> resolver_ctx = GetContext();
                    if (NULLPTR != resolver_ctx) {
                        dns_resolver_ = make_shared_object<ppp::dns::DnsResolver>(*resolver_ctx);

#if defined(_ANDROID)
                        // Android VPNService socket protection normally requires
                        // Java/Kotlin protect(fd) or a coroutine JNI context.  The
                        // pure-async DnsResolver path cannot safely fabricate a
                        // YieldContext, and ProtectEvent is not wired on this object
                        // today.  Do not fail all provider-DNS sockets here; rely on
                        // route-based protection and keep a clear TODO for a future
                        // synchronous VPNService.protect bridge.
                        if (NULLPTR != dns_resolver_) {
                            dns_resolver_->SetProtectSocketCallback(
                                [](int /*handle*/) noexcept -> bool {
                                    return true;
                                });
                        }
#elif defined(_LINUX)
                        // Wire Linux socket-protect into DnsResolver.
                        //
                        // ProtectorNetwork::ProtectSync() provides a synchronous
                        // overload that does not require a YieldContext.  On
                        // non-Android Linux it calls SO_BINDTODEVICE; on Android
                        // it delegates to ProtectEvent if set, otherwise returns
                        // false (caller falls back to route-based protection).
                        if (NULLPTR != dns_resolver_ && NULLPTR != protect_network_) {
                            auto pn = protect_network_;
                            dns_resolver_->SetProtectSocketCallback(
                                [pn](int handle) noexcept -> bool {
                                    return pn->ProtectSync(handle);
                                });
                        }
                        elif (NULLPTR != dns_resolver_) {
                            // No ProtectorNetwork available.  Provide a no-op
                            // callback; DnsResolver-created sockets will still
                            // bypass the VPN via the host-route entries installed
                            // by AddRouteWithDnsServers().
                            dns_resolver_->SetProtectSocketCallback(
                                [](int /*handle*/) noexcept -> bool {
                                    return true;
                                });
                        }
#endif
                    }

                    // Configure default DNS providers from application configuration.
                    // These are used by ResolveAsyncWithFallback when intercept_unmatched is true
                    // and no explicit DNS rule matches a query.
                    if (NULLPTR != dns_resolver_) {
                        ppp::string domestic = configuration_->dns.servers.domestic;
                        ppp::string foreign  = configuration_->dns.servers.foreign;
                        if (!domestic.empty() || !foreign.empty()) {
                            dns_resolver_->SetDefaultProviders(domestic, foreign);
                        }

                        // Configure EDNS Client Subnet (ECS) injection.
                        // When dns.ecs.enabled is true, domestic DNS queries sent
                        // through DnsResolver will have an ECS OPT RR appended.
                        dns_resolver_->SetEcsConfig(
                            configuration_->dns.ecs.enabled,
                            configuration_->dns.ecs.override_ip);
                        dns_resolver_->SetTlsVerifyPeer(configuration_->dns.tls.verify_peer);

                        // Configure STUN candidates for exit IP detection (Phase D).
                        // When dns.stun.candidates is non-empty, the resolver uses
                        // these instead of the built-in defaults.
                        if (!configuration_->dns.stun.candidates.empty()) {
                            ppp::vector<ppp::dns::StunCandidate> stun_cands;
                            for (const ppp::string& cs : configuration_->dns.stun.candidates) {
                                ppp::dns::StunCandidate sc;
                                if (ParseStunCandidate(cs, sc)) {
                                    stun_cands.emplace_back(std::move(sc));
                                }
                                else {
                                    ppp::telemetry::Log(Level::kInfo, "client", "DNS STUN candidate ignored: %s", cs.c_str());
                                }
                            }
                            if (!stun_cands.empty()) {
                                dns_resolver_->SetStunCandidates(std::move(stun_cands));
                            }
                        }
                    }
                }

                // New the beast network bandwidth aggregator.
                if (static_mode_ && configuration_->udp.static_.aggligator > 0) {
                    if (!PreparedAggregator()) {
                        return false;
                    }
                }

#if defined(_ANDROID) || defined(_IPHONE)
                if (!AddAllRoute(tap)) {
                    IDisposable::DisposeReferences(qos, exchanger, http_proxy);
                    return false;
                }
#else
                // Load all IPList route table configuration files that need to be loaded.
                if (auto underlying_ni = underlying_ni_; NULLPTR != underlying_ni) {
                    LoadAllIPListWithFilePaths(underlying_ni->GatewayServer);

                    // Add VPN remote server to IPList bypass route table iplist.
                    if (!AddRemoteEndPointToIPList(underlying_ni->GatewayServer)) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteAddFailed);
                    }
                }
#endif

                // Attempt to load the routing table configuration if the routing table is configured correctly.
                if (RouteInformationTablePtr rib = rib_; NULLPTR != rib) {
                    ForwardInformationTablePtr fib = make_shared_object<ForwardInformationTable>();
                    if (NULLPTR != fib) {
                        fib->Fill(*rib);

                        if (fib->IsAvailable()) {
                            fib_ = fib;
                        }
                    }
                }

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Add VPN route table information to the operating system.
                if (tap->IsHostedNetwork() && !exchangeof(route_added_, true)) {
#if defined(_WIN32)
                    // Use the Paper-Airplane NSP/LSP session layer forwarding plugins!
                    if (!UsePaperAirplaneController()) {
                        return false;
                    }
#endif

                    // VPN routes need to be configured for the operating system to configure the bearer network and overlapping network links.
                    AddRoute();

                    {
                        ppp::telemetry::SpanScope span("client.dns.apply");
                        struct ScopedDnsApplyHistogram final {
                            std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                            ~ScopedDnsApplyHistogram() noexcept {
                                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                                ppp::telemetry::Histogram("client.dns.apply.us", elapsed);
                            }
                        } dns_apply_histogram;

#if defined(_WIN32)
                        // Configure all network card DNS servers in the entire operating system, because not doing so will cause DNS Leak and DNS contamination problems only Windows.
                        auto tun_ni = tun_ni_;
                        if (NULLPTR != tun_ni) {
                            ppp::win32::network::SetAllNicsDnsAddresses(tun_ni->DnsAddresses, ni_dns_servers_);
                        }

                        // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after
                        // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record
                        // Available in the region where the VPN server is located.
                        ppp::tap::TapWindows::DnsFlushResolverCache();

                        // Delete the default route of a physical network card in a single attempt without a reason.
                        auto underlying_ni = underlying_ni_;
                        if (NULLPTR != underlying_ni) {
                            ppp::win32::network::DeleteAllDefaultGatewayRoutes(underlying_ni->GatewayServer);
                        }
#else
                        // Set tun/tap vnic binding dns servers list to the linux operating system configuration files.
                        auto tun_ni = tun_ni_;
                        if (NULLPTR != tun_ni) {
                            ppp::unix__::UnixAfx::SetDnsAddresses(tun_ni->DnsAddresses);
                        }
#endif
                    }
                    ppp::telemetry::Log(Level::kDebug, "client", "DNS setup");
                    ppp::telemetry::Count("client.dns.setup", 1);

                    // Run the default gateway route protector.
                    ProtectDefaultRoute();
                }
#endif
                ppp::telemetry::Log(Level::kInfo, "client", "client connected");
                ppp::telemetry::Count("client.connect", 1);
                return true;
            }

#if defined(_WIN32)
            /** @brief Starts optional PaperAirplane helper service on Windows. */
            bool VEthernetNetworkSwitcher::UsePaperAirplaneController() noexcept {
                // Open the [PaperAirplane NSP/LSP] paper airplane server controller,
                // Depending on the configuration and whether it is a CLI command line hosted network flag.
                if (configuration_->client.paper_airplane.tcp) {
                    PaperAirplaneControllerPtr controller = NewPaperAirplaneController();
                    if (NULLPTR == controller) {
                        return false;
                    }

                    // Clean up resources constructed by the current function when opening the server side of the paper plane fails.
                    auto tun_ni = tun_ni_;
                    if (NULLPTR != tun_ni) {
                        auto tap = GetTap();
                        if (NULLPTR != tap) {
                            if (!controller->Open(tun_ni->Index, tap->IPAddress, tap->SubmaskAddress)) {
                                IDisposable::DisposeReferences(controller);
                                return false;
                            }
                        }
                    }

                    // Open the paper plane successfully when you move the created instance on the local variable to
                    // The virtual ethernet switch hosted fields.
                    paper_airplane_ctrl_ = std::move(controller);
                }
                return true;
            }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            /** @brief Attempts to restore default route on underlying physical NIC. */
            bool VEthernetNetworkSwitcher::FixUnderlyingNgw() noexcept {
                auto ni = underlying_ni_;
                if (NULLPTR == ni) {
                    return false;
                }

                auto gw = ni->GatewayServer;
                if (gw.is_v4() && !IPEndPoint::IsInvalid(gw) && !gw.is_loopback()) {
                    uint32_t next_hop = htonl(gw.to_v4().to_uint());
#if defined(_WIN32)
                    // Repair physical ethernet route table information on windows platform!
                    ppp::win32::network::Router::Add(IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop, 1);
#elif defined(_MACOS)
                    ppp::darwin::tun::utun_add_route2(IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop);
#else
                    // Repair physical ethernet route table information on linux platform!
                    ppp::tap::TapLinux::AddRoute(ni->Name, IPEndPoint::AnyAddress, IPEndPoint::AnyAddress, next_hop);
#endif
                    return true;
                }

                return false;
            }

            /** @brief Installs VPN route entries into host operating system. */
            void VEthernetNetworkSwitcher::AddRoute() noexcept {
                ppp::telemetry::SpanScope span("client.route.apply");
                struct ScopedRouteApplyHistogram final {
                    std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                    ~ScopedRouteApplyHistogram() noexcept {
                        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                        ppp::telemetry::Histogram("client.route.apply.us", elapsed);
                    }
                } route_apply_histogram;

                ppp::telemetry::Log(Level::kDebug, "client", "route add");
                ppp::telemetry::Count("client.route.add", 1);
#if defined(_WIN32)
                // Find and delete all default route information!
                if (auto tap = GetTap(); NULLPTR != tap) {
                    ppp::win32::network::DeleteAllDefaultGatewayRoutes(default_routes_, { tap->GatewayServer });
                }

                // Adds the loaded route table to the operating system.
                ppp::win32::network::AddAllRoutes(rib_);
#elif defined(_MACOS)
                // Delete all found default gateway routes.
                if (auto underlying_ni = GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    if (auto tap = GetTap(); NULLPTR != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULLPTR != darwin_tap && !darwin_tap->IsPromisc()) {
                            if (UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get()); NULLPTR != ni) {
                                for (auto&& [ip, gw] : ni->DefaultRoutes) {
                                    ppp::darwin::tun::utun_del_route(ip, gw);
                                }
                            }
                        }
                    }

                    // Adds the loaded route table to the operating system.
                    ppp::tap::TapDarwin::AddAllRoutes(rib_);
                }
#else
                // Adds the loaded route table to the operating system.
                if (auto underlying_ni = GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    if (auto tap_ni = GetTapNetworkInterface(); NULLPTR != tap_ni) {
                        // Find and delete all default route information.
                        if (auto tap = GetTap(); NULLPTR != tap) {
                            // Find all default gateway routing lists and remove them, but only in non-promiscuous mode.
                            ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                            if (NULLPTR != linux_tap && !linux_tap->IsPromisc()) {
                                RouteInformationTablePtr default_routes = ppp::tap::TapLinux::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                                default_routes_ = default_routes;

                                // Delete all default route table information found.
                                if (NULLPTR != default_routes) {
                                    ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), default_routes);
                                }
                            }

                            // Add all routes configured in VPN/RIB to the operating system.
                            ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), rib_);
                        }
                    }
                }
#endif
                // Configure the DNS servers used by the virtual network adapter to route to the operating system.
                AddRouteWithDnsServers();
            }

            /** @brief Deletes conflicting default routes while VPN is active. */
            bool VEthernetNetworkSwitcher::DeleteAllDefaultRoute() noexcept {
                if (auto tap = GetTap(); NULLPTR != tap) {
#if defined(_WIN32)
                    // Find and delete all disallowed windows gateway routes.
                    ppp::vector<MIB_IPFORWARDROW> default_routes;
                    ppp::win32::network::DeleteAllDefaultGatewayRoutes(default_routes, { tap->GatewayServer });
                    return true;
#else
#if defined(_MACOS)
                    auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
#else
                    auto unix_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
#endif
                    if (NULLPTR != unix_tap && !unix_tap->IsPromisc()) {
#if defined(_MACOS)
                        // Find and delete all disallowed macos gateway routes.
                        auto rib = ppp::tap::TapDarwin::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                        if (NULLPTR != rib) {
                            for (auto&& [ip, gw] : *rib) {
                                ppp::darwin::tun::utun_del_route(ip, gw);
                            }
                        }
#else
                        // Find and delete all disallowed linux gateway routes.
                        auto rib = ppp::tap::TapLinux::FindAllDefaultGatewayRoutes({ tap->GatewayServer });
                        if (NULLPTR != rib) {
                            ppp::tap::TapLinux::DeleteAllRoutes2(rib);
                        }
#endif
                        return true;
                    }
#endif
                }
                return false;
            }

            /** @brief Removes VPN route entries and restores system defaults. */
            void VEthernetNetworkSwitcher::DeleteRoute() noexcept {
                ppp::telemetry::Log(Level::kDebug, "client", "route delete");
                ppp::telemetry::Count("client.route.delete", 1);
#if defined(_WIN32)
                // Delete the loaded route table from the windows operating system.
                ppp::win32::network::DeleteAllRoutes(rib_);

                // Add and delete all windows default route information!
                ppp::win32::network::AddAllRoutes(default_routes_);

                // Force to set the network card gateway server, not just manually add the routing table,
                // In the previous system can add routes,
                // The system will automatically set the network card, but the latest WIN11 can not.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULLPTR != ni) {
                    ppp::win32::network::SetDefaultIPGateway(ni->Index, { ni->GatewayServer });
                }
#elif defined(_MACOS)
                // Delete the loaded route table from the osx operating system.
                if (auto underlying_ni = GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    // Delete all rib route table information found.
                    ppp::tap::TapDarwin::DeleteAllRoutes(rib_);

                    // Add and delete all os-x default route information!
                    if (auto tap = GetTap(); NULLPTR != tap) {
                        ppp::tap::TapDarwin* darwin_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
                        if (NULLPTR != darwin_tap && !darwin_tap->IsPromisc()) {
                            if (UnixNetworkInterface* ni = dynamic_cast<UnixNetworkInterface*>(underlying_ni.get()); NULLPTR != ni) {
                                for (auto&& [ip, gw] : ni->DefaultRoutes) {
                                    ppp::darwin::tun::utun_add_route(ip, gw);
                                }
                            }
                        }
                    }
                }
#else
                // Delete the loaded route table from the linux operating system.
                if (auto underlying_ni = GetUnderlyingNetworkInterface(); NULLPTR != underlying_ni) {
                    if (auto tap_ni = GetTapNetworkInterface(); NULLPTR != tap_ni) {
                        if (auto tap = GetTap(); NULLPTR != tap) {
                            // Delete all rib route table information found.
                            ppp::tap::TapLinux::DeleteAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), rib_);

                            // Add and delete all linux-t default route information!
                            if (auto default_routes = default_routes_; NULLPTR != default_routes) {
                                ppp::tap::TapLinux::AddAllRoutes(Linux_GetNetworkInterfaceName(tap, tap_ni, underlying_ni, nics_), default_routes);
                            }
                        }
                    }
                }
#endif

                // Fix and restore physical nic next hop route settings.
                FixUnderlyingNgw();

                // Delete all vpn dns server routes from the operating system.
                DeleteRouteWithDnsServers();
            }

            /** @brief Returns formatted cached remote URI string. */
            ppp::string VEthernetNetworkSwitcher::GetRemoteUri() noexcept {
                return server_ru_;
            }

            /** @brief Sets preferred physical NIC hint for route operations. */
            void VEthernetNetworkSwitcher::PreferredNic(const ppp::string& nic) noexcept {
                preferred_nic_ = nic;
            }

            /** @brief Sets preferred physical gateway hint for route operations. */
            void VEthernetNetworkSwitcher::PreferredNgw(const boost::asio::ip::address& gw) noexcept {
                preferred_ngw_ = gw;
            }

            /** @brief Registers IP-list file or URL source for later route loading. */
            bool VEthernetNetworkSwitcher::AddLoadIPList(
                const ppp::string&                                              path,
#if defined(_LINUX)
                const ppp::string&                                              nic,
#endif
                const boost::asio::ip::address&                                 gw,
                const ppp::string&                                              url) noexcept {

                using File = ppp::io::File;

                if (path.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                ppp::string fullpath = File::RewritePath(path.data());
                if (fullpath.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                fullpath = File::GetFullPath(path.data());
                if (fullpath.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::FilePathInvalid);
                }

                bool vbgp_url = ppp::net::http::HttpClient::VerifyUri(url, NULLPTR, NULLPTR, NULLPTR, NULLPTR);
                if (!vbgp_url && !File::Exists(fullpath.data())) {
                    if (ppp::diagnostics::ErrorCode::FileNotFound == ppp::diagnostics::GetLastErrorCode()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteListFileNotFound);
                    }

                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigRouteLoadFailed);
                    }

                    return false;
                }

                uint32_t ngw = IPEndPoint::AnyAddress;
                if (
#if defined(_LINUX)
                    !nic.empty() &&
#endif
                    gw.is_v4() && !IPEndPoint::IsInvalid(gw)) {
                    ngw = htonl(gw.to_v4().to_uint());
                }

                LoadIPListFileVectorPtr ribs = ribs_;
                if (NULLPTR == ribs) {
                    ribs = make_shared_object<LoadIPListFileVector>();
                    ribs_ = ribs;
                }

                if (NULLPTR == ribs) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }
                else {
                    auto tail = std::find_if(ribs->begin(), ribs->end(),
                        [&fullpath](const std::pair<ppp::string, uint32_t>& i) noexcept {
                            return i.first == fullpath;
                        });
                    if (tail != ribs->end()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RouteListRegistrationDuplicate);
                    }
                }

                if (vbgp_url) {
                    RouteIPListTablePtr vbgp = vbgp_;
                    if (NULLPTR == vbgp)  {
                        vbgp = make_shared_object<RouteIPListTable>();
                        if (NULLPTR == vbgp) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VbgpRouteTableAllocFailed);
                        }

                        vbgp_ = vbgp;
                    }

                    vbgp->emplace(std::make_pair(fullpath, url));
                }

#if defined(_LINUX)
                if (ngw != IPEndPoint::AnyAddress) {
                    nics_.emplace(std::make_pair(ngw, nic));
                }
#endif

                ribs->emplace_back(std::make_pair(fullpath, ngw));
                return true;
            }

            /** @brief Loads all registered IP-list files into route information table. */
            bool VEthernetNetworkSwitcher::LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept {
                rib_ = NULLPTR;
                fib_ = NULLPTR;

                // Load all the route table iplist configuration files that need to be loaded.
                bool any = false;
                if (gw.is_v4()) {
                    // Obtain the numerical address of the next hop in the IP route table, which is a function implementation of the bypass-iplist.
                    boost::asio::ip::address_v4 in = gw.to_v4();
                    if (uint32_t next_hop = htonl(in.to_uint()); !IPEndPoint::IsInvalid(in)) {
                        if (LoadIPListFileVectorPtr ribs = std::move(ribs_); NULLPTR != ribs) {
                            // Loop in all iplist route table configuration files.
                            RouteInformationTablePtr rib = make_shared_object<RouteInformationTable>();
                            if (NULLPTR != rib) {
                                for (auto&& kv : *ribs) {
                                    const ppp::string& path = kv.first;
                                    const uint32_t ngw = kv.second != IPEndPoint::AnyAddress ? kv.second : next_hop;
                                    any |= rib->AddAllRoutesByIPList(path, ngw);
                                }

                                // Loading is considered valid only if any route is added.
                                if (any) {
                                    rib_ = rib;
                                    ppp::telemetry::Log(Level::kDebug, "client", "bypass list updated");
                                }
                            }
                        }
                    }
                }

                // A value filled once can only be used once and then reset.
                ribs_.reset();
                return any;
            }

            /** @brief Adds DNS-specific route exceptions to operating system table. */
            void VEthernetNetworkSwitcher::AddRouteWithDnsServers() noexcept {
                // Clear the current cached dns server ip address list.
                for (auto& dns_servers : dns_serverss_) {
                    dns_servers.clear();
                }

                // Obtain the IP address list of the DNS server configured on the current physical bearer NIC and VPN virtual network adapter.
                auto add_dns_server_to_dns_servers =
                    [](const std::shared_ptr<NetworkInterface>& ni, ppp::unordered_set<uint32_t>& dns_servers) noexcept {
                        if (NULLPTR == ni) {
                            return false;
                        }

                        uint32_t ips[2] = { IPEndPoint::AnyAddress, IPEndPoint::AnyAddress };
                        boost::asio::ip::address nips[] = { ni->IPAddress, ni->SubmaskAddress };
                        for (int i = 0; i < arraysizeof(nips); i++) {
                            boost::asio::ip::address& ip = nips[i];
                            if (ip.is_v4()) {
                                ips[i] = ip.to_v4().to_uint();
                            }
                        }

                        uint32_t rip = ips[0] & ips[1];
                        for (boost::asio::ip::address& ip : ni->DnsAddresses) {
                            if (ip.is_v6()) {
                                continue;
                            }

                            if (!ip.is_v4()) {
                                continue;
                            }

                            if (ip.is_multicast()) {
                                continue;
                            }

                            if (ip.is_loopback()) {
                                continue;
                            }

                            if (ip.is_unspecified()) {
                                continue;
                            }

                            if (IPEndPoint::IsInvalid(ip)) {
                                continue;
                            }

                            uint32_t dip = ip.to_v4().to_uint();
                            uint32_t tip = (dip & ips[1]);
                            if (tip == rip) {
                                continue;
                            }

                            dip = htonl(dip);
                            dns_servers.emplace(dip);
                        }
                        return true;
                    };

                add_dns_server_to_dns_servers(tun_ni_, dns_serverss_[0]);
                add_dns_server_to_dns_servers(underlying_ni_, dns_serverss_[1]);

                // Helper: add a single "ip[:port]" address literal to dns_serverss_[1]
                // so that DnsResolver-created sockets (DoH/DoT/TCP/UDP) can reach the
                // upstream IP directly through the underlying NIC, bypassing the TUN
                // and avoiding the recursive DNS-redirect loop that would otherwise
                // occur when the system default route still points at the VPN tunnel.
                // (See docs/DNS_MODULE_DESIGN.md "Socket protection / bypass routing".)
                auto add_bypass_ip_literal =
                    [this](const ppp::string& address) noexcept -> bool {
                        if (address.empty()) {
                            return false;
                        }

                        ppp::string host;
                        int port = 0;
                        if (!ppp::net::Ipep::ParseEndPoint(address, host, port)) {
                            // Treat the entire string as a bare IP literal as a fallback
                            // (some configurations omit the :port suffix).
                            host = address;
                        }
                        if (host.empty()) {
                            return false;
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::address ip = ppp::StringToAddress(host.data(), ec);
                        if (ec || !ip.is_v4() || ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()) {
                            return false;
                        }

                        uint32_t ipnet = htonl(ip.to_v4().to_uint());
                        dns_serverss_[1].emplace(ipnet);
                        return true;
                    };

                // Helper: expand a built-in provider short name (e.g. "doh.pub",
                // "cloudflare") to its IPv4 endpoints and add them to the bypass set.
                auto add_bypass_provider =
                    [&add_bypass_ip_literal](const ppp::string& provider_name) noexcept {
                        if (provider_name.empty()) {
                            return;
                        }

                        const ppp::vector<ppp::dns::ServerEntry>* provider =
                            ppp::dns::DnsResolver::GetProvider(provider_name);
                        if (NULLPTR == provider) {
                            return;
                        }

                        for (const ppp::dns::ServerEntry& entry : *provider) {
                            add_bypass_ip_literal(entry.address);
                        }
                    };

                // Helper: walk a list of structured DnsServerEntry objects and add
                // both their primary address and any bootstrap_ips to the bypass set.
                auto add_bypass_dns_entries =
                    [&add_bypass_ip_literal](const ppp::vector<ppp::configurations::AppConfiguration::DnsServerEntry>& entries) noexcept {
                        for (const auto& ce : entries) {
                            add_bypass_ip_literal(ce.address);
                            for (const auto& b : ce.bootstrap) {
                                add_bypass_ip_literal(b);
                            }
                        }
                    };

                // Add dns route set rules.
                for (auto&& dns_rules : dns_ruless_) {
                    for (auto& [_, r] : dns_rules) {
                        // Provider-based rule: route DnsResolver upstream IPs via the
                        // underlying NIC.  For these rules `Nic` is repurposed as the
                        // domestic/foreign selector (see Rule.h) and MUST NOT be used
                        // to choose dns_serverss_ slot — provider sockets always need
                        // the host route bypass to function.
                        if (!r->ProviderName.empty()) {
                            add_bypass_provider(r->ProviderName);
                            continue;
                        }

                        boost::asio::ip::address server = r->Server;
                        if (!server.is_v4()) {
                            continue;
                        }

                        uint32_t ip = htonl(server.to_v4().to_uint());
                        if (r->Nic) {
                            dns_serverss_[1].emplace(ip);
                        }
                        else {
                            dns_serverss_[0].emplace(ip);
                        }
                    }
                }

                // Pre-register provider IPs for the unmatched-query interception path.
                // When intercept_unmatched is enabled, RedirectDnsServer routes DNS
                // queries that do not match any rule through DnsResolver using the
                // dns.servers.{domestic,foreign} configuration.  Those upstream IPs
                // need the same bypass treatment as rule-driven provider IPs.
                // The hardcoded "cloudflare" final fallback in ResolveAsyncWithFallback
                // is also covered so the failover chain remains reachable.
                if (configuration_->dns.intercept_unmatched) {
                    add_bypass_provider(configuration_->dns.servers.domestic);
                    add_bypass_provider(configuration_->dns.servers.foreign);
                    add_bypass_provider("cloudflare");
                    add_bypass_dns_entries(configuration_->dns.servers.domestic_entries);
                    add_bypass_dns_entries(configuration_->dns.servers.foreign_entries);
                }

                // Compare two lists and remove duplicate ip addresses that appear in both lists.
                ppp::collections::Dictionary::DeduplicationList(dns_serverss_[1], dns_serverss_[0]);

                // Add the routing gateway of these DNS as the vpn server, mainly to solve the problem of interference.
                if (std::shared_ptr<ITap> tap = GetTap(); NULLPTR != tap) {
                    for (uint32_t ip : dns_serverss_[0]) {
                        AddRoute(ip, tap->GatewayServer, 32);
                    }
                }

                // Add the dns route table to the loopback settings of the physical nic.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
                        for (uint32_t ip : dns_serverss_[1]) {
                            AddRoute(ip, next_hop, 32);
                        }
                    }
                }
            }

            /** @brief Adds one host route entry to operating system table. */
            bool VEthernetNetworkSwitcher::AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
#if defined(_WIN32)
                MIB_IPFORWARDROW route;
                if (ppp::win32::network::Router::GetBestRoute(ip, route)) {
                    if (route.dwForwardDest == ip && route.dwForwardNextHop != gw) {
                        ppp::win32::network::Router::Delete(route);
                    }
                }

                // Add dns server list IP routing to the windows operating system.
                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                return ppp::win32::network::Router::Add(ip, mask, gw, 1);
#elif defined(_MACOS)
                // Add dns server list IP routing to the macos operating system.
                return ppp::darwin::tun::utun_add_route(ip, prefix, gw);
#else
                // If gateway is of a physical network card, it means that this is the NS route for physical network card.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address next_hop = ni->GatewayServer;
                    if (next_hop.is_v4() && htonl(next_hop.to_v4().to_uint()) == gw) {
                        return ppp::tap::TapLinux::AddRoute(ni->Name, ip, 32, gw);
                    }
                }

                // Add dns server list IP routing to the linux operating system.
                std::shared_ptr<ppp::tap::ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                if (NULLPTR == linux_tap) {
                    return false;
                }

                return linux_tap->AddRoute(ip, prefix, gw);
#endif
            }

#if defined(_WIN32)
            /** @brief Deletes one host route entry from Windows route table snapshot. */
            bool VEthernetNetworkSwitcher::DeleteRoute(const std::shared_ptr<MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept {
                // Delete the IP route for the dns server list added for the windows operating system.
                if (NULLPTR == mib) {
                    return false;
                }

                uint32_t mask = IPEndPoint::PrefixToNetmask(prefix);
                return ppp::win32::network::Router::Delete(mib, ip, mask, gw);
            }
#else
            /** @brief Deletes one host route entry from Unix route table. */
            bool VEthernetNetworkSwitcher::DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept {
#if defined(_MACOS)
                // Delete the IP route for the dns server list added for the macos operating system.
                return ppp::darwin::tun::utun_del_route(ip, prefix, gw);
#else
                // // If gateway is of a physical network card, it means that this is the NS route for physical network card.
                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address next_hop = ni->GatewayServer;
                    if (next_hop.is_v4() && htonl(next_hop.to_v4().to_uint()) == gw) {
                        return ppp::tap::TapLinux::DeleteRoute(ni->Name, ip, 32, gw);
                    }
                }

                // Delete the IP route for the dns server list added for the linux operating system.
                std::shared_ptr<ppp::tap::ITap> tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
                if (NULLPTR == linux_tap) {
                    return false;
                }

                return linux_tap->DeleteRoute(ip, prefix, gw);
#endif
            }
#endif

            /** @brief Removes DNS-specific route exceptions from operating system table. */
            void VEthernetNetworkSwitcher::DeleteRouteWithDnsServers() noexcept {
                // Delete all vpn dns server routes from the operating system.
                if (std::shared_ptr<ppp::tap::ITap> tap = GetTap(); NULLPTR != tap) {
#if defined(_WIN32)
                    // Delete the IP route for the dns server list added for the windows operating system.
                    if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULLPTR != mib) {
                        for (uint32_t ip : dns_serverss_[0]) {
                            DeleteRoute(mib, ip, tap->GatewayServer, 32);
                        }
                    }
#else
                    // Delete the IP route for the dns server list added for the macos operating system.
                    for (uint32_t ip : dns_serverss_[0]) {
                        DeleteRoute(ip, tap->GatewayServer, 32);
                    }
#endif
                }

                if (std::shared_ptr<NetworkInterface> ni = underlying_ni_; NULLPTR != ni) {
                    boost::asio::ip::address gw = ni->GatewayServer;
                    if (gw.is_v4()) {
                        uint32_t next_hop = htonl(gw.to_v4().to_uint());
#if defined(_WIN32)
                        // Delete the IP route for the dns server list added for the windows operating system.
                        if (auto mib = ppp::win32::network::Router::GetIpForwardTable(); NULLPTR != mib) {
                            for (uint32_t ip : dns_serverss_[1]) {
                                DeleteRoute(mib, ip, next_hop, 32);
                            }
                        }
#else
                        // Delete the IP route for the dns server list added for the macos operating system.
                        for (uint32_t ip : dns_serverss_[1]) {
                            DeleteRoute(ip, next_hop, 32);
                        }
#endif
                    }
                }

                // Clear the current cached dns server ip address list.
                for (auto& dns_servers : dns_serverss_) {
                    dns_servers.clear();
                }
            }

            // Routes need to be protected on Windows to prevent third - party programs(such as network card drivers)
            // From silently modifying the current gateway route and forcing out the VPN virtual gateway route.According to our observation,
            // In some PC and network production environments, third - party programs will destroy VPN deployment routing table information
            // At certain times.In PPP PRIVATE NETWORK™ 1, this NETWORK route protector exists by default, but PPP PRIVATE Network ™ 2 does
            // Not currently exist, so a new implementation of this section is needed.
            /** @brief Starts background default-route protector worker. */
            bool VEthernetNetworkSwitcher::ProtectDefaultRoute() noexcept {
                auto tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

#if !defined(_WIN32)
#if defined(_MACOS)
                auto unix_tap = dynamic_cast<ppp::tap::TapDarwin*>(tap.get());
#else
                auto unix_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
#endif
                if (NULLPTR == unix_tap || unix_tap->IsPromisc()) {
                    return false;
                }
#endif

                // Create a new network protection backend subthread.
                auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
                /** @brief Background loop that periodically repairs default-route drift. */
                std::thread([self]() noexcept {
                    auto prepare = [self]() noexcept {
                        // If the current VEthernet framework object instance is released, the process is break.
                        if (self->IsDisposed()) {
                            return false;
                        }

                        // If the route is not added to the system, the route pops out without setting the flag.
                        if (!self->route_added_) {
                            return false;
                        }

                        // Check whether the physical nic interface information still exists.
                        std::shared_ptr<NetworkInterface> underlying_ni = self->underlying_ni_;
                        if (NULLPTR == underlying_ni) {
                            return false;
                        }

                        // If the physical network adapter gateway server is not IPV4, the process is displayed.
                        boost::asio::ip::address gw = underlying_ni->GatewayServer;
                        if (!gw.is_v4()) {
                            return false;
                        }

                        return true;
                    };

                    ppp::SetThreadName("protector");
                    for (;;) {
                        // Gets the current process processing start time.
                        uint64_t start = ppp::GetTickCount();

                        // If the pre-preparation check processing fails, just jump out of the loop because the object is being released.
                        bool ok = prepare();
                        if (!ok) {
                            break;
                        }

                        // Try to get the lock, if you can't get the lock, do not deal with it and wait for the next execution.
                        if (self->prdr_.try_lock()) {
                            ok = prepare();
                            if (ok) {
                                ok = self->DeleteAllDefaultRoute();
                            }

                            // Release the obtained prdr lock and decide whether to exit the process.
                            self->prdr_.unlock();
                            if (!ok) {
                                break;
                            }
                        }

                        // Calculate how much time the thread has to wait for sleep.
                        uint64_t now = ppp::GetTickCount();
                        uint64_t delta = 0;
                        if (now >= start) {
                            delta = 1000 - std::min<uint64_t>(1000, now - start);
                        }

                        // Check whether the default gateway route is faulty every second.
                        ppp::Sleep(delta);
                    }
                }).detach();
                return true;
            }
#endif

            /** @brief Checks whether destination IP should bypass VPN forwarding path. */
            bool VEthernetNetworkSwitcher::IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v4()) {
                    return false;
                }

                if (ip.is_unspecified()) {
                    return false;
                }

                if (ip.is_multicast()) {
                    return false;
                }

                if (ppp::net::IPEndPoint::IsInvalid(ip)) {
                    return false;
                }

                auto tap = GetTap();
                if (NULLPTR == tap) {
                    return false;
                }

                uint32_t nip = htonl(ip.to_v4().to_uint());
#if defined(_ANDROID)
                // RIB
                if (auto fib = fib_; NULLPTR != fib) {
                    uint32_t ngw = fib->GetNextHop(nip);
                    return ngw != tap->GatewayServer;
                }

                return false;
#elif defined(_WIN32)
                DWORD dwInterfaceIndex;
                if (!::GetBestInterface((IPAddr)nip, &dwInterfaceIndex)) {
                    return false;
                }

                return dwInterfaceIndex != (DWORD)tap->GetInterfaceIndex();
#else
                // OS X provides basic routing table processing so that the HTTP proxy provided by the VPN can route
                // The traffic instead of having to deliver it to the VPN server for processing.
                //
                // It is only supported when the VPN opens the network card promisbity mode,
                // Which is to support the PC only a single network card can provide a reliable VPN virtual network
                // For the local area network through the kernel SNAT mechanism.
                //
                // Note: Google Android and Huawei HarmonyOS platforms (the VPN network adapter promiscuous mode must be enabled)
                // Snat: iptables -t nat -I POSTROUTING -s 192.168.0.24 -j SNAT --to-source 10.0.0.2
                return ppp::net::Socket::GetBestInterfaceIP(nip) != tap->IPAddress;
#endif
            }

            /** @brief Releases all runtime services, routes, and related resources. */
            void VEthernetNetworkSwitcher::ReleaseAllObjects() noexcept {
                ppp::telemetry::Log(Level::kInfo, "client", "client disconnected");
                ppp::telemetry::Count("client.disconnect", 1);

#if !defined(_ANDROID) && !defined(_IPHONE)
                // Windows platform needs to set the prdr synchronization lock state to prevent the problem of multi-thread concurrent competition.
                SynchronizedObjectScope scope(prdr_);
#endif

                // Clear event bindings.
                TickEvent = NULLPTR;

                // Stop and release the http-proxy service.
                if (VEthernetHttpProxySwitcherPtr http_proxy = std::move(http_proxy_); NULLPTR != http_proxy) {
                    http_proxy->Dispose();
                }

                // Stop and release the socks-proxy service.
                if (VEthernetSocksProxySwitcherPtr socks_proxy = std::move(socks_proxy_); NULLPTR != socks_proxy) {
                    socks_proxy->Dispose();
                }

                // Close and release the exchanger.
                if (std::shared_ptr<VEthernetExchanger> exchanger = std::move(exchanger_); NULLPTR != exchanger) {
                    exchanger->Dispose();
                }

                // Shutdown and release the qos control module.
                if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = std::move(qos_);  NULLPTR != qos) {
                    qos->Dispose();
                }

                // Close and release the aggligator.
                if (std::shared_ptr<aggligator::aggligator> aggligator = std::move(aggligator_); NULLPTR != aggligator) {
                    aggligator->close();
                }

                // Close and release the forwarding.
                if (IForwardingPtr forwarding = std::move(forwarding_); NULLPTR != forwarding) {
                    forwarding->Dispose();
                }

                // Release the multi-protocol DNS resolver.
                dns_resolver_.reset();

#if defined(_WIN32)
                // On Windows platforms, you need to try to turn off the [PaperAirplane NSP/LSP] server-side controller.
                if (PaperAirplaneControllerPtr controller = std::move(paper_airplane_ctrl_);  NULLPTR != controller) {
                    controller->Dispose();
                }
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
                RestoreAssignedIPv6();

                // Delete VPN route table information configured in the operating system!
                if (exchangeof(route_added_, false)) {
                    // Delete routes entries configured by the VPN program from the operating system.
                    DeleteRoute();

#if defined(_WIN32)
                    ppp::telemetry::Log(Level::kDebug, "client", "DNS teardown");
                    // Restore all dns servers addresses that have been configured when VPN routes are enabled.
                    ppp::win32::network::SetAllNicsDnsAddresses(ni_dns_servers_);

                    // Windows clients need to request the operating system FLUSH to reset all DNS query cache immediately after
                    // The VPN is constructed, because the original DNS cache may not be the best destination IP resolution record
                    // Available in the region where the VPN server is located.
                    ppp::tap::TapWindows::DnsFlushResolverCache();
#else
                    ppp::telemetry::Log(Level::kDebug, "client", "DNS teardown");
                    // Restore the original linux /etc/resolve.conf to linux operating system configuration files.
                    UnixNetworkInterface::SetDnsResolveConfiguration(GetUnderlyingNetworkInterface());
#endif
                }

                // To clean up the managed and unmanaged data currently held by the class,
                // You need to go through the complete construct fill process again after the Release of this function.
                ribs_.reset();
                tun_ni_.reset();
                underlying_ni_.reset();

                // Clear the reference pointers of the held vBGP without making specific clarification, as this may pose thread safety issues.
                vbgp_ = NULLPTR;

#if !defined(_MACOS)
                // Clear the routing table, forwarding table, and DNS server list of the network card, including cache.
                rib_ = NULLPTR;
                fib_ = NULLPTR;
#endif

                // Clear all route tables and forwarding tables held by the current object.
                LoadAllIPListWithFilePaths(boost::asio::ip::address_v4::any());
#endif

#if defined(_LINUX)
                // Release the network protector held by the current VPN local client switcher.
                if (auto protector = std::move(protect_network_); NULLPTR != protector) {
                    // In android platform you need to request the DetachJNI function of the network protector.
#if defined(_ANDROID)
                    protector->DetachJNI();
#endif
                }
#endif
            }

            /** @brief Removes timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::DeleteTimeout(void* k) noexcept {
                if (NULLPTR == k) {
                    return false;
                }

                SynchronizedObjectScope scope(GetSynchronizedObject());
                return Dictionary::RemoveValueByKey(timeouts_, k);
            }

            /** @brief Registers timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept {
                if (NULLPTR == k || NULLPTR == timeout) {
                    return false;
                }

                SynchronizedObjectScope scope(GetSynchronizedObject());
                auto r = timeouts_.emplace(k, timeout);
                return r.second;
            }

            /** @brief Loads DNS redirect rules from file or inline content. */
            bool VEthernetNetworkSwitcher::LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept {
                if (rules.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetNetworkSwitcherDnsRulesEmpty);
                }

                int events = 0;
                if (load_file_or_string) {
                    events = ppp::app::client::dns::Rule::LoadFile(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                }
                else {
                    events = ppp::app::client::dns::Rule::Load(rules, dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                }

                if (1 > events) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigDnsRuleLoadFailed);
                }

                return true;
            }

            /** @brief Adds remote endpoints and static servers to route/bypass tables. */
            bool VEthernetNetworkSwitcher::AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept {
                using ProtocolType = VEthernetExchanger::ProtocolType;

                // This function must be executed after the remote exchanger object has been created.
                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    return false;
                }

                // Initialize and try the proxy forwarding object if the link does require proxy forwarding services.
                IForwardingPtr forwarding = make_shared_object<IForwarding>(GetContext(), configuration_);
                if (NULLPTR == forwarding) {
                    return false;
                }
                elif(forwarding->Open()) {
                    forwarding_ = forwarding;
#if defined(_LINUX)
                    forwarding->ProtectorNetwork = GetProtectorNetwork();
#endif
                }
                else {
                    forwarding->Dispose();
                    forwarding.reset();
                }

                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                // Obtaining the IP endpoint address of the VPN remote server may involve synchronizing the network, as it may be in domain-name format.
                static constexpr ppp::coroutines::YieldContext* y = NULLPTR;

                if (!exchanger->GetRemoteEndPoint(y, hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return false;
                }
                else {
                    server_ru_ = "[";
                    server_ru_ += hostname;
                    server_ru_ += "]";
                    server_ru_ += ":";
                    server_ru_ += stl::to_string<ppp::string>(NULLPTR != forwarding ? forwarding->GetRemotePort() : port);
                    server_ru_ += "/";

                    if (protocol_type == ProtocolType::ProtocolType_Http || protocol_type == ProtocolType::ProtocolType_WebSocket) {
                        server_ru_ += "ppp+ws";
                    }
                    elif(protocol_type == ProtocolType::ProtocolType_HttpSSL || protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                        server_ru_ += "ppp+wss";
                    }
                    else {
                        server_ru_ += "ppp+tcp";
                    }

                    if (NULLPTR != forwarding) {
                        remoteEP = forwarding->GetProxyEndPoint();
                    }
                }

                // Add the default IP address of the vpn virtual network adapter to the RIB route table.
                RouteInformationTablePtr rib = rib_;
                if (NULLPTR == rib) {
                    rib = make_shared_object<RouteInformationTable>();
                    rib_ = rib;
                }

                // CIDR: 0.0.0.0/0; 0.0.0.0/1; 128.0.0.0/1
                if (NULLPTR != rib) {
                    if (auto tap = GetTap(); NULLPTR != tap) {
                        rib->AddRoute(IPEndPoint::AnyAddress, 0, tap->GatewayServer);
                        rib->AddRoute(IPEndPoint::AnyAddress, 1, tap->GatewayServer);
                        rib->AddRoute(inet_addr("128.0.0.0"), 1, tap->GatewayServer);
                    }
                }

                // Note that we only need to set IPV4 routes, not IPV6 routes.
                boost::asio::ip::address remoteIP = remoteEP.address();
                IPEndPoint serverEP = IPEndPoint::ToEndPoint(remoteEP);
                if (IPEndPoint::IsInvalid(serverEP)) {
                    return false;
                }

                // Add IPV4 route table settings.
                auto fib_add_route_ipv4 =
                    [&rib, &gw](const boost::asio::ip::address& remoteIP) noexcept {
                        if (remoteIP.is_v6()) {
                            return true;
                        }

                        if (NULLPTR == rib) {
                            return false;
                        }

                        bool processed = gw.is_v4() && remoteIP.is_v4();
                        if (!processed) {
                            return false;
                        }

                        // First convert the IP addresses of both.
                        uint32_t ip = htonl(remoteIP.to_v4().to_uint());
                        uint32_t nx = htonl(gw.to_v4().to_uint());

                        // Add route information to rib!
                        return rib->AddRoute(ip, 32, nx);
                    };

                // Check whether the static tunnel specifies an IP address endpoint (required for transit).
                ppp::unordered_set<boost::asio::ip::tcp::endpoint> servers;
                /** @brief Parses and registers one static tunnel server endpoint. */
                auto StaticEchoAddRemoteEndPoint =
                    [this, &servers, &fib_add_route_ipv4, &exchanger](const ppp::string& server_string) noexcept {
                        if (server_string.empty()) {
                            return false;
                        }

                        ppp::string host_string;
                        int port;

                        if (!ppp::net::Ipep::ParseEndPoint(server_string, host_string, port)) {
                            return false;
                        }

                        if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                            return false;
                        }

                        IPEndPoint remoteEP = ppp::net::Ipep::GetEndPoint(host_string, port);
                        if (IPEndPoint::IsInvalid(remoteEP)) {
                            return false;
                        }

                        boost::asio::ip::udp::endpoint ep =
                            IPEndPoint::ToEndPoint<boost::asio::ip::udp>(remoteEP);
                        if (!remoteEP.IsLoopback() && !fib_add_route_ipv4(ep.address())) {
                            return false;
                        }

                        if (aggligator_) {
                            auto r = servers.emplace(
                                IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(remoteEP));
                            return r.second;
                        }

                        return exchanger->StaticEchoAddRemoteEndPoint(ep);
                    };

                for (const ppp::string& server_string : configuration_->udp.static_.servers) {
                    if (!StaticEchoAddRemoteEndPoint(server_string)) {
                        return false;
                    }
                }

                // Open the beast network bandwidth aggregator.
                if (std::shared_ptr<aggligator::aggligator> aggligator = aggligator_; NULLPTR != aggligator) {
                    if (servers.empty()) {
                        aggligator_.reset();
                        aggligator->close();
                    }
                    elif(!aggligator->client_open(configuration_->udp.static_.aggligator, servers)) {
                        return false;
                    }
                }

                // The gateway address must be IPV4 or it is considered a failure because there is no V6 gateway serving the V4 address.
                if (serverEP.IsLoopback()) {
                    return true;
                }

                return fib_add_route_ipv4(remoteIP);
            }

            /** @brief Coroutine DNS redirect implementation for one outbound query. */
            bool VEthernetNetworkSwitcher::RedirectDnsServer(
                ppp::coroutines::YieldContext&                              y,
                const std::shared_ptr<boost::asio::ip::udp::socket>&        socket,
                const std::shared_ptr<Byte>&                                buffer,
                const boost::asio::ip::address&                             serverIP,
                const std::shared_ptr<UdpFrame>&                            frame,
                const std::shared_ptr<ppp::net::packet::BufferSegment>&     messages,
                const std::shared_ptr<boost::asio::io_context>&             context,
                const boost::asio::ip::address&                             destinationIP) noexcept {

                boost::system::error_code ec;
                boost::asio::ip::udp::endpoint serverEP(serverIP, frame->Destination.Port);

                bool opened = ppp::coroutines::asio::async_open(y, *socket, serverEP.protocol());
                if (!opened) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect socket_open failed server=%s",
                        serverIP.to_string().c_str());
#endif
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                }

                int handle = socket->native_handle();
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect socket_open fd=%d server=%s port=%d",
                    handle,
                    serverIP.to_string().c_str(),
                    (int)frame->Destination.Port);
#endif
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, serverIP.is_v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);

#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter.
                // IPV6 does not need to be linked, because VPN is IPV4,
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (!serverIP.is_loopback()) {
                    auto protector_network = GetProtectorNetwork();
                    if (NULLPTR != protector_network) {
                        if (!protector_network->Protect(handle, y)) {
#if defined(_ANDROID)
                            __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect protect failed fd=%d server=%s",
                                handle,
                                serverIP.to_string().c_str());
#endif
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                        }
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect protect ok fd=%d server=%s",
                            handle,
                            serverIP.to_string().c_str());
#endif
                    }
#if defined(_ANDROID)
                    else {
                        __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect protector missing fd=%d server=%s",
                            handle,
                            serverIP.to_string().c_str());
                    }
#endif
                }
#endif

                socket->send_to(boost::asio::buffer(messages->Buffer.get(), messages->Length), serverEP,
                    boost::asio::socket_base::message_end_of_record, ec);
                if (ec) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_ERROR, "openppp2", "dns_redirect send failed fd=%d server=%s ec=%d",
                        handle,
                        serverIP.to_string().c_str(),
                        ec.value());
#endif
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpSendFailed);
                }
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect send ok fd=%d server=%s bytes=%d",
                    handle,
                    serverIP.to_string().c_str(),
                    NULLPTR != messages ? (int)messages->Length : -1);
#endif

                const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                const std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();

                const auto self = shared_from_this();
                const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                    [self, socket_weak, handle](Timer*) noexcept {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect timeout fd=%d", handle);
#endif
                        const std::shared_ptr<boost::asio::ip::udp::socket> socket = socket_weak.lock();
                        if (socket) {
                            ppp::net::Socket::Closesocket(socket);
                        }
                    });
                if (NULLPTR == cb) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                const auto timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, *cb);
                if (NULLPTR == timeout) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                }

                if (!EmplaceTimeout(socket.get(), cb)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                const auto max_buffer_size = PPP_BUFFER_SIZE;
                boost::asio::ip::udp::endpoint sourceEP = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                boost::asio::ip::udp::endpoint destinationEP(destinationIP, frame->Destination.Port);

                const auto serverEPPtr = make_shared_object<boost::asio::ip::udp::endpoint>();
                if (NULLPTR == serverEPPtr) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                socket->async_receive_from(boost::asio::buffer(buffer.get(), max_buffer_size), *serverEPPtr,
                    [self, this, socket, timeout, buffer, sourceEP, destinationEP, serverEPPtr, handle](boost::system::error_code ec, size_t sz) noexcept {
                        DeleteTimeout(socket.get());
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
#if defined(_ANDROID)
                                __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect recv ok fd=%d bytes=%d",
                                    handle,
                                    (int)sz);
#endif
                                DatagramOutput(sourceEP, destinationEP, buffer.get(), sz);
                            }
                        }
#if defined(_ANDROID)
                        else {
                            __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect recv failed fd=%d ec=%d",
                                handle,
                                ec.value());
                        }
#endif

                        ppp::net::Socket::Closesocket(socket);
                        if (timeout) {
                            timeout->Stop();
                            timeout->Dispose();
                        }
                    });
                return true;
            }

            /**
             * @brief Centralised DnsResolver response handler for RedirectDnsServer().
             *
             * Hardens the Stage-1 tunnel fallback so that the original DNS query is
             * always forwarded through the VPN tunnel when DnsResolver fails to
             * deliver a usable response.  Failure modes covered:
             *   1. DnsResolver returns an empty response (timeout, all protocols
             *      exhausted, etc).
             *   2. Non-empty response but DatagramOutput cannot inject it into TUN.
             *   3. Any std::exception thrown in AddCache/DatagramOutput/SendTo
             *      (the calling lambda is noexcept; an uncaught throw would
             *      terminate the process).
             *
             * Telemetry counters: dns.redirect.success / .fallback / .dropped /
             * .exception.  DnsResolver guarantees single-shot callback so no
             * explicit re-entrance guard is required here.
             */
            void VEthernetNetworkSwitcher::HandleDnsResolverResponse(
                const std::shared_ptr<VEthernetNetworkSwitcher>& self,
                const std::shared_ptr<VEthernetExchanger>&       exchanger,
                const std::shared_ptr<BufferSegment>&            messages,
                const boost::asio::ip::udp::endpoint&            sourceEP,
                const boost::asio::ip::udp::endpoint&            destEP,
                ppp::vector<Byte>                                response) noexcept {
                try {
                    if (!response.empty() && NULLPTR != self) {
                        try {
                            ppp::net::asio::vdns::AddCache(
                                response.data(),
                                static_cast<int>(response.size()));
                        }
                        catch (...) { /* cache failure is non-fatal */ }

                        bool injected = self->DatagramOutput(
                            sourceEP, destEP,
                            response.data(),
                            static_cast<int>(response.size()),
                            false);
                        if (injected) {
                            ppp::telemetry::Count("dns.redirect.success", 1);
                            return;
                        }

                        ppp::telemetry::Log(Level::kDebug, "dns",
                            "redirect inject failed; tunnel fallback dst=%s:%d bytes=%d",
                            destEP.address().to_string().data(),
                            (int)destEP.port(),
                            (int)response.size());
                    }

                    /* Tunnel fallback: forward the original DNS query through the
                     * VPN.  Preserves pre-DoH behaviour (docs/DNS_MODULE_DESIGN.md
                     * "default zero-disruption changes"). */
                    if (NULLPTR != exchanger && NULLPTR != messages &&
                        NULLPTR != messages->Buffer.get() && messages->Length > 0) {
                        ppp::telemetry::Count("dns.redirect.fallback", 1);
                        ppp::telemetry::Log(Level::kDebug, "dns",
                            "tunnel fallback dst=%s:%d bytes=%d",
                            destEP.address().to_string().data(),
                            (int)destEP.port(),
                            (int)messages->Length);
                        exchanger->SendTo(sourceEP, destEP,
                            messages->Buffer.get(), messages->Length);
                    }
                    else {
                        ppp::telemetry::Count("dns.redirect.dropped", 1);
                    }
                }
                catch (const std::exception&) {
                    ppp::telemetry::Count("dns.redirect.exception", 1);
                }
                catch (...) {
                    ppp::telemetry::Count("dns.redirect.exception", 1);
                }
            }

            /** @brief Entry point for DNS redirection decision and async execution. */
            bool VEthernetNetworkSwitcher::RedirectDnsServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, const std::shared_ptr<BufferSegment>& messages) noexcept {
                ::dns::Message m;
                if (m.decode(static_cast<uint8_t*>(messages->Buffer.get()), messages->Length) != ::dns::BufferResult::NoError) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect decode failed payload=%d",
                        NULLPTR != messages ? (int)messages->Length : -1);
#endif
                    return false;
                }

                if (m.questions.empty()) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect empty questions");
#endif
                    return false;
                }

                boost::asio::ip::address destinationIP = Ipep::ToAddress(packet->Destination);
                ::dns::QuestionSection& qs = *m.questions.data();
#if defined(_ANDROID)
                __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect query host=%s type=%d dst=%s",
                    qs.mName.c_str(),
                    (int)qs.mType,
                    destinationIP.to_string().c_str());
#endif

                /**
                 * @brief Short-circuit AAAA queries when the VPN session has no
                 *        managed IPv6 assignment. Returning a synthetic empty
                 *        NOERROR response immediately avoids a 30+ second
                 *        connect stall when the OS resolver tries an IPv6
                 *        destination it cannot reach. Behaviour is gated by
                 *        DnsResolver::SetAllowIPv6Response() which is driven
                 *        from the server's information envelope.
                 */
                if (qs.mType == ::dns::RecordType::kAAAA && NULLPTR != dns_resolver_ && !dns_resolver_->IsAllowIPv6Response()) {
                    ppp::vector<Byte> synthesized = ppp::dns::DnsResolver::BuildAaaaBlockedResponse(
                        static_cast<const Byte*>(messages->Buffer.get()),
                        messages->Length);
                    if (!synthesized.empty()) {
                        ppp::telemetry::Count("dns.redirect.aaaa_blocked", 1);
                        return DatagramOutput(
                            IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source),
                            boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT),
                            synthesized.data(), static_cast<int>(synthesized.size()), false);
                    }
                }

                if (!ppp::net::asio::vdns::QueryCache2(qs.mName.data(), m, qs.mType == ::dns::RecordType::kA ?
                    ppp::net::asio::vdns::AddressFamily::kA : ppp::net::asio::vdns::AddressFamily::kAAAA).empty()) {

                    std::size_t dns_size = 0;
                    char dns_packet[PPP_MAX_DNS_PACKET_BUFFER_SIZE];

                    if (m.encode(dns_packet, PPP_MAX_DNS_PACKET_BUFFER_SIZE, dns_size) == ::dns::BufferResult::NoError && dns_size > 0) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect cache hit host=%s bytes=%d",
                            qs.mName.c_str(),
                            (int)dns_size);
#endif
                        return DatagramOutput(
                            IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source),
                            boost::asio::ip::udp::endpoint(destinationIP, PPP_DNS_SYS_PORT), dns_packet, dns_size, false);
                    }
                }

                boost::asio::ip::address serverIP;
                if (std::shared_ptr<ITap> tap = GetTap(); IPAddressIsGatewayServer(packet->Destination, tap->GatewayServer, tap->SubmaskAddress)) {
                    auto& dnsServers = ppp::net::asio::vdns::servers;
                    if (dnsServers->empty()) {
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect gateway but empty upstream list host=%s",
                            qs.mName.c_str());
#endif
                        return false;
                    }

                    serverIP = dnsServers->begin()->address();
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect gateway upstream=%s host=%s",
                        serverIP.to_string().c_str(),
                        qs.mName.c_str());
#endif
                }
                else {
                    ppp::app::client::dns::Rule::Ptr rulePtr = ppp::app::client::dns::Rule::Get(stl::transform<ppp::string>(qs.mName), dns_ruless_[0], dns_ruless_[1], dns_ruless_[2]);
                    if (NULLPTR == rulePtr) {
#if defined(_ANDROID)
                        // On Android: if intercept_unmatched is enabled, use DnsResolver.
                        // Prefer configured entries first (foreign/domestic), then
                        // fall back to provider-based ResolveAsyncWithFallback.
                        if (configuration_->dns.intercept_unmatched && NULLPTR != dns_resolver_) {
                            ppp::string domestic = configuration_->dns.servers.domestic;
                            ppp::string foreign  = configuration_->dns.servers.foreign;

                            boost::asio::ip::udp::endpoint sourceEP =
                                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                            boost::asio::ip::udp::endpoint destEP(destinationIP, PPP_DNS_SYS_PORT);

                            auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(
                                shared_from_this());

                            // Phase A: prefer structured entries from config.
                            ppp::vector<ppp::dns::ServerEntry> foreign_entries =
                                BuildResolverEntries(configuration_->dns.servers.foreign_entries);
                            ppp::vector<ppp::dns::ServerEntry> domestic_entries =
                                BuildResolverEntries(configuration_->dns.servers.domestic_entries);

                            if (!foreign_entries.empty()) {
                                // Unmatched queries prefer foreign entries first, preserving the
                                // legacy no-ECS behaviour of the foreign tier.
                                dns_resolver_->ResolveAsyncWithEntries(
                                    foreign_entries, false,
                                    static_cast<const Byte*>(messages->Buffer.get()),
                                    messages->Length,
                                    [self, sourceEP, destEP, exchanger, messages](ppp::vector<Byte> response) noexcept {
                                        HandleDnsResolverResponse(self, exchanger, messages, sourceEP, destEP, std::move(response));
                                    });
                                return true;
                            }

                            if (!domestic_entries.empty()) {
                                // If only domestic structured entries are configured, treat the
                                // query as domestic so ECS injection semantics match the
                                // provider-based domestic fallback path.
                                dns_resolver_->ResolveAsyncWithEntries(
                                    domestic_entries, true,
                                    static_cast<const Byte*>(messages->Buffer.get()),
                                    messages->Length,
                                    [self, sourceEP, destEP, exchanger, messages](ppp::vector<Byte> response) noexcept {
                                        HandleDnsResolverResponse(self, exchanger, messages, sourceEP, destEP, std::move(response));
                                    });
                                return true;
                            }

                            // Fallback: no structured entries, use legacy provider-based path.
                            dns_resolver_->ResolveAsyncWithFallback(
                                foreign, domestic, "cloudflare",
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length,
                                [self, sourceEP, destEP, exchanger, messages](ppp::vector<Byte> response) noexcept {
                                    HandleDnsResolverResponse(self, exchanger, messages, sourceEP, destEP, std::move(response));
                                });
                            return true;
                        }

                        serverIP = destinationIP;
                        __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect android fallback upstream=%s host=%s",
                            serverIP.to_string().c_str(),
                            qs.mName.c_str());
#else
                        // Desktop: if intercept_unmatched is enabled, use DnsResolver.
                        // Prefer configured entries first (foreign/domestic), then
                        // fall back to provider-based ResolveAsyncWithFallback.
                        if (configuration_->dns.intercept_unmatched && NULLPTR != dns_resolver_) {
                            ppp::string domestic = configuration_->dns.servers.domestic;
                            ppp::string foreign  = configuration_->dns.servers.foreign;

                            boost::asio::ip::udp::endpoint sourceEP =
                                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                            boost::asio::ip::udp::endpoint destEP(destinationIP, PPP_DNS_SYS_PORT);

                            auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(
                                shared_from_this());

                            // Phase A: prefer structured entries from config.
                            ppp::vector<ppp::dns::ServerEntry> foreign_entries =
                                BuildResolverEntries(configuration_->dns.servers.foreign_entries);
                            ppp::vector<ppp::dns::ServerEntry> domestic_entries =
                                BuildResolverEntries(configuration_->dns.servers.domestic_entries);

                            if (!foreign_entries.empty()) {
                                // Unmatched queries prefer foreign entries first, preserving the
                                // legacy no-ECS behaviour of the foreign tier.
                                dns_resolver_->ResolveAsyncWithEntries(
                                    foreign_entries, false,
                                    static_cast<const Byte*>(messages->Buffer.get()),
                                    messages->Length,
                                    [self, sourceEP, destEP, exchanger, messages](ppp::vector<Byte> response) noexcept {
                                        HandleDnsResolverResponse(self, exchanger, messages, sourceEP, destEP, std::move(response));
                                    });
                                return true;
                            }

                            if (!domestic_entries.empty()) {
                                // If only domestic structured entries are configured, treat the
                                // query as domestic so ECS injection semantics match the
                                // provider-based domestic fallback path.
                                dns_resolver_->ResolveAsyncWithEntries(
                                    domestic_entries, true,
                                    static_cast<const Byte*>(messages->Buffer.get()),
                                    messages->Length,
                                    [self, sourceEP, destEP, exchanger, messages](ppp::vector<Byte> response) noexcept {
                                        HandleDnsResolverResponse(self, exchanger, messages, sourceEP, destEP, std::move(response));
                                    });
                                return true;
                            }

                            // Fallback: no structured entries, use legacy provider-based path.
                            dns_resolver_->ResolveAsyncWithFallback(
                                foreign, domestic, "cloudflare",
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length,
                                [self, sourceEP, destEP, exchanger, messages](ppp::vector<Byte> response) noexcept {
                                    HandleDnsResolverResponse(self, exchanger, messages, sourceEP, destEP, std::move(response));
                                });
                            return true;
                        }

                        return false;
#endif
                    }
                    else {
                        if (!rulePtr->ProviderName.empty()) {
                            // Provider-based DNS resolution via DnsResolver (DoH/DoT/TCP/UDP).
                            // This path is taken when dns-rules.txt contains a provider short name
                            // (e.g. "doh.pub", "cloudflare") instead of a raw IP address.
                            bool domestic = rulePtr->Nic;
                            boost::asio::ip::udp::endpoint sourceEP =
                                IPEndPoint::ToEndPoint<boost::asio::ip::udp>(frame->Source);
                            boost::asio::ip::udp::endpoint destEP(destinationIP, PPP_DNS_SYS_PORT);

                            // Capture shared_from_this() to guarantee the switcher outlives
                            // the async DnsResolver callback — never use a bare `this` pointer.
                            auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(
                                shared_from_this());

                            dns_resolver_->ResolveAsync(
                                rulePtr->ProviderName, domestic,
                                static_cast<const Byte*>(messages->Buffer.get()),
                                messages->Length,
                                [self, sourceEP, destEP, exchanger, messages](ppp::vector<Byte> response) noexcept {
                                    HandleDnsResolverResponse(self, exchanger, messages, sourceEP, destEP, std::move(response));
                                });
                            return true;
                        }

                        // Legacy IP-based path: direct UDP forwarding to rulePtr->Server.
                        serverIP = rulePtr->Server;
#if defined(_ANDROID)
                        __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect rule upstream=%s host=%s",
                            serverIP.to_string().c_str(),
                            qs.mName.c_str());
#endif
                    }

#if !defined(_ANDROID)
                    if (serverIP == destinationIP) {
                        return false;
                    }
#endif
                }

                std::shared_ptr<boost::asio::io_context> context = exchanger->GetContext();
                if (NULLPTR == context) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect missing context host=%s",
                        qs.mName.c_str());
#endif
                    return false;
                }

                std::shared_ptr<Byte> buffer = exchanger->GetBuffer();
                if (NULLPTR == buffer) {
                    const auto allocator = configuration_->GetBufferAllocator();
                    if (allocator) {
                        buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
                    }
                    if (NULLPTR == buffer) {
                        buffer = std::shared_ptr<Byte>(new Byte[PPP_BUFFER_SIZE], std::default_delete<Byte[]>());
                    }
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_INFO, "openppp2", "dns_redirect temp buffer alloc host=%s ptr=%p",
                        qs.mName.c_str(),
                        buffer.get());
#endif
                }

                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*context);
                if (!socket) {
#if defined(_ANDROID)
                    __android_log_print(ANDROID_LOG_WARN, "openppp2", "dns_redirect socket alloc failed host=%s",
                        qs.mName.c_str());
#endif
                    return false;
                }

                const auto self = shared_from_this();
                const auto allocator = configuration_->GetBufferAllocator();

                return ppp::coroutines::YieldContext::Spawn(allocator.get(), *context,
                    [self, this, socket, buffer, frame, messages, context, serverIP, destinationIP](ppp::coroutines::YieldContext& y) noexcept {
                        return RedirectDnsServer(y, socket, buffer, serverIP, frame, messages, context, destinationIP);
                    });
            }

            /** @brief Gets current static mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::StaticMode(bool* static_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = static_mode_;
                if (NULLPTR != static_mode) {
                    static_mode_ = *static_mode;
                }

                return snow;
            }

            /** @brief Gets current mux size and optionally updates it. */
            uint16_t VEthernetNetworkSwitcher::Mux(uint16_t* mux) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint16_t snow = mux_;
                if (NULLPTR != mux) {
                    mux_ = *mux;
                }

                return snow;
            }

            /** @brief Gets current mux acceleration flags and optionally updates them. */
            uint8_t VEthernetNetworkSwitcher::MuxAcceleration(uint8_t* mux_acceleration) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                uint8_t snow = mux_acceleration_;
                if (NULLPTR != mux_acceleration) {
                    mux_acceleration_ = *mux_acceleration;
                }

                return snow;
            }

            /** @brief Performs periodic update work for static-echo socket rotation. */
            bool VEthernetNetworkSwitcher::OnUpdate(uint64_t now) noexcept {
                if (VEthernet::OnUpdate(now)) {
                    std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                    if (NULLPTR != exchanger) {
                        exchanger->StaticEchoSwapAsynchronousSocket();
                    }
                }

                return false;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_LINUX)
            /** @brief Gets current Linux protect mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::ProtectMode(bool* protect_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = protect_mode_;
                if (NULLPTR != protect_mode) {
                    protect_mode_ = *protect_mode;
                }

                return snow;
            }
#endif
#endif
        }
    }
}
