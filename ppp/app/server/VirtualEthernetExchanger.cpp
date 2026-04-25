#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualInternetControlMessageProtocol.h>
#include <ppp/app/server/VirtualInternetControlMessageProtocolStatic.h>
#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/app/server/VirtualEthernetIPv6.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualEthernetExchanger.cpp
 * @brief Implements per-session packet forwarding, NAT, DNS relay and mapping handlers.
 * @author OPENPPP2 Team
 * @license GPL-3.0
 */

typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
typedef ppp::collections::Dictionary                                Dictionary;
typedef ppp::net::AddressFamily                                     AddressFamily;
typedef ppp::net::Socket                                            Socket;
typedef ppp::net::Ipep                                              Ipep;
typedef ppp::threading::Timer                                       Timer;
typedef ppp::net::IPEndPoint                                        IPEndPoint;
typedef ppp::net::native::ip_hdr                                    ip_hdr;
typedef ppp::net::native::icmp_hdr                                  icmp_hdr;
typedef ppp::net::packet::IPFrame                                   IPFrame;
typedef ppp::net::packet::IcmpFrame                                 IcmpFrame;
typedef ppp::threading::Executors                                   Executors;
typedef ppp::collections::Dictionary                                Dictionary;

namespace {
    /**
     * @brief Converts matching ICMPv6 gateway echo requests into echo replies in-place.
     * @param packet Raw IPv6 packet buffer.
     * @param packet_length Packet length in bytes.
     * @param gateway Expected gateway destination address.
     * @return True when packet was transformed to a valid echo reply.
     */
    static bool HandleIPv6GatewayEchoReply(ppp::Byte* packet, int packet_length, const boost::asio::ip::address_v6& gateway) noexcept {
        if (NULLPTR == packet || packet_length < 48) {
            return false;
        }

        ppp::app::server::VirtualEthernetIPv6MinimalHeader* header = reinterpret_cast<ppp::app::server::VirtualEthernetIPv6MinimalHeader*>(packet);
        boost::asio::ip::address_v6 source;
        boost::asio::ip::address_v6 destination;
        ppp::Byte next_header = 0;
        int payload_length = 0;
        if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination, &next_header, &payload_length) || next_header != IPPROTO_ICMPV6) {
            return false;
        }

        if (destination != gateway) {
            return false;
        }

        icmp_hdr* icmp = reinterpret_cast<icmp_hdr*>(packet + ppp::ipv6::IPv6_HEADER_MIN_SIZE);
        int icmp_length = payload_length;
        if (icmp_length < static_cast<int>(sizeof(icmp_hdr))) {
            return false;
        }

        if (icmp->icmp_type != 128 || icmp->icmp_code != 0) {
            return false;
        }

        boost::asio::ip::address_v6::bytes_type source_bytes = source.to_bytes();
        boost::asio::ip::address_v6::bytes_type gateway_bytes = gateway.to_bytes();
        memcpy(header->Source, gateway_bytes.data(), gateway_bytes.size());
        memcpy(header->Destination, source_bytes.data(), source_bytes.size());
        header->HopLimit = ppp::ipv6::IPv6_DEFAULT_HOP_LIMIT;

        icmp->icmp_type = 129;
        icmp->icmp_chksum = 0;
        icmp->icmp_chksum = ppp::app::server::VirtualEthernetIPv6PseudoChecksum(reinterpret_cast<unsigned char*>(icmp), icmp_length, gateway, source, IPPROTO_ICMPV6);
        return true;
    }
}

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Initializes exchanger state for one virtual session.
             */
            VirtualEthernetExchanger::VirtualEthernetExchanger(
                const VirtualEthernetSwitcherPtr&                       switcher,
                const AppConfigurationPtr&                              configuration,
                const ITransmissionPtr&                                 transmission,
                const Int128&                                           id) noexcept 
                : VirtualEthernetLinklayer(configuration, transmission->GetContext(), id)
                , disposed_(false)
                , address_(IPEndPoint::NoneAddress)
                , switcher_(switcher)
                , transmission_(transmission)
                , static_echo_session_id_(0) {

                std::shared_ptr<boost::asio::io_context> context = transmission->GetContext();
                buffer_ = Executors::GetCachedBuffer(context);
                firewall_ = switcher->GetFirewall();
                managed_server_ = switcher->GetManagedServer();

                for (;;) {
                    ITransmissionPtr transmission = transmission_; 
                    if (NULLPTR != transmission) {
                        std::shared_ptr<ITransmissionStatistics> statistics = transmission->Statistics;
                        if (NULLPTR != statistics) {
                            statistics_ = statistics;
                            break;
                        }
                    }

                    statistics_ = switcher->GetStatistics();
                    break;
                }

                static_echo_source_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0);
            }

            /** @brief Releases exchanger resources. */
            VirtualEthernetExchanger::~VirtualEthernetExchanger() noexcept {
                Finalize();
            }

            /** @brief Gets preferred TUN descriptor hint. */
            int VirtualEthernetExchanger::GetPreferredTunFd() noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return preferred_tun_fd_;
            }

            /** @brief Sets preferred TUN descriptor hint. */
            void VirtualEthernetExchanger::SetPreferredTunFd(int fd) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                preferred_tun_fd_ = fd;
            }

            /** @brief Defers finalization onto exchanger io context. */
            void VirtualEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            /** @brief Finalizes all runtime objects and unregisters session from switcher. */
            void VirtualEthernetExchanger::Finalize() noexcept {
                // BUG-15 + BUG-17: Guard against double-finalization.  disposed_ must be set
                // to true at the very top, BEFORE any map is cleared, so that any concurrent
                // async callback that checks disposed_ first will bail out immediately and will
                // not touch datagrams_, mappings_, or timeouts_ after we release them.
                if (disposed_) {
                    return;
                }

                disposed_ = true;

                static_echo_source_ep_ = boost::asio::ip::udp::endpoint(boost::asio::ip::address_v4::any(), 0);
                for (;;) {
                    Dictionary::ReleaseAllObjects(datagrams_);
                    datagrams_.clear();

                    Dictionary::ReleaseAllObjects(mappings_);
                    mappings_.clear();

                    Timer::ReleaseAllTimeouts(timeouts_);
                    timeouts_.clear(); 

                    VirtualInternetControlMessageProtocolPtr echo = std::move(echo_); 
                    std::shared_ptr<VirtualInternetControlMessageProtocolStatic> static_echo = std::move(static_echo_); 
                    ITransmissionPtr transmission = std::move(transmission_); 
                    std::shared_ptr<vmux::vmux_net> mux = std::move(mux_);

                    if (NULLPTR != echo) {
                        echo->Dispose();
                    }

                    if (NULLPTR != static_echo) {
                        static_echo->Dispose();
                    }

                    if (NULLPTR != transmission) {
                        transmission->Dispose();
                    }

                    if (NULLPTR != mux) {
                        mux->close_exec();
                    }

                    break;
                }

                VirtualEthernetDatagramPortStaticTable static_echo_datagram_ports; 
                for (;;) {
                    SynchronizedObjectScope scope(static_echo_syncobj_);
                    static_echo_datagram_ports = std::move(static_echo_datagram_ports_);
                    static_echo_datagram_ports_.clear();
                    break;
                }

                UploadTrafficToManagedServer();
                Dictionary::ReleaseAllObjects(static_echo_datagram_ports);

                static_allocated_context_.reset();

                // BUG-15: Guard every switcher call with a null check — switcher_ may be null
                // if the constructor did not receive a valid switcher reference.
                if (switcher_) {
                    switcher_->DeleteIPv6Exchanger(GetId());
                    switcher_->DeleteExchanger(this);
                    switcher_->DeleteNatInformation(this, address_);
                    switcher_->StaticEchoUnallocated(static_echo_session_id_.exchange(0));
                }
            }

            /** @brief Gets firewall assigned to this exchanger. */
            VirtualEthernetExchanger::FirewallPtr VirtualEthernetExchanger::GetFirewall() noexcept {
                return firewall_;
            }

            /** @brief Rejects direct connect requests to enforce server-side safety policy. */
            bool VirtualEthernetExchanger::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Rejects direct push requests to enforce server-side safety policy. */
            bool VirtualEthernetExchanger::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Rejects direct disconnect requests to enforce server-side safety policy. */
            bool VirtualEthernetExchanger::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Handles logical echo acknowledgment from client. */
            bool VirtualEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                DoEcho(transmission, ack_id, y);
                return true;
            }

            /** @brief Handles ICMP echo payload forwarded from client. */
            bool VirtualEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                SendEchoToDestination(transmission, packet, packet_length);
                return true;
            }

            /** @brief Handles UDP send request from virtual client endpoint. */
            bool VirtualEthernetExchanger::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                SendPacketToDestination(transmission, sourceEP, destinationEP, packet, packet_length, y);
                return true;
            }

            /** @brief Rejects connect-ack packets from client side for safety hardening. */
            bool VirtualEthernetExchanger::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Rejects legacy information packet to keep protocol surface strict. */
            bool VirtualEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Processes extended information packets, including IPv6 assignment requests. */
            bool VirtualEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept {
                if (disposed_ || NULLPTR == switcher_ || NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                const VirtualEthernetInformationExtensions& request = information.Extensions;
                bool has_ipv6_request = request.RequestedIPv6Address.is_v6();
                bool is_server_response = request.AssignedIPv6Address.is_v6() || request.IPv6StatusCode != VirtualEthernetInformationExtensions::IPv6Status_None;
                if (!has_ipv6_request || is_server_response) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    return false;
                }

                VirtualEthernetInformationExtensions response;
                if (!switcher_->UpdateIPv6Request(GetId(), request, response)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                    return false;
                }

                VirtualEthernetInformation info;
                info.Clear();
                
                VirtualEthernetSwitcher::InformationEnvelope envelope;
                envelope.Base = info;
                envelope.Extensions = response;
                envelope.ExtendedJson = response.ToJson();
                return DoInformation(transmission, envelope, y);
            }

            /** @brief Allocates static-echo relay session for client. */
            bool VirtualEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                StaticEcho(transmission, y);
                return true;
            }

            /** @brief Rejects client-originated static assignment packets for safety hardening. */
            bool VirtualEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the server.
            }

            /** @brief Applies VMUX enable/disable request and acknowledges resulting state. */
            bool VirtualEthernetExchanger::OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept {
                bool err = true;
                for (;;) {
                    if (disposed_) {
                        break;
                    }

                    bool clean = vlan == 0 || max_connections == 0;
                    std::shared_ptr<vmux::vmux_net> mux = mux_;
                    if (NULLPTR != mux) {
                        if (clean || mux->Vlan != vlan || mux->get_max_connections() != max_connections || mux->is_disposed()) {
                            mux_.reset();
                            mux->close_exec();
                        }
                        else {
                            break;
                        }
                    }

                    if (clean) {
                        break;
                    }

                    ppp::threading::Executors::StrandPtr vmux_strand;
                    ppp::threading::Executors::ContextPtr vmux_context = ppp::threading::Executors::SelectScheduler(vmux_strand);
                    if (NULLPTR == vmux_context) {
                        break;
                    }

                    mux = make_shared_object<vmux::vmux_net>(vmux_context, vmux_strand, max_connections, true, acceleration);
                    if (NULLPTR != mux) {
                        mux->Vlan = vlan;
                        mux->Firewall = GetFirewall();
                        mux->Logger = switcher_->GetLogger();
                        mux->AppConfiguration = switcher_->GetConfiguration();
                        mux->BufferAllocator = transmission->BufferAllocator;

                        if (mux->update()) {
                            err = false;
                            mux_ = mux;
                        }
                        else {
                            mux_.reset();
                            mux->close_exec();
                        }
                    }

                    break;
                }

                if (err) {
                    if (std::shared_ptr<vmux::vmux_net> mux = std::move(mux_); NULLPTR != mux) {
                        mux->close_exec();
                    }

                    DoMux(transmission, 0, 0, false, y);
                }
                else {
                    DoMux(transmission, vlan, max_connections, acceleration, y);
                }

                return true;
            }

            /** @brief Handles client NAT packet and forwards via IPv4 or IPv6 routing path. */
            bool VirtualEthernetExchanger::OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                if (NULLPTR != logger) {
                    logger->Packet(GetId(), packet, packet_length, VirtualEthernetLogger::PacketDirection::ClientToServer);
                }

                AppConfigurationPtr configuration = GetConfiguration();
                bool forwarded = false;
                if (configuration->server.subnet) {
                    forwarded = ForwardNatPacketToDestination(packet, packet_length, y);
                }

                if (!forwarded && switcher_->IsIPv6ServerEnabled()) {
                    ForwardIPv6PacketToDestination(packet, packet_length, y);
                }

                return true;
            }

            /** @brief Forwards IPv6 packet toward local exchanger or transit gateway. */
            bool VirtualEthernetExchanger::ForwardIPv6PacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();

                if (!switcher_->IsIPv6ServerEnabled()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                    return false;
                }

                VirtualEthernetInformationExtensions approved;
                if (!switcher_->TryGetAssignedIPv6Extensions(GetId(), approved) || !approved.AssignedIPv6Address.is_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6LeaseUnavailable);
                    return false;
                }

                if (source != approved.AssignedIPv6Address.to_v6()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                    return false;
                }

                boost::asio::ip::address gateway = switcher_->GetIPv6TransitGateway();
                if (gateway.is_v6()) {
                    if (HandleIPv6GatewayEchoReply(packet, packet_length, gateway.to_v6())) {
                        return DoNat(transmission_, packet, packet_length, y);
                    }
                }

                // Reject packets destined for loopback or multicast addresses; these
                // must never be forwarded into the virtual network fabric.
                if (destination.is_loopback() || destination.is_multicast()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PacketRejected);
                    return false;
                }

                VirtualEthernetSwitcher::VirtualEthernetExchangerPtr exchanger = switcher_->FindIPv6Exchanger(destination);
                if (NULLPTR == exchanger) {
                    return switcher_->SendIPv6TransitPacket(packet, packet_length);
                }

                if (!configuration->server.subnet && configuration->server.ipv6.mode != AppConfiguration::IPv6Mode_Gua) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ModeInvalid);
                    return false;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (exchanger->DoNat(transmission, packet, packet_length, y)) {
                    VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                    if (NULLPTR != logger) {
                        logger->Packet(exchanger->GetId(), packet, packet_length, VirtualEthernetLogger::PacketDirection::ServerToClient);
                    }
                    return true;
                }

                transmission->Dispose();
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6SubnetForwardFailed);
                return false;
            }

            /** @brief Registers NAT mapping after LAN information announcement. */
            bool VirtualEthernetExchanger::OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (configuration->server.subnet) {
                    Arp(transmission, ip, mask);
                }

                return true;
            }

            /** @brief Allocates static echo context and responds with assigned session values. */
            bool VirtualEthernetExchanger::StaticEcho(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                int remote_port = IPEndPoint::MinPort;
                int allocated_id = 0;

                Int128 guid = GetId();
                auto allocated_context = switcher_->StaticEchoAllocated(guid, allocated_id, remote_port);

                if (NULLPTR != allocated_context) {
                    static_echo_session_id_.exchange(allocated_id);
                    static_allocated_context_ = allocated_context;

                    return DoStatic(transmission, allocated_context->fsid, allocated_id, remote_port, y);
                }
                else {
                    return DoStatic(transmission, 0, 0, IPEndPoint::MinPort, y);
                }
            }

            /** @brief Registers this exchanger in switcher NAT table using announced IP/mask. */
            bool VirtualEthernetExchanger::Arp(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask) noexcept {
                using VES = VirtualEthernetSwitcher;

                if (disposed_) {
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionCreateFailed);
                    return false;
                }

                VES::NatInformationPtr nat = switcher_->AddNatInformation(exchanger, ip, mask);
                if (NULLPTR == nat) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionCreateFailed);
                    return false;
                }
            
                VirtualEthernetLoggerPtr logger = switcher_->GetLogger(); 
                if (NULLPTR != logger) {
                    logger->Arp(GetId(), transmission, ip, mask);
                }

                address_ = ip;
                return true;
            }

            /** @brief Removes timeout callback entry by native key pointer. */
            bool VirtualEthernetExchanger::DeleteTimeout(void* k) noexcept {
                if (NULLPTR == k) {
                    return false;
                }
                else {
                    return Dictionary::RemoveValueByKey(timeouts_, k);
                }
            }

            /** @brief Forwards one UDP payload to destination through cached/new datagram port. */
            bool VirtualEthernetExchanger::SendPacketToDestination(const ITransmissionPtr& transmission, 
                const boost::asio::ip::udp::endpoint&   sourceEP, 
                const boost::asio::ip::udp::endpoint&   destinationEP, 
                Byte*                                   packet, 
                int                                     packet_length, 
                YieldContext&                           y) noexcept {

                if (disposed_) {
                    return false;
                }

                bool fin = false;
                if (NULLPTR == packet && packet_length != 0) {
                    return false;
                }
                elif(NULLPTR == packet || packet_length < 1) {
                    fin = true;
                }
               
                FirewallPtr firewall = firewall_;
                int destinationPort = destinationEP.port();

                if (NULLPTR != firewall) {
                    if (firewall->IsDropNetworkPort(destinationPort, false)) {
                        return false;
                    }

                    boost::asio::ip::address destinationIP = destinationEP.address();
                    if (firewall->IsDropNetworkSegment(destinationIP)) {
                        return false;
                    }
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                if (destinationPort == PPP_DNS_SYS_PORT) {
                    uint16_t queries_type = 0;
                    uint16_t queries_clazz = 0;
                    ppp::string hostDomain = ppp::net::native::dns::ExtractHostY(packet, packet_length,
                        [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                            queries_type = type;
                            queries_clazz = clazz;
                            return true;
                        });

                    if (hostDomain.size() > 0) {
                        if (NULLPTR != logger) {
                            logger->Dns(GetId(), transmission, hostDomain);
                        }

                        if (NULL != firewall) {
                            if (firewall->IsDropNetworkDomains(hostDomain)) {
                                return false;
                            }
                        }
                    }

                    int status = VirtualEthernetDatagramPort::NamespaceQuery(switcher_, this, sourceEP, destinationEP, hostDomain, 
                        packet, packet_length, queries_type, queries_clazz, false);
                    if (status < 0) {
                        return false;
                    }
                    elif(status > 0) {
                        return true;
                    }

                    status = RedirectDnsQuery(transmission, sourceEP, destinationEP, packet, packet_length, false);
                    if (status > -1) {
                        return status != 0;
                    }
                }

                VirtualEthernetDatagramPortPtr datagram = GetDatagramPort(sourceEP);
                if (NULLPTR != datagram) {
                    if (fin) {
                        datagram->MarkFinalize();
                        datagram->Dispose();
                        return true;
                    }
                    else {
                        return datagram->SendTo(packet, packet_length, destinationEP);
                    }
                }
                elif(fin) {
                    return false;
                }
                else {
                    datagram = NewDatagramPort(transmission, sourceEP);
                    if (NULLPTR != datagram) {
                        bool ok = false;
                        if (auto r = datagrams_.emplace(sourceEP, datagram); r.second) {
                            ok = datagram->Open();
                            if (!ok) {
                                datagrams_.erase(r.first);
                            }
                        }

                        if (ok) {
                            if (NULLPTR != logger) {
                                logger->Port(GetId(), transmission, datagram->GetSourceEndPoint(), datagram->GetLocalEndPoint());
                            }

                            return datagram->SendTo(packet, packet_length, destinationEP);
                        }
                        else {
                            datagram->Dispose();
                        }
                    }
                    return false;
                }
            }

            /**
             * @brief Sends DNS query to redirect endpoint and relays async response.
             */
            bool VirtualEthernetExchanger::INTERNAL_RedirectDnsQuery(
                ITransmissionPtr                                    transmission,
                boost::asio::ip::udp::endpoint                      redirectEP,
                boost::asio::ip::udp::endpoint                      sourceEP, 
                boost::asio::ip::udp::endpoint                      destinationEP,
                std::shared_ptr<Byte>                               packet,
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                if (disposed_) {
                    return false;
                }

                const std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    return false;
                }
                
                const auto context = transmission->GetContext();
                const std::shared_ptr<boost::asio::ip::udp::socket> socket = make_shared_object<boost::asio::ip::udp::socket>(*context);
                if (!socket) {
                    return false;
                }

                boost::system::error_code ec;
                socket->open(destinationEP.protocol(), ec);
                if (ec) {
                    return false;
                }

                int handle = socket->native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, destinationEP.protocol() == boost::asio::ip::udp::v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);

                socket->send_to(boost::asio::buffer(packet.get(), packet_length), redirectEP, 
                    boost::asio::socket_base::message_end_of_record, ec);
                if (ec) {
                    return false;
                }

                /** @brief Timer callback closes socket if redirect query times out. */
                const std::weak_ptr<boost::asio::ip::udp::socket> socket_weak(socket);
                const auto cb = make_shared_object<Timer::TimeoutEventHandler>(
                    [socket_weak](Timer*) noexcept {
                        const std::shared_ptr<boost::asio::ip::udp::socket> socket = socket_weak.lock();
                        if (socket) {
                            Socket::Closesocket(socket);
                        }
                    });
                if (NULLPTR == cb) {
                    return false;
                }

                const auto timeout = Timer::Timeout(context, (uint64_t)configuration->udp.dns.timeout * 1000, *cb);
                if (NULLPTR == timeout) {
                    return false;
                }
                
                if (!timeouts_.emplace(socket.get(), cb).second) {
                    return false;
                }

                const auto max_buffer_size = PPP_BUFFER_SIZE;
                const auto self = shared_from_this();
                
                // BUG-16: buffer_ is a shared scratch buffer owned by this exchanger.
                // Multiple concurrent INTERNAL_RedirectDnsQuery calls are possible when
                // the client sends several DNS queries in quick succession before any
                // reply arrives.  Each outstanding async_receive_from must have its own
                // dedicated receive buffer; sharing buffer_ across concurrent receives
                // would cause later arriving data to corrupt an earlier in-flight read.
                // Allocate a per-call heap buffer so every outstanding receive is
                // independently owned and there is no aliasing between concurrent calls.
                const std::shared_ptr<ppp::threading::BufferswapAllocator> recv_allocator = transmission->BufferAllocator;
                const std::shared_ptr<Byte> recv_buffer = ppp::threading::BufferswapAllocator::MakeByteArray(recv_allocator, max_buffer_size);
                if (NULLPTR == recv_buffer) {
                    return false;
                }

                const auto responseEP = make_shared_object<boost::asio::ip::udp::endpoint>();
                if (NULLPTR == responseEP) {
                    return false;
                }

                /** @brief Receives redirect DNS response and forwards to static/dynamic path. */
                socket->async_receive_from(boost::asio::buffer(recv_buffer.get(), max_buffer_size),
                    *responseEP,
                    [self, this, socket, sourceEP, timeout, static_transit, transmission, destinationEP, responseEP, recv_buffer](boost::system::error_code ec, size_t sz) noexcept {
                        DeleteTimeout(socket.get());
                        if (ec == boost::system::errc::success) {
                            int bytes_transferred = static_cast<int>(sz);
                            if (bytes_transferred > 0) {
                                if (static_transit) {
                                    VirtualEthernetDatagramPortStatic::Output(switcher_.get(), this, recv_buffer.get(), bytes_transferred, sourceEP, destinationEP);
                                }
                                elif(!DoSendTo(transmission, sourceEP, destinationEP, recv_buffer.get(), bytes_transferred, nullof<YieldContext>())) {
                                    transmission->Dispose();
                                }

                                AppConfigurationPtr configuration = GetConfiguration();
                                if (NULLPTR != configuration && configuration->udp.dns.cache) {
                                    VirtualEthernetDatagramPort::NamespaceQuery(switcher_, recv_buffer.get(), bytes_transferred);
                                }
                            }
                        }

                        Socket::Closesocket(socket);
                        if (timeout) {
                            timeout->Stop();
                            timeout->Dispose();
                        }
                    });
                return true;
            }

            /**
             * @brief Resolves configured DNS redirect host and dispatches redirect send.
             */
            bool VirtualEthernetExchanger::INTERNAL_RedirectDnsQuery(
                const ITransmissionPtr&                             transmission, 
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                Byte*                                               packet, 
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                if (!packet || packet_length < 1) {
                    return false;
                }

                if (!transmission) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                const std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;
                const auto buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_length);
                if (NULLPTR == buffer) {
                    return false;
                }
                else {
                    memcpy(buffer.get(), packet, packet_length);
                }

                const boost::asio::ip::udp::endpoint destination = destinationEP;
                const boost::asio::ip::udp::endpoint source = sourceEP;
                const ITransmissionPtr in = transmission;

                const auto configuration = GetConfiguration();
                const auto self = shared_from_this();
                const std::shared_ptr<boost::asio::io_context> context = in->GetContext();

                const Ipep::GetAddressByHostNameCallback cb = 
                    [self, this, buffer, packet_length, static_transit, source, in, destination, context](const std::shared_ptr<IPEndPoint>& redirectEP) noexcept {
                        if (!redirectEP) {
                            return false;
                        }

                        boost::asio::ip::udp::endpoint redirect = IPEndPoint::ToEndPoint<boost::asio::ip::udp>(*redirectEP);
                        boost::asio::post(*context, 
                            [self, this, buffer, packet_length, static_transit, source, in, destination, redirect]() noexcept {
                                return INTERNAL_RedirectDnsQuery(in, redirect, source, destination, buffer, packet_length, static_transit);
                            });
                        return true;
                    };

                return Ipep::GetAddressByHostName(*context, configuration->udp.dns.redirect, PPP_DNS_SYS_PORT, cb);
            }

            /**
             * @brief Applies DNS redirect policy for one outgoing DNS query packet.
             */
            int VirtualEthernetExchanger::RedirectDnsQuery(
                const ITransmissionPtr&                             transmission,
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                Byte*                                               packet,
                int                                                 packet_length,
                bool                                                static_transit) noexcept {

                std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
                if (configuration->udp.dns.redirect.empty()) {
                    return -1;
                }

                if (disposed_) {
                    return 0;
                }

                boost::asio::ip::udp::endpoint redirect_server = switcher_->GetDnsserverEndPoint();
                boost::asio::ip::address dnsserverIP = redirect_server.address();
                if (dnsserverIP.is_unspecified()) {
                    return INTERNAL_RedirectDnsQuery(transmission, sourceEP, destinationEP, packet, packet_length, static_transit);
                }

                boost::asio::ip::udp::endpoint dnsserverEP(dnsserverIP, PPP_DNS_SYS_PORT);
                return INTERNAL_RedirectDnsQuery(transmission,
                    dnsserverEP,
                    sourceEP,
                    destinationEP,
                    wrap_shared_pointer(packet), packet_length, static_transit);
            }

            /** @brief Schedules periodic maintenance for all exchanger-owned runtime objects. */
            bool VirtualEthernetExchanger::Update(UInt64 now) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this, now]() noexcept {
                        int session_id = static_echo_session_id_.load();
                        if (session_id != 0) {
                            // D1-4: Do NOT call UpdateAllObjects (which invokes Dispose() on expired
                            // ports) while static_echo_syncobj_ is held.  Disposing a UDP datagram
                            // port may trigger OS socket-close syscalls and re-entrant callbacks,
                            // both of which must not run under the lock.
                            //
                            // Instead, collect all stale ports into a local vector under the lock,
                            // erase them from the map, release the lock, and then dispose them
                            // outside the lock.  This is the standard snapshot-and-release pattern.
                            ppp::vector<VirtualEthernetDatagramPortStaticPtr> stale_ports;

                            {
                                SynchronizedObjectScope scope(static_echo_syncobj_);
                                for (auto tail = static_echo_datagram_ports_.begin(); tail != static_echo_datagram_ports_.end();) {
                                    const VirtualEthernetDatagramPortStaticPtr& port = tail->second;
                                    if (NULLPTR == port || port->IsPortAging(now)) {
                                        if (NULLPTR != port) {
                                            stale_ports.emplace_back(port);
                                        }

                                        tail = static_echo_datagram_ports_.erase(tail);
                                    }
                                    else {
                                        ++tail;
                                    }
                                }
                            }

                            // Dispose expired ports outside the lock to avoid holding
                            // static_echo_syncobj_ across socket-close syscalls.
                            for (auto& port : stale_ports) {
                                IDisposable::Dispose(*port);
                            }
                        }

                        UploadTrafficToManagedServer();
                        DoMuxEvents();
                        DoKeepAlived(GetTransmission(), now);

                        Dictionary::UpdateAllObjects(datagrams_, now);
                        Dictionary::UpdateAllObjects2(mappings_, now);
                    });
                return true;
            }

            /** @brief Polls VMUX and tears it down when update fails. */
            bool VirtualEthernetExchanger::DoMuxEvents() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULLPTR != mux) {
                    if (mux->update()) {
                        return true;
                    }

                    mux_.reset();
                    mux->close_exec();
                }

                return false;
            }

            /** @brief Uploads traffic delta counters to managed server when link is available. */
            bool VirtualEthernetExchanger::UploadTrafficToManagedServer() noexcept {
                VirtualEthernetManagedServerPtr server = managed_server_;
                if (NULLPTR == server) {
                    return false;
                }
                
                bool link_is_available = server->LinkIsAvailable();
                if (!link_is_available) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                ITransmissionStatisticsPtr statistics = transmission->Statistics;
                if (NULLPTR == statistics) {
                    return false;
                }
                
                statistics = statistics->Clone();
                if (NULLPTR == statistics) {
                    return false;
                }

                int64_t rx = 0;
                int64_t tx = 0;

                ITransmissionStatisticsPtr statistics_last = statistics_last_;
                if (NULLPTR != statistics_last) {
                    rx = statistics->IncomingTraffic - statistics_last->IncomingTraffic;
                    tx = statistics->OutgoingTraffic - statistics_last->OutgoingTraffic;
                }
                else {
                    rx = statistics->IncomingTraffic;
                    tx = statistics->OutgoingTraffic;
                }

                statistics_last_ = statistics;
                server->UploadTrafficToManagedServer(GetId(), rx, tx);
                return true;
            }

            /** @brief Creates ICMP and static-ICMP helper components for this exchanger. */
            bool VirtualEthernetExchanger::Open() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionCreateFailed);
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return false;
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return false;
                }

                ITransmissionPtr transmission = GetTransmission();
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                VirtualInternetControlMessageProtocolPtr echo = NewEchoTransmissions(transmission);
                if (NULLPTR == echo) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                    return false;
                }

                std::shared_ptr<VirtualInternetControlMessageProtocolStatic> static_echo = make_shared_object<VirtualInternetControlMessageProtocolStatic>(exchanger, configuration, context);
                if (NULLPTR == static_echo) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                echo_ = std::move(echo);
                static_echo_ = std::move(static_echo);
                return true;
            }

            /** @brief Constructs echo forwarding helper bound to current session. */
            VirtualEthernetExchanger::VirtualInternetControlMessageProtocolPtr VirtualEthernetExchanger::NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                return make_shared_object<VirtualInternetControlMessageProtocol>(exchanger, transmission);
            }

            /** @brief Constructs UDP datagram port proxy for one source endpoint. */
            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }
                
                auto my = shared_from_this();
                auto self = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                return make_shared_object<VirtualEthernetDatagramPort>(self, transmission, sourceEP);
            }

            /** @brief Finds a cached datagram port by source endpoint key. */
            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::FindObjectByKey(datagrams_, sourceEP);
            }

            /** @brief Removes and returns cached datagram port by source endpoint key. */
            VirtualEthernetExchanger::VirtualEthernetDatagramPortPtr VirtualEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                return Dictionary::ReleaseObjectByKey(datagrams_, sourceEP);
            }

            /** @brief Parses and forwards ICMP packet to echo subsystem after firewall checks. */
            bool VirtualEthernetExchanger::SendEchoToDestination(const ITransmissionPtr& transmission, Byte* packet, int packet_length) noexcept {
                if (disposed_) {
                    return false;
                }

                VirtualInternetControlMessageProtocolPtr echo = echo_;
                if (NULLPTR == echo) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = echo->BufferAllocator;
                std::shared_ptr<IPFrame> ip = IPFrame::Parse(allocator, packet, packet_length);
                if (NULLPTR == ip) {
                    return false;
                }

                if (ip->ProtocolType != ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }

                FirewallPtr firewall = firewall_;
                if (NULLPTR != firewall) {
                    boost::asio::ip::address destinationIP = Ipep::ToAddress(ip->Destination);
                    if (firewall->IsDropNetworkSegment(destinationIP)) {
                        return false;
                    }
                }

                std::shared_ptr<IcmpFrame> icmp = IcmpFrame::Parse(ip.get());
                if (NULLPTR == icmp) {
                    return false;
                }

                return echo->Echo(ip, icmp, IPEndPoint(icmp->Destination, IPEndPoint::MinPort));
            }

            /** @brief Forwards IPv4 NAT packet to matching peer exchangers in same subnet. */
            bool VirtualEthernetExchanger::ForwardNatPacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept {
                using VES = VirtualEthernetSwitcher;
                
                if (disposed_) {
                    return false;
                }

                ppp::net::native::ip_hdr* ip = ppp::net::native::ip_hdr::Parse(packet, packet_length);
                if (NULLPTR == ip) {
                    return false;
                }

                VES::NatInformationPtr source = switcher_->FindNatInformation(ip->src);
                if (NULLPTR == source) {
                    return false;
                }

                /** @brief Delivers a packet to the exchanger that owns destination address. */
                static const auto forward = 
                    [](VirtualEthernetSwitcher* switcher, uint32_t destination, Byte* packet, int packet_length, YieldContext& y) noexcept -> int {
                        VES::NatInformationPtr nat = switcher->FindNatInformation(destination);
                        if (NULLPTR == nat) {
                            return 0;
                        }

                        uint32_t mask = nat->SubmaskAddress;
                        std::shared_ptr<VirtualEthernetExchanger>& exchanger = nat->Exchanger;

                        if ((destination & mask) != (nat->IPAddress & mask)) {
                            return 0;
                        }

                        ITransmissionPtr transmission = exchanger->GetTransmission(); 
                        if (NULLPTR != transmission) {
                            if (exchanger->DoNat(transmission, packet, packet_length, y)) {
                                VirtualEthernetLoggerPtr logger = switcher->GetLogger();
                                if (NULLPTR != logger) {
                                    logger->Packet(exchanger->GetId(), packet, packet_length, VirtualEthernetLogger::PacketDirection::ServerToClient);
                                }
                                return 1;
                            }

                            transmission->Dispose();
                        }

                        return -1;
                    };

                if (uint32_t destination = ip->dest; destination != IPEndPoint::BroadcastAddress) {
                    return forward(switcher_.get(), destination, packet, packet_length, y) > 0;
                }
                else {
                    // BUG-19: The original loop iterated every host address in the subnet,
                    // which is up to 16 million iterations for a /8 — blocking the IO thread
                    // for an unbounded time.  Cap the broadcast walk at 256 host addresses to
                    // bound worst-case latency while still covering practical subnet sizes
                    // (/24 and smaller, which are the common deployment configurations).
                    // Subnets larger than /24 will only have their first 256 hosts forwarded;
                    // this is an intentional safety limit, not a correctness regression, because
                    // iterating millions of addresses synchronously would stall every other
                    // session on the same IO thread.
                    static constexpr uint32_t kMaxBroadcastHosts = 256;

                    bool any = false;
                    uint32_t current = htonl(ip->src);
                    uint32_t mask = ntohl(source->SubmaskAddress);
                    uint32_t first = current & mask;
                    uint32_t boardcast = first | (~mask); // first | (~first & 0xff);
                    uint32_t walked = 0;

                    for (uint32_t address = first; address < boardcast && walked < kMaxBroadcastHosts; address++) {
                        if (current == address) {
                            continue;
                        }

                        walked++;
                        int status = forward(switcher_.get(), htonl(address), packet, packet_length, y);
                        if (status < 0) {
                            break;
                        }

                        any |= status > 0;
                    }

                    return any;
                }
            }

            /** @brief Handles FRP mapping entry registration notification. */
            bool VirtualEthernetExchanger::OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (configuration->server.mapping) {
                    RegisterMappingPort(in, tcp, remote_port);
                }

                return true;
            }

            /** @brief Forwards FRP UDP payload to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpSendTo(packet, packet_length, sourceEP);
                }

                return true;
            }

            /** @brief Forwards FRP connect result to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpConnectOK(connection_id, error_code);
                }

                return true;
            }

            /** @brief Forwards FRP disconnect event to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpDisconnect(connection_id);
                }

                return true;
            }

            /** @brief Forwards FRP TCP stream payload to corresponding mapping port. */
            bool VirtualEthernetExchanger::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Server_OnFrpPush(connection_id, packet, packet_length);
                }

                return true;
            }

            /** @brief Creates, opens and registers FRP mapping port if absent. */
            bool VirtualEthernetExchanger::RegisterMappingPort(bool in, bool tcp, int remote_port) noexcept {
                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, tcp, remote_port);
                if (NULLPTR != mapping_port) {
                    return false;
                }

                mapping_port = NewMappingPort(in, tcp, remote_port);
                if (NULLPTR == mapping_port) {
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger();
                bool ok = mapping_port->OpenFrpServer(logger);
                if (ok) {
                    ok = VirtualEthernetMappingPort::AddMappingPort(mappings_, in, tcp, remote_port, mapping_port);
                }

                if (ok) {
                    if (NULLPTR != logger) {
                        logger->MPEntry(GetId(), transmission, mapping_port->BoundEndPointOfFrpServer(), tcp);
                    }
                }
                else {
                    mapping_port->Dispose();
                }
                return ok;
            }

            /** @brief Builds FRP mapping port object with disposal hook. */
            VirtualEthernetExchanger::VirtualEthernetMappingPortPtr VirtualEthernetExchanger::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class MappingPort : public VirtualEthernetMappingPort {
                public:
                    MappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    /** @brief Unregisters mapping key asynchronously, then disposes base resources. */
                    virtual void Dispose() noexcept override {
                        // Remove the mapping entry after leaving the current call stack so
                        // disposal cannot re-enter the exchanger while its lock is held.
                        if (std::shared_ptr<VirtualEthernetLinklayer> linklayer = GetLinklayer(); NULLPTR != linklayer) {
                            if (std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(linklayer); NULLPTR != exchanger) {
                                auto self = shared_from_this();
                                std::shared_ptr<boost::asio::io_context> context = exchanger->GetContext();
                                auto remove_mapping = [exchanger, self]() noexcept {
                                    SynchronizedObjectScope scope(exchanger->syncobj_);
                                    VirtualEthernetMappingPort::DeleteMappingPort(
                                        exchanger->mappings_, self->ProtocolIsNetworkV4(), self->ProtocolIsTcpNetwork(), self->GetRemotePort());
                                };

                                if (NULLPTR != context) {
                                    boost::asio::post(*context, std::move(remove_mapping));
                                }
                                else {
                                    remove_mapping();
                                }
                            }
                        }

                        VirtualEthernetMappingPort::Dispose();
                    }
                };

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto self = shared_from_this();
                return make_shared_object<MappingPort>(self, transmission, tcp, in, remote_port);
            }

            /** @brief Finds FRP mapping port by direction/protocol/remote-port key. */
            VirtualEthernetExchanger::VirtualEthernetMappingPortPtr VirtualEthernetExchanger::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                return VirtualEthernetMappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
            }

            /** @brief Runs keepalive and disposes exchanger when keepalive fails. */
            bool VirtualEthernetExchanger::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                if (disposed_) {
                    return false;
                }
                
                if (VirtualEthernetLinklayer::DoKeepAlived(transmission, now)) {
                    return true;
                }

                IDisposable::Dispose(this);
                return false;
            }

            /** @brief Handles static-echo ICMP packet and relays via static echo engine. */
            bool VirtualEthernetExchanger::StaticEchoEchoToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (disposed_) {
                    return false;
                }

                if (NULLPTR == packet) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;
                std::shared_ptr<ppp::net::packet::IPFrame> ip = packet->GetIPPacket(allocator);
                if (NULLPTR == ip) {
                    return false;
                }
                elif(ip->ProtocolType != ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                    return false;
                }
                elif(ip->Source == IPEndPoint::LoopbackAddress) {
                    std::shared_ptr<VirtualInternetControlMessageProtocolStatic> echo = static_echo_;
                    if (NULLPTR == echo) {
                        return false;
                    }

                    ppp::app::protocol::VirtualEthernetPacket::FillBytesToPayload(ip.get());
                    return echo->Output(ip.get(), IPEndPoint::ToEndPoint(sourceEP));
                }

                std::shared_ptr<ppp::net::packet::IcmpFrame> frame = ppp::net::packet::IcmpFrame::Parse(ip.get());
                if (NULLPTR == ip || NULLPTR == frame) {
                    return false;
                }

                std::shared_ptr<VirtualInternetControlMessageProtocolStatic> echo = static_echo_;
                if (NULLPTR == echo) {
                    return false;
                }

                return echo->Echo(ip, frame, IPEndPoint::ToEndPoint(sourceEP));
            }

            /** @brief Releases static-echo datagram port by source address and port. */
            bool VirtualEthernetExchanger::StaticEchoReleasePort(uint32_t source_ip, int source_port) noexcept {
                std::shared_ptr<VirtualEthernetDatagramPortStatic> datagram_port;
                if (source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    return false;
                }

                uint64_t key = MAKE_QWORD(source_ip, source_port);
                if (key) {
                    SynchronizedObjectScope scope(static_echo_syncobj_);
                    Dictionary::TryRemove(static_echo_datagram_ports_, key, datagram_port);
                }

                if (NULLPTR == datagram_port) {
                    return false;
                }

                datagram_port->Dispose();
                return true;
            }

            /** @brief Forwards static-echo UDP packet to destination through cached/static port. */
            bool VirtualEthernetExchanger::StaticEchoSendToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept {
                if (disposed_) {
                    return false;
                }

                if (NULLPTR == packet) {
                    return false;
                }

                auto my = shared_from_this();
                std::shared_ptr<VirtualEthernetExchanger> exchanger = std::dynamic_pointer_cast<VirtualEthernetExchanger>(my);
                if (NULLPTR == exchanger) {
                    return false;
                }

                std::shared_ptr<Byte> messages = packet->Payload;
                if (NULLPTR == messages) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetDatagramPortStatic> datagram_port;
                int source_port = packet->SourcePort;
                uint32_t source_ip = packet->SourceIP;

                boost::asio::ip::address destinationIP = Ipep::ToAddress(packet->DestinationIP);
                boost::asio::ip::udp::endpoint destinationEP = boost::asio::ip::udp::endpoint(destinationIP, packet->DestinationPort);

                if (source_ip == IPEndPoint::AnyAddress || source_ip == IPEndPoint::NoneAddress) {
                    return false;
                }
                elif(source_port <= IPEndPoint::MinPort || source_port > IPEndPoint::MaxPort) {
                    return false;
                }
                elif(packet->DestinationPort <= IPEndPoint::MinPort || packet->DestinationPort > IPEndPoint::MaxPort) {
                    return false;
                }
                elif(packet->DestinationIP == IPEndPoint::AnyAddress || packet->DestinationIP == IPEndPoint::NoneAddress) {
                    return false;
                }

                VirtualEthernetLoggerPtr logger = switcher_->GetLogger(); 
                if (packet->DestinationPort == PPP_DNS_SYS_PORT) {
                    uint16_t queries_type = 0;
                    uint16_t queries_clazz = 0;
                    ppp::string hostDomain = ppp::net::native::dns::ExtractHostY(messages.get(), packet->Length,
                        [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                            queries_type = type;
                            queries_clazz = clazz;
                            return true;
                        });

                    if (hostDomain.size() > 0) {
                        if (NULLPTR != logger) {
                            logger->Dns(GetId(), transmission, hostDomain);
                        }

                        FirewallPtr firewall = firewall_;
                        if (NULL != firewall && firewall->IsDropNetworkDomains(hostDomain)) {
                            return false;
                        }
                    }

                    boost::asio::ip::udp::endpoint sourceEP =
                        IPEndPoint::ToEndPoint<boost::asio::ip::udp>(IPEndPoint(source_ip, source_port));

                    int status = VirtualEthernetDatagramPort::NamespaceQuery(switcher_, this, sourceEP, destinationEP, hostDomain, 
                        messages.get(), packet->Length, queries_type, queries_clazz, true);
                    if (status < 0) {
                        return false;
                    }
                    elif(status > 0) {
                        return true;
                    }

                    status = RedirectDnsQuery(transmission, sourceEP, destinationEP, messages.get(), packet->Length, true);
                    if (status > -1) {
                        return status != 0;
                    }
                }

                for (;;) {
                    uint64_t key = MAKE_QWORD(source_ip, source_port);
                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULLPTR == context) {
                        break;
                    }

                    /**
                     * @brief Fast path: check whether a port already exists without opening a socket.
                     *
                     * The map lookup runs under the lock; if a port is found, we avoid
                     * allocating a new socket entirely.
                     */
                    bool already_exists = false;
                    {
                        SynchronizedObjectScope scope(static_echo_syncobj_);
                        already_exists = ppp::collections::Dictionary::TryGetValue(static_echo_datagram_ports_, key, datagram_port);
                    }

                    if (already_exists) {
                        break;
                    }

                    /**
                     * @brief Slow path: create and open the socket BEFORE acquiring the lock.
                     *
                     * Performing the UDP socket allocation and Open() syscall outside the lock
                     * prevents static_echo_syncobj_ from being held during potentially blocking
                     * OS operations.  A concurrent thread may race to insert the same key;
                     * the second check inside the lock below resolves such races.
                     */
                    std::shared_ptr<VirtualEthernetDatagramPortStatic> new_port =
                        make_shared_object<VirtualEthernetDatagramPortStatic>(exchanger, context, source_ip, source_port);
                    if (NULLPTR == new_port) {
                        return false;
                    }

                    if (!new_port->Open()) {
                        new_port->Dispose();
                        return false;
                    }

                    /**
                     * @brief Under the lock: attempt to insert the newly opened port.
                     *
                     * If another thread already inserted a port for the same key during the
                     * Open() window, TryAdd returns false; we discard our port and use theirs.
                     */
                    bool inserted = false;
                    {
                        SynchronizedObjectScope scope(static_echo_syncobj_);
                        if (!ppp::collections::Dictionary::TryGetValue(static_echo_datagram_ports_, key, datagram_port)) {
                            inserted = ppp::collections::Dictionary::TryAdd(static_echo_datagram_ports_, key, new_port);
                            if (inserted) {
                                datagram_port = new_port;
                            }
                        }
                        /** @brief datagram_port now holds whichever entry won the insertion race. */
                    }

                    if (inserted) {
                        if (NULLPTR != logger) {
                            logger->Port(GetId(), transmission, datagram_port->GetSourceEndPoint(), datagram_port->GetLocalEndPoint());
                        }
                    }
                    else {
                        /** @brief Lost the insertion race; dispose our redundant port. */
                        new_port->Dispose();
                    }

                    break;
                }

                if (NULLPTR == datagram_port) {
                    return false;
                }

                return datagram_port->SendTo(messages.get(), packet->Length, destinationEP);
            }
        }
    }
}
