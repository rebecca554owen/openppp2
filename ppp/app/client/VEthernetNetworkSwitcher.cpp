#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/ClientNetworkInterfaceResolver.h>
#include <ppp/app/client/VEthernetNetworkTcpipStack.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/RouteTableManager.h>
#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/ClientConnectionTeardown.h>
#include <ppp/app/client/ClientConnectionOpener.h>
#include <ppp/app/client/ClientPacketDispatchHandler.h>
#include <ppp/app/client/ClientBypassRouteLoader.h>
#include <ppp/app/client/QuicRejectRateLimiter.h>
#include <ppp/app/client/PeerPrefixRouteManager.h>
#include <ppp/app/client/AggregatorLoader.h>
#include <ppp/app/client/RemoteEndpointLoader.h>
#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <common/aggligator/aggligator.h>
#include <ppp/IDisposable.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/TelemetryFwd.h>
#include <ppp/ipv6/IPv6Packet.h>

#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/rib.h>

#include <ppp/net/asio/vdns.h>
#include <ppp/net/Ipep.h>

#include <chrono>

#if defined(_ANDROID)
#include <android/log.h>
#include <android/OpenPPP2VpnProtectBridge.h>

static bool AndroidDnsRedirectTraceEnabled() noexcept {
#ifdef NDEBUG
    return false;
#else
    return true;
#endif
}

#define ANDROID_DNS_REDIRECT_TRACE(...) \
    do { \
        if (AndroidDnsRedirectTraceEnabled()) { \
            __android_log_print(ANDROID_LOG_INFO, "openppp2", __VA_ARGS__); \
        } \
    } while (0)
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
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/net/ProtectorNetwork.h>
#endif
#endif

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
using ppp::net::packet::IPFrame;
using ppp::net::packet::UdpFrame;
using ppp::net::packet::BufferSegment;
using ppp::transmissions::ITransmission;
using ppp::transmissions::proxys::IForwarding;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {
            /** @brief Constructs network switcher and initializes baseline state flags. */
            VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
                : VEthernet(context, lwip, vnet, mta)
                , configuration_(configuration)
                , dns_interceptor_(std::make_shared<dns::DnsInterceptor>())
                , route_table_(std::make_unique<RouteTableManager>())
                , address_manager_(std::make_unique<AssignedAddressManager>())
                , teardown_(std::make_unique<ClientConnectionTeardown>())
                , connection_opener_(std::make_unique<ClientConnectionOpener>())
                , packet_dispatch_(std::make_unique<ClientPacketDispatchHandler>())
                , bypass_loader_(std::make_unique<ClientBypassRouteLoader>())
                , quic_reject_limiter_(std::make_unique<QuicRejectRateLimiter>())
                , peer_prefix_routes_(std::make_unique<PeerPrefixRouteManager>())
                , aggregator_loader_(std::make_unique<AggregatorLoader>())
                , remote_endpoint_loader_(std::make_unique<RemoteEndpointLoader>())
                , timeout_registry_(std::make_unique<SwitcherTimeoutRegistry>())
                , information_extensions_(std::make_unique<VirtualEthernetInformationExtensions>())
                , icmppackets_aid_(0) {

                route_table_->Bind(this);
                address_manager_->Bind(this);
                teardown_->Bind(this);
                connection_opener_->Bind(this);
                packet_dispatch_->Bind(this);
                bypass_loader_->Bind(this);
                peer_prefix_routes_->Bind(this);
                aggregator_loader_->Bind(this);
                remote_endpoint_loader_->Bind(this);
                timeout_registry_->Bind(&GetSynchronizedObject());

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

#if defined(_WIN32)
            VEthernetNetworkSwitcher::PaperAirplaneControllerPtr VEthernetNetworkSwitcher::GetPaperAirplaneController() noexcept {
                return paper_airplane_ctrl_;
            }
#elif defined(_LINUX)
            VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::GetProtectorNetwork() noexcept {
                return protect_network_;
            }
#endif

            std::shared_ptr<ppp::configurations::AppConfiguration> VEthernetNetworkSwitcher::GetConfiguration() noexcept {
                return configuration_;
            }

            std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::GetExchanger() noexcept {
                return exchanger_;
            }

            void VEthernetNetworkSwitcher::RequestedIPv6(const ppp::string& value) noexcept {
                requested_ipv6_ = value;
            }

            ppp::string VEthernetNetworkSwitcher::RequestedIPv6() noexcept {
                return requested_ipv6_;
            }

            std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::GetQoS() noexcept {
                return qos_;
            }

            std::shared_ptr<ppp::transmissions::ITransmissionStatistics> VEthernetNetworkSwitcher::GetStatistics() noexcept {
                return statistics_;
            }

            VEthernetNetworkSwitcher::VirtualEthernetInformationExtensions VEthernetNetworkSwitcher::GetInformationExtensions() noexcept {
                return *information_extensions_;
            }

            VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::GetHttpProxy() noexcept {
                return http_proxy_;
            }

            VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::GetSocksProxy() noexcept {
                return socks_proxy_;
            }

            VEthernetNetworkSwitcher::RouteInformationTablePtr VEthernetNetworkSwitcher::GetRib() noexcept {
                return rib_;
            }

            VEthernetNetworkSwitcher::ForwardInformationTablePtr VEthernetNetworkSwitcher::GetFib() noexcept {
                return fib_;
            }

            VEthernetNetworkSwitcher::IForwardingPtr VEthernetNetworkSwitcher::GetForwarding() noexcept {
                return forwarding_;
            }

            std::shared_ptr<aggligator::aggligator> VEthernetNetworkSwitcher::GetAggligator() noexcept {
                return aggligator_;
            }

            VEthernetNetworkSwitcher::RouteIPListTablePtr VEthernetNetworkSwitcher::GetVbgp() noexcept {
                return vbgp_;
            }

            bool VEthernetNetworkSwitcher::IsBlockQUIC() noexcept {
                return block_quic_;
            }

            bool VEthernetNetworkSwitcher::IsMuxEnabled() noexcept {
                return mux_ > 0;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            std::shared_ptr<ClientNetworkInterface> VEthernetNetworkSwitcher::GetTapNetworkInterface() noexcept {
                return tun_ni_;
            }

            std::shared_ptr<ClientNetworkInterface> VEthernetNetworkSwitcher::GetUnderlyingNetworkInterface() noexcept {
                return underlying_ni_;
            }
#endif

            bool VEthernetNetworkSwitcher::IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept {
                return ip == gw ? true : htonl((ntohl(gw) & ntohl(mask)) + 1) == ip;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            boost::asio::ip::address VEthernetNetworkSwitcher::LastAssignedIPv6() noexcept {
                return address_manager_->LastAssignedIPv6();
            }

            bool VEthernetNetworkSwitcher::TryApplyHostedNetworkRoutes() noexcept {
                return route_table_->TryApplyHostedNetworkRoutes();
            }
#endif

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
                return packet_dispatch_->OnPacketInput(packet, packet_length, header_length, proto, vnet);
            }

            /** @brief Handles raw IPv6 packet input and forwards approved traffic. */
            bool VEthernetNetworkSwitcher::OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept {
                return packet_dispatch_->OnPacketInput(packet, packet_length, vnet);
            }

            /** @brief Routes parsed IP frame to protocol-specific handlers. */
            bool VEthernetNetworkSwitcher::OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept {
                return packet_dispatch_->OnPacketInput(packet);
            }

            /** @brief Resolves ACK identifier and emits appropriate ICMP response packet. */
            bool VEthernetNetworkSwitcher::ERORTE(int ack_id) noexcept {
                return packet_dispatch_->ERORTE(ack_id);
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
#if !defined(_ANDROID) && !defined(_IPHONE)
                RestoreAssignedIPv4();
#endif
                ReleaseAllObjects();
                ReleaseAllPackets();
                ReleaseAllTimeouts();
            }

            /** @brief Clears all tracked ICMP packet records. */
            void VEthernetNetworkSwitcher::ReleaseAllPackets() noexcept {
                // Clear all ICMP packet container.
                SynchronizedObjectScope scope(GetSynchronizedObject());
                icmppackets_.clear();
                quic_reject_limiter_->Clear();
            }

            /** @brief Releases all registered timeout callbacks. */
            void VEthernetNetworkSwitcher::ReleaseAllTimeouts() noexcept {
                timeout_registry_->ReleaseAll();
            }

#if defined(_ANDROID) || defined(_IPHONE)
            void VEthernetNetworkSwitcher::SetBypassIpList(ppp::string&& bypass_ip_list) noexcept {
                bypass_loader_->SetBypassIpList(std::move(bypass_ip_list));
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
            boost::asio::ip::address VEthernetNetworkSwitcher::RewriteFakeIpAddress(const boost::asio::ip::address& addr) const noexcept {
                if (!addr.is_v4() || NULLPTR == dns_interceptor_) {
                    return addr;
                }

                std::shared_ptr<const dns::FakeIpPool> pool = dns_interceptor_->GetFakeIpPool();
                if (NULLPTR == pool || !pool->IsEnabled()) {
                    return addr;
                }

                const uint32_t fake_host = addr.to_v4().to_uint();
                const uint32_t real_host = pool->LookupRealIpHostOrder(fake_host);
                if (real_host == 0) {
                    return addr;
                }

                return boost::asio::ip::address_v4(real_host);
            }

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
            bool VEthernetNetworkSwitcher::ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept {
                return address_manager_->ApplyAssignedIPv6(extensions);
            }

            void VEthernetNetworkSwitcher::RestoreAssignedIPv6() noexcept {
                address_manager_->RestoreAssignedIPv6();
            }

            bool VEthernetNetworkSwitcher::ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept {
                return address_manager_->ApplyAssignedIPv4(extensions);
            }

            void VEthernetNetworkSwitcher::RestoreAssignedIPv4() noexcept {
                address_manager_->RestoreAssignedIPv4();
            }

#endif

            void VEthernetNetworkSwitcher::ClearPeerPrefixRoutes() noexcept {
                peer_prefix_routes_->Clear();
            }

            bool VEthernetNetworkSwitcher::ApplyPeerPrefixRoutes(const VirtualEthernetInformationExtensions& extensions) noexcept {
                return peer_prefix_routes_->Apply(extensions);
            }

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
                bool previous_assignment = HasManagedIPv6Assignment(*information_extensions_);
                bool current_assignment = HasManagedIPv6Assignment(extensions);
                if (address_manager_->Ipv6Applied() && (!previous_assignment || !current_assignment || !SameManagedIPv6Configuration(*information_extensions_, extensions))) {
                    RestoreAssignedIPv6();
                }

                *information_extensions_ = extensions;

                if (NULLPTR != dns_interceptor_) {
                    dns_interceptor_->OnSessionInfo(extensions, HasManagedIPv6Assignment(extensions));
                }

                bool valid_ipv6_assignment = HasManagedIPv6Assignment(extensions);
                if (!valid_ipv6_assignment && address_manager_->Ipv6Applied()) {
                    RestoreAssignedIPv6();
                }

                if (valid_ipv6_assignment &&
                    (extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Nat66 ||
                        extensions.AssignedIPv6Mode == VirtualEthernetInformationExtensions::IPv6Mode_Gua) &&
                    !address_manager_->Ipv6Applied()) {
                    ApplyAssignedIPv6(extensions);
                }

                // Apply server-assigned IPv4 address to TAP interface.
                {
                    const auto& ipv4 = extensions.ClientIPv4Assign;
                    if (ipv4.enabled && ipv4.accepted) {
                        if (!address_manager_->Ipv4Applied()) {
                            ApplyAssignedIPv4(extensions);
                        }
                    }
                    elif (address_manager_->Ipv4Applied()) {
                        RestoreAssignedIPv4();
                    }
                }
#else
                *information_extensions_ = extensions;

                if (NULLPTR != dns_interceptor_) {
                    dns_interceptor_->OnSessionInfo(extensions, HasManagedIPv6Assignment(extensions));
                }
#endif

                // Parse and log IPv4 assignment response from server.
                // The assignment is stored in information_extensions_ (already saved above)
                // and logged here for telemetry.  TAP application of the assigned IPv4
                // address is intentionally deferred to a future phase.
                if (extensions.ClientIPv4Assign.enabled) {
                    const auto& ipv4 = extensions.ClientIPv4Assign;
                    if (ipv4.accepted) {
                        ppp::telemetry::Count("client.ipv4.assigned", 1);
                        ppp::telemetry::Log(Level::kInfo, "client", "ipv4 assigned: %s/%s gw=%s (mode=%s conflict=%d)",
                            ipv4.address.c_str(), ipv4.mask.c_str(), ipv4.gateway.c_str(),
                            ipv4.mode.c_str(), static_cast<int>(ipv4.conflict));
                    }
                    else {
                        ppp::telemetry::Count("client.ipv4.rejected", 1);
                        ppp::telemetry::Log(Level::kInfo, "client", "ipv4 request rejected: reason=%s mode=%s",
                            ipv4.reason.c_str(), ipv4.mode.c_str());
                    }
                }

                if (extensions.P2P.HasAny()) {
                    const auto& p2p = extensions.P2P;
                    ppp::telemetry::Log(Level::kInfo, "p2p", "control action=%s mode=%s peer=%s candidates=%zu reason=%s",
                        p2p.action.c_str(),
                        p2p.mode.c_str(),
                        ppp::net::IPEndPoint::ToAddressString(p2p.peer_virtual_ip).c_str(),
                        p2p.candidates.size(),
                        p2p.reason.c_str());
                    ppp::telemetry::Count("p2p.control", 1);
                }

                if (extensions.PeerRouteTable.HasAny()) {
                    dynamic_peer_routes_ = extensions.PeerRouteTable.routes;
                    ApplyPeerPrefixRoutes(extensions);
                }
                elif (!configuration_->client.peer_routes.empty()) {
                    ApplyPeerPrefixRoutes(extensions);
                }

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
                if (!route_table_->AddAllRoute(tap)) {
                    return false;
                }

                return AddRemoteEndPointToIPList(Ipep::ToAddress(IPEndPoint::LoopbackAddress));
            }
#endif

            /** @brief Creates and configures static-mode aggligator instance. */
            bool VEthernetNetworkSwitcher::PreparedAggregator() noexcept {
                return aggregator_loader_->Prepare();
            }

            /** @brief Initializes switcher runtime components and opens all services. */
            bool VEthernetNetworkSwitcher::Open(const std::shared_ptr<ITap>& tap) noexcept {
                return connection_opener_->Open(tap);
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

            /** @brief Removes VPN route entries and restores system defaults. */
            void VEthernetNetworkSwitcher::DeleteRoute() noexcept {
                ClearPeerPrefixRoutes();
                route_table_->DeleteRoute();
                FixUnderlyingNgw();
                route_table_->DeleteRouteWithDnsServers();
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
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
            bool VEthernetNetworkSwitcher::AddLoadIPList(
                const ppp::string& path,
#if defined(_LINUX)
                const ppp::string& nic,
#endif
                const boost::asio::ip::address& gw,
                const ppp::string& url) noexcept {
                return bypass_loader_->AddLoadIPList(path,
#if defined(_LINUX)
                    nic,
#endif
                    gw, url);
            }

            bool VEthernetNetworkSwitcher::LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept {
                return bypass_loader_->LoadAllIPListWithFilePaths(gw);
            }
#endif

            bool VEthernetNetworkSwitcher::IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept {
                return bypass_loader_->IsBypassIpAddress(ip);
            }

            /** @brief Releases all runtime services, routes, and related resources. */
            void VEthernetNetworkSwitcher::ReleaseAllObjects() noexcept {
                teardown_->ReleaseAllObjects();
            }

            /** @brief Removes timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::DeleteTimeout(void* k) noexcept {
                return timeout_registry_->Delete(k);
            }

            /** @brief Registers timeout callback associated with a key. */
            bool VEthernetNetworkSwitcher::EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept {
                return timeout_registry_->Emplace(k, timeout);
            }

            /** @brief Loads DNS redirect rules from file or inline content. */
            bool VEthernetNetworkSwitcher::LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept {
                if (rules.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VEthernetNetworkSwitcherDnsRulesEmpty);
                }

                int events = 0;
                if (NULLPTR != dns_interceptor_) {
                    events = dns_interceptor_->LoadRules(rules, load_file_or_string);
                }

                if (1 > events) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigDnsRuleLoadFailed);
                }

                return true;
            }

            /** @brief Adds remote endpoints and static servers to route/bypass tables. */
            bool VEthernetNetworkSwitcher::AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept {
                return remote_endpoint_loader_->Apply(gw);
            }

            bool VEthernetNetworkSwitcher::StaticEchoAddRemoteEndPoint(
                boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                if (NULLPTR == exchanger_) {
                    return false;
                }
                return exchanger_->StaticEchoAddRemoteEndPoint(remoteEP);
            }

            /** @brief Entry point for DNS redirection decision and async execution. */
            dns::DnsHostPorts VEthernetNetworkSwitcher::BuildDnsHostPorts(
                const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {

                const auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
                auto datagram_output =
                    [self](const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destinationEP,
                        void* packet,
                        int packet_size,
                        bool caching) noexcept {
                        return self->DatagramOutput(
                            sourceEP, destinationEP, packet, packet_size, caching);
                    };

                dns::DnsHostPorts host;
                host.datagram_output = datagram_output;
                host.get_tap = [self]() noexcept { return self->GetTap(); };
                host.get_configuration = [self]() noexcept { return self->GetConfiguration(); };
                host.get_buffer_allocator = [self]() noexcept { return self->GetBufferAllocator(); };
                host.emplace_timeout =
                    [self](void* key,
                        const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& timeout) noexcept {
                        return self->EmplaceTimeout(key, timeout);
                    };
                host.delete_timeout = [self](void* key) noexcept { return self->DeleteTimeout(key); };
#if defined(_LINUX)
                host.get_protector_network = [self]() noexcept { return self->GetProtectorNetwork(); };
#endif
                host.handle_resolver_response =
                    [exchanger, datagram_output, self](
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destEP,
                        ppp::vector<Byte> response) noexcept {
                        dns::DnsResponseHandlerPorts ports;
                        const std::shared_ptr<ppp::configurations::AppConfiguration> configuration =
                            self->GetConfiguration();
                        if (NULLPTR != configuration && configuration->udp.dns.cache) {
                            ports.enable_dns_cache = true;
                            ports.write_cache =
                                [](const Byte* packet, int packet_size) noexcept {
                                    ppp::net::asio::vdns::AddCache(packet, packet_size);
                                };
                        }
                        ports.datagram_output = datagram_output;
                        if (NULLPTR != exchanger) {
                            ports.tunnel_send =
                                [exchanger](const boost::asio::ip::udp::endpoint& sourceEP,
                                    const boost::asio::ip::udp::endpoint& destinationEP,
                                    const void* packet,
                                    int packet_size) noexcept {
                                    return exchanger->SendTo(
                                        sourceEP, destinationEP, packet, packet_size);
                                };
                        }
                        dns::DnsResponseHandler::HandleWithPorts(
                            ports, messages, sourceEP, destEP, std::move(response));
                    };
                return host;
            }

            const dns::DnsHostPorts& VEthernetNetworkSwitcher::DnsHostPortsFor(
                const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {

#if !defined(_ANDROID) && !defined(_IPHONE)
                SynchronizedObjectScope scope(prdr_);
#else
                SynchronizedObjectScope scope(GetSynchronizedObject());
#endif

                if (std::shared_ptr<VEthernetExchanger> cached = dns_host_ports_exchanger_.lock();
                    cached == exchanger && NULLPTR != dns_host_ports_cache_ && dns_host_ports_cache_->IsValid()) {
                    ppp::telemetry::Log(Level::kDebug, "client", "dns_host_ports cache hit");
                    return *dns_host_ports_cache_;
                }

                if (NULLPTR == dns_host_ports_cache_) {
                    dns_host_ports_cache_ = std::make_unique<dns::DnsHostPorts>();
                }

                ppp::telemetry::Log(Level::kDebug, "client", "dns_host_ports cache rebuild");
                *dns_host_ports_cache_ = BuildDnsHostPorts(exchanger);
                dns_host_ports_exchanger_ = exchanger;
                return *dns_host_ports_cache_;
            }

            void VEthernetNetworkSwitcher::InvalidateDnsHostPorts() noexcept {
#if !defined(_ANDROID) && !defined(_IPHONE)
                SynchronizedObjectScope scope(prdr_);
#else
                SynchronizedObjectScope scope(GetSynchronizedObject());
#endif
                ppp::telemetry::Log(Level::kDebug, "client", "dns_host_ports cache invalidate");
                InvalidateDnsHostPortsLocked();
            }

            bool VEthernetNetworkSwitcher::RedirectDnsServer(
                const std::shared_ptr<VEthernetExchanger>& exchanger,
                const std::shared_ptr<IPFrame>& packet,
                const std::shared_ptr<UdpFrame>& frame,
                const std::shared_ptr<BufferSegment>& messages) noexcept {

                if (NULLPTR == dns_interceptor_) {
                    return false;
                }

                return dns_interceptor_->HandleQuery(
                    DnsHostPortsFor(exchanger),
                    exchanger, packet, frame, messages);
            }

            route::RouteHostPorts VEthernetNetworkSwitcher::BuildRouteHostPorts() noexcept {
                route::RouteHostPorts host;
#if !defined(_ANDROID) && !defined(_IPHONE)
                const auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
                host.get_tap = [self]() noexcept { return self->GetTap(); };
#if !defined(_ANDROID) && !defined(_IPHONE)
                host.get_tap_ni = [self]() noexcept { return self->GetTapNetworkInterface(); };
                host.get_underlying_ni = [self]() noexcept { return self->GetUnderlyingNetworkInterface(); };
#else
                host.get_tap_ni = []() noexcept { return std::shared_ptr<ClientNetworkInterface>(); };
                host.get_underlying_ni = []() noexcept { return std::shared_ptr<ClientNetworkInterface>(); };
#endif
                host.get_rib = [self]() noexcept { return self->GetRib(); };
                host.set_rib = [self](route::RouteInformationTablePtr rib) noexcept { self->rib_ = std::move(rib); };
                host.get_fib = [self]() noexcept { return self->GetFib(); };
                host.set_fib = [self](route::ForwardInformationTablePtr fib) noexcept { self->fib_ = std::move(fib); };
#if !defined(_ANDROID) && !defined(_IPHONE)
                host.get_route_added = [self]() noexcept { return self->route_added_; };
                host.set_route_added = [self](bool value) noexcept { self->route_added_ = value; };
                host.get_route_apply_ready = [self]() noexcept { return self->route_apply_ready_; };
                host.add_dns_server_ip =
                    [self](uint32_t ip, int bucket) noexcept {
                        if (bucket >= 0 && bucket < static_cast<int>(std::size(self->dns_serverss_))) {
                            self->dns_serverss_[bucket].emplace(ip);
                        }
                    };
                host.clear_dns_servers =
                    [self]() noexcept {
                        for (auto& dns_servers : self->dns_serverss_) {
                            dns_servers.clear();
                        }
                    };
                host.get_dns_server_bucket =
                    [self](int bucket) noexcept -> ppp::unordered_set<uint32_t>* {
                        if (bucket < 0 || bucket >= static_cast<int>(std::size(self->dns_serverss_))) {
                            return nullptr;
                        }
                        return &self->dns_serverss_[bucket];
                    };
                host.dedupe_dns_servers =
                    [self]() noexcept {
                        ppp::collections::Dictionary::DeduplicationList(self->dns_serverss_[1], self->dns_serverss_[0]);
                    };
                host.collect_dns_reachability =
                    [self]() noexcept {
                        if (NULLPTR == self->dns_interceptor_ || NULLPTR == self->configuration_) {
                            return;
                        }

                        self->dns_interceptor_->CollectReachabilityIps(
                            self->configuration_,
                            self->configuration_->dns.intercept_unmatched,
                            [self](uint32_t ip) noexcept { self->dns_serverss_[0].emplace(ip); },
                            [self](uint32_t ip) noexcept { self->dns_serverss_[1].emplace(ip); });
                    };
#else
                // Mobile route/DNS bookkeeping lives in RouteTableManager_mobile, not switcher members.
                host.get_route_added = []() noexcept { return false; };
                host.set_route_added = [](bool) noexcept {};
                host.get_route_apply_ready = []() noexcept { return true; };
                host.add_dns_server_ip = [](uint32_t, int) noexcept {};
                host.clear_dns_servers = []() noexcept {};
                host.get_dns_server_bucket = [](int) noexcept -> ppp::unordered_set<uint32_t>* { return nullptr; };
                host.dedupe_dns_servers = []() noexcept {};
                host.collect_dns_reachability = []() noexcept {};
#endif
                // ponytail: non-owning shared_ptr view; DnsInterceptor is owned by dns_interceptor_.
                // Upgrade path: store shared_ptr if callers need ownership past switcher teardown.
                host.get_dns_interceptor =
                    [self]() noexcept -> std::shared_ptr<dns::DnsInterceptor> {
                        if (NULLPTR == self->dns_interceptor_) {
                            return NULLPTR;
                        }
                        return std::shared_ptr<dns::DnsInterceptor>(
                            self->dns_interceptor_.get(),
                            [](dns::DnsInterceptor*) noexcept {});
                    };
                host.get_configuration = [self]() noexcept { return self->GetConfiguration(); };
#if defined(_LINUX)
                host.get_default_routes = [self]() noexcept { return self->default_routes_; };
                host.set_default_routes =
                    [self](route::RouteInformationTablePtr routes) noexcept { self->default_routes_ = std::move(routes); };
                host.get_nics = [self]() noexcept { return &self->nics_; };
#else
                // default_routes_/nics_ back only the linux route backend; other platforms keep
                // these ports valid with empty stand-ins because their route managers never call them.
                host.get_default_routes = []() noexcept { return route::RouteInformationTablePtr(); };
                host.set_default_routes = [](route::RouteInformationTablePtr) noexcept {};
                host.get_nics = []() noexcept -> ppp::unordered_map<uint32_t, ppp::string>* {
                    static ppp::unordered_map<uint32_t, ppp::string> empty_nics;
                    return &empty_nics;
                };
#endif // _LINUX vs other desktops
#endif // !_ANDROID && !_IPHONE: mobile uses RouteTableManager_mobile, no route-ports consumer
                return host;
            }

#if !defined(_ANDROID) && !defined(_IPHONE)
            void VEthernetNetworkSwitcher::AddRoute() noexcept {
                route_table_->AddRoute();
            }
#endif

            /** @brief Gets current static mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::StaticMode(bool* static_mode) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool snow = static_mode_;
                if (NULLPTR != static_mode) {
                    static_mode_ = *static_mode;
                }

                return snow;
            }

            /** @brief Gets current proxy-only mode and optionally updates it. */
            bool VEthernetNetworkSwitcher::ProxyOnly(bool* proxy_only) noexcept {
                SynchronizedObjectScope scope(GetSynchronizedObject());
                bool previous = proxy_only_;
                if (NULLPTR != proxy_only) {
                    proxy_only_ = *proxy_only;
                }

                return previous;
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
