#pragma once

/**
 * @file VEthernetNetworkSwitcher.h
 * @brief Client-side virtual Ethernet network switcher declarations.
 *
 * Top-level client runtime coordinator: TAP/TUN, remote session, proxies, routing,
 * DNS redirection, and ICMP handling. All callbacks run on the owning io_context strand.
 */

namespace ppp::configurations { class AppConfiguration; }
namespace aggligator { class aggligator; }
namespace ppp::transmissions {
    class ITransmissionQoS;
    class ITransmissionStatistics;
    namespace proxys { class IForwarding; }
}
#if defined(__linux__)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

#include <ppp/net/packet/IPFrame.h>
#include <ppp/ethernet/VEthernet.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/ClientNetworkInterface.h>
#include <ppp/net/native/rib.h>
#include <memory>

#if defined(_WIN32)
struct _MIB_IPFORWARDROW;
typedef struct _MIB_IPFORWARDROW MIB_IPFORWARDROW;
#endif

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetDatagramPort;
            class RouteTableManager;
            class AssignedAddressManager;
            class ClientConnectionTeardown;
            class ClientConnectionOpener;
            class ClientPacketDispatchHandler;
            class ClientBypassRouteLoader;
            class QuicRejectRateLimiter;
            class PeerPrefixRouteManager;
            class RemoteEndpointLoader;
            class SwitcherTimeoutRegistry;

            namespace dns {
                class DnsResponseHandler;
                class DnsUdpRelay;
                class DnsInterceptor;
                struct DnsHostPorts;
            }

            namespace proxys {
                class VEthernetHttpProxySwitcher;
                class VEthernetSocksProxySwitcher;
            }

#if defined(_WIN32)
            namespace lsp { class PaperAirplaneController; }
#endif

            /**
             * @brief Top-level client runtime coordinating TAP, session, proxies, routing, and DNS.
             */
            class VEthernetNetworkSwitcher : public ppp::ethernet::VEthernet {
            private:
                friend class VEthernetExchanger;
                friend class VEthernetDatagramPort;
                friend class RouteTableManager;
                friend class AssignedAddressManager;
                friend class ClientConnectionTeardown;
                friend class ClientConnectionOpener;
                friend class ClientPacketDispatchHandler;
                friend class ClientBypassRouteLoader;
                friend class PeerPrefixRouteManager;
                friend class RemoteEndpointLoader;
                friend struct ExchangerStaticEchoDetail;
                friend class VEthernetNetworkTcpipStack;
                friend dns::DnsHostPorts dns::MakeDnsHostPorts(
                    const std::shared_ptr<VEthernetNetworkSwitcher>& self,
                    const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

            private:
                typedef struct {
                    UInt64                                                          datetime;
                    IPFrame::IPFramePtr                                             packet;
                }                                                                   VEthernetIcmpPacket;

                typedef ppp::unordered_map<int, VEthernetIcmpPacket>                VEthernetIcmpPacketTable;
                typedef ppp::threading::Timer                                       Timer;
                typedef ppp::vector<std::pair<ppp::string, uint32_t>/**/>           LoadIPListFileVector;
                typedef std::shared_ptr<LoadIPListFileVector>                       LoadIPListFileVectorPtr;
                typedef ppp::vector<boost::asio::ip::address>                       NicDnsServerAddresses;
                typedef ppp::unordered_map<int, NicDnsServerAddresses>              AllNicDnsServerAddresses;
                typedef std::shared_ptr<ppp::transmissions::proxys::IForwarding>      IForwardingPtr;

            public:
                typedef ClientNetworkInterface                                        NetworkInterface;
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions    VirtualEthernetInformationExtensions;
                typedef proxys::VEthernetHttpProxySwitcher                          VEthernetHttpProxySwitcher;
                typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;
                typedef proxys::VEthernetSocksProxySwitcher                         VEthernetSocksProxySwitcher;
                typedef std::shared_ptr<VEthernetSocksProxySwitcher>                VEthernetSocksProxySwitcherPtr;
                typedef ppp::function<void(VEthernetNetworkSwitcher*, UInt64)>      VEthernetTickEventHandler;
                typedef ppp::transmissions::ITransmissionStatistics                   ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                    ITransmissionStatisticsPtr;
                typedef ppp::net::native::RouteInformationTable                     RouteInformationTable;
                typedef std::shared_ptr<RouteInformationTable>                      RouteInformationTablePtr;
                typedef ppp::net::native::ForwardInformationTable                   ForwardInformationTable;
                typedef std::shared_ptr<ForwardInformationTable>                    ForwardInformationTablePtr;
                typedef ppp::unordered_map<ppp::string, ppp::string>                RouteIPListTable;
                typedef std::shared_ptr<RouteIPListTable>                           RouteIPListTablePtr;

#if defined(_WIN32)
                typedef lsp::PaperAirplaneController                                PaperAirplaneController;
                typedef std::shared_ptr<PaperAirplaneController>                    PaperAirplaneControllerPtr;
#elif defined(_LINUX)
                typedef ppp::net::ProtectorNetwork                                    ProtectorNetwork;
                typedef std::shared_ptr<ProtectorNetwork>                           ProtectorNetworkPtr;
#endif

                VEthernetTickEventHandler                                           TickEvent;

            public:
                VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;
                VEthernetNetworkSwitcher(const VEthernetNetworkSwitcher&) = delete;
                VEthernetNetworkSwitcher& operator=(const VEthernetNetworkSwitcher&) = delete;
                VEthernetNetworkSwitcher(VEthernetNetworkSwitcher&&) = delete;
                VEthernetNetworkSwitcher& operator=(VEthernetNetworkSwitcher&&) = delete;
                virtual ~VEthernetNetworkSwitcher() noexcept;

#if defined(_WIN32)
                PaperAirplaneControllerPtr                                          GetPaperAirplaneController() noexcept { return paper_airplane_ctrl_; }
                virtual bool                                                        SetHttpProxyToSystemEnv()    noexcept;
                virtual bool                                                        ClearHttpProxyToSystemEnv()  noexcept;
#elif defined(_LINUX)
                ProtectorNetworkPtr                                                 GetProtectorNetwork()        noexcept { return protect_network_; }
#endif

                std::shared_ptr<ppp::configurations::AppConfiguration>              GetConfiguration()           noexcept { return configuration_; }
                std::shared_ptr<VEthernetExchanger>                                 GetExchanger()               noexcept { return exchanger_; }
                void                                                                RequestedIPv6(const ppp::string& value) noexcept { requested_ipv6_ = value; }
                ppp::string                                                         RequestedIPv6() noexcept { return requested_ipv6_; }
#if !defined(_ANDROID) && !defined(_IPHONE)
                boost::asio::ip::address                                            LastAssignedIPv6() noexcept;
#else
                boost::asio::ip::address                                            LastAssignedIPv6() noexcept { return {}; }
#endif
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>               GetQoS()                     noexcept { return qos_; }
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>          GetStatistics()              noexcept { return statistics_; }
                std::shared_ptr<VirtualEthernetInformation>                         GetInformation()             noexcept;
                VirtualEthernetInformationExtensions                                GetInformationExtensions()   noexcept { return information_extensions_; }
                VEthernetHttpProxySwitcherPtr                                       GetHttpProxy()               noexcept { return http_proxy_; }
                VEthernetSocksProxySwitcherPtr                                      GetSocksProxy()              noexcept { return socks_proxy_; }
                RouteInformationTablePtr                                            GetRib()                     noexcept { return rib_; }
                ForwardInformationTablePtr                                          GetFib()                     noexcept { return fib_; }
                IForwardingPtr                                                      GetForwarding()              noexcept { return forwarding_; }
                std::shared_ptr<aggligator::aggligator>                             GetAggligator()              noexcept { return aggligator_; }
                RouteIPListTablePtr                                                 GetVbgp()                    noexcept { return vbgp_; }
                bool                                                                IsBlockQUIC()                noexcept { return block_quic_; }
                bool                                                                IsMuxEnabled()               noexcept { return mux_ > 0; }
                bool                                                                IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept;

                virtual bool                                                        LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept;
                bool                                                                StaticMode(bool* static_mode) noexcept;
                bool                                                                ProxyOnly(bool* proxy_only) noexcept;
                uint16_t                                                            Mux(uint16_t* mux) noexcept;
                uint8_t                                                             MuxAcceleration(uint8_t* mux_acceleration) noexcept;

#if defined(_ANDROID) || defined(_IPHONE)
                void                                                                SetBypassIpList(ppp::string&& bypass_ip_list) noexcept;
#else
#if defined(_LINUX)
                bool                                                                ProtectMode(bool* protect_mode) noexcept;
#endif
                std::shared_ptr<ClientNetworkInterface>                             GetTapNetworkInterface()        noexcept { return tun_ni_; }
                std::shared_ptr<ClientNetworkInterface>                             GetUnderlyingNetworkInterface() noexcept { return underlying_ni_; }
                virtual void                                                        PreferredNgw(const boost::asio::ip::address& gw) noexcept;
                virtual void                                                        PreferredNic(const ppp::string& nic) noexcept;
                virtual bool                                                        AddLoadIPList(
                    const ppp::string&                                              path,
#if defined(_LINUX)
                    const ppp::string&                                              nic,
#endif
                    const boost::asio::ip::address&                                 gw,
                    const ppp::string&                                              url) noexcept;
                virtual ppp::string                                                 GetRemoteUri() noexcept;
#endif

                virtual bool                                                        Open(const std::shared_ptr<ITap>& tap) noexcept override;
                virtual void                                                        Dispose() noexcept override;
                virtual std::shared_ptr<ppp::threading::BufferswapAllocator>        GetBufferAllocator() noexcept override;
                virtual bool                                                        BlockQUIC(bool value) noexcept;

            protected:
                virtual bool                                                        OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept override;
                virtual bool                                                        OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept override;
                virtual bool                                                        OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept override;
                virtual bool                                                        OnTick(uint64_t now) noexcept override;
                virtual bool                                                        OnUpdate(uint64_t now) noexcept override;
                virtual bool                                                        OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information) noexcept;
                virtual bool                                                        OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information, const VirtualEthernetInformationExtensions& extensions) noexcept;
                bool                                                                ApplyPeerPrefixRoutes(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                ClearPeerPrefixRoutes() noexcept;

                virtual std::shared_ptr<VEthernetExchanger>                         NewExchanger() noexcept;
                virtual std::shared_ptr<ppp::ethernet::VNetstack>                   NewNetstack() noexcept override;
                virtual VEthernetHttpProxySwitcherPtr                               NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                virtual VEthernetSocksProxySwitcherPtr                              NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                virtual std::shared_ptr<ppp::transmissions::ITransmissionQoS>         NewQoS() noexcept;
                virtual ITransmissionStatisticsPtr                                  NewStatistics() noexcept;

#if defined(_WIN32)
                virtual PaperAirplaneControllerPtr                                  NewPaperAirplaneController() noexcept;
#elif defined(_LINUX)
                virtual ProtectorNetworkPtr                                         NewProtectorNetwork() noexcept;
#endif

                virtual bool                                                        DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching = true) noexcept;
                boost::asio::ip::address                                           RewriteFakeIpAddress(const boost::asio::ip::address& addr) const noexcept;

            private:
#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                FixUnderlyingNgw() noexcept;
                void                                                                DeleteRoute() noexcept;
#else
                bool                                                                AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept;
#endif

                bool                                                                RedirectDnsServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;
                const dns::DnsHostPorts&                                            DnsHostPortsFor(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                void                                                                InvalidateDnsHostPorts() noexcept;
                bool                                                                EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept;
                bool                                                                DeleteTimeout(void* k) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                TryApplyHostedNetworkRoutes() noexcept;
#else
                bool                                                                TryApplyHostedNetworkRoutes() noexcept { return true; }
#endif

                void                                                                ReleaseAllObjects() noexcept;
                void                                                                ReleaseAllPackets() noexcept;
                void                                                                ReleaseAllTimeouts() noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
#if defined(_WIN32)
                bool                                                                UsePaperAirplaneController() noexcept;
#endif
                bool                                                                LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif

                void                                                                Finalize() noexcept;
                bool                                                                AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept;
                bool                                                                StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
                bool                                                                ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv6() noexcept;
                bool                                                                ApplyAssignedIPv4(const VirtualEthernetInformationExtensions& extensions) noexcept;
                void                                                                RestoreAssignedIPv4() noexcept;
#endif

                bool                                                                ERORTE(int ack_id) noexcept;
                bool                                                                PreparedAggregator() noexcept;
                bool                                                                IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept { return ip == gw ? true : htonl((ntohl(gw) & ntohl(mask)) + 1) == ip; }

            private:
                std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                ppp::string                                                         requested_ipv6_;
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>                 qos_;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>          statistics_;
                VEthernetIcmpPacketTable                                            icmppackets_;
                std::unique_ptr<QuicRejectRateLimiter>                              quic_reject_limiter_;
                struct {
                    int                                                             icmppackets_aid_  = 0;
                    bool                                                            block_quic_       = false;
                    bool                                                            static_mode_      = false;
                    bool                                                            proxy_only_       = false;
                    uint16_t                                                        mux_              = 0;
                    uint8_t                                                         mux_acceleration_ = 0;
                };
                VEthernetHttpProxySwitcherPtr                                       http_proxy_;
                VEthernetSocksProxySwitcherPtr                                      socks_proxy_;
                std::unique_ptr<SwitcherTimeoutRegistry>                            timeout_registry_;
                std::unique_ptr<dns::DnsInterceptor>                                dns_interceptor_;
                RouteInformationTablePtr                                            rib_;
                ForwardInformationTablePtr                                          fib_;
                RouteInformationTablePtr                                            peer_prefix_rib_;
                ForwardInformationTablePtr                                          peer_prefix_fib_;
                RouteIPListTablePtr                                                 vbgp_;
                ppp::string                                                         server_ru_;
                std::shared_ptr<aggligator::aggligator>                             aggligator_;
                IForwardingPtr                                                      forwarding_;
                VirtualEthernetInformationExtensions                                information_extensions_;
                ppp::vector<ppp::app::protocol::PeerPrefixRouteEntry>               dynamic_peer_routes_;
                ppp::vector<net::native::RouteEntry>                                applied_peer_prefix_routes_;

#if !defined(_ANDROID) && !defined(_IPHONE)
                SynchronizedObject                                                  prdr_;
#if defined(_LINUX)
                bool                                                                protect_mode_  = false;
                ppp::unordered_map<uint32_t, ppp::string>                           nics_;
#endif
#endif

#if defined(_LINUX)
                ProtectorNetworkPtr                                                 protect_network_;
#endif

#if defined(_ANDROID) || defined(_IPHONE)
                ppp::string                                                         bypass_ip_list_;
#else
                bool                                                                route_added_   = false;
                bool                                                                route_apply_ready_ = false;
                LoadIPListFileVectorPtr                                             ribs_;
                std::shared_ptr<ClientNetworkInterface>                             tun_ni_;
                std::shared_ptr<ClientNetworkInterface>                             underlying_ni_;
                ppp::string                                                         preferred_nic_;
                boost::asio::ip::address                                            preferred_ngw_;
                ppp::unordered_set<uint32_t>                                        dns_serverss_[3];

#if defined(_WIN32)
                PaperAirplaneControllerPtr                                          paper_airplane_ctrl_;
                ppp::vector<MIB_IPFORWARDROW>                                       default_routes_;
                AllNicDnsServerAddresses                                            ni_dns_servers_;
#elif defined(_LINUX)
                ppp::string                                                         ni_dns_servers_;
                RouteInformationTablePtr                                            default_routes_;
#endif
#endif
                std::unique_ptr<RouteTableManager>                                  route_table_;
                std::unique_ptr<AssignedAddressManager>                             address_manager_;
                std::unique_ptr<ClientConnectionTeardown>                           teardown_;
                std::unique_ptr<ClientConnectionOpener>                           connection_opener_;
                std::unique_ptr<ClientPacketDispatchHandler>                        packet_dispatch_;
                std::unique_ptr<ClientBypassRouteLoader>                          bypass_loader_;
                std::unique_ptr<PeerPrefixRouteManager>                         peer_prefix_routes_;
                std::unique_ptr<RemoteEndpointLoader>                           remote_endpoint_loader_;
                std::unique_ptr<dns::DnsHostPorts>                                  dns_host_ports_cache_;
                std::weak_ptr<VEthernetExchanger>                                 dns_host_ports_exchanger_;
            };
        }
    }
}
