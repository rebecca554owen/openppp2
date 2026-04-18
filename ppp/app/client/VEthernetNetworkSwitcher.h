 #pragma once

/**
 * @file VEthernetNetworkSwitcher.h
 * @brief Client-side virtual Ethernet network switcher declarations.
 * @details Licensed under GPL-3.0.
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <ppp/net/native/rib.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/ethernet/VEthernet.h>
#include <ppp/ethernet/VNetstack.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <ppp/transmissions/ITransmissionStatistics.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/dns/Rule.h>
#include <ppp/app/client/proxys/VEthernetHttpProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>

#if defined(_WIN32)
#include <windows/ppp/win32/network/Router.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#include <windows/ppp/app/client/lsp/PaperAirplaneController.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

#include <common/aggligator/aggligator.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetDatagramPort;

            /**
             * @brief Virtual Ethernet client switcher coordinating local and remote paths.
             */
            class VEthernetNetworkSwitcher : public ppp::ethernet::VEthernet {
            private:
                friend class                                                        VEthernetExchanger;
                friend class                                                        VEthernetDatagramPort;

            private:    
                /** @brief Cached ICMP probe packet record with expiration time. */
                typedef struct {    
                    UInt64                                                          datetime;
                    IPFrame::IPFramePtr                                             packet;
                }                                                                   VEthernetIcmpPacket;
                typedef ppp::unordered_map<int, VEthernetIcmpPacket>                VEthernetIcmpPacketTable;
                typedef ppp::app::client::dns::Rule::Ptr                            DNSRulePtr;
                typedef ppp::unordered_map<ppp::string, DNSRulePtr>                 DNSRuleTable;
                typedef ppp::threading::Timer                                       Timer;
                typedef Timer::TimeoutEventHandlerPtr                                TimeoutEventHandlerPtr;
                typedef ppp::unordered_map<void*, TimeoutEventHandlerPtr>            TimeoutEventHandlerTable;
                typedef ppp::vector<std::pair<ppp::string, uint32_t>/**/>           LoadIPListFileVector;
                typedef std::shared_ptr<LoadIPListFileVector>                       LoadIPListFileVectorPtr;
                typedef ppp::vector<boost::asio::ip::address>                       NicDnsServerAddresses;
                typedef ppp::unordered_map<int, NicDnsServerAddresses>              AllNicDnsServerAddresses;
                typedef ppp::transmissions::proxys::IForwarding                     IForwarding;
                typedef std::shared_ptr<IForwarding>                                IForwardingPtr;

            public: 
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions    VirtualEthernetInformationExtensions;
                typedef ppp::app::client::proxys::VEthernetHttpProxySwitcher        VEthernetHttpProxySwitcher;
                typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;
                typedef ppp::app::client::proxys::VEthernetSocksProxySwitcher       VEthernetSocksProxySwitcher;
                typedef std::shared_ptr<VEthernetSocksProxySwitcher>                VEthernetSocksProxySwitcherPtr;
                typedef ppp::function<void(VEthernetNetworkSwitcher*, UInt64)>      VEthernetTickEventHandler;
                typedef ppp::transmissions::ITransmissionStatistics                 ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                    ITransmissionStatisticsPtr;
                using IPv6AppliedState                                              = ppp::ipv6::auxiliary::ClientState;
                /** @brief Network interface snapshot used by route and DNS operations. */
                class NetworkInterface {    
                public: 
                    ppp::string                                                     Name;
#if !defined(_MACOS)    
                    ppp::string                                                     Id;
#endif  
                    int                                                             Index = -1;
                    ppp::vector<boost::asio::ip::address>                           DnsAddresses;

                public: 
                    /** @brief Initializes interface metadata defaults. */
                    NetworkInterface() noexcept;    
                    /** @brief Destroys interface snapshot object. */
                    virtual ~NetworkInterface() noexcept = default;

                public: 
                    boost::asio::ip::address                                        IPAddress;
                    boost::asio::ip::address                                        GatewayServer;
                    boost::asio::ip::address                                        SubmaskAddress;

#if defined(_WIN32) 
                public: 
                    ppp::string                                                     Description;
#elif defined(_MACOS)   
                    ppp::unordered_map<uint32_t, uint32_t>                          DefaultRoutes;
#endif  
                };
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
                typedef ppp::net::ProtectorNetwork                                  ProtectorNetwork;
                typedef std::shared_ptr<ProtectorNetwork>                           ProtectorNetworkPtr;
#endif

            public: 
                /** @brief Optional periodic tick callback invoked by switcher. */
                VEthernetTickEventHandler                                           TickEvent;

            public:
                /** @brief Constructs a virtual Ethernet network switcher instance. */
                VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;
                /** @brief Destroys switcher and releases resources. */
                virtual ~VEthernetNetworkSwitcher() noexcept;

            public:
#if defined(_WIN32)
                /** @brief Gets optional Windows PaperAirplane controller. */
                PaperAirplaneControllerPtr                                          GetPaperAirplaneController() noexcept { return paper_airplane_ctrl_; }
                /** @brief Applies local HTTP proxy endpoint to system proxy settings. */
                virtual bool                                                        SetHttpProxyToSystemEnv()    noexcept;
                /** @brief Clears system HTTP proxy settings applied by switcher. */
                virtual bool                                                        ClearHttpProxyToSystemEnv()  noexcept;
#elif defined(_LINUX)   
                /** @brief Gets optional network protector used on Linux platforms. */
                ProtectorNetworkPtr                                                 GetProtectorNetwork()        noexcept { return protect_network_; }
#endif  
                /** @brief Gets switcher runtime configuration. */
                std::shared_ptr<ppp::configurations::AppConfiguration>              GetConfiguration()           noexcept { return configuration_; }
                /** @brief Gets remote exchanger associated with this switcher. */
                std::shared_ptr<VEthernetExchanger>                                 GetExchanger()               noexcept { return exchanger_; }
                /** @brief Sets preferred IPv6 address requested from server. */
                void                                                                RequestedIPv6(const ppp::string& value) noexcept { requested_ipv6_ = value; }
                /** @brief Gets preferred IPv6 address requested from server. */
                ppp::string                                                         RequestedIPv6() noexcept { return requested_ipv6_; }
                /** @brief Gets QoS controller used by transport channels. */
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>               GetQoS()                     noexcept { return qos_; }
                /** @brief Gets traffic statistics collector. */
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>        GetStatistics()              noexcept { return statistics_; }
                /** @brief Gets latest server information from exchanger. */
                std::shared_ptr<VirtualEthernetInformation>                         GetInformation()             noexcept;
                /** @brief Gets last received information extensions. */
                VirtualEthernetInformationExtensions                                GetInformationExtensions()   noexcept { return information_extensions_; }
                /** @brief Gets local HTTP proxy switcher. */
                VEthernetHttpProxySwitcherPtr                                       GetHttpProxy()               noexcept { return http_proxy_; }
                /** @brief Gets local SOCKS proxy switcher. */
                VEthernetSocksProxySwitcherPtr                                      GetSocksProxy()              noexcept { return socks_proxy_; }
                /** @brief Gets loaded route information base. */
                RouteInformationTablePtr                                            GetRib()                     noexcept { return rib_; }
                /** @brief Gets loaded forwarding information base. */
                ForwardInformationTablePtr                                          GetFib()                     noexcept { return fib_; }
                /** @brief Gets optional proxy-forwarding helper. */
                IForwardingPtr                                                      GetForwarding()              noexcept { return forwarding_; }
                /** @brief Gets optional static-mode bandwidth aggligator. */
                std::shared_ptr<aggligator::aggligator>                             GetAggligator()              noexcept { return aggligator_; }
                /** @brief Gets vBGP URL mapping table. */
                RouteIPListTablePtr                                                 GetVbgp()                    noexcept { return vbgp_; }
                /** @brief Returns whether outbound QUIC is blocked. */
                bool                                                                IsBlockQUIC()                noexcept { return block_quic_; }
                /** @brief Returns whether mux mode is enabled. */
                bool                                                                IsMuxEnabled()               noexcept { return mux_ > 0; }
                /** @brief Checks whether IP should bypass VPN route path. */
                bool                                                                IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept;

            public: 
                /** @brief Loads DNS rules from file path or inline rule text. */
                virtual bool                                                        LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept;
                /** @brief Gets or sets static transmission mode. */
                bool                                                                StaticMode(bool* static_mode) noexcept;
                /** @brief Gets or sets mux connection count. */
                uint16_t                                                            Mux(uint16_t* mux) noexcept;
                /** @brief Gets or sets mux acceleration flags. */
                uint8_t                                                             MuxAcceleration(uint8_t* mux_acceleration) noexcept;

#if defined(_ANDROID) || defined(_IPHONE)   
                /** @brief Sets bypass IP-list text used on mobile platforms. */
                void                                                                SetBypassIpList(ppp::string&& bypass_ip_list) noexcept;
#else   
#if defined(_LINUX)
                /** @brief Gets or sets Linux protect mode state. */
                bool                                                                ProtectMode(bool* protect_mode) noexcept;
#endif
                /** @brief Gets TAP-side network interface snapshot. */
                std::shared_ptr<NetworkInterface>                                   GetTapNetworkInterface()        noexcept { return tun_ni_; }
                /** @brief Gets underlying physical network interface snapshot. */
                std::shared_ptr<NetworkInterface>                                   GetUnderlyingNetworkInterface() noexcept { return underlying_ni_; }
                /** @brief Sets preferred physical gateway for route operations. */
                virtual void                                                        PreferredNgw(const boost::asio::ip::address& gw) noexcept;
                /** @brief Sets preferred physical NIC name for interface selection. */
                virtual void                                                        PreferredNic(const ppp::string& nic) noexcept;
                /** @brief Registers one IP-list source for route loading. */
                virtual bool                                                        AddLoadIPList(
                    const ppp::string&                                              path, 
#if defined(_LINUX) 
                    const ppp::string&                                              nic,
#endif  
                    const boost::asio::ip::address&                                 gw,
                    const ppp::string&                                              url) noexcept;
                /** @brief Gets formatted remote server URI string. */
                virtual ppp::string                                                 GetRemoteUri() noexcept;
#endif  
            public: 
                /** @brief Opens switcher and initializes all runtime services. */
                virtual bool                                                        Open(const std::shared_ptr<ITap>& tap) noexcept override;
                /** @brief Disposes switcher and releases runtime services. */
                virtual void                                                        Dispose() noexcept override;
                /** @brief Returns active buffer allocator. */
                virtual std::shared_ptr<ppp::threading::BufferswapAllocator>        GetBufferAllocator() noexcept override;
                /** @brief Enables or disables outgoing QUIC blocking. */
                virtual bool                                                        BlockQUIC(bool value) noexcept;

            protected:  
                /** @brief Handles IPv4 native packet input path. */
                virtual bool                                                        OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept override;
                /** @brief Handles raw IPv6 packet input path. */
                virtual bool                                                        OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept override;
                /** @brief Handles parsed IP frame input path. */
                virtual bool                                                        OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept override;
                /** @brief Handles periodic tick event. */
                virtual bool                                                        OnTick(uint64_t now) noexcept override;
                /** @brief Handles periodic update event. */
                virtual bool                                                        OnUpdate(uint64_t now) noexcept override;
                /** @brief Handles information callback without extensions. */
                virtual bool                                                        OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information) noexcept;
                /** @brief Handles information callback with extensions. */
                virtual bool                                                        OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information, const VirtualEthernetInformationExtensions& extensions) noexcept;

            protected:  
                /** @brief Creates exchanger instance for this switcher. */
                virtual std::shared_ptr<VEthernetExchanger>                         NewExchanger() noexcept;
                /** @brief Creates TCP/IP netstack implementation. */
                virtual std::shared_ptr<ppp::ethernet::VNetstack>                   NewNetstack() noexcept override;
                /** @brief Creates local HTTP proxy switcher. */
                virtual VEthernetHttpProxySwitcherPtr                               NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                /** @brief Creates local SOCKS proxy switcher. */
                virtual VEthernetSocksProxySwitcherPtr                              NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                /** @brief Creates QoS controller instance. */
                virtual std::shared_ptr<ppp::transmissions::ITransmissionQoS>       NewQoS() noexcept;
                /** @brief Creates transmission statistics collector. */
                virtual ITransmissionStatisticsPtr                                  NewStatistics() noexcept;
#if defined(_WIN32) 
                /** @brief Creates Windows PaperAirplane controller. */
                virtual PaperAirplaneControllerPtr                                  NewPaperAirplaneController() noexcept;
#elif defined(_LINUX)   
                /** @brief Creates Linux network protector. */
                virtual ProtectorNetworkPtr                                         NewProtectorNetwork() noexcept;
#endif  
                /** @brief Emits UDP payload back to local virtual network. */
                virtual bool                                                        DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching = true) noexcept;

            protected:  
#if !defined(_ANDROID) && !defined(_IPHONE)     
                /** @brief Installs VPN routes into host operating system. */
                virtual void                                                        AddRoute() noexcept;
                /** @brief Removes VPN routes from host operating system. */
                virtual void                                                        DeleteRoute() noexcept;
#endif  
                /** @brief Handles UDP frame input processing. */
                virtual bool                                                        OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;
                /** @brief Handles ICMP frame input processing. */
                virtual bool                                                        OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;

            private:    
#if !defined(_ANDROID) && !defined(_IPHONE) 
                /** @brief Attempts to repair underlying NIC default gateway route. */
                bool                                                                FixUnderlyingNgw() noexcept;
                /** @brief Deletes all default routes conflicting with VPN gateway. */
                bool                                                                DeleteAllDefaultRoute() noexcept;
#else   
                /** @brief Builds mobile route table for VPN and bypass handling. */
                bool                                                                AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept;
#endif  

            private:
                /** @brief Validates whether IPv6 packet is allowed for forwarding. */
                bool                                                                IsApprovedIPv6Packet(Byte* packet, int packet_length) noexcept;
                /** @brief Redirects DNS packet based on rules and resolver strategy. */
                bool                                                                RedirectDnsServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;
                /** @brief Coroutine implementation of DNS redirection exchange. */
                bool                                                                RedirectDnsServer(
                    ppp::coroutines::YieldContext&                                  y,
                    const std::shared_ptr<boost::asio::ip::udp::socket>&            socket,
                    const std::shared_ptr<Byte>&                                    buffer,
                    const boost::asio::ip::address&                                 serverIP,
                    const std::shared_ptr<UdpFrame>&                                frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>&         messages,
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const boost::asio::ip::address&                                 destinationIP) noexcept;
                /** @brief Registers timeout callback by opaque key. */
                bool                                                                EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept;
                /** @brief Removes timeout callback by opaque key. */
                bool                                                                DeleteTimeout(void* k) noexcept;

            private:
                /** @brief Releases all managed runtime objects. */
                void                                                                ReleaseAllObjects() noexcept;
                /** @brief Clears all pending ICMP packet tracking records. */
                void                                                                ReleaseAllPackets() noexcept;
                /** @brief Stops and clears all timeout handlers. */
                void                                                                ReleaseAllTimeouts() noexcept;

            private:    
#if !defined(_ANDROID) && !defined(_IPHONE)     
#if defined(_WIN32) 
                /** @brief Starts optional PaperAirplane helper on Windows. */
                bool                                                                UsePaperAirplaneController() noexcept;
#endif  
                /** @brief Adds route entries for DNS server exceptions. */
                void                                                                AddRouteWithDnsServers() noexcept;
                /** @brief Removes route entries for DNS server exceptions. */
                void                                                                DeleteRouteWithDnsServers() noexcept;
                /** @brief Adds one host route into operating system table. */
                bool                                                                AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;
#if defined(_WIN32) 
                /** @brief Deletes one host route from Windows table snapshot. */
                bool                                                                DeleteRoute(const std::shared_ptr<MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept;
#else   
                /** @brief Deletes one host route from Unix route table. */
                bool                                                                DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;
#endif  
                /** @brief Starts default-route guard worker. */
                bool                                                                ProtectDefaultRoute() noexcept;
                /** @brief Loads all configured IP-list files into RIB. */
                bool                                                                LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif
                /** @brief Finalizes switcher release sequence. */
                void                                                                Finalize() noexcept;
                /** @brief Adds remote server endpoint to bypass/route tables. */
                bool                                                                AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept;
                
            private:    
                /** @brief Applies server-assigned managed IPv6 configuration. */
                bool                                                                ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept;
                /** @brief Restores original IPv6 configuration if previously applied. */
                void                                                                RestoreAssignedIPv6() noexcept;

            private:    
                /** @brief Emits ICMP Echo Reply or equivalent response. */
                bool                                                                ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                /** @brief Emits ICMP Time Exceeded response. */
                bool                                                                TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                /** @brief Processes ICMP ACK callback from remote echo path. */
                bool                                                                ERORTE(int ack_id) noexcept;
                
            private:
                /** @brief Prepares optional static-mode traffic aggligator. */
                bool                                                                PreparedAggregator() noexcept;
                /** @brief Checks whether destination IP matches local gateway semantics. */
                bool                                                                IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept { return ip == gw ? true : htonl((ntohl(gw) & ntohl(mask)) + 1) == ip; }
                /** @brief Handles ICMP forwarding for non-gateway targets. */
                bool                                                                EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                /** @brief Handles ICMP forwarding targeted at gateway semantics. */
                bool                                                                EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

            private:
                std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                ppp::string                                                         requested_ipv6_;
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>               qos_;
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>        statistics_;
                VEthernetIcmpPacketTable                                            icmppackets_;
                struct {
                    int                                                             icmppackets_aid_  = 0;
                    bool                                                            block_quic_       = false;
                    bool                                                            static_mode_      = false;
                    uint16_t                                                        mux_              = 0;
                    uint8_t                                                         mux_acceleration_ = 0;
                };
                VEthernetHttpProxySwitcherPtr                                       http_proxy_;
                VEthernetSocksProxySwitcherPtr                                      socks_proxy_;
                TimeoutEventHandlerTable                                            timeouts_;
                DNSRuleTable                                                        dns_ruless_[3];
                RouteInformationTablePtr                                            rib_;
                ForwardInformationTablePtr                                          fib_;
                RouteIPListTablePtr                                                 vbgp_;
                ppp::string                                                         server_ru_;
                std::shared_ptr<aggligator::aggligator>                             aggligator_;
                IForwardingPtr                                                      forwarding_;
                VirtualEthernetInformationExtensions                                information_extensions_;
                bool                                                                ipv6_applied_ = false;
                IPv6AppliedState                                                    ipv6_state_;
                
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
                LoadIPListFileVectorPtr                                             ribs_;

                std::shared_ptr<NetworkInterface>                                   tun_ni_;
                std::shared_ptr<NetworkInterface>                                   underlying_ni_;
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
            };
        }
    }
}
