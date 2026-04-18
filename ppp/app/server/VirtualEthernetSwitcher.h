#pragma once

/**
 * @file VirtualEthernetSwitcher.h
 * @brief Declares the virtual ethernet switcher and related control helpers.
 */

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/Firewall.h>
#include <ppp/net/native/rib.h>
#include <ppp/threading/Timer.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/tap/ITap.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualInternetControlMessageProtocolStatic;
            class VirtualEthernetManagedServer;
            class VirtualEthernetExchanger;
            class VirtualEthernetNetworkTcpipConnection;
            class VirtualEthernetNamespaceCache;

            /**
             * @brief Coordinates virtual ethernet sessions, forwarding, and control planes.
             */
            class VirtualEthernetSwitcher : public std::enable_shared_from_this<VirtualEthernetSwitcher> { 
                friend class                                            VirtualEthernetNetworkTcpipConnection;
                friend class                                            VirtualEthernetExchanger;
                friend class                                            VirtualEthernetManagedServer;
                friend class                                            VirtualInternetControlMessageProtocolStatic;
                friend class                                            VirtualEthernetDatagramPortStatic;
                /**
                 * @brief Stores NAT ownership and mask information for an IPv4 address.
                 */
                struct NatInformation {
                    uint32_t                                            IPAddress;
                    uint32_t                                            SubmaskAddress;
                    std::shared_ptr<VirtualEthernetExchanger>           Exchanger;
                };
                typedef std::shared_ptr<NatInformation>                 NatInformationPtr;
                typedef std::unordered_map<uint32_t, NatInformationPtr> NatInformationTable;
                typedef std::unordered_map<ppp::string, std::shared_ptr<class VirtualEthernetExchanger>> IPv6ExchangerTable;
                /**
                 * @brief Tracks IPv6 assignment request result for a session.
                 */
                struct IPv6RequestEntry {
                    bool                                                 Present = false;
                    bool                                                 Accepted = false;
                    Byte                                                 StatusCode = VirtualEthernetInformationExtensions::IPv6Status_None;
                    boost::asio::ip::address                             RequestedAddress;
                    ppp::string                                          StatusMessage;
                };
                /**
                 * @brief Represents an active IPv6 lease bound to a session.
                 */
                struct IPv6LeaseEntry {
                    Int128                                               SessionId = 0;
                    UInt64                                               ExpiresAt = 0;
                    boost::asio::ip::address                             Address;
                    Byte                                                 AddressPrefixLength = 0;
                    bool                                                 StaticBinding = false;
                };
                typedef ppp::unordered_map<Int128, IPv6RequestEntry>     IPv6RequestTable;
                typedef ppp::unordered_map<Int128, IPv6LeaseEntry>       IPv6LeaseTable;
                typedef ppp::cryptography::Ciphertext                   Ciphertext;
                typedef std::shared_ptr<Ciphertext>                     CiphertextPtr;

            public:
                typedef ppp::app::protocol::VirtualEthernetInformation  VirtualEthernetInformation;
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions VirtualEthernetInformationExtensions;
                typedef ppp::app::protocol::VirtualEthernetLinklayer::InformationEnvelope InformationEnvelope;
                typedef std::shared_ptr<VirtualEthernetInformation>     VirtualEthernetInformationPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;
                typedef ppp::unordered_map<Int128,
                    VirtualEthernetExchangerPtr>                        VirtualEthernetExchangerTable;
                typedef std::shared_ptr<VirtualEthernetManagedServer>   VirtualEthernetManagedServerPtr;
                typedef std::shared_ptr<ppp::tap::ITap>                 ITapPtr;
                typedef ppp::app::protocol::VirtualEthernetLogger       VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>          VirtualEthernetLoggerPtr;
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef ppp::threading::Timer                           Timer;
                typedef std::shared_ptr<Timer>                          TimerPtr;
                typedef ppp::net::Firewall                              Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>             FirewallPtr;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::coroutines::YieldContext                   YieldContext;
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                typedef ppp::transmissions::ITransmissionStatistics     ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>        ITransmissionStatisticsPtr;
                typedef std::shared_ptr<
                    VirtualEthernetNetworkTcpipConnection>              VirtualEthernetNetworkTcpipConnectionPtr;
                typedef ppp::unordered_map<void*,
                    VirtualEthernetNetworkTcpipConnectionPtr>           VirtualEthernetNetworkTcpipConnectionTable;
                /**
                 * @brief Stores static-echo cryptographic context for an allocated channel.
                 */
                struct VirtualEthernetStaticEchoAllocatedContext {
                    Int128                                              guid = 0;
                    Int128                                              fsid = 0;
                    int                                                 myid = 0;
                    std::shared_ptr<ppp::cryptography::Ciphertext>      transport;
                    std::shared_ptr<ppp::cryptography::Ciphertext>      protocol;
                };
                typedef std::shared_ptr<
                    VirtualEthernetStaticEchoAllocatedContext>          VirtualEthernetStaticEchoAllocatedContextPtr;
                typedef ppp::unordered_map<int, 
                    VirtualEthernetStaticEchoAllocatedContextPtr>       VirtualEthernetStaticEchoAllocatedTable;
                typedef ppp::app::server::VirtualEthernetNamespaceCache VirtualEthernetNamespaceCache;
                typedef std::shared_ptr<VirtualEthernetNamespaceCache>  VirtualEthernetNamespaceCachePtr;

            public:
                /**
                 * @brief Creates a virtual switcher instance.
                 * @param configuration Shared app configuration.
                 * @param tun_name Optional TUN interface name.
                 * @param tun_ssmt Optional SSMT worker count.
                 * @param tun_ssmt_mq Enables multi-queue mode when true.
                 */
                VirtualEthernetSwitcher(const AppConfigurationPtr& configuration, const ppp::string& tun_name = ppp::string(), int tun_ssmt = 0, bool tun_ssmt_mq = false) noexcept;
                /** @brief Destroys the switcher and releases owned resources. */
                virtual ~VirtualEthernetSwitcher() noexcept;

            public:
                /** @brief Gets the configured logical node identifier. */
                int                                                     GetNode() noexcept               { return configuration_->server.node; }
                /** @brief Gets a shared self reference. */
                std::shared_ptr<VirtualEthernetSwitcher>                GetReference() noexcept          { return shared_from_this(); }
                /** @brief Gets the firewall instance. */
                FirewallPtr                                             GetFirewall() noexcept           { return firewall_; }
                /** @brief Gets the primary I/O context. */
                ContextPtr                                              GetContext() noexcept            { return context_; }
                /** @brief Gets the active app configuration. */
                AppConfigurationPtr                                     GetConfiguration() noexcept      { return configuration_; }
                /** @brief Gets the synchronization mutex. */
                SynchronizedObject&                                     GetSynchronizedObject() noexcept { return syncobj_; }
                /** @brief Gets the virtual ethernet logger. */
                VirtualEthernetLoggerPtr                                GetLogger() noexcept             { return logger_; }
                /** @brief Gets the managed server helper. */
                VirtualEthernetManagedServerPtr                         GetManagedServer() noexcept      { return managed_server_; }
                /** @brief Gets the namespace cache helper. */
                VirtualEthernetNamespaceCachePtr                        GetNamespaceCache() noexcept     { return namespace_cache_; }
                /** @brief Sets preferred NIC name for routing/proxy operations. */
                void                                                    PreferredNic(const ppp::string& nic) noexcept { preferred_nic_ = nic; }

            public:
                /** @brief Opens switcher services and firewall resources. */
                virtual bool                                            Open(const ppp::string& firewall) noexcept;
                /** @brief Runs acceptors and packet processing loops. */
                virtual bool                                            Run() noexcept;
                /** @brief Disposes switcher resources and active sessions. */
                virtual void                                            Dispose() noexcept;
                /** @brief Indicates whether switcher was disposed. */
                virtual bool                                            IsDisposed() noexcept;

            public:
                /** @brief Gets traffic statistics collector. */
                ITransmissionStatisticsPtr&                             GetStatistics() noexcept        { return statistics_; }
                /** @brief Gets local interface IP used by switcher. */
                boost::asio::ip::address                                GetInterfaceIP() noexcept       { return interfaceIP_; }
                /** @brief Gets configured DNS upstream endpoint. */
                boost::asio::ip::udp::endpoint                          GetDnsserverEndPoint() noexcept { return dnsserverEP_; }
                /** @brief Gets total active exchangers count. */
                int                                                     GetAllExchangerNumber() noexcept;

            public:
                /**
                 * @brief Categorizes inbound TCP acceptors used by the switcher.
                 */
                typedef enum {
                    NetworkAcceptorCategories_Min,
                    NetworkAcceptorCategories_Tcpip = NetworkAcceptorCategories_Min,
                    NetworkAcceptorCategories_WebSocket,
                    NetworkAcceptorCategories_WebSocketSSL,
                    NetworkAcceptorCategories_CDN1,
                    NetworkAcceptorCategories_CDN2,
                    NetworkAcceptorCategories_Max,
                    NetworkAcceptorCategories_Udpip = NetworkAcceptorCategories_Max,
                }                                                       NetworkAcceptorCategories;
                /** @brief Gets local endpoint bound for a given acceptor category. */
                boost::asio::ip::tcp::endpoint                          GetLocalEndPoint(NetworkAcceptorCategories categories) noexcept;

            protected:
                /** @brief Creates a transmission for an accepted socket. */
                virtual ITransmissionPtr                                Accept(int categories, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                /** @brief Establishes protocol state for a new session. */
                virtual bool                                            Establish(const ITransmissionPtr& transmission, const Int128& session_id, const VirtualEthernetInformationPtr& i, YieldContext& y) noexcept;
                /** @brief Performs session connect handshake. */
                virtual int                                             Connect(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept;
                /** @brief Processes periodic maintenance tick. */
                virtual bool                                            OnTick(UInt64 now) noexcept;
                /** @brief Handles control information packet for a session. */
                virtual bool                                            OnInformation(const Int128& session_id, const std::shared_ptr<VirtualEthernetInformation>& info, YieldContext& y) noexcept;

            protected:
                /** @brief Creates logger implementation. */
                virtual VirtualEthernetLoggerPtr                        NewLogger() noexcept;
                /** @brief Creates managed server implementation. */
                virtual VirtualEthernetManagedServerPtr                 NewManagedServer() noexcept;
                /** @brief Creates firewall implementation. */
                virtual FirewallPtr                                     NewFirewall() noexcept;
                /** @brief Creates namespace cache with given TTL. */
                virtual VirtualEthernetNamespaceCachePtr                NewNamespaceCache(int ttl) noexcept;
                /** @brief Creates transmission statistics collector. */
                virtual ITransmissionStatisticsPtr                      NewStatistics() noexcept;
                /** @brief Creates exchanger for a connected session. */
                virtual VirtualEthernetExchangerPtr                     NewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                /** @brief Creates TCP/IP connection wrapper for a session. */
                virtual VirtualEthernetNetworkTcpipConnectionPtr        NewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;

            private:
                /** @brief Finalizes shutdown state and owned resources. */
                void                                                    Finalize() noexcept;
                /** @brief Accepts a socket under a specific category. */
                bool                                                    Accept(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int categories) noexcept;
                /** @brief Runs processing loop for one transmission. */
                int                                                     Run(const ContextPtr& context, const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Removes exchanger by pointer key. */
                VirtualEthernetExchangerPtr                             DeleteExchanger(VirtualEthernetExchanger* exchanger) noexcept;
                /** @brief Finds exchanger by session identifier. */
                VirtualEthernetExchangerPtr                             GetExchanger(const Int128& session_id) noexcept;
                /** @brief Creates and registers a new exchanger. */
                VirtualEthernetExchangerPtr                             AddNewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                /** @brief Creates and registers a new connection object. */
                VirtualEthernetNetworkTcpipConnectionPtr                AddNewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept;
                /** @brief Deletes a registered TCP/IP connection. */
                bool                                                    DeleteConnection(const VirtualEthernetNetworkTcpipConnection* connection) noexcept;

            private:
                /** @brief Parses DNS server endpoint string. */
                boost::asio::ip::udp::endpoint                          ParseDNSEndPoint(const ppp::string& dnserver_endpoint) noexcept;
                /** @brief Ticks all exchangers for timeout and housekeeping. */
                void                                                    TickAllExchangers(UInt64 now) noexcept;
                /** @brief Ticks all TCP/IP connections for housekeeping. */
                void                                                    TickAllConnections(UInt64 now) noexcept;
                /** @brief Starts managed server when configured and needed. */
                bool                                                    OpenManagedServerIfNeed() noexcept;
                /** @brief Checks whether runtime supports IPv6 data plane. */
                bool                                                    SupportsIPv6DataPlane() noexcept;
                /** @brief Checks whether IPv6 server functions are enabled. */
                bool                                                    IsIPv6ServerEnabled() noexcept;
                /** @brief Opens IPv6 transit plane if enabled. */
                bool                                                    OpenIPv6TransitIfNeed() noexcept;
                /** @brief Opens SSMT contexts for IPv6 transit tap. */
                bool                                                    OpenIPv6TransitSsmtIfNeed(const ITapPtr& tap) noexcept;
                /** @brief Closes all IPv6 transit SSMT contexts. */
                void                                                    CloseIPv6TransitSsmtContexts() noexcept;
                /** @brief Gets configured IPv6 transit gateway address. */
                boost::asio::ip::address                                GetIPv6TransitGateway() noexcept;

            private:
                /** @brief Releases an allocated static-echo slot. */
                VirtualEthernetStaticEchoAllocatedContextPtr            StaticEchoUnallocated(int allocated_id) noexcept;
                /** @brief Queries static-echo context by allocation id. */
                bool                                                    StaticEchoQuery(int allocated_id, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept;
                /** @brief Allocates static-echo context for a session. */
                VirtualEthernetStaticEchoAllocatedContextPtr            StaticEchoAllocated(Int128 session_id, int& allocated_id, int& remote_port) noexcept;
                /** @brief Processes inbound static-echo packet data. */
                bool                                                    StaticEchoPacketInput(const VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /** @brief Selects protocol or transport ciphertext for static echo. */
                std::shared_ptr<ppp::cryptography::Ciphertext>          StaticEchoSelectCiphertext(int allocated_id, bool protocol_or_transport, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept;

            private:
                /** @brief Creates firewall ruleset from path. */
                bool                                                    CreateFirewall(const ppp::string& path) noexcept;
                /** @brief Closes all listening acceptors. */
                void                                                    CloseAllAcceptors() noexcept;
                /** @brief Creates all configured listening acceptors. */
                bool                                                    CreateAllAcceptors() noexcept;
                /** @brief Stops global timeout timer if active. */
                bool                                                    CloseAlwaysTimeout() noexcept;
                /** @brief Creates global timeout timer. */
                bool                                                    CreateAlwaysTimeout() noexcept;
                /** @brief Opens datagram socket for static echo. */
                bool                                                    OpenDatagramSocket() noexcept;
                /** @brief Initializes namespace cache if required. */
                bool                                                    OpenNamespaceCacheIfNeed() noexcept;
                /** @brief Enables loopback path for datagram socket. */
                bool                                                    LoopbackDatagramSocket() noexcept;
                /** @brief Initializes logger if available. */
                bool                                                    OpenLogger() noexcept;
                /** @brief Performs initial transmission arrangement workflow. */
                bool                                                    FlowerArrangement(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Builds outbound information envelope for a session. */
                InformationEnvelope                                     BuildInformationEnvelope(const Int128& session_id, const VirtualEthernetInformation& info) noexcept;
                /** @brief Builds IPv6 extension response data. */
                bool                                                    BuildInformationIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept;
                /** @brief Gets assigned IPv6 extension state if present. */
                bool                                                    TryGetAssignedIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept;
                /** @brief Updates IPv6 request state and fills response metadata. */
                bool                                                    UpdateIPv6Request(const Int128& session_id, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept;
                /** @brief Expires stale IPv6 leases. */
                void                                                    TickIPv6Leases(UInt64 now) noexcept;
                /** @brief Revokes IPv6 lease bound to a session. */
                void                                                    RevokeIPv6Lease(const Int128& session_id) noexcept;
                /** @brief Registers IPv6 exchanger mapping for a session. */
                bool                                                    AddIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept;
                /** @brief Removes IPv6 exchanger mapping by session id. */
                bool                                                    DeleteIPv6Exchanger(const Int128& session_id) noexcept;
                /** @brief Removes IPv6 exchanger mapping using extension data. */
                bool                                                    DeleteIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept;
                /** @brief Finds IPv6 exchanger by destination address. */
                VirtualEthernetExchangerPtr                             FindIPv6Exchanger(const boost::asio::ip::address& ip) noexcept;
                /** @brief Opens IPv6 neighbor proxy facility if needed. */
                bool                                                    OpenIPv6NeighborProxyIfNeed() noexcept;
                /** @brief Closes IPv6 neighbor proxy facility if owned. */
                bool                                                    CloseIPv6NeighborProxyIfNeed() noexcept;
                /** @brief Refreshes neighbor proxy bindings if needed. */
                bool                                                    RefreshIPv6NeighborProxyIfNeed() noexcept;
                /** @brief Adds one IPv6 neighbor proxy entry. */
                bool                                                    AddIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept;
                /** @brief Deletes one IPv6 neighbor proxy entry. */
                bool                                                    DeleteIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept;
                /** @brief Deletes a neighbor proxy entry for specific interface. */
                bool                                                    DeleteIPv6NeighborProxy(const ppp::string& ifname, const boost::asio::ip::address& ip) noexcept;
                /** @brief Adds transit route for IPv6 prefix. */
                bool                                                    AddIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept;
                /** @brief Deletes transit route for IPv6 prefix. */
                bool                                                    DeleteIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept;
                /** @brief Clears IPv6 exchanger table without external synchronization. */
                void                                                    ClearIPv6ExchangersUnsafe() noexcept;
                /** @brief Sends raw packet into IPv6 transit path. */
                bool                                                    SendIPv6TransitPacket(Byte* packet, int packet_length) noexcept;
                /** @brief Processes raw packet received from IPv6 transit path. */
                bool                                                    ReceiveIPv6TransitPacket(Byte* packet, int packet_length) noexcept;
                /** @brief Sends IPv6 packet to a specific client session. */
                bool                                                    SendIPv6PacketToClient(const ITransmissionPtr& transmission, const Int128& session_id, Byte* packet, int packet_length) noexcept;
                /** @brief Deletes NAT entry tied to exchanger and IPv4 address. */
                bool                                                    DeleteNatInformation(VirtualEthernetExchanger* key, uint32_t ip) noexcept;
                /** @brief Finds NAT entry by IPv4 address. */
                NatInformationPtr                                       FindNatInformation(uint32_t ip) noexcept;
                /** @brief Adds NAT ownership for an exchanger and IPv4 subnet pair. */
                NatInformationPtr                                       AddNatInformation(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, uint32_t ip, uint32_t mask) noexcept;
            private:
                template <typename TTransmission>
                typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>/**/>::type
                /**
                 * @brief Creates websocket transmission and applies host/path overrides.
                 * @tparam TTransmission Concrete transmission type derived from ITransmission.
                 * @param context I/O context used to construct transmission.
                 * @param socket Accepted TCP socket.
                 * @return Constructed transmission on success; otherwise null.
                 */
                inline                                                  NewWebsocketTransmission(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                    const ppp::string& host = configuration_->websocket.host;
                    const ppp::string& path = configuration_->websocket.path;

                    ppp::threading::Executors::StrandPtr strand;
                    auto transmission = make_shared_object<TTransmission>(context, strand, socket, configuration_);
                    if (NULLPTR == transmission) {
                        return NULLPTR;
                    }
                    
                    /**
                     * @brief Applies configured websocket host/path only when both are present.
                     */
                    if (!host.empty() && !path.empty()) {
                        transmission->Host = host;
                        transmission->Path = path;
                    }
                    return transmission;
                }

            private:
                SynchronizedObject                                      syncobj_;
                bool                                                    disposed_  = false;

                VirtualEthernetLoggerPtr                                logger_;
                NatInformationTable                                     nats_;
                IPv6ExchangerTable                                      ipv6s_;
                IPv6RequestTable                                        ipv6_requests_;
                IPv6LeaseTable                                          ipv6_leases_;
                FirewallPtr                                             firewall_;
                VirtualEthernetExchangerTable                           exchangers_;
                TimerPtr                                                timeout_;
                AppConfigurationPtr                                     configuration_;
                ContextPtr                                              context_;
                boost::asio::ip::udp::endpoint                          dnsserverEP_;
                boost::asio::ip::address                                interfaceIP_;
                ppp::string                                             tun_name_;
                int                                                     tun_ssmt_ = 0;
                bool                                                    tun_ssmt_mq_ = false;
                ppp::string                                             preferred_nic_;
                ppp::string                                             ipv6_neighbor_proxy_ifname_;
                bool                                                    ipv6_neighbor_proxy_owned_ = false;
                ITapPtr                                                 ipv6_transit_tap_;
                ppp::vector<std::shared_ptr<boost::asio::io_context>>   ipv6_transit_ssmt_contexts_;
                VirtualEthernetNetworkTcpipConnectionTable              connections_;
                ITransmissionStatisticsPtr                              statistics_;
                VirtualEthernetManagedServerPtr                         managed_server_;
                VirtualEthernetNamespaceCachePtr                        namespace_cache_;
                boost::asio::ip::udp::socket                            static_echo_socket_;
                int                                                     static_echo_bind_port_ = 0;
                std::shared_ptr<Byte>                                   static_echo_buffers_;
                boost::asio::ip::udp::endpoint                          static_echo_source_ep_;
                VirtualEthernetStaticEchoAllocatedTable                 static_echo_allocateds_;

                std::shared_ptr<boost::asio::ip::tcp::acceptor>         acceptors_[NetworkAcceptorCategories_Max];
            };
        }
    }
}
