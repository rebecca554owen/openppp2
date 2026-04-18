#pragma once

/**
 * @file VEthernetExchanger.h
 * @brief Client-side virtual Ethernet exchanger declarations.
 * @details Licensed under GPL-3.0.
 */

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/mux/vmux_net.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/Int128.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/threading/Timer.h>
#include <ppp/auxiliary/UriAuxiliary.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;
            class VEthernetDatagramPort;

            /**
             * @brief Handles client transport exchange for virtual Ethernet traffic.
             */
            class VEthernetExchanger : public ppp::app::protocol::VirtualEthernetLinklayer {
                friend class                                                            VEthernetDatagramPort;
                friend class                                                            VEthernetNetworkSwitcher;

            public:
                typedef std::shared_ptr<VEthernetNetworkSwitcher>                       VEthernetNetworkSwitcherPtr;
                typedef ppp::app::protocol::VirtualEthernetInformation                  VirtualEthernetInformation;
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions        VirtualEthernetInformationExtensions;
                typedef ppp::auxiliary::UriAuxiliary                                    UriAuxiliary;
                typedef UriAuxiliary::ProtocolType                                      ProtocolType;
                typedef ppp::threading::Timer                                           Timer;
                typedef std::shared_ptr<Timer>                                          TimerPtr;
                typedef ppp::unordered_map<void*, TimerPtr>                             TimerTable;
                typedef std::shared_ptr<VEthernetDatagramPort>                          VEthernetDatagramPortPtr;
                typedef ppp::threading::Executors::StrandPtr                            StrandPtr;
                typedef std::mutex                                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                             SynchronizedObjectScope;

            private:
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,
                    VEthernetDatagramPortPtr>                                           VEthernetDatagramPortTable;
                typedef ppp::app::protocol::VirtualEthernetMappingPort                  VirtualEthernetMappingPort;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                     VirtualEthernetMappingPortPtr;
                typedef ppp::unordered_map<uint32_t, VirtualEthernetMappingPortPtr>     VirtualEthernetMappingPortTable;
                typedef ppp::cryptography::Ciphertext                                   Ciphertext;
                typedef std::shared_ptr<Ciphertext>                                     CiphertextPtr;
                typedef std::shared_ptr<boost::asio::deadline_timer>                    DeadlineTimerPtr;
                typedef ppp::unordered_map<void*, DeadlineTimerPtr>                     DeadlineTimerTable;

            public:
                /** @brief Constructs a new exchanger instance. */
                VEthernetExchanger(
                    const VEthernetNetworkSwitcherPtr&                                  switcher,
                    const AppConfigurationPtr&                                          configuration,
                    const ContextPtr&                                                   context,
                    const Int128&                                                       id) noexcept;
                /** @brief Destroys the exchanger and frees managed resources. */
                virtual ~VEthernetExchanger() noexcept;

            public:
                typedef enum {
                    NetworkState_Connecting,
                    NetworkState_Established,
                    NetworkState_Reconnecting,
                }                                                                       NetworkState;

            public:
                /** @brief Gets current logical network state. */
                NetworkState                                                            GetNetworkState()       noexcept { return network_state_.load(); }
                /** @brief Gets cached receive buffer shared by async paths. */
                std::shared_ptr<Byte>                                                   GetBuffer()             noexcept { return buffer_; }
                /** @brief Gets current vmux instance, if available. */
                std::shared_ptr<vmux::vmux_net>                                         GetMux()                noexcept { return mux_; }
                /** @brief Gets owning network switcher. */
                VEthernetNetworkSwitcherPtr                                             GetSwitcher()           noexcept { return switcher_; }
                /** @brief Gets latest server information snapshot. */
                std::shared_ptr<VirtualEthernetInformation>                             GetInformation()        noexcept { return information_; }
                /** @brief Gets active transmission channel. */
                ITransmissionPtr                                                        GetTransmission()       noexcept { return transmission_; }
                /** @brief Gets reconnect attempts since last established state. */
                int                                                                     GetReconnectionCount()  noexcept { return reconnection_count_; }
                /** @brief Gets mux network state based on vmux lifecycle. */
                NetworkState                                                            GetMuxNetworkState()    noexcept;
                /** @brief Starts asynchronous exchange loop. */
                virtual bool                                                            Open()                  noexcept;
                /** @brief Schedules asynchronous exchanger disposal. */
                virtual void                                                            Dispose()               noexcept;
                /** @brief Opens an additional transmission for mux sub-link. */
                virtual ITransmissionPtr                                                ConnectTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept;
                
            public:
                /** @brief Executes a callable in exchanger context. */
                template <typename F>
                void                                                                    Post(F&& f) noexcept {
#if defined(_ANDROID)
                    auto context = GetContext();
                    if (context) {
                        auto self = shared_from_this();
                        boost::asio::post(*context, 
                            [self, f]() noexcept {
                                f();
                            });
                    }
#else   
                    f();
#endif
                }

            public:
                /** @brief Sends an IP packet to remote NAT channel. */
                virtual bool                                                            Nat(const void* packet, int packet_size) noexcept;
                /** @brief Sends requested IPv6 configuration envelope. */
                bool                                                                    SendRequestedIPv6Configuration(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Sends an ACK-based echo request. */
                virtual bool                                                            Echo(int ack_id) noexcept;
                /** @brief Sends a packet-based echo request. */
                virtual bool                                                            Echo(const void* packet, int packet_size) noexcept;
                /** @brief Sends UDP payload from source endpoint to destination endpoint. */
                virtual bool                                                            SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept;
                /** @brief Performs periodic maintenance and keepalive processing. */
                virtual bool                                                            Update() noexcept;
                /** @brief Checks whether static-echo transport is fully allocated. */
                bool                                                                    StaticEchoAllocated() noexcept;
                /** @brief Resolves, validates, and caches remote endpoint details. */
                virtual bool                                                            GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept;

            protected:
                /** @brief Handles inbound LAN event from transport. */
                virtual bool                                                            OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept override;
                /** @brief Handles inbound NAT packet from transport. */
                virtual bool                                                            OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles base information envelope from transport. */
                virtual bool                                                            OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept override;
                /** @brief Handles extended information envelope from transport. */
                virtual bool                                                            OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept override;
                /** @brief Handles push event from transport. */
                virtual bool                                                            OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles connect event from transport. */
                virtual bool                                                            OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override;
                /** @brief Handles connect acknowledgment event from transport. */
                virtual bool                                                            OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override;
                /** @brief Handles disconnect event from transport. */
                virtual bool                                                            OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept override;
                /** @brief Handles ACK echo callback from transport. */
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept override;
                /** @brief Handles packet echo callback from transport. */
                virtual bool                                                            OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles UDP send-to callback from transport. */
                virtual bool                                                            OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles static negotiation callback without payload. */
                virtual bool                                                            OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept override;
                /** @brief Handles static negotiation callback with session data. */
                virtual bool                                                            OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept override;
                /** @brief Handles mux negotiation callback from transport. */
                virtual bool                                                            OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept override;

            protected:
                /** @brief Creates a new datagram relay port. */
                virtual VEthernetDatagramPortPtr                                        NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /** @brief Gets datagram relay port by source endpoint. */
                virtual VEthernetDatagramPortPtr                                        GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /** @brief Releases datagram relay port by source endpoint. */
                virtual VEthernetDatagramPortPtr                                        ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            protected:
                /** @brief Creates transmission instance for selected protocol type. */
                virtual ITransmissionPtr                                                NewTransmission(
                    const ContextPtr&                                                   context,
                    const StrandPtr&                                                    strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                    ProtocolType                                                        protocol_type,
                    const ppp::string&                                                  host,
                    const ppp::string&                                                  path) noexcept;
                /** @brief Opens a transmission channel to remote endpoint. */
                virtual ITransmissionPtr                                                OpenTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept;

            protected:
                /** @brief Allocates and configures asynchronous TCP socket. */
                virtual std::shared_ptr<boost::asio::ip::tcp::socket>                   NewAsynchronousSocket(const ContextPtr& context, const StrandPtr& strand, const boost::asio::ip::tcp& protocol, ppp::coroutines::YieldContext& y) noexcept;
                /** @brief Executes main connect-handshake-reconnect loop. */
                virtual bool                                                            Loopback(const ContextPtr& context, YieldContext& y) noexcept;
                /** @brief Handles decoded packet input from base linklayer. */
                virtual bool                                                            PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                /** @brief Opens transmission without a dedicated strand. */
                ITransmissionPtr                                                        OpenTransmission(const ContextPtr& context, YieldContext& y) noexcept {
                    StrandPtr strand;
                    return OpenTransmission(context, strand, y);
                }
                /** @brief Finalizes exchanger state and disposes owned objects. */
                void                                                                    Finalize() noexcept;
                /** @brief Moves state machine to established state. */
                void                                                                    ExchangeToEstablishState() noexcept;
                /** @brief Moves state machine to connecting state. */
                void                                                                    ExchangeToConnectingState() noexcept;
                /** @brief Moves state machine to reconnecting state. */
                void                                                                    ExchangeToReconnectingState() noexcept;
                /** @brief Sends LAN identity information to remote exchanger. */
                int                                                                     EchoLanToRemoteExchanger(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Sends keepalive echo or closes stale link. */
                bool                                                                    SendEchoKeepAlivePacket(UInt64 now, bool immediately) noexcept;
                /** @brief Routes UDP packet received from remote destination. */
                bool                                                                    ReceiveFromDestination(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length) noexcept;
                /** @brief Adds datagram port if missing and returns it. */
                VEthernetDatagramPortPtr                                                AddNewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                /** @brief Creates websocket transmission object with optional host/path. */
                template <typename TTransmission>
                typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>/**/>::type
                inline                                                                  NewWebsocketTransmission(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const ppp::string& host, const ppp::string& path) noexcept {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    if (NULLPTR == configuration) {
                        return NULLPTR;
                    }

                    auto transmission = make_shared_object<TTransmission>(context, strand, socket, configuration);
                    if (NULLPTR == transmission) {
                        return NULLPTR;
                    }
                    
                    if (host.size() > 0 && path.size() > 0) {
                        transmission->Host = host;
                        transmission->Path = path;
                    }

                    return transmission;
                }

            private:
                /** @brief Gets mapping port by direction/protocol/remote-port key. */
                VirtualEthernetMappingPortPtr                                           GetMappingPort(bool in, bool tcp, int remote_port) noexcept;
                /** @brief Allocates a new mapping port object. */
                VirtualEthernetMappingPortPtr                                           NewMappingPort(bool in, bool tcp, int remote_port) noexcept;
                /** @brief Registers one configured mapping port entry. */
                bool                                                                    RegisterMappingPort(ppp::configurations::AppConfiguration::MappingConfiguration& mapping) noexcept;
                /** @brief Unregisters all mapping ports. */
                void                                                                    UnregisterAllMappingPorts() noexcept;
                /** @brief Registers all mapping ports from configuration. */
                bool                                                                    RegisterAllMappingPorts() noexcept;
                /** @brief Removes and cancels a tracked deadline timer. */
                bool                                                                    ReleaseDeadlineTimer(const boost::asio::deadline_timer* deadline_timer) noexcept;
                /** @brief Creates and tracks asynchronous deadline timer. */
                bool                                                                    NewDeadlineTimer(const ContextPtr& context, int64_t timeout, const ppp::function<void(bool)>& event) noexcept;
                /** @brief Suspends coroutine for the specified timeout. */
                bool                                                                    Sleep(int64_t timeout, const ContextPtr& context, YieldContext& y) noexcept;
#if defined(_ANDROID)
                /** @brief Waits for Android protector JNI attach readiness. */
                bool                                                                    AwaitJniAttachThread(const ContextPtr& context, YieldContext& y) noexcept;
#endif
                /** @brief Runs keepalive checks for established link. */
                virtual bool                                                            DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept override;
                /** @brief Drives mux lifecycle update and negotiation. */
                bool                                                                    DoMuxEvents() noexcept;
                /** @brief Connects all mux linklayers required by vmux session. */
                bool                                                                    MuxConnectAllLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<vmux::vmux_net>& mux) noexcept;

            private:
                /** @brief UDP socket wrapper used by static-echo channel. */
                class StaticEchoDatagarmSocket final : public boost::asio::ip::udp::socket {
                public:
                    /** @brief Constructs socket wrapper and resets state flag. */
                    StaticEchoDatagarmSocket(boost::asio::io_context& context) noexcept 
                        : basic_datagram_socket(context)
                        , opened(false) {

                    }
                    /** @brief Unregisters native socket on destruction. */
                    virtual ~StaticEchoDatagarmSocket() noexcept {
                        boost::asio::ip::udp::socket* my = this;
                        destructor_invoked(my);
                    }

                public:
                    /** @brief Checks native or logical open status. */
                    bool                                                                is_open(bool only_native = false) noexcept { return only_native ? basic_datagram_socket::is_open() : opened && basic_datagram_socket::is_open(); }

                public:
                    bool                                                                opened = false;
                };
                /** @brief Adds a static-echo remote endpoint into balance pool. */
                bool                                                                    StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;
                /** @brief Selects next static-echo remote endpoint. */
                boost::asio::ip::udp::endpoint                                          StaticEchoGetRemoteEndPoint() noexcept;
                /** @brief Clears static-echo sockets and session state. */
                void                                                                    StaticEchoClean() noexcept;
                /** @brief Computes next timeout for static-echo socket rotation. */
                bool                                                                    StaticEchoNextTimeout() noexcept;
                /** @brief Rotates static-echo sockets when timeout is reached. */
                bool                                                                    StaticEchoSwapAsynchronousSocket() noexcept;
                /** @brief Sends gateway keepalive packet through static-echo channel. */
                bool                                                                    StaticEchoGatewayServer(int ack_id) noexcept;
                /** @brief Processes one received static-echo datagram payload. */
                int                                                                     StaticEchoYieldReceiveForm(Byte* incoming_packet, int incoming_traffic) noexcept;
                /** @brief Starts recursive async receive loop for static-echo socket. */
                bool                                                                    StaticEchoLoopbackSocket(const std::shared_ptr<StaticEchoDatagarmSocket>& socket) noexcept;
                /** @brief Opens and configures static-echo UDP socket. */
                bool                                                                    StaticEchoOpenAsynchronousSocket(StaticEchoDatagarmSocket& socket, YieldContext& y) noexcept;
                /** @brief Allocates static-echo resources and negotiates with remote. */
                bool                                                                    StaticEchoAllocatedToRemoteExchanger(YieldContext& y) noexcept;
                /** @brief Sends packed static-echo packet to remote endpoint. */
                bool                                                                    StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;
                /** @brief Packs and sends IP frame through static-echo channel. */
                bool                                                                    StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept;
                /** @brief Packs and sends UDP frame through static-echo channel. */
                bool                                                                    StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept;
                /** @brief Injects received static-echo packet into switcher path. */
                bool                                                                    StaticEchoPacketInput(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept;
                /** @brief Decodes and decrypts static-echo packet payload. */
                std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>              StaticEchoReadPacket(const void* packet, int packet_length) noexcept;

            private:
                /** @brief Handles FRP UDP callback from remote side. */
                virtual bool                                                            OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles FRP TCP connect callback from remote side. */
                virtual bool                                                            OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept override;
                /** @brief Handles FRP TCP disconnect callback from remote side. */
                virtual bool                                                            OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept override;
                /** @brief Handles FRP TCP data callback from remote side. */
                virtual bool                                                            OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept override;

            private:
                SynchronizedObject                                                      syncobj_;

                struct {
                    bool                                                                disposed_           : 1;
                    bool                                                                static_echo_input_  : 7;
                };

                std::shared_ptr<Byte>                                                   buffer_;            

                UInt64                                                                  sekap_last_         = 0;
                UInt64                                                                  sekap_next_         = 0;

                VEthernetNetworkSwitcherPtr                                             switcher_;
                std::shared_ptr<VirtualEthernetInformation>                             information_;
                VEthernetDatagramPortTable                                              datagrams_;
                ITransmissionPtr                                                        transmission_;
                std::atomic<NetworkState>                                               network_state_      = NetworkState_Connecting;
                VirtualEthernetMappingPortTable                                         mappings_;
                DeadlineTimerTable                                                      deadline_timers_;

                std::shared_ptr<vmux::vmux_net>                                         mux_;
                uint16_t                                                                mux_vlan_           = 0;
                
                int                                                                     reconnection_count_ = 0;

                struct {
                    boost::asio::ip::tcp::endpoint                                      remoteEP;
                    ppp::string                                                         hostname;
                    ppp::string                                                         address;
                    ppp::string                                                         path;
                    ppp::string                                                         server;
                    int                                                                 port                = 0;
                    ProtocolType                                                        protocol_type       = ProtocolType::ProtocolType_PPP;
                }                                                                       server_url_;

                CiphertextPtr                                                           static_echo_protocol_;
                CiphertextPtr                                                           static_echo_transport_;
                std::shared_ptr<StaticEchoDatagarmSocket>                               static_echo_sockets_[2];
                boost::asio::ip::udp::endpoint                                          static_echo_source_ep_;
                ppp::list<boost::asio::ip::udp::endpoint>                               static_echo_server_ep_balances_;
                ppp::unordered_set<boost::asio::ip::udp::endpoint>                      static_echo_server_ep_set_;
                
                uint64_t                                                                static_echo_timeout_     = 0;
                int                                                                     static_echo_session_id_  = 0;
                int                                                                     static_echo_remote_port_ = 0;
            };
        }
    }
}
