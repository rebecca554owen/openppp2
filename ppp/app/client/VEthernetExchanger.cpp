#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/app/client/PortMappingManager.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
typedef ppp::app::protocol::VirtualEthernetPacket                   VirtualEthernetPacket;
typedef ppp::collections::Dictionary                                Dictionary;
typedef ppp::auxiliary::StringAuxiliary                             StringAuxiliary;
typedef ppp::net::AddressFamily                                     AddressFamily;
typedef ppp::net::Socket                                            Socket;
typedef ppp::net::IPEndPoint                                        IPEndPoint;
typedef ppp::net::Ipep                                              Ipep;
typedef ppp::threading::Timer                                       Timer;
typedef ppp::threading::Executors                                   Executors;
typedef ppp::transmissions::ITransmission                           ITransmission;
typedef ppp::transmissions::ITcpipTransmission                      ITcpipTransmission;
typedef ppp::transmissions::IWebsocketTransmission                  IWebsocketTransmission;
typedef ppp::transmissions::ISslWebsocketTransmission               ISslWebsocketTransmission;

namespace ppp {
    namespace app {
        namespace client {
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT = 1000;
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT = 5000;
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT = SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT << 2;

            VEthernetExchanger::VEthernetExchanger(
                const VEthernetNetworkSwitcherPtr&      switcher,
                const AppConfigurationPtr&              configuration,
                const ContextPtr&                       context,
                const Int128&                           id) noexcept
                : VirtualEthernetLinklayer(configuration, context, id)
                , disposed_(false)
                , sekap_last_(0)
                , sekap_next_(0)
                , switcher_(switcher)
                , network_state_(NetworkState_Connecting) {

                if (configuration->key.protocol.size() > 0 && configuration->key.protocol_key.size() > 0 &&
                    configuration->key.transport.size() > 0 && configuration->key.transport_key.size() > 0) {
                    if (Ciphertext::Support(configuration->key.protocol) && Ciphertext::Support(configuration->key.transport)) {
                        static_echo_protocol_ = make_shared_object<Ciphertext>(configuration->key.protocol, configuration->key.protocol_key);
                        static_echo_transport_ = make_shared_object<Ciphertext>(configuration->key.transport, configuration->key.transport_key);
                    }
                }

                buffer_                   = Executors::GetCachedBuffer(context);
                server_url_.port          = 0;
                server_url_.protocol_type = ProtocolType::ProtocolType_PPP;
            }

            VEthernetExchanger::~VEthernetExchanger() noexcept {
                Finalize();
            }

            void VEthernetExchanger::Finalize() noexcept {
                VEthernetDatagramPortTable datagrams;
                ITransmissionPtr transmission;
                DeadlineTimerTable deadline_timers;
                std::shared_ptr<PortMappingManager> port_mapping_manager;
                std::shared_ptr<vmux::vmux_net> mux;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_datagrams_);
                    datagrams = std::move(datagrams_);
                    datagrams_.clear();
                    break;
                }

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);

                    transmission = std::move(transmission_);
                    transmission_.reset();

                    deadline_timers = std::move(deadline_timers_);
                    deadline_timers_.clear();

                    port_mapping_manager = std::move(port_mapping_manager_);
                    port_mapping_manager_.reset();

                    mux_vlan_ = 0;
                    mux = std::move(mux_);
                    mux_.reset();
                    break;
                }

                StaticEchoClean();
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                disposed_ = true;
                for (auto&& [_, deadline_timer] : deadline_timers) {
                    ppp::net::Socket::Cancel(*deadline_timer);
                }

                Dictionary::ReleaseAllObjects(datagrams);

                if (NULLPTR != port_mapping_manager) {
                    port_mapping_manager->Dispose();
                }

                if (NULLPTR != mux) {
                    mux->close_exec();
                }
            }

            void VEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this, context]() noexcept {
                        Finalize();
                    });
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::NewTransmission(
                const ContextPtr&                                                   context,
                const StrandPtr&                                                    strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                ProtocolType                                                        protocol_type,
                const ppp::string&                                                  host,
                const ppp::string&                                                  path) noexcept {

                ITransmissionPtr transmission;
                if (protocol_type == ProtocolType::ProtocolType_Http ||
                    protocol_type == ProtocolType::ProtocolType_WebSocket) {
                    transmission = NewWebsocketTransmission<IWebsocketTransmission>(context, strand, socket, host, path);
                }
                elif(protocol_type == ProtocolType::ProtocolType_HttpSSL ||
                    protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ISslWebsocketTransmission>(context, strand, socket, host, path);
                }
                else {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    transmission = make_shared_object<ITcpipTransmission>(context, strand, socket, configuration);
                }

                if (NULLPTR != transmission) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    if (switcher) {
                        transmission->QoS = switcher->GetQoS();
                        transmission->Statistics = switcher->GetStatistics();
                    }
                }
                
                return transmission;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetExchanger::NewAsynchronousSocket(const ContextPtr& context, const StrandPtr& strand, const boost::asio::ip::tcp& protocol, ppp::coroutines::YieldContext& y) noexcept {
                if (disposed_) {
                    return NULLPTR;
                }

                if (!context) {
                    return NULLPTR;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
                if (!socket) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return NULLPTR;
                }

                if (!ppp::coroutines::asio::async_open(y, *socket, protocol)) {
                    return NULLPTR;
                }

                Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                Socket::AdjustSocketOptional(*socket, protocol == boost::asio::ip::tcp::v4(), configuration->tcp.fast_open, configuration->tcp.turbo);
                return socket;
            }

            bool VEthernetExchanger::GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                if (disposed_) {
                    return false;
                }

                if (server_url_.port > IPEndPoint::MinPort && server_url_.port <= IPEndPoint::MaxPort) {
                    remoteEP      = server_url_.remoteEP;
                    hostname      = server_url_.hostname;
                    address       = server_url_.address;
                    path          = server_url_.path;
                    server        = server_url_.server;
                    port          = server_url_.port;
                    protocol_type = server_url_.protocol_type;
                    return true;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                ppp::string& client_server_string = configuration->client.server;
                if (client_server_string.empty()) {
                    return false;
                }

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                std::shared_ptr<ppp::transmissions::proxys::IForwarding> forwarding;
                if (switcher) {
                    forwarding = switcher->GetForwarding();
                }
                if (NULLPTR != forwarding) {
                    ppp::string abs_url;
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, &abs_url, *y, false);
                }
                else {
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, *y);
                }

                if (server.empty()) {
                    return false;
                }

                if (hostname.empty()) {
                    return false;
                }

                if (NULLPTR != forwarding) {
                    boost::asio::ip::tcp::endpoint forwarding_to_endpoint = forwarding->GetLocalEndPoint();
                    if (int forwarding_to_port = forwarding_to_endpoint.port(); forwarding_to_port > IPEndPoint::MinPort && forwarding_to_port < IPEndPoint::MaxPort) {
                        forwarding->SetRemoteEndPoint(hostname, port);
                        port = forwarding_to_port;
                        address = forwarding_to_endpoint.address().to_string();
                    }
                }

                if (address.empty()) {
                    return false;
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    return false;
                }

                IPEndPoint ipep(address.data(), port);
                if (IPEndPoint::IsInvalid(ipep)) {
                    return false;
                }

                remoteEP                  = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep);
                server_url_.remoteEP      = remoteEP;
                server_url_.hostname      = hostname;
                server_url_.address       = address;
                server_url_.path          = path;
                server_url_.server        = server;
                server_url_.port          = port;
                server_url_.protocol_type = protocol_type;
                return true;
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::OpenTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept {
                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                if (!GetRemoteEndPoint(y.GetPtr(), hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return NULLPTR;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (IPEndPoint::IsInvalid(remoteIP)) {
                    return NULLPTR;
                }

                int remotePort = remoteEP.port();
                if (remotePort <= IPEndPoint::MinPort || remotePort > IPEndPoint::MaxPort) {
                    return NULLPTR;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = NewAsynchronousSocket(context, strand, remoteEP.protocol(), y);
                if (!socket) {
                    return NULLPTR;
                }

#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter.
                // IPV6 does not need to be linked, because VPN is IPV4,
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (remoteIP.is_v4() && !remoteIP.is_loopback()) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    if (switcher) {
                        auto protector_network = switcher->GetProtectorNetwork();
                        if (NULLPTR != protector_network) {
                            if (!protector_network->Protect(socket->native_handle(), y)) {
                                return NULLPTR;
                            }
                        }
                    }
                }
#endif

                bool ok = ppp::coroutines::asio::async_connect(*socket, remoteEP, y);
                if (!ok) {
                    return NULLPTR;
                }

                return NewTransmission(context, strand, socket, protocol_type, hostname, path);
            }

            bool VEthernetExchanger::Open() noexcept {
                if (disposed_) {
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                ContextPtr context = GetContext();
                if (!context) {
                    return false;
                }

                auto self = shared_from_this();
                auto allocator = configuration->GetBufferAllocator();

                if (!port_mapping_manager_) {
                    auto exchanger = std::static_pointer_cast<VEthernetExchanger>(shared_from_this());
                    port_mapping_manager_ = make_shared_object<PortMappingManager>(exchanger, configuration, context);
                }

                return YieldContext::Spawn(allocator.get(), *context,
                    [self, this, context](YieldContext& y) noexcept {
                        Loopback(context, y);
                    });
            }

            bool VEthernetExchanger::Update() noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context,
                    [self, this, context]() noexcept {
                        uint64_t now = ppp::threading::Executors::GetTickCount();
                        SendEchoKeepAlivePacket(now, false);
                        DoMuxEvents();
                        DoKeepAlived(GetTransmission(), now);

                        for (;;) {
                            SynchronizedObjectScope scope(syncobj_datagrams_);
                            Dictionary::UpdateAllObjects(datagrams_, now);
                            break;
                        }

                        for (;;) {
                            SynchronizedObjectScope scope(syncobj_);
                            if (port_mapping_manager_) {
                                port_mapping_manager_->UpdateAllMappings(now);
                            }
                            break;
                        }
                    });
                return true;
            }

            bool VEthernetExchanger::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                if (disposed_) {
                    return false;
                }
                
                NetworkState network_state = GetNetworkState();
                if (network_state != NetworkState_Established) {
                    return true;
                }

                if (VirtualEthernetLinklayer::DoKeepAlived(transmission, now)) {
                    return true;
                }

                IDisposable::Dispose(transmission);
                return false;
            }

            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::ConnectTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y) noexcept {
                if (NULLPTR == context) {
                    return NULLPTR;
                }

                if (disposed_) {
                    return NULLPTR;
                }

                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                ITransmissionPtr owner_link = transmission_; 
                if (NULLPTR == owner_link) {
                    return NULLPTR;
                }

                ITransmissionPtr transmission = OpenTransmission(context, strand, y);
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                bool noerror = transmission->HandshakeServer(y, GetId(), false);
                if (noerror) {
                    return transmission;
                }
                else {
                    transmission->Dispose();
                    return NULLPTR;
                }
            }

#if defined(_ANDROID)
            bool VEthernetExchanger::AwaitJniAttachThread(const ContextPtr& context, YieldContext& y) noexcept {
                // On the Android platform, when the VPN tunnel transport layer is enabled,
                // Ensure that the JVM thread has been attached to the PPP. Otherwise, the link cannot be protected,
                // Resulting in loop problems and VPN loopback crashes.
                bool attach_ok = false;
                while (!disposed_) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    if (switcher) {
                        if (std::shared_ptr<ppp::net::ProtectorNetwork> protector = switcher->GetProtectorNetwork(); NULLPTR != protector) {
                            if (NULLPTR != protector->GetContext() && NULLPTR != protector->GetEnvironment()) {
                                attach_ok = true;
                                break;
                            }
                        }
                    }
                    else {
                        break;
                    }

                    bool sleep_ok = Sleep(10, context, y); // Poll.
                    if (!sleep_ok) {
                        break;
                    }
                }

                return attach_ok;
            }
#endif

            bool VEthernetExchanger::Loopback(const ContextPtr& context, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }
#if defined(_ANDROID)
                elif(!AwaitJniAttachThread(context, y)) {
                    return false;
                }
#endif
                bool run_once = false;
                while (!disposed_) {
                    ExchangeToConnectingState(); {
                        ITransmissionPtr transmission = OpenTransmission(context, y);
                        if (transmission) {
                            if (transmission->HandshakeServer(y, GetId(), true) && EchoLanToRemoteExchanger(transmission, y) > -1) {
                                ExchangeToEstablishState(); {
                                    transmission_ = transmission; {
                                        if (port_mapping_manager_) {
                                            port_mapping_manager_->RegisterAllMappingPorts();
                                        }
                                        if (StaticEchoAllocatedToRemoteExchanger(y) && Run(transmission, y)) {
                                            run_once = true;
                                            StaticEchoClean();
                                        }

                                        if (port_mapping_manager_) {
                                            port_mapping_manager_->UnregisterAllMappingPorts();
                                        }
                                    }
                                    transmission_.reset();
                                }
                            }

                            transmission->Dispose();
                            transmission.reset();
                        }
                    } ExchangeToReconnectingState();

                    int64_t reconnection_timeout = static_cast<int64_t>(configuration->client.reconnections.timeout) * 1000;
                    Sleep(reconnection_timeout, context, y);
                }
                return run_once;
            }

            bool VEthernetExchanger::DoMuxEvents() noexcept {
                bool successes = false;
                while (!disposed_) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    if (!switcher) {
                        break;
                    }

                    uint16_t max_connections = switcher->mux_;
                    if (max_connections == 0) {
                        break;
                    }

                    if (network_state_.load() != NetworkState_Established) {
                        break;
                    }

                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULLPTR == configuration) {
                        break;
                    }

                    std::shared_ptr<vmux::vmux_net> mux = mux_;
                    if (NULLPTR != mux) {
                        bool breaking = true;
                        successes = true;

                        if (mux->Vlan != mux_vlan_) {
                            mux->close_exec();
                        }
                        elif(!mux->update()) {
                            int64_t reconnection_timeout = static_cast<int64_t>(configuration->client.reconnections.timeout) * 1000;
                            uint64_t mux_last = mux->get_last();

                            uint64_t now = mux->now_tick();
                            if (now >= (mux_last + (uint64_t)reconnection_timeout)) {
                                mux_.reset();
                                breaking = false;
                            }

                            mux->close_exec();
                        }

                        if (breaking) {
                            break;
                        }
                    }

                    ppp::threading::Executors::StrandPtr vmux_strand;
                    ppp::threading::Executors::ContextPtr vmux_context = ppp::threading::Executors::SelectScheduler(vmux_strand);
                    if (NULLPTR == vmux_context) {
                        break;
                    }
                    else {
                        mux = make_shared_object<vmux::vmux_net>(vmux_context, vmux_strand, max_connections, false, (switcher->mux_acceleration_ & PPP_MUX_ACCELERATION_LOCAL) != 0);
                        if (NULLPTR == mux) {
                            break;
                        }
                    }

                    ITransmissionPtr vnet_transmission = GetTransmission();
                    if (NULLPTR == vnet_transmission) {
                        break;
                    }

                    ppp::threading::Executors::ContextPtr vnet_context = GetContext();
                    if (NULLPTR == vnet_context) {
                        break;
                    }

                    std::shared_ptr<ppp::threading::BufferswapAllocator> buffer_allocator = switcher->GetBufferAllocator();
                    mux->AppConfiguration = configuration;
                    mux->BufferAllocator  = buffer_allocator;
#if defined(_LINUX)
                    mux->ProtectorNetwork = switcher->GetProtectorNetwork();
#endif

                    for (;;) {
                        uint16_t vlan = (uint16_t)vmux::vmux_net::ftt_random_aid(1, UINT16_MAX);
                        if (vlan != 0 && vlan != mux_vlan_) {
                            mux_vlan_ = vlan;
                            mux->Vlan = vlan;
                            break;
                        }
                    }

                    std::shared_ptr<VirtualEthernetLinklayer> self = shared_from_this();
                    mux_ = mux;

                    uint8_t mux_acceleration = switcher->mux_acceleration_;
                    successes = YieldContext::Spawn(buffer_allocator.get(), *vnet_context,
                        [self, this, vnet_transmission, mux, vnet_context, mux_acceleration](YieldContext& y) noexcept {
                            bool ok = false;
                            if (!disposed_) {
                                uint16_t max_connections = mux->get_max_connections();
                                ok = DoMux(vnet_transmission, mux->Vlan, max_connections, (mux_acceleration & PPP_MUX_ACCELERATION_REMOTE) != 0, y);
                            }

                            if (!ok) {
                                mux->close_exec();
                            }
                        });
                    break;
                }

                if (!successes) {
                    std::shared_ptr<vmux::vmux_net> mux = std::move(mux_);
                    mux_.reset();

                    if (NULLPTR != mux) {
                        mux->close_exec();
                    }
                }

                return successes;
            }

            VEthernetExchanger::NetworkState VEthernetExchanger::GetMuxNetworkState() noexcept {
                if (disposed_) {
                    return NetworkState_Reconnecting;
                }

                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULLPTR == mux) {
                    return NetworkState_Connecting;
                }

                if (mux->is_disposed()) {
                    return NetworkState_Reconnecting;
                }

                if (mux->is_established()) {
                    return NetworkState_Established;
                }

                return NetworkState_Connecting;
            }

            bool VEthernetExchanger::MuxConnectAllLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<vmux::vmux_net>& mux) noexcept {
                using ppp::app::protocol::VirtualEthernetTcpipConnection;
                
                std::shared_ptr<boost::asio::io_context> context = mux->get_context();
                if (NULLPTR == context) {
                    return false;
                }

                auto self = shared_from_this();
                auto strand = mux->get_strand();

                return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, mux, context, strand](YieldContext& y) noexcept -> bool {
                        if (disposed_ || mux != mux_) {
                            mux->close_exec();
                            return false;
                        }

                        int max_connections = mux->get_max_connections();
                        int bok_connections = 0;

                        const uint32_t& tx_seq = mux->get_tx_seq();
                        const uint32_t& rx_ack = mux->get_rx_ack();
                        if (!mux->ftt(vmux::vmux_net::ftt_random_aid(1, INT32_MAX), vmux::vmux_net::ftt_random_aid(1, INT32_MAX))) {
                            mux->close_exec();
                            return false;
                        }

                        auto context = mux->get_context();
                        auto strand = mux->get_strand();
                        
                        for (int i = 0; i < max_connections; i++) {
                            if (disposed_ || mux != mux_) {
                                bok_connections = -1;
                                break;
                            }

                            if (mux->is_established()) {
                                return true;
                            }

                            ITransmissionPtr transmission = ConnectTransmission(context, strand, y);
                            if (NULLPTR == transmission) {
                                break;
                            }

                            std::shared_ptr<boost::asio::ip::tcp::socket> default_socket;
                            std::shared_ptr<VirtualEthernetTcpipConnection> connection =
                                make_shared_object<VirtualEthernetTcpipConnection>(
                                    mux->AppConfiguration, context, strand, GetId(), default_socket);
                            if (NULLPTR == connection) {
                                break;
                            }

                            // In this lightweight and simple vmux circuit switch, seq and ack are delivered by the client, and the server and client are opposite.
                            if (!connection->ConnectMux(y, transmission, mux->Vlan, rx_ack, tx_seq)) {
                                break;
                            }

                            bool bok = mux->do_yield(y,
                                [self, mux, connection]() noexcept -> bool {
                                    vmux::vmux_net::vmux_linklayer_ptr linklayer;
                                    vmux::vmux_net::vmux_native_add_linklayer_after_success_before_callback handling;
                                    return mux->add_linklayer(connection, linklayer, handling);
                                });

                            if (!bok) {
                                break;
                            }

                            bok_connections++;
                        }

                        if (bok_connections >= max_connections) {
                            return true;
                        }

                        mux->close_exec();
                        return false;
                    });
            }

            bool VEthernetExchanger::ReleaseDeadlineTimer(const boost::asio::deadline_timer* deadline_timer) noexcept {
                if (NULLPTR == deadline_timer) {
                    return false;
                }

                DeadlineTimerPtr reference;
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    Dictionary::TryRemove(deadline_timers_, (void*)deadline_timer, reference);
                    break;
                }

                if (NULLPTR == reference) {
                    return false;
                }

                Socket::Cancel(*reference);
                return true;
            }

            bool VEthernetExchanger::NewDeadlineTimer(const ContextPtr& context, int64_t timeout, const ppp::function<void(bool)>& event) noexcept {
                std::shared_ptr<boost::asio::deadline_timer> t = make_shared_object<boost::asio::deadline_timer>(*context);
                if (NULLPTR == t) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }
                else {
                    timeout = std::max<int64_t>(1, timeout);
                }

                auto self = shared_from_this();
                boost::asio::deadline_timer* deadline_timer = t.get();

                t->expires_from_now(Timer::DurationTime(timeout));
                t->async_wait(
                    [self, this, deadline_timer, event](const boost::system::error_code& ec) noexcept {
                        ReleaseDeadlineTimer(deadline_timer);
                        event(ec == boost::system::errc::success);
                    });

                auto r = deadline_timers_.emplace(deadline_timer, std::move(t));
                if (r.second) {
                    return true;
                }

                Socket::Cancel(*t);
                return false;
            }

            void VEthernetExchanger::ExchangeToEstablishState() noexcept {
                uint64_t now = Executors::GetTickCount();
                sekap_last_ = Executors::GetTickCount();
                sekap_next_ = now + RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT, SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT);
                network_state_.exchange(NetworkState_Established);
                reconnection_count_ = 0;
            }

            void VEthernetExchanger::ExchangeToConnectingState() noexcept {
                sekap_last_ = 0;
                sekap_next_ = 0;
                network_state_.exchange(NetworkState_Connecting);
            }

            void VEthernetExchanger::ExchangeToReconnectingState() noexcept {
                sekap_last_ = 0;
                sekap_next_ = 0;
                network_state_.exchange(NetworkState_Reconnecting);
                reconnection_count_++;
            }

            bool VEthernetExchanger::OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                // For the client, LAN traffic should be allowed normally.
                // The server handles subnet configuration and ARP.
                return true;
            }

            bool VEthernetExchanger::OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (!switcher) {
                    return false;
                }

                bool vnet = switcher->IsVNet();
                if (vnet) {
                    return switcher->Output(packet, packet_length);
                }
                else {
                    return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
                }
            }

            bool VEthernetExchanger::OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept {
                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULLPTR != mux) {
                    bool successed = false;
                    if (vlan != 0 && max_connections > 0 && mux->Vlan == vlan && max_connections == mux->get_max_connections() && !mux->is_disposed()) {
                        bool established = mux->is_established();
                        successed = true;

                        if (!established) {
                            auto configuration = GetConfiguration();
                            auto allocator = configuration->GetBufferAllocator();
                        
                            successed = MuxConnectAllLinklayers(allocator, mux);
                        }
                    }
                    
                    if (!successed) {
                        mux->close_exec();
                    }
                }

                return true;
            }

            bool VEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULLPTR == context) {
                    return false;
                }

                auto ei = make_shared_object<VirtualEthernetInformation>(information);
                if (NULLPTR == ei) {
                    return false;
                }

                auto self = shared_from_this();
                boost::asio::post(*context,
                    [self, this, context, ei]() noexcept {
                        information_ = ei;
                        if (!disposed_) {
                            std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                            if (switcher) {
                                switcher->OnInformation(ei);
                            }
                        }
                    });
                return true;
            }

            bool VEthernetExchanger::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                return false; // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept {
                if (remote_port < IPEndPoint::MinPort || remote_port > IPEndPoint::MaxPort) {
                    return false;
                }

                if (session_id < 0) {
                    return false;
                }

                // If the server does not support static tunneling, clean up the pre-prepared resources.
                if (remote_port == IPEndPoint::MinPort || session_id == 0) {
                    StaticEchoClean();
                }
                else {
                    if (static_echo_tunnel_) {
                        static_echo_tunnel_->SetSessionId(session_id);
                        static_echo_tunnel_->SetRemotePort(remote_port);

                        AppConfigurationPtr configuration = GetConfiguration();
                        VirtualEthernetPacket::Ciphertext(configuration, GetId(), fsid, session_id, static_echo_protocol_, static_echo_transport_);
                    }
                }

                StaticEchoGatewayServer(StaticEchoTunnel::STATIC_ECHO_KEEP_ALIVED_ID);
                return true;
            }

            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                if (ack_id != 0) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    if (switcher) {
                        switcher->ERORTE(ack_id);
                    }
                }

                return true;
            }

            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (switcher) {
                    switcher->Output(packet, packet_length);
                }
                return true;
            }

            bool VEthernetExchanger::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                ReceiveFromDestination(sourceEP, destinationEP, packet, packet_length);
                return true;
            }

            bool VEthernetExchanger::ReceiveFromDestination(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length) noexcept {
                if (disposed_) {
                    return false;
                }

                VEthernetDatagramPortPtr datagram = GetDatagramPort(sourceEP);
                if (NULLPTR != datagram) {
                    if (NULLPTR != packet && packet_length > 0) {
                        datagram->OnMessage(packet, packet_length, destinationEP);
                    }
                    else {
                        datagram->MarkFinalize();
                        datagram->Dispose();
                    }
                }
                elif(NULLPTR != packet && packet_length > 0) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    if (switcher) {
                        switcher->DatagramOutput(sourceEP, destinationEP, packet, packet_length);
                    }
                }

                return true;
            }

            bool VEthernetExchanger::SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                VEthernetDatagramPortPtr datagram = AddNewDatagramPort(transmission, sourceEP);
                if (NULLPTR == datagram) {
                    return false;
                }

                return datagram->SendTo(packet, packet_size, destinationEP);
            }

            bool VEthernetExchanger::Echo(int ack_id) noexcept {
                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                bool ok = DoEcho(transmission, ack_id, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            bool VEthernetExchanger::Echo(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                bool ok = DoEcho(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            bool VEthernetExchanger::Nat(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return false;
                }

                bool ok = DoNat(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            int VEthernetExchanger::EchoLanToRemoteExchanger(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_) {
                    return -1;
                }

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (!switcher) {
                    return -1;
                }

                bool vnet = switcher->IsVNet();
                if (!vnet) {
                    return 0;
                }

                if (NULLPTR == transmission) {
                    return -1;
                }

                std::shared_ptr<ppp::tap::ITap> tap = switcher->GetTap();
                if (NULLPTR == tap) {
                    return -1;
                }

                bool ok = DoLan(transmission, tap->IPAddress, tap->SubmaskAddress, y);
                if (ok) {
                    return 1;
                }

                transmission->Dispose();
                return -1;
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::AddNewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (disposed_) {
                    return NULLPTR;
                }

                auto my = shared_from_this();
                std::shared_ptr<VEthernetExchanger> exchanger
                    = std::dynamic_pointer_cast<VEthernetExchanger>(my);

                VEthernetDatagramPortPtr datagram_port = make_shared_object<VEthernetDatagramPort>(exchanger, transmission, sourceEP);
                if (NULLPTR == datagram_port) {
                    return NULLPTR;
                }

                SynchronizedObjectScope scope(syncobj_datagrams_);
                datagrams_[sourceEP] = datagram_port;
                return datagram_port;
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto my = shared_from_this();
                std::shared_ptr<VEthernetExchanger> exchanger
                    = std::dynamic_pointer_cast<VEthernetExchanger>(my);

                VEthernetDatagramPortPtr datagram_port = make_shared_object<VEthernetDatagramPort>(exchanger, transmission, sourceEP);
                if (NULLPTR == datagram_port) {
                    return NULLPTR;
                }

                SynchronizedObjectScope scope(syncobj_datagrams_);
                datagrams_[sourceEP] = datagram_port;
                return datagram_port;
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                SynchronizedObjectScope scope(syncobj_datagrams_);
                auto iter = datagrams_.find(sourceEP);
                if (iter != datagrams_.end()) {
                    return iter->second;
                }
                return NULLPTR;
            }

            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                SynchronizedObjectScope scope(syncobj_datagrams_);
                auto iter = datagrams_.find(sourceEP);
                if (iter != datagrams_.end()) {
                    VEthernetDatagramPortPtr datagram_port = iter->second;
                    datagrams_.erase(iter);
                    return datagram_port;
                }
                return NULLPTR;
            }

            bool VEthernetExchanger::SendEchoKeepAlivePacket(UInt64 now, bool immediately) noexcept {
                if (network_state_ != NetworkState_Established) {
                    return false;
                }

                UInt64 next = sekap_last_ + SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT;
                if (now >= next) {
                    ITransmissionPtr transmission = transmission_;
                    if (transmission) {
                        transmission->Dispose();
                        return false;
                    }
                }

                if (!immediately) {
                    if (now < sekap_next_) {
                        return false;
                    }
                }

                sekap_next_ = now + RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT, SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT);
                return Echo(0);
            }

            bool VEthernetExchanger::PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept {
                bool successed = VirtualEthernetLinklayer::PacketInput(transmission, p, packet_length, y);
                if (successed) {
                    if (network_state_ == NetworkState_Established) {
                        sekap_last_ = Executors::GetTickCount();
                    }
                }

                return successed;
            }

            bool VEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (port_mapping_manager_) {
                    return port_mapping_manager_->OnFrpSendTo(transmission, in, remote_port, sourceEP, packet, packet_length, y);
                }
                return false;
            }

            bool VEthernetExchanger::OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
                if (port_mapping_manager_) {
                    return port_mapping_manager_->OnFrpConnect(transmission, connection_id, in, remote_port, y);
                }
                return false;
            }

            bool VEthernetExchanger::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                if (port_mapping_manager_) {
                    return port_mapping_manager_->OnFrpDisconnect(transmission, connection_id, in, remote_port);
                }
                return false;
            }

            bool VEthernetExchanger::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept {
                if (port_mapping_manager_) {
                    return port_mapping_manager_->OnFrpPush(transmission, connection_id, in, remote_port, packet, packet_length);
                }
                return false;
            }

            void VEthernetExchanger::StaticEchoClean() noexcept {
                if (static_echo_tunnel_) {
                    static_echo_tunnel_->Clean();
                }
            }

            bool VEthernetExchanger::StaticEchoAllocated() noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->Allocated();
                }
                return false;
            }

            bool VEthernetExchanger::StaticEchoSwapAsynchronousSocket() noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->SwapAsynchronousSocket();
                }
                return false;
            }

            bool VEthernetExchanger::StaticEchoGatewayServer(int ack_id) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->GatewayServer(ack_id);
                }
                return false;
            }

            bool VEthernetExchanger::StaticEchoAllocatedToRemoteExchanger(YieldContext& y) noexcept {
                StaticEchoClean();
                if (disposed_) {
                    return false;
                }

                if (StaticEchoAllocated()) {
                    return true;
                }

                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULLPTR == context) {
                    return false;
                }

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (!switcher) {
                    return false;
                }

                bool static_mode = switcher->StaticMode(NULLPTR);
                if (!static_mode) {
                    return true;
                }

                // Create the StaticEchoTunnel object if it doesn't exist
                if (!static_echo_tunnel_) {
                    AppConfigurationPtr configuration = GetConfiguration();
                    if (NULLPTR == configuration) {
                        return false;
                    }

                    static_echo_tunnel_ = make_shared_object<StaticEchoTunnel>(
                        switcher,
                        configuration,
                        context,
                        buffer_,
                        static_echo_protocol_,
                        static_echo_transport_,
                        server_url_.remoteEP,
                        server_url_.port,
                        server_url_.protocol_type
                    );
                    if (NULLPTR == static_echo_tunnel_) {
                        return false;
                    }
                }

                return static_echo_tunnel_->AllocatedToRemoteExchanger(y);
            }

            bool VEthernetExchanger::StaticEchoNextTimeout() noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->NextTimeout();
                }
                return false;
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->PacketToRemoteExchanger(packet);
                }
                return false;
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->PacketToRemoteExchanger(frame);
                }
                return false;
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->PacketToRemoteExchanger(packet, packet_length);
                }
                return false;
            }

            std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket> VEthernetExchanger::StaticEchoReadPacket(const void* packet, int packet_length) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->ReadPacket(packet, packet_length);
                }
                return NULLPTR;
            }

            bool VEthernetExchanger::StaticEchoPacketInput(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->PacketInput(packet);
                }
                return false;
            }

            int VEthernetExchanger::StaticEchoYieldReceiveForm(Byte* incoming_packet, int incoming_traffic) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->YieldReceiveForm(incoming_packet, incoming_traffic);
                }
                return incoming_traffic;
            }

            bool VEthernetExchanger::Sleep(int64_t timeout, const ContextPtr& context, YieldContext& y) noexcept {
                using atomic_int = std::atomic<int>;

                std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                if (NULLPTR == status) {
                    return false;
                }

                auto self = shared_from_this();
                context->post(
                    [self, this, context, timeout, status, &y]() noexcept {
                        bool ok = NewDeadlineTimer(context, timeout, 
                            [status, &y](bool b) noexcept {
                                ppp::coroutines::asio::R(y, *status, b);
                            });
                        
                        if (!ok) {
                            ppp::coroutines::asio::R(y, *status, false);
                        }
                    });

                y.Suspend();
                return status->load() > 0;
            }
            
            bool VEthernetExchanger::StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->AddRemoteEndPoint(remoteEP);
                }
                return false;
            }

            boost::asio::ip::udp::endpoint VEthernetExchanger::StaticEchoGetRemoteEndPoint() noexcept {
                if (static_echo_tunnel_) {
                    return static_echo_tunnel_->GetRemoteEndPoint();
                }
                return boost::asio::ip::udp::endpoint();
            }

        }
    }
}