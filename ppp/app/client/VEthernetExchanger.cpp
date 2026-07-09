#include <ppp/configurations/AppConfiguration.h>
#include <ppp/transmissions/proxys/IForwarding.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetDatagramPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/diagnostics/LinkTelemetry.h>
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
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include <chrono>

#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

/**
 * @file VEthernetExchanger.cpp
 * @brief Client-side virtual Ethernet exchanger implementation.
 * @details Licensed under GPL-3.0.
 */

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
            using ppp::telemetry::Level;
            /** @brief Minimum keepalive echo interval in milliseconds. */
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT = 1000;
            /** @brief Maximum keepalive echo interval in milliseconds. */
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT = 5000;
            /** @brief Hard timeout threshold before keepalive is considered stale. */
#if defined(_IPHONE) || defined(_ANDROID)
            // Mobile OS may freeze the VPN process in background; use a longer
            // stale threshold so a Doze wake does not immediately dispose the
            // main transmission (iOS Packet Tunnel already relied on 120s).
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT = 120000;
#else
            static constexpr int SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT = SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT << 2;
#endif
#if defined(_IPHONE)
            // Under ctcp load the io_context may not service the main transmission read
            // loop for tens of seconds while hundreds of per-flow handshakes run.
            // mux=0 opens one server TCP+handshake per TUN flow; cap to stay inside NE memory.
            static constexpr int IOS_CHILD_TRANSMISSION_LIMIT = 96;
            // Soft mark for telemetry only; uploads can legitimately queue above this.
            static constexpr int IOS_CHILD_CONNECT_WAITER_SOFT_LIMIT = 96;
            // Absolute emergency cap for callers that bypass BeginAcceptClient() backpressure.
            static constexpr int IOS_CHILD_CONNECT_WAITER_BURST_LIMIT = 192;
            static constexpr int IOS_CHILD_SLOT_WAIT_INTERVAL_MS = 25;
            static constexpr int IOS_CHILD_SLOT_WAIT_MAX_MS = 15000;
#endif
            const char* TransmissionRoleName(ppp::transmissions::TcpTransmissionRole role) noexcept {
                switch (role) {
                case ppp::transmissions::TcpTransmissionRole::Main:
                    return "main";
                case ppp::transmissions::TcpTransmissionRole::Server:
                    return "server";
                case ppp::transmissions::TcpTransmissionRole::Child:
                default:
                    return "child";
                }
            }

            /** @brief Reserved ACK identifier used for static-echo keepalive signaling. */
            static constexpr int STATIC_ECHO_KEEP_ALIVED_ID              = IPEndPoint::NoneAddress - 1;

            /** @brief Constructs exchanger and initializes optional static-echo ciphers. */
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
                , network_state_(NetworkState_Connecting)
                , static_echo_input_(false)
                , static_echo_timeout_(UINT64_MAX)
                , static_echo_session_id_(0)
                , static_echo_remote_port_(IPEndPoint::MinPort) {

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
                static_echo_.Bind(this);
            }

            /** @brief Finalizes exchanger on destruction. */
            VEthernetExchanger::~VEthernetExchanger() noexcept {
                Finalize();
            }

            /** @brief Sends requested IPv6/IPv4 information extensions to the remote endpoint. */
            bool VEthernetExchanger::SendRequestedIPv6Configuration(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (NULLPTR == transmission || NULLPTR == configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                VirtualEthernetInformationExtensions request;
                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_;
                boost::system::error_code ec;
                if (switcher && !switcher->RequestedIPv6().empty()) {
                    boost::asio::ip::address address = StringToAddress(switcher->RequestedIPv6(), ec);
                    if (!ec && address.is_v6()) {
                        request.RequestedIPv6Address = address;
                    }
                }

                // Hint fallback: if no explicit RequestedIPv6() preference was configured,
                // but a previous session successfully applied an IPv6 address, re-request that
                // same address so the server can honour address continuity on reconnect.
                if (!request.HasAny() && switcher) {
                    boost::asio::ip::address hint = switcher->LastAssignedIPv6();
                    if (hint.is_v6()) {
                        request.RequestedIPv6Address = hint;
                    }
                }

                // Only send the newer INFO extension request when the local profile explicitly
                // opts into server-side IPv4 allocation. Older servers treat any client-originated
                // extended INFO packet as invalid, so the default mobile/static-TUN path stays
                // on the legacy handshake.
                if (configuration->server.ipv4_pool.configured) {
                    ppp::app::protocol::ClientIPv4Request ipv4_req;
                    ipv4_req.enabled = true;

                    bool is_static = switcher && switcher->StaticMode(NULLPTR);
                    if (is_static && switcher) {
                        std::shared_ptr<ppp::tap::ITap> tap = switcher->GetTap();
                        if (NULLPTR != tap && tap->IPAddress != IPEndPoint::AnyAddress && tap->IPAddress != IPEndPoint::NoneAddress) {
                            ipv4_req.mode = "manual";
                            ipv4_req.address = Ipep::ToAddress(tap->IPAddress).to_string();
                            ipv4_req.gateway = Ipep::ToAddress(tap->GatewayServer).to_string();
                            ipv4_req.mask = Ipep::ToAddress(tap->SubmaskAddress).to_string();
                        }
                        else {
                            ipv4_req.mode = "auto";
                        }
                    }
                    else {
                        ipv4_req.mode = "auto";
                    }

                    request.ClientIPv4Req = ipv4_req;
                }

                if (configuration->p2p.enabled) {
                    request.P2P.enabled = true;
                    request.P2P.mode = configuration->p2p.mode;
                    request.P2P.action = "register";
                    if (switcher) {
                        std::shared_ptr<ppp::tap::ITap> tap = switcher->GetTap();
                        if (NULLPTR != tap) {
                            request.P2P.virtual_ip = tap->IPAddress;
                        }
                    }
                }

                if (!configuration->client.peer_route_announce.empty()) {
                    request.PeerRouteAnnounce.enabled = true;
                    request.PeerRouteAnnounce.action = "register";
                    for (const auto& item : configuration->client.peer_route_announce) {
                        ppp::app::protocol::PeerPrefixRouteEntry entry;
                        entry.network = item.network;
                        entry.prefix = item.prefix;
                        request.PeerRouteAnnounce.prefixes.emplace_back(std::move(entry));
                    }
                }

                if (!request.HasAny()) {
                    return true;
                }

                InformationEnvelope envelope;
                envelope.Base.Clear();
                envelope.Extensions = request;
                envelope.ExtendedJson = request.ToJson();
                return DoInformation(transmission, envelope, y);
            }

            /** @brief Disposes and releases all owned runtime objects. */
            void VEthernetExchanger::Finalize() noexcept {
                /** @brief One-shot guard: only the first caller proceeds with cleanup. */
                if (disposed_.exchange(true, std::memory_order_acq_rel)) {
                    return;
                }

                VirtualEthernetMappingPortTable mappings;
                VEthernetDatagramPortTable datagrams;
                ITransmissionPtr transmission;
                DeadlineTimerTable deadline_timers;
                std::shared_ptr<vmux::vmux_net> mux;

                /** @brief Atomically swaps internal tables/resources before releasing outside lock. */
                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);

                    mappings = std::move(mappings_);
                    mappings_.clear();

                    datagrams = std::move(datagrams_);
                    datagrams_.clear();

                    deadline_timers = std::move(deadline_timers_);
                    deadline_timers_.clear();

                    mux_vlan_ = 0;
                    mux = std::move(mux_);
                    transmission = std::move(transmission_);
                    break;
                }

                static_echo_.StaticEchoClean();
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

                for (auto&& [_, deadline_timer] : deadline_timers) {
                    ppp::net::Socket::Cancel(*deadline_timer);
                }

                Dictionary::ReleaseAllObjects(mappings);
                Dictionary::ReleaseAllObjects(datagrams);

                ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger finalized");

                if (NULLPTR != mux) {
                    mux->close_exec();
                }
            }

            /** @brief Posts exchanger finalization to execution context. */
            void VEthernetExchanger::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context,
                    [self, this, context]() noexcept {
                        Finalize();
                    });
            }

            template <typename TTransmission>
            typename std::enable_if<std::is_base_of<ITransmission, TTransmission>::value, std::shared_ptr<TTransmission>>::type
            VEthernetExchanger::NewWebsocketTransmission(
                const ContextPtr& context,
                const StrandPtr& strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                const ppp::string& host,
                const ppp::string& path) noexcept {

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

            template std::shared_ptr<IWebsocketTransmission> VEthernetExchanger::NewWebsocketTransmission<IWebsocketTransmission>(
                const ContextPtr& context,
                const StrandPtr& strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                const ppp::string& host,
                const ppp::string& path) noexcept;

            template std::shared_ptr<ISslWebsocketTransmission> VEthernetExchanger::NewWebsocketTransmission<ISslWebsocketTransmission>(
                const ContextPtr& context,
                const StrandPtr& strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
                const ppp::string& host,
                const ppp::string& path) noexcept;

            /** @brief Creates a transport object based on selected protocol type. */
            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::NewTransmission(
                const ContextPtr&                                                   context,
                const StrandPtr&                                                    strand,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&                socket,
                ProtocolType                                                        protocol_type,
                const ppp::string&                                                  host,
                const ppp::string&                                                  path,
                ppp::transmissions::TcpTransmissionRole                             role) noexcept {

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
                    transmission = make_shared_object<ITcpipTransmission>(context, strand, socket, configuration, role);
                }

                if (NULLPTR != transmission) {
                    transmission->QoS = switcher_->GetQoS();
                    transmission->Statistics = switcher_->GetStatistics();
                    ppp::telemetry::Log(Level::kDebug, "client_exchanger", "transmission created: protocol=%d role=%s",
                        (int)protocol_type,
                        TransmissionRoleName(role));
                }

                return transmission;
            }

            /** @brief Creates and configures an asynchronous TCP socket. */
            std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetExchanger::NewAsynchronousSocket(const ContextPtr& context, const StrandPtr& strand, const boost::asio::ip::tcp& protocol, ppp::coroutines::YieldContext& y) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                if (!context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand ?
                    make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
                if (!socket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                if (!configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                if (!ppp::coroutines::asio::async_open(y, *socket, protocol)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketOpenFailed, std::shared_ptr<boost::asio::ip::tcp::socket>(NULLPTR));
                }

                Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                Socket::AdjustSocketOptional(*socket, protocol == boost::asio::ip::tcp::v4(), configuration->tcp.fast_open, configuration->tcp.turbo);
                return socket;
            }

            /** @brief Resolves, validates, and caches the remote server endpoint. */
            bool VEthernetExchanger::GetRemoteEndPoint(YieldContext* y, ppp::string& hostname, ppp::string& address, ppp::string& path, int& port, ProtocolType& protocol_type, ppp::string& server, boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
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
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                }

                ppp::string& client_server_string = configuration->client.server;
                if (client_server_string.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                std::shared_ptr<ppp::transmissions::proxys::IForwarding> forwarding = switcher_->GetForwarding(); ;
                if (NULLPTR != forwarding) {
                    ppp::string abs_url;
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, &abs_url, *y, false);
                }
                else {
                    server = UriAuxiliary::Parse(client_server_string, hostname, address, path, port, protocol_type, *y);
                }

                if (server.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                if (hostname.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                ppp::telemetry::Count("client_exchanger.dns.resolve", 1);
                ppp::telemetry::Log(Level::kDebug, "client_exchanger", "dns resolved: %s", hostname.c_str());

                if (NULLPTR != forwarding) {
                    ppp::string session_guid = StringAuxiliary::Int128ToGuidString(GetId());
                    ppp::telemetry::SpanScope span("client.proxy.setup", session_guid.c_str());
                    struct ScopedProxySetupHistogram final {
                        std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

                        ~ScopedProxySetupHistogram() noexcept {
                            int64_t elapsed = static_cast<int64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                            ppp::telemetry::Histogram("client.proxy.setup.us", elapsed);
                        }
                    } proxy_setup_histogram;

                    boost::asio::ip::tcp::endpoint forwarding_to_endpoint = forwarding->GetLocalEndPoint();
                    if (int forwarding_to_port = forwarding_to_endpoint.port(); forwarding_to_port > IPEndPoint::MinPort && forwarding_to_port <= IPEndPoint::MaxPort) {
                        forwarding->SetRemoteEndPoint(hostname, port);
                        port = forwarding_to_port;
                        address = forwarding_to_endpoint.address().to_string();
                        ppp::telemetry::Count("client_exchanger.proxy.setup", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger", "proxy forwarding setup: %s:%d", hostname.c_str(), port);
                    }
                }

                if (address.empty()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "network port invalid in GetRemoteEndPoint port=%d server=%s hostname=%s address=%s", port, client_server_string.c_str(), hostname.c_str(), address.c_str());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                IPEndPoint ipep(address.data(), port);
                if (IPEndPoint::IsInvalid(ipep)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
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

            /** @brief Opens a transport connection to current remote endpoint. */
            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::OpenTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y, ppp::transmissions::TcpTransmissionRole role) noexcept {
                boost::asio::ip::tcp::endpoint remoteEP;
                ppp::string hostname;
                ppp::string address;
                ppp::string path;
                ppp::string server;
                int port = IPEndPoint::MinPort;
                ProtocolType protocol_type = ProtocolType::ProtocolType_PPP;

                if (!GetRemoteEndPoint(y.GetPtr(), hostname, address, path, port, protocol_type, server, remoteEP)) {
                    return NULLPTR;
                }

                boost::asio::ip::address remoteIP = remoteEP.address();
                if (IPEndPoint::IsInvalid(remoteIP)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                int remotePort = remoteEP.port();
                if (remotePort <= IPEndPoint::MinPort || remotePort > IPEndPoint::MaxPort) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "network port invalid in OpenTransmission remote_port=%d server=%s hostname=%s address=%s", remotePort, server.c_str(), hostname.c_str(), address.c_str());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = NewAsynchronousSocket(context, strand, remoteEP.protocol(), y);
                if (!socket) {
                    return NULLPTR;
                }

#if defined(_LINUX)
                // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter.
                // IPV6 does not need to be linked, because VPN is IPV4,
                // And IPV6 does not affect the physical layer network communication of the VPN.
                if (!remoteIP.is_loopback()) {
                    auto protector_network = switcher_->GetProtectorNetwork();
                    if (NULLPTR != protector_network) {
                        if (!protector_network->Protect(socket->native_handle(), y)) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                        }
                    }
                }
#endif

                ppp::telemetry::Count("client_exchanger.connect.attempt", 1);
                ppp::telemetry::Log(Level::kInfo, "client_exchanger", "tcp connecting: %s:%d address=%s", hostname.c_str(), remotePort, remoteIP.to_string().c_str());

                bool ok = ppp::coroutines::asio::async_connect(*socket, remoteEP, y);
                if (!ok) {
                    ppp::telemetry::Count("client_exchanger.connect.fail.tcp", 1);
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "tcp connect failed: %s:%d address=%s error=%d", hostname.c_str(), remotePort, remoteIP.to_string().c_str(), (int)ppp::diagnostics::ErrorCode::TcpConnectFailed);
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TcpConnectFailed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                ppp::telemetry::Log(Level::kInfo, "client_exchanger", "tcp connected: %s:%d role=%s", hostname.c_str(), remotePort, TransmissionRoleName(role));
                return NewTransmission(context, strand, socket, protocol_type, hostname, path, role);
            }

            /** @brief Starts main asynchronous exchanger loop. */
            bool VEthernetExchanger::Open() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                }

                ContextPtr context = GetContext();
                if (!context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto self = shared_from_this();
                auto allocator = configuration->GetBufferAllocator();

                return YieldContext::Spawn(allocator.get(), *context,
                    [self, this, context](YieldContext& y) noexcept {
                        Loopback(context, y);
                    });
            }

            /** @brief Schedules periodic maintenance tasks on exchanger context. */
            bool VEthernetExchanger::Update() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context,
                    [self, this, context]() noexcept {
                        static thread_local VEthernetExchanger* in_update_owner = NULLPTR;
                        if (NULLPTR != in_update_owner) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TCPLinkDeadlockDetected);
                            return;
                        }

                        in_update_owner = this;
                        struct UpdateScope final {
                            VEthernetExchanger*& owner;

                            ~UpdateScope() noexcept {
                                owner = NULLPTR;
                            }
                        } update_scope{ in_update_owner };

                        uint64_t now = ppp::threading::Executors::GetTickCount();
                        SendEchoKeepAlivePacket(now, false);
                        DoMuxEvents();
                        DoKeepAlived(GetTransmission(), now);

                        ppp::vector<std::pair<boost::asio::ip::udp::endpoint, VEthernetDatagramPortPtr>> datagram_candidates;
                        ppp::vector<std::pair<uint32_t, VirtualEthernetMappingPortPtr>> mapping_candidates;
                        ppp::vector<std::pair<boost::asio::ip::udp::endpoint, VEthernetDatagramPortPtr>> stale_datagram_candidates;
                        ppp::vector<std::pair<uint32_t, VirtualEthernetMappingPortPtr>> stale_mapping_candidates;
                        ppp::vector<VEthernetDatagramPortPtr> stale_datagrams;
                        ppp::vector<VirtualEthernetMappingPortPtr> stale_mappings;

                        for (;;) {
                            SynchronizedObjectScope scope(syncobj_);

                            for (auto&& kv : datagrams_) {
                                datagram_candidates.emplace_back(kv.first, kv.second);
                            }

                            for (auto&& kv : mappings_) {
                                mapping_candidates.emplace_back(kv.first, kv.second);
                            }

                            break;
                        }

                        for (auto&& kv : datagram_candidates) {
                            VEthernetDatagramPortPtr& datagram = kv.second;
                            if (NULLPTR == datagram || datagram->IsPortAging(now)) {
                                stale_datagram_candidates.emplace_back(kv.first, datagram);
                            }
                        }

                        for (auto&& kv : mapping_candidates) {
                            VirtualEthernetMappingPortPtr& mapping = kv.second;
                            if (NULLPTR == mapping || !mapping->Update(now)) {
                                stale_mapping_candidates.emplace_back(kv.first, mapping);
                            }
                        }

                        for (;;) {
                            SynchronizedObjectScope scope(syncobj_);

                            for (auto&& stale_datagram_candidate : stale_datagram_candidates) {
                                auto&& object_key = stale_datagram_candidate.first;
                                auto tail = datagrams_.find(object_key);
                                auto endl = datagrams_.end();
                                if (tail == endl || tail->second != stale_datagram_candidate.second) {
                                    continue;
                                }

                                VEthernetDatagramPortPtr datagram = std::move(tail->second);
                                datagrams_.erase(tail);
                                if (NULLPTR != datagram) {
                                    stale_datagrams.emplace_back(std::move(datagram));
                                }
                            }

                            for (auto&& stale_mapping_candidate : stale_mapping_candidates) {
                                auto&& object_key = stale_mapping_candidate.first;
                                auto tail = mappings_.find(object_key);
                                auto endl = mappings_.end();
                                if (tail == endl || tail->second != stale_mapping_candidate.second) {
                                    continue;
                                }

                                VirtualEthernetMappingPortPtr mapping = std::move(tail->second);
                                mappings_.erase(tail);
                                if (NULLPTR != mapping) {
                                    stale_mappings.emplace_back(std::move(mapping));
                                }
                            }

                            break;
                        }

                        for (auto&& datagram : stale_datagrams) {
                            IDisposable::Dispose(*datagram);
                        }

                        for (auto&& mapping : stale_mappings) {
                            IDisposable::Dispose(*mapping);
                        }
                    });
                return true;
            }

            /** @brief Executes keepalive timeout logic for established state. */
            bool VEthernetExchanger::DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
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

            /** @brief Connects and handshakes a child transmission for mux use. */
            VEthernetExchanger::ITransmissionPtr VEthernetExchanger::ConnectTransmission(const ContextPtr& context, const StrandPtr& strand, YieldContext& y, uint64_t* ios_child_slot_generation) noexcept {
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                ITransmissionPtr owner_link = transmission_;
                if (NULLPTR == owner_link) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                }

#if defined(_IPHONE)
                const bool ios_child_slot = (NULLPTR != ios_child_slot_generation);
                uint64_t ios_reserved_generation = 0;
                if (NULLPTR != ios_child_slot_generation) {
                    *ios_child_slot_generation = 0;
                }
                if (ios_child_slot) {
                    if (!TryReserveIosChildTransmissionSlot(context, y, ios_reserved_generation)) {
                        if (disposed_.load(std::memory_order_acquire)) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                        }

                        ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                        if (code == ppp::diagnostics::ErrorCode::Success) {
                            code = ppp::diagnostics::ErrorCode::SessionQuotaExceeded;
                        }

                        return ppp::diagnostics::SetLastError(code, VEthernetExchanger::ITransmissionPtr(NULLPTR));
                    }
                }
#endif

                ITransmissionPtr transmission = OpenTransmission(context, strand, y, ppp::transmissions::TcpTransmissionRole::Child);
                if (NULLPTR == transmission) {
#if defined(_IPHONE)
                    if (ios_child_slot) {
                        ReleaseIosChildTransmissionSlot(ios_reserved_generation);
                    }
#endif
                    return NULLPTR;
                }

                bool noerror = transmission->HandshakeServer(y, GetId(), false);
                if (noerror) {
#if defined(_IPHONE)
                    if (ios_child_slot && NULLPTR != ios_child_slot_generation) {
                        *ios_child_slot_generation = ios_reserved_generation;
                    }
#endif
                    return transmission;
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                    transmission->Dispose();
#if defined(_IPHONE)
                    if (ios_child_slot) {
                        ReleaseIosChildTransmissionSlot(ios_reserved_generation);
                    }
#endif
                    return NULLPTR;
                }
            }

#if defined(_IPHONE)
            bool VEthernetExchanger::IosPeerConnectBackpressured() const noexcept {
                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULLPTR != mux && mux->is_established()) {
                    return false;
                }

                return ios_child_connect_waiters_.load(std::memory_order_relaxed) >= IOS_CHILD_CONNECT_WAITER_BURST_LIMIT;
            }

            void VEthernetExchanger::ResetIosChildTransmissionSlots(const char* reason) noexcept {
                int stale_active = 0;
                uint64_t generation = 0;
                {
                    std::lock_guard<std::mutex> lock(ios_child_slots_mutex_);
                    stale_active = ios_child_transmission_active_.exchange(0, std::memory_order_acq_rel);
                    generation = ios_child_slot_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
                }
                if (stale_active > 0) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                        "ios child slots reset reason=%s stale_active=%d generation=%llu",
                        (NULLPTR != reason && reason[0] != '\0') ? reason : "unknown",
                        stale_active,
                        (unsigned long long)generation);
                }
            }

            void VEthernetExchanger::ReleaseIosChildTransmissionSlot(uint64_t generation) noexcept {
                if (generation == 0) {
                    return;
                }

                std::lock_guard<std::mutex> lock(ios_child_slots_mutex_);
                uint64_t current_generation = ios_child_slot_generation_.load(std::memory_order_acquire);
                if (generation != current_generation) {
                    ppp::telemetry::Log(Level::kDebug, "client_exchanger",
                        "ios child slot stale release ignored generation=%llu current=%llu active=%d",
                        (unsigned long long)generation,
                        (unsigned long long)current_generation,
                        ios_child_transmission_active_.load(std::memory_order_acquire));
                    return;
                }

                int active = ios_child_transmission_active_.load(std::memory_order_acquire);
                if (active <= 0) {
                    ios_child_transmission_active_.store(0, std::memory_order_release);
                    return;
                }
                ios_child_transmission_active_.store(active - 1, std::memory_order_release);
            }

            bool VEthernetExchanger::TryReserveIosChildTransmissionSlot(const ContextPtr& context, YieldContext& y, uint64_t& generation) noexcept {
                generation = 0;
                ios_child_connect_waiters_.fetch_add(1, std::memory_order_relaxed);
                struct WaiterGuard final {
                    std::atomic<int>& counter;
                    bool released = false;
                    ~WaiterGuard() noexcept {
                        if (!released) {
                            counter.fetch_sub(1, std::memory_order_relaxed);
                        }
                    }
                } waiter_guard{ios_child_connect_waiters_};

                int waited_ms = 0;
                for (;;) {
                    if (disposed_.load(std::memory_order_acquire)) {
                        return false;
                    }

                    if (GetNetworkState() != NetworkState_Established) {
                        return false;
                    }

                    if (NULLPTR == transmission_) {
                        return false;
                    }

                    const int waiters = ios_child_connect_waiters_.load(std::memory_order_relaxed);
                    int active = 0;
                    {
                        std::lock_guard<std::mutex> lock(ios_child_slots_mutex_);
                        active = ios_child_transmission_active_.load(std::memory_order_acquire);
                        if (active < IOS_CHILD_TRANSMISSION_LIMIT) {
                            ios_child_transmission_active_.store(active + 1, std::memory_order_release);
                            generation = ios_child_slot_generation_.load(std::memory_order_acquire);
                            waiter_guard.released = true;
                            ios_child_connect_waiters_.fetch_sub(1, std::memory_order_relaxed);
                            ppp::telemetry::Histogram("client_exchanger.ios_child_slot.active", active + 1);
                            if (waited_ms > 0) {
                                ppp::telemetry::Histogram("client_exchanger.ios_child_slot.wait_ms", waited_ms);
                            }
                            return true;
                        }
                    }

                    if (waiters > IOS_CHILD_CONNECT_WAITER_BURST_LIMIT) {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.waiter_rejected", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                            "ios child slot waiter burst rejected waiters=%d active=%d active_limit=%d burst_limit=%d",
                            waiters,
                            active,
                            IOS_CHILD_TRANSMISSION_LIMIT,
                            IOS_CHILD_CONNECT_WAITER_BURST_LIMIT);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                        return false;
                    }

                    if (waiters > IOS_CHILD_CONNECT_WAITER_SOFT_LIMIT) {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.wait.backpressure", 1);
                    }
                    else {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.wait", 1);
                    }

                    if (!Sleep(IOS_CHILD_SLOT_WAIT_INTERVAL_MS, context, y)) {
                        if (!disposed_.load(std::memory_order_acquire)
                            && GetNetworkState() == NetworkState_Established
                            && NULLPTR != transmission_
                            && ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                        }
                        return false;
                    }

                    waited_ms += IOS_CHILD_SLOT_WAIT_INTERVAL_MS;
                    if (waited_ms >= IOS_CHILD_SLOT_WAIT_MAX_MS) {
                        ppp::telemetry::Count("client_exchanger.ios_child_slot.wait_timeout", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                            "ios child slot wait timeout waiters=%d active=%d active_limit=%d waited_ms=%d",
                            waiters,
                            active,
                            IOS_CHILD_TRANSMISSION_LIMIT,
                            waited_ms);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                        return false;
                    }
                }
            }
#endif

#if defined(_ANDROID)
            /** @brief Waits until Android protector JNI context becomes available. */
            bool VEthernetExchanger::AwaitJniAttachThread(const ContextPtr& context, YieldContext& y) noexcept {
                // On the Android platform, when the VPN tunnel transport layer is enabled,
                // Ensure that the JVM thread has been attached to the PPP. Otherwise, the link cannot be protected,
                // Resulting in loop problems and VPN loopback crashes.
                bool attach_ok = false;
                while (!disposed_.load(std::memory_order_acquire)) {
                    if (std::shared_ptr<ppp::net::ProtectorNetwork> protector = switcher_->GetProtectorNetwork(); NULLPTR != protector) {
                        if (NULLPTR != protector->GetContext() && NULLPTR != protector->GetEnvironment()) {
                            attach_ok = true;
                            break;
                        }
                    }

                    bool sleep_ok = Sleep(10, context, y); // Poll.
                    if (!sleep_ok) {
                        break;
                    }
                }

                return attach_ok;
            }
#endif

            /** @brief Runs connect-handshake-run-reconnect loop until disposed. */
            bool VEthernetExchanger::Loopback(const ContextPtr& context, YieldContext& y) noexcept {
                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                }
#if defined(_ANDROID)
                elif(!AwaitJniAttachThread(context, y)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                }
#endif
                bool run_once = false;
                /** @brief Main lifecycle loop for connection establishment and reconnection. */
                while (!disposed_.load(std::memory_order_acquire)) {
                    ExchangeToConnectingState(); {
                        ITransmissionPtr transmission = OpenTransmission(context, y, ppp::transmissions::TcpTransmissionRole::Main);
                        if (transmission) {
                            bool established = transmission->HandshakeServer(y, GetId(), true) && EchoLanToRemoteExchanger(transmission, y) > -1;
                            if (established) {
                                transmission_ = transmission;
                                ExchangeToEstablishState(); {
                                    ppp::telemetry::Count("client_exchanger.connect", 1);
                                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger connected");
#if !defined(_ANDROID) && !defined(_IPHONE)
                                    if (std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_; NULLPTR != switcher) {
                                        if (!switcher->TryApplyHostedNetworkRoutes()) {
                                            ppp::telemetry::Log(Level::kInfo, "client_exchanger", "route setup failed after exchanger connected");
                                            ppp::telemetry::Count("client_exchanger.route_setup.fail", 1);
                                        }
                                    }
#endif
                                    if (!SendRequestedIPv6Configuration(transmission, y)) {
                                        transmission->Dispose();
                                        continue;
                                    }
                                    RegisterAllMappingPorts();
                                    ppp::telemetry::Log(Level::kInfo, "protocol", "session established role=main");
                                    bool main_run_ok = false;
                                    if (static_echo_.StaticEchoAllocatedToRemoteExchanger(y) && Run(transmission, y)) {
                                        main_run_ok = true;
                                        run_once = true;
                                        static_echo_.StaticEchoClean();
                                    }
                                    ppp::telemetry::Log(Level::kInfo, "protocol",
                                        "session disposed role=main reason=loop_end ok=%d error=%d",
                                        main_run_ok ? 1 : 0,
                                        (int)ppp::diagnostics::GetLastErrorCode());

                                    /**
                                     * @brief Link telemetry: the connection was established but has now ended.
                                     *
                                     * When Run() returns, the link has dropped — this is an unexpected
                                     * interruption from the tunnel's perspective (the underlying transport
                                     * returned EOF or an error).  Record as a fault.
                                     *
                                     * Note: Clean FIN with 0-byte payload that leads to Run() returning
                                     * is still counted as a fault here because the tunnel link itself was
                                     * interrupted, not a single TCP connection within the tunnel.
                                     */
                                    link_telemetry_.RecordFault();
                                    ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().RecordFault();

                                    ppp::telemetry::Count("client_exchanger.disconnect", 1);
                                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger disconnecting");
                                    UnregisterAllMappingPorts();
                                }
                                transmission_.reset();
#if defined(_IPHONE)
                                ResetIosChildTransmissionSlots("main_transmission_end");
#endif
                            }
                            else {
                                ppp::telemetry::Count("client_exchanger.connect.fail.handshake", 1);
                                ppp::telemetry::Log(Level::kInfo, "client_exchanger", "exchanger handshake failed error=%d", (int)ppp::diagnostics::GetLastErrorCode());
                            }

                            transmission->Dispose();
                        }
                        else {
                            ppp::telemetry::Count("client_exchanger.connect.fail.open_transmission", 1);
                            ppp::telemetry::Log(Level::kInfo, "client_exchanger", "open transmission failed error=%d", (int)ppp::diagnostics::GetLastErrorCode());
                        }
                    }
                    ExchangeToReconnectingState();

                    int64_t reconnection_timeout = static_cast<int64_t>(configuration->client.reconnections.timeout) * 1000;
                    Sleep(reconnection_timeout, context, y);
                }
                return run_once;
            }

            /** @brief Maintains vmux session and negotiates mux when required. */
            bool VEthernetExchanger::DoMuxEvents() noexcept {
                bool successes = false;
                while (!disposed_.load(std::memory_order_acquire)) {
                    uint16_t max_connections = switcher_->mux_;
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
                            // turbo dynamic pool: if the quality controller asked to
                            // grow, connect that many extra carrier links at runtime
                            // and attach each through add_linklayer's established-
                            // session path (single-link, single forwarding coroutine).
                            if (mux->is_established()) {
                                int grow = mux->take_turbo_pending_grow();
                                if (grow > 0) {
                                    MuxGrowLinklayers(switcher_->GetBufferAllocator(), mux, grow);
                                }
                            }
                            break;
                        }
                    }

                    ppp::threading::Executors::StrandPtr vmux_strand;
                    ppp::threading::Executors::ContextPtr vmux_context = ppp::threading::Executors::SelectScheduler(vmux_strand);
                    if (NULLPTR == vmux_context) {
                        break;
                    }
                    else {
                        vmux::vmux_net::mux_mode mux_mode = vmux::vmux_net::parse_mode(configuration->GetEffectiveMuxMode());
                        mux = make_shared_object<vmux::vmux_net>(vmux_context, vmux_strand, max_connections, false, (switcher_->mux_acceleration_ & PPP_MUX_ACCELERATION_LOCAL) != 0, mux_mode);
                        if (NULLPTR == mux) {
                            break;
                        }

                        // turbo dynamic pool: raise the carrier-link ceiling to
                        // base * PPP_MUX_TURBO_FACTOR_MAX so the quality controller
                        // can grow the pool past --tun-mux under poor quality. The
                        // base (max_connections) is still what is established and
                        // negotiated on the wire; growth happens at runtime.
                        if (mux_mode == vmux::vmux_net::mux_mode_flow &&
                            NULLPTR != configuration && configuration->mux.turbo) {
                            uint32_t hard = (uint32_t)max_connections * (uint32_t)PPP_MUX_TURBO_FACTOR_MAX;
                            if (hard > UINT16_MAX) {
                                hard = UINT16_MAX;
                            }
                            mux->set_pool_hard_max((uint16_t)hard);
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

                    std::shared_ptr<ppp::threading::BufferswapAllocator> buffer_allocator = switcher_->GetBufferAllocator();
                    mux->AppConfiguration = configuration;
                    mux->BufferAllocator  = buffer_allocator;
#if defined(_LINUX)
                    mux->ProtectorNetwork = switcher_->GetProtectorNetwork();
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

                    successes = YieldContext::Spawn(buffer_allocator.get(), *vnet_context,
                        [self, this, vnet_transmission, mux, vnet_context, configuration](YieldContext& y) noexcept {
                            bool ok = false;
                            if (!disposed_.load(std::memory_order_acquire)) {
                                uint16_t max_connections = mux->get_max_connections();
                                // Advertise per-flow (flow v2) receiver ordering when the active
                                // scheduler configuration needs it (balance/stripe, or flow+turbo).
                                // The server echoes the agreed result in its MUX reply (see OnMux);
                                // negotiation is an intersection, so an older peer transparently
                                // falls back to compat.
                                bool advertise_flow_v2 = vmux::vmux_net::mode_requires_flow_v2(
                                    mux->get_mode(), NULLPTR != configuration && configuration->mux.turbo);
                                Byte ordering_caps = advertise_flow_v2
                                    ? (Byte)vmux::vmux_net::ordering_caps_flow_v2 : (Byte)0;
                                ok = DoMux(vnet_transmission, mux->Vlan, max_connections, (switcher_->mux_acceleration_ & PPP_MUX_ACCELERATION_REMOTE) != 0, ordering_caps, y);
                            }

                            if (!ok) {
                                mux->close_exec();
                            }
                        });
                    break;
                }

                if (!successes) {
                    std::shared_ptr<vmux::vmux_net> mux = std::move(mux_);
                    if (NULLPTR != mux) {
                        mux->close_exec();
                    }
                }

                return successes;
            }

            /** @brief Derives mux state from current vmux runtime object. */
            VEthernetExchanger::NetworkState VEthernetExchanger::GetMuxNetworkState() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
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

            /** @brief Establishes all required vmux child linklayers. */
            bool VEthernetExchanger::MuxConnectAllLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<vmux::vmux_net>& mux) noexcept {
                using ppp::app::protocol::VirtualEthernetTcpipConnection;

                std::shared_ptr<boost::asio::io_context> context = mux->get_context();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto self = shared_from_this();
                auto strand = mux->get_strand();

                return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, mux, context, strand](YieldContext& y) noexcept -> bool {
                        if (disposed_.load(std::memory_order_acquire) || mux != mux_) {
                            mux->close_exec();
                            return false;
                        }

                        int max_connections = mux->get_max_connections();
                        int bok_connections = 0;

                        const uint32_t& tx_seq = mux->get_tx_seq();
                        const uint32_t& rx_ack = mux->get_rx_ack();
                        if (!mux->ftt(vmux::vmux_net::ftt_random_aid(1, INT32_MAX), vmux::vmux_net::ftt_random_aid(1, INT32_MAX))) {
                            mux->close_exec();
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        }

                        auto context = mux->get_context();
                        auto strand = mux->get_strand();

                        for (int i = 0; i < max_connections; i++) {
                            if (disposed_.load(std::memory_order_acquire) || mux != mux_) {
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
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                                break;
                            }

                            // In this lightweight and simple vmux circuit switch, seq and ack are delivered by the client, and the server and client are opposite.
                            if (!connection->ConnectMux(y, transmission, mux->Vlan, rx_ack, tx_seq)) {
                                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                                }
                                break;
                            }

                            bool bok = mux->do_yield(y,
                                [self, mux, connection]() noexcept -> bool {
                                    vmux::vmux_net::vmux_linklayer_ptr linklayer;
                                    vmux::vmux_net::vmux_native_add_linklayer_after_success_before_callback handling;
                                    return mux->add_linklayer(connection, linklayer, handling);
                                });

                            if (!bok) {
                                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                                }
                                break;
                            }

                            bok_connections++;
                        }

                        if (bok_connections >= max_connections) {
                            return true;
                        }

                        mux->close_exec();
                        if (!disposed_.load(std::memory_order_acquire) && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        }
                        return false;
                    });
            }

            /** @brief Connects `count` extra carrier links at runtime (turbo grow, C-B3 caller). */
            bool VEthernetExchanger::MuxGrowLinklayers(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<vmux::vmux_net>& mux, int count) noexcept {
                using ppp::app::protocol::VirtualEthernetTcpipConnection;

                if (NULLPTR == mux || count <= 0) {
                    return false;
                }

                std::shared_ptr<boost::asio::io_context> context = mux->get_context();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto self = shared_from_this();
                auto strand = mux->get_strand();

                return YieldContext::Spawn(allocator.get(), *context, strand.get(),
                    [self, this, mux, count, context, strand](YieldContext& y) noexcept -> bool {
                        // Grow is best-effort and non-fatal: a failed extra link must
                        // never tear down the established base pool. Stop on the first
                        // failure and leave the existing links untouched.
                        const uint32_t& tx_seq = mux->get_tx_seq();
                        const uint32_t& rx_ack = mux->get_rx_ack();

                        for (int i = 0; i < count; i++) {
                            if (disposed_.load(std::memory_order_acquire) || mux != mux_ || mux->is_disposed()) {
                                break;
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

                            if (!connection->ConnectMux(y, transmission, mux->Vlan, rx_ack, tx_seq)) {
                                break;
                            }

                            bool bok = mux->do_yield(y,
                                [self, mux, connection]() noexcept -> bool {
                                    vmux::vmux_net::vmux_linklayer_ptr linklayer;
                                    vmux::vmux_net::vmux_native_add_linklayer_after_success_before_callback handling;
                                    // The mux strand enforces the runtime hard ceiling.
                                    // add_linklayer detects the established session and
                                    // attaches this as a single runtime link (one
                                    // forwarding coroutine; no batch re-spawn).
                                    return mux->add_linklayer(connection, linklayer, handling);
                                });

                            if (!bok) {
                                break;
                            }
                        }

                        return true;
                    });
            }

            /** @brief Removes a deadline timer from tracking table and cancels it. */
            bool VEthernetExchanger::ReleaseDeadlineTimer(const boost::asio::steady_timer* deadline_timer) noexcept {
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

            /** @brief Creates and tracks one asynchronous deadline timer. */
            bool VEthernetExchanger::NewDeadlineTimer(const ContextPtr& context, int64_t timeout, const ppp::function<void(bool)>& event) noexcept {
                std::shared_ptr<boost::asio::steady_timer> t = make_shared_object<boost::asio::steady_timer>(*context);
                if (NULLPTR == t) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_.load(std::memory_order_acquire)) {
                    return false;
                }
                else {
                    timeout = std::max<int64_t>(1, timeout);
                }

                auto self = shared_from_this();
                boost::asio::steady_timer* deadline_timer = t.get();

                t->expires_after(Timer::DurationTime(timeout));
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
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
            }

            /** @brief Transitions state to established and initializes keepalive schedule. */
            void VEthernetExchanger::ExchangeToEstablishState() noexcept {
                uint64_t now = Executors::GetTickCount();
                sekap_last_ = now;
                sekap_next_ = now + RandomNext(SEND_ECHO_KEEP_ALIVE_PACKET_MIN_TIMEOUT, SEND_ECHO_KEEP_ALIVE_PACKET_MAX_TIMEOUT);
                network_state_.exchange(NetworkState_Established);
                reconnection_count_ = 0;
            }

            /** @brief Transitions state to connecting. */
            void VEthernetExchanger::ExchangeToConnectingState() noexcept {
                sekap_last_ = 0;
                sekap_next_ = 0;
                network_state_.exchange(NetworkState_Connecting);
            }

            /** @brief Transitions state to reconnecting and increments retry count. */
            void VEthernetExchanger::ExchangeToReconnectingState() noexcept {
                sekap_last_ = 0;
                sekap_next_ = 0;
                network_state_.exchange(NetworkState_Reconnecting);
                reconnection_count_++;
#if defined(_IPHONE)
                ResetIosChildTransmissionSlots("reconnecting");
#endif
            }

            /** @brief Registers all configured FRP mapping ports. */
            bool VEthernetExchanger::RegisterAllMappingPorts() noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                AppConfigurationPtr configuration = GetConfiguration();
                for (ppp::configurations::MappingConfiguration& mapping : configuration->client.mappings) {
                    RegisterMappingPort(mapping);
                }

                return true;
            }

            /** @brief Unregisters and disposes all FRP mapping ports. */
            void VEthernetExchanger::UnregisterAllMappingPorts() noexcept {
                VirtualEthernetMappingPortTable mappings; {
                    SynchronizedObjectScope scope(syncobj_);
                    mappings = std::move(mappings_);
                    mappings_.clear();
                }

                ppp::collections::Dictionary::ReleaseAllObjects(mappings);
            }

            /** @brief Rejects unsolicited LAN messages for security hardening. */
            bool VEthernetExchanger::OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Forwards NAT payload from remote side to local switcher output. */
            bool VEthernetExchanger::OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                if (NULLPTR == switcher_) {
                    return false;
                }

                AppConfigurationPtr configuration = GetConfiguration();
                if (NULLPTR != configuration && !configuration->client.peer_gateway_forward) {
                    ppp::net::native::ip_hdr* ip = ppp::net::native::ip_hdr::Parse(packet, packet_length);
                    if (NULLPTR == ip) {
                        return false;
                    }

                    std::shared_ptr<ppp::tap::ITap> tap = switcher_->GetTap();
                    if (NULLPTR == tap) {
                        return false;
                    }

                    if (ip->dest != tap->IPAddress) {
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger", "peer gateway forward rejected");
                        ppp::telemetry::Count("client.peer_gateway_forward.rejected", 1);
                        return false;
                    }
                }

                return switcher_->Output(packet, packet_length);
            }

            /** @brief Handles mux negotiation callback and starts vmux linking. */
            bool VEthernetExchanger::OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, Byte ordering_caps, YieldContext& y) noexcept {
                std::shared_ptr<vmux::vmux_net> mux = mux_;
                if (NULLPTR != mux) {
                    bool successed = false;
                    if (vlan != 0 && max_connections > 0 && mux->Vlan == vlan && max_connections == mux->get_max_connections() && !mux->is_disposed()) {
                        bool established = mux->is_established();
                        successed = true;

                        if (!established) {
                            auto configuration = GetConfiguration();
                            auto allocator = configuration->GetBufferAllocator();

                            // Apply the negotiated receiver ordering mode (flow v2) before linking.
                            // The server echoes the agreed capability in its MUX reply; agreed
                            // FLOW_V2 requires this end to also need it — i.e. an active scheduler
                            // configuration that uses per-flow ordering (balance/stripe, or
                            // flow+turbo). Fail-safe: any mismatch or older peer falls back to
                            // compat global ordering.
                            bool local_supports_flow_v2 = vmux::vmux_net::mode_requires_flow_v2(
                                mux->get_mode(), NULLPTR != configuration && configuration->mux.turbo);
                            bool agreed_flow_v2 = local_supports_flow_v2 && ((ordering_caps & vmux::vmux_net::ordering_caps_flow_v2) != 0);
                            mux->set_ordering_mode(agreed_flow_v2 ? vmux::vmux_net::ordering_flow_v2 : vmux::vmux_net::ordering_compat);

                            successed = MuxConnectAllLinklayers(allocator, mux);
                        }
                    }

                    if (!successed) {
                        mux->close_exec();
                    }
                }

                return true;
            }

            /** @brief Adapts base information payload to extended envelope handler. */
            bool VEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept {
                InformationEnvelope envelope;
                envelope.Base = information;
                return OnInformation(transmission, envelope, y);
            }

            /** @brief Updates cached information and notifies network switcher. */
            bool VEthernetExchanger::OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept {
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                if (NULLPTR == context) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                }

                auto ei = make_shared_object<VirtualEthernetInformation>(information.Base);
                if (NULLPTR == ei) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                auto self = shared_from_this();
                boost::asio::post(*context,
                    [self, this, context, ei, information]() noexcept {
                        information_ = ei;
                        if (!disposed_.load(std::memory_order_acquire)) {
                            switcher_->OnInformation(ei, information.Extensions);
                        }
                    });
                return true;
            }

            /** @brief Rejects unsolicited push events for security hardening. */
            bool VEthernetExchanger::OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsolicited connect events for security hardening. */
            bool VEthernetExchanger::OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsolicited connect-ack events for security hardening. */
            bool VEthernetExchanger::OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsolicited disconnect events for security hardening. */
            bool VEthernetExchanger::OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Rejects unsupported static callback variant. */
            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid); // Immediate return false and forcefully close the connection due to a suspected malicious attack on the client.
            }

            /** @brief Applies static session parameters received from server. */
            bool VEthernetExchanger::OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept {
                if (remote_port < IPEndPoint::MinPort || remote_port > IPEndPoint::MaxPort) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                }

                if (session_id < 0) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                }

                // If the server does not support static tunneling, clean up the pre-prepared resources.
                if (remote_port == IPEndPoint::MinPort || session_id == 0) {
                    static_echo_.StaticEchoClean();
                }
                else {
                    static_echo_session_id_ = session_id;
                    static_echo_remote_port_ = remote_port;

                    AppConfigurationPtr configuration = GetConfiguration();
                    VirtualEthernetPacket::Ciphertext(configuration, GetId(), fsid, session_id, static_echo_protocol_, static_echo_transport_);
                }

                StaticEchoGatewayServer(STATIC_ECHO_KEEP_ALIVED_ID);
                return true;
            }

            /** @brief Handles ACK echo callback from server. */
            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept {
                if (ack_id != 0) {
                    switcher_->ERORTE(ack_id);
                }

                return true;
            }

            /** @brief Handles packet echo callback from server. */
            bool VEthernetExchanger::OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept {
                switcher_->Output(packet, packet_length);
                return true;
            }

            /** @brief Handles UDP callback packet delivered by remote exchanger. */
            bool VEthernetExchanger::OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
                ReceiveFromDestination(sourceEP, destinationEP, packet, packet_length);
                return true;
            }

            /** @brief Routes inbound UDP payload to matching datagram port or switcher. */
            bool VEthernetExchanger::ReceiveFromDestination(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return false;
                }

                if (NULLPTR != packet && packet_length > 0) {
                    if (TryHandleDatagram(sourceEP, destinationEP, packet, packet_length)) {
                        return true;
                    }
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
                    switcher_->DatagramOutput(sourceEP, destinationEP, packet, packet_length);
                }

                return true;
            }

            /** @brief Sends UDP packet using source-bound datagram relay port. */
            bool VEthernetExchanger::SendTo(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                VEthernetDatagramPortPtr datagram = AddNewDatagramPort(transmission, sourceEP);
                if (NULLPTR == datagram) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "UDP mapping failed source=%s:%u destination=%s:%u",
                        sourceEP.address().to_string().c_str(),
                        sourceEP.port(),
                        destinationEP.address().to_string().c_str(),
                        destinationEP.port());
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::UdpMappingFailed);
                }

                bool ok = datagram->SendTo(packet, packet_size, destinationEP);
                if (destinationEP.port() == PPP_DNS_SYS_PORT || !ok) {
                    ppp::telemetry::Log(Level::kInfo, "client_exchanger", "UDP datagram send source=%s:%u destination=%s:%u bytes=%d ok=%d error=%d",
                        sourceEP.address().to_string().c_str(),
                        sourceEP.port(),
                        destinationEP.address().to_string().c_str(),
                        destinationEP.port(),
                        packet_size,
                        ok ? 1 : 0,
                        (int)ppp::diagnostics::GetLastErrorCode());
                }
                return ok;
            }

            /** @brief Registers a local datagram reply handler for a specific source endpoint. */
            bool VEthernetExchanger::RegisterDatagramHandler(const boost::asio::ip::udp::endpoint& sourceEP, const DatagramPacketHandler& handler) noexcept {
                if (!handler) {
                    return false;
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                SynchronizedObjectScope scope(syncobj_);
                datagram_handlers_[sourceEP] = handler;
                return true;
            }

            /** @brief Removes a local datagram reply handler. */
            bool VEthernetExchanger::ReleaseDatagramHandler(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                bool removed = false;
                VEthernetDatagramPortPtr datagram;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    removed = datagram_handlers_.erase(sourceEP) > 0;
                    datagram = Dictionary::ReleaseObjectByKey(datagrams_, sourceEP);
                }

                if (NULLPTR != datagram) {
                    datagram->MarkFinalize();
                    datagram->Dispose();
                }

                return removed;
            }

            /** @brief Dispatches a datagram reply to a registered local handler before TAP injection. */
            bool VEthernetExchanger::TryHandleDatagram(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size) noexcept {
                DatagramPacketHandler handler;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = datagram_handlers_.find(sourceEP);
                    if (tail != datagram_handlers_.end()) {
                        handler = tail->second;
                    }
                }

                if (!handler) {
                    return false;
                }

                return handler(sourceEP, destinationEP, packet, packet_size);
            }

            /** @brief Sends ACK-based keepalive/echo packet through active transport. */
            bool VEthernetExchanger::Echo(int ack_id) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                bool ok = DoEcho(transmission, ack_id, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            /** @brief Sends packet-based echo payload through active transport. */
            bool VEthernetExchanger::Echo(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                bool ok = DoEcho(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            /** @brief Sends NAT payload packet through active transport. */
            bool VEthernetExchanger::Nat(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPacketMalformed);
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                bool ok = DoNat(transmission, (Byte*)packet, packet_size, nullof<YieldContext>());
                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            /** @brief Announces local LAN information to remote exchanger when needed. */
            int VEthernetExchanger::EchoLanToRemoteExchanger(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                bool vnet = switcher_->IsVNet();
                if (!vnet) {
                    return 0;
                }

                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                }

                std::shared_ptr<ppp::tap::ITap> tap = switcher_->GetTap();
                if (NULLPTR == tap) {
                    return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }

                bool ok = DoLan(transmission, tap->IPAddress, tap->SubmaskAddress, y);
                if (ok) {
                    return 1;
                }

                transmission->Dispose();
                return ppp::diagnostics::SetLastError<int>(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
            }

            /** @brief Creates and registers datagram relay port for source endpoint. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::AddNewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetExchanger::VEthernetDatagramPortPtr(NULLPTR));
                }

                VEthernetDatagramPortPtr datagram = GetDatagramPort(sourceEP);
                if (NULLPTR != datagram) {
                    return datagram;
                }

                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed, VEthernetExchanger::VEthernetDatagramPortPtr(NULLPTR));
                }

                bool ok = true;
                datagram = NewDatagramPort(transmission, sourceEP);

                if (NULLPTR == datagram) {
                    ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                    if (ppp::diagnostics::ErrorCode::Success == code) {
                        code = ppp::diagnostics::ErrorCode::MemoryAllocationFailed;
                    }

                    return ppp::diagnostics::SetLastError(code, VEthernetExchanger::VEthernetDatagramPortPtr(NULLPTR));
                }
                else {
                    SynchronizedObjectScope scope(syncobj_);
                    auto r = datagrams_.emplace(sourceEP, datagram);
                    ok = r.second;
                }

                if (!ok) {
                    datagram->Dispose();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict, VEthernetExchanger::VEthernetDatagramPortPtr(NULLPTR));
                }

                return datagram;
            }

            /** @brief Allocates a new datagram relay port object. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == transmission) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetExchanger::VEthernetDatagramPortPtr(NULLPTR));
                }

                auto my = shared_from_this();
                std::shared_ptr<VEthernetExchanger> exchanger
                    = std::dynamic_pointer_cast<VEthernetExchanger>(my);

                return make_shared_object<VEthernetDatagramPort>(exchanger, transmission, sourceEP);
            }

            /** @brief Returns datagram relay port by source endpoint key. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::FindObjectByKey(datagrams_, sourceEP);
            }

            /** @brief Removes and returns datagram relay port by source endpoint key. */
            VEthernetExchanger::VEthernetDatagramPortPtr VEthernetExchanger::ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::ReleaseObjectByKey(datagrams_, sourceEP);
            }

            /** @brief Sends scheduled keepalive echo and handles stale-link timeout. */
            bool VEthernetExchanger::SendEchoKeepAlivePacket(UInt64 now, bool immediately) noexcept {
                if (network_state_ != NetworkState_Established) {
                    return false;
                }

                UInt64 next = sekap_last_ + SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT;
                if (now >= next) {
                    ITransmissionPtr transmission = transmission_;
                    if (transmission) {
#if defined(_IPHONE)
                        if (NULLPTR == mux_
                            && ios_child_transmission_active_.load(std::memory_order_acquire) > 0) {
                            sekap_last_ = now;
                            ppp::telemetry::Count("client_exchanger.keepalive.defer_children", 1);
                            return false;
                        }
#endif
                        ppp::telemetry::Count("client_exchanger.keepalive.timeout", 1);
                        ppp::telemetry::Log(Level::kInfo, "client_exchanger",
                            "echo keepalive stale disposing transmission silence_ms=%llu threshold_ms=%d",
                            (unsigned long long)(now - sekap_last_),
                            SEND_ECHO_KEEP_ALIVE_PACKET_MMX_TIMEOUT);
                        transmission->Dispose();
#if defined(_IPHONE)
                        ResetIosChildTransmissionSlots("keepalive_stale");
#endif
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

            /** @brief Processes incoming linklayer packet and refreshes keepalive timer. */
            bool VEthernetExchanger::PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept {
                bool successed = VirtualEthernetLinklayer::PacketInput(transmission, p, packet_length, y);
                if (successed) {
                    if (network_state_ == NetworkState_Established) {
                        sekap_last_ = Executors::GetTickCount();
                    }
                }

                return successed;
            }

            /** @brief Registers one configured FRP mapping endpoint. */
            bool VEthernetExchanger::RegisterMappingPort(ppp::configurations::MappingConfiguration& mapping) noexcept {
                if (disposed_.load(std::memory_order_acquire)) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = StringToAddress(mapping.local_ip.data(), ec);
                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                boost::asio::ip::address remote_ip = StringToAddress(mapping.remote_ip.data(), ec);
                if (ec) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                }

                bool in = remote_ip.is_v4();
                bool protocol_tcp_or_udp = mapping.protocol_tcp_or_udp;

                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULLPTR != mapping_port) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                }

                mapping_port = NewMappingPort(in, protocol_tcp_or_udp, mapping.remote_port);
                if (NULLPTR == mapping_port) {
                    ppp::diagnostics::ErrorCode code = ppp::diagnostics::GetLastErrorCode();
                    if (ppp::diagnostics::ErrorCode::Success == code) {
                        code = ppp::diagnostics::ErrorCode::MemoryAllocationFailed;
                    }

                    return ppp::diagnostics::SetLastError(code);
                }

                bool ok = mapping_port->OpenFrpClient(local_ip, mapping.local_port);
                if (ok) {
                    SynchronizedObjectScope scope(syncobj_);
                    ok = VirtualEthernetMappingPort::AddMappingPort(mappings_, in, protocol_tcp_or_udp, mapping.remote_port, mapping_port);
                }

                if (!ok) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MappingOpenFailed);
                    }
                    mapping_port->Dispose();
                }

                return ok;
            }

            /** @brief Creates one FRP mapping port object bound to this exchanger. */
            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::NewMappingPort(bool in, bool tcp, int remote_port) noexcept {
                class VIRTUAL_ETHERNET_MAPPING_PORT final : public VirtualEthernetMappingPort {
                public:
                    /** @brief Constructs mapping port implementation bound to exchanger linklayer. */
                    VIRTUAL_ETHERNET_MAPPING_PORT(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                        : VirtualEthernetMappingPort(linklayer, transmission, tcp, in, remote_port) {

                    }

                public:
                    /** @brief Defers parent-table removal and then disposes base resources. */
                    virtual void Dispose() noexcept override {
                        // Defer parent-table removal so Dispose() never runs child finalization
                        // while the exchanger lock is held.
                        if (std::shared_ptr<VirtualEthernetLinklayer> linklayer = GetLinklayer(); NULLPTR != linklayer) {
                            if (std::shared_ptr<VEthernetExchanger> exchanger = std::dynamic_pointer_cast<VEthernetExchanger>(linklayer); NULLPTR != exchanger) {
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
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionTransportMissing, VEthernetExchanger::VirtualEthernetMappingPortPtr(NULLPTR));
                }

                auto self = shared_from_this();
                return make_shared_object<VIRTUAL_ETHERNET_MAPPING_PORT>(self, transmission, tcp, in, remote_port);
            }

            /** @brief Returns FRP mapping port by direction/protocol/port key. */
            VEthernetExchanger::VirtualEthernetMappingPortPtr VEthernetExchanger::GetMappingPort(bool in, bool tcp, int remote_port) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return VirtualEthernetMappingPort::FindMappingPort(mappings_, in, tcp, remote_port);
            }

            /** @brief Dispatches FRP UDP payload callback to mapped client port. */
            bool VEthernetExchanger::OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept {
#if defined(_ANDROID)
                AppConfigurationPtr configuration = GetConfiguration();
                if (!configuration) {
                    return false;
                }

                std::shared_ptr<Byte> packet_managed = ppp::net::asio::IAsynchronousWriteIoQueue::Copy(configuration->GetBufferAllocator(), packet, packet_length);
                Post(
                    [this, packet_managed, sourceEP, packet_length, in, remote_port]() noexcept {
                        VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                        if (NULLPTR != mapping_port) {
                            mapping_port->Client_OnFrpSendTo(packet_managed.get(), packet_length, sourceEP);
                        }
                    });
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, false, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpSendTo(packet, packet_length, sourceEP);
                }
#endif
                return true;
            }

            /** @brief Dispatches FRP TCP connect callback to mapped client port. */
            bool VEthernetExchanger::OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept {
#if defined(_ANDROID)
                Post(
                    [this, in, remote_port, connection_id]() noexcept {
                        VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                        if (NULLPTR != mapping_port) {
                            mapping_port->Client_OnFrpConnect(connection_id);
                        }
                    });
#else
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpConnect(connection_id);
                }
#endif
                return true;
            }

            /** @brief Dispatches FRP TCP disconnect callback to mapped client port. */
            bool VEthernetExchanger::OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpDisconnect(connection_id);
                }

                return true;
            }

            /** @brief Dispatches FRP TCP payload callback to mapped client port. */
            bool VEthernetExchanger::OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept {
                VirtualEthernetMappingPortPtr mapping_port = GetMappingPort(in, true, remote_port);
                if (NULLPTR != mapping_port) {
                    mapping_port->Client_OnFrpPush(connection_id, packet, packet_length);
                }

                return true;
            }

            bool VEthernetExchanger::StaticEchoAllocated() noexcept {
                return static_echo_.StaticEchoAllocated();
            }

            bool VEthernetExchanger::StaticEchoAddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                return static_echo_.StaticEchoAddRemoteEndPoint(remoteEP);
            }

            void VEthernetExchanger::StaticEchoClean() noexcept {
                static_echo_.StaticEchoClean();
            }

            bool VEthernetExchanger::StaticEchoSwapAsynchronousSocket() noexcept {
                return static_echo_.StaticEchoSwapAsynchronousSocket();
            }

            bool VEthernetExchanger::StaticEchoGatewayServer(int ack_id) noexcept {
                return static_echo_.StaticEchoGatewayServer(ack_id);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept {
                return static_echo_.StaticEchoPacketToRemoteExchanger(packet);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept {
                return static_echo_.StaticEchoPacketToRemoteExchanger(frame);
            }

            bool VEthernetExchanger::StaticEchoPacketToRemoteExchanger(const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
                return static_echo_.StaticEchoPacketToRemoteExchanger(packet, packet_length);
            }

            bool VEthernetExchanger::Sleep(int64_t timeout, const ContextPtr& context, YieldContext& y) noexcept {
                using atomic_int = std::atomic<int>;

                std::shared_ptr<atomic_int> status = ppp::make_shared_object<atomic_int>(-1);
                if (NULLPTR == status) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                }

                auto self = shared_from_this();
                boost::asio::post(*context,
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

        }
    }
}
