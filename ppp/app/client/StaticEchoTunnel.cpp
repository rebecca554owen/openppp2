#include <ppp/app/client/StaticEchoTunnel.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmissionQoS.h>
#include <common/aggligator/aggligator.h>

typedef ppp::app::protocol::VirtualEthernetPacket                   VirtualEthernetPacket;
typedef ppp::net::AddressFamily                                     AddressFamily;
typedef ppp::net::Socket                                            Socket;
typedef ppp::net::IPEndPoint                                        IPEndPoint;
typedef ppp::net::Ipep                                              Ipep;
typedef ppp::threading::Timer                                       Timer;
typedef ppp::threading::Executors                                   Executors;

namespace ppp {
    namespace app {
        namespace client {
            StaticEchoTunnel::StaticEchoTunnel(
                const VEthernetNetworkSwitcherPtr&                                  switcher,
                const AppConfigurationPtr&                                          configuration,
                const ContextPtr&                                                   context,
                const std::shared_ptr<Byte>&                                        buffer,
                const CiphertextPtr&                                                protocol,
                const CiphertextPtr&                                                transport,
                const boost::asio::ip::tcp::endpoint&                               remoteEP,
                int                                                                 port,
                ppp::auxiliary::UriAuxiliary::ProtocolType                         protocol_type) noexcept
                : disposed_(false)
                , static_echo_input_(false)
                , static_echo_timeout_(UINT64_MAX)
                , static_echo_session_id_(0)
                , static_echo_remote_port_(IPEndPoint::MinPort)
                , buffer_(buffer)
                , switcher_(switcher)
                , configuration_(configuration)
                , context_(context)
                , static_echo_protocol_(protocol)
                , static_echo_transport_(transport)
                , server_remoteEP_(remoteEP)
                , server_port_(port)
                , server_protocol_type_(protocol_type) {

            }

            StaticEchoTunnel::~StaticEchoTunnel() noexcept {
                disposed_.store(true, std::memory_order_relaxed);
                Clean();
            }

            void StaticEchoTunnel::Clean() noexcept {
                for (int i = 0; i < arraysizeof(static_echo_sockets_); i++) {
                    std::shared_ptr<StaticEchoDatagarmSocket>& r = static_echo_sockets_[i];
                    std::shared_ptr<StaticEchoDatagarmSocket> socket = std::move(r);
                    r.reset();

                    Socket::Closesocket(socket);
                }

                static_echo_input_.store(false, std::memory_order_relaxed);
                static_echo_timeout_.store(UINT64_MAX, std::memory_order_relaxed);
                static_echo_session_id_.store(0, std::memory_order_relaxed);
                static_echo_remote_port_.store(IPEndPoint::MinPort, std::memory_order_relaxed);

                static_echo_protocol_ = NULLPTR;
                static_echo_transport_ = NULLPTR;
            }

            bool StaticEchoTunnel::Allocated() noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<StaticEchoDatagarmSocket> socket = static_echo_sockets_[0];
                if (NULLPTR == socket) {
                    return false;
                }

                return socket->is_open() &&
                       static_echo_timeout_.load(std::memory_order_relaxed) != 0 &&
                       static_echo_session_id_.load(std::memory_order_relaxed) != 0 &&
                       static_echo_remote_port_.load(std::memory_order_relaxed) != 0;
            }

            bool StaticEchoTunnel::SwapAsynchronousSocket() noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (!switcher) {
                    return false;
                }

                uint64_t timeout_value = static_echo_timeout_.load(std::memory_order_relaxed);
                if (timeout_value != UINT64_MAX && switcher->StaticMode(NULLPTR)) {
                    UInt64 now = Executors::GetTickCount();
                    if (now >= timeout_value) {
                        std::shared_ptr<StaticEchoDatagarmSocket> socket = std::move(static_echo_sockets_[0]);
                        static_echo_sockets_[0] = std::move(static_echo_sockets_[1]);
                        static_echo_sockets_[1] = NULLPTR;

                        static_echo_input_.store(false, std::memory_order_relaxed);
                        if (!NextTimeout()) {
                            return false;
                        }

                        auto self = shared_from_this();
                        auto notifiy_if_need =
                            [self, this]() noexcept {
                                // Notifies the VPN server of domestic port changes for smoother dynamic switchover of virtual links.
                                if (!static_echo_input_.load(std::memory_order_relaxed) && static_echo_sockets_[0]) {
                                    GatewayServer(STATIC_ECHO_KEEP_ALIVED_ID);
                                }
                            };

                        // Here do not close the socket immediately, delay one second, because the data sent by the VPN server may not reach the network card,
                        // Reduce the packet loss rate during switching and improve the smoothness of the cross.
                        bool closesocket = true;
                        std::shared_ptr<boost::asio::io_context> context = context_;
                        if (NULLPTR != context) {
                            int milliseconds = RandomNext(500, 1000);
                            std::shared_ptr<Timer> timeout = Timer::Timeout(context, milliseconds,
                                [socket, notifiy_if_need](Timer*) noexcept {
                                    notifiy_if_need();
                                    Socket::Closesocket(socket);
                                });
                            if (NULLPTR != timeout) {
                                closesocket = false;
                            }
                        }

                        // Handles whether you can delay closing the socket. If not, close the socket immediately.
                        if (closesocket) {
                            Socket::Closesocket(socket);
                        }

                        if (NULLPTR == context) {
                            return false;
                        }

                        // Re-instance and try to open the Datagram Port.
                        socket = make_shared_object<StaticEchoDatagarmSocket>(*context);
                        if (NULLPTR == socket) {
                            return false;
                        }

                        auto configuration = configuration_;
                        auto allocator = configuration->GetBufferAllocator();
                        static_echo_sockets_[1] = socket;

                        return YieldContext::Spawn(allocator.get(), *context,
                            [self, this, socket, context](YieldContext& y) noexcept {
                                bool opened = OpenAsynchronousSocket(*socket, y);
                                if (opened) {
                                    LoopbackSocket(socket);
                                }
                            });
                    }
                }

                return true;
            }

            bool StaticEchoTunnel::GatewayServer(int ack_id) noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<ppp::net::packet::IPFrame> packet = make_shared_object<ppp::net::packet::IPFrame>();
                if (NULLPTR == packet) {
                    return false;
                }

                packet->AddressesFamily = AddressFamily::InterNetwork;
                packet->Destination = htonl(ack_id);
                packet->Id = ppp::net::packet::IPFrame::NewId();
                packet->Source = IPEndPoint::LoopbackAddress;
                packet->ProtocolType = ppp::net::native::ip_hdr::IP_PROTO_ICMP;
                VirtualEthernetPacket::FillBytesToPayload(packet.get());

                return PacketToRemoteExchanger(packet.get());
            }

            bool StaticEchoTunnel::AllocatedToRemoteExchanger(YieldContext& y) noexcept {
                Clean();
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                if (Allocated()) {
                    return true;
                }

                std::shared_ptr<boost::asio::io_context> context = context_;
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

                for (int i = 0; i < arraysizeof(static_echo_sockets_); i++) {
                    std::shared_ptr<StaticEchoDatagarmSocket>& socket = static_echo_sockets_[i];
                    if (NULLPTR == socket) {
                        socket = make_shared_object<StaticEchoDatagarmSocket>(*context);
                        if (NULLPTR == socket) {
                            return false;
                        }
                    }

                    if (socket->is_open(true)) {
                        continue;
                    }

                    bool opened = OpenAsynchronousSocket(*socket, y) && LoopbackSocket(socket);
                    if (!opened) {
                        socket.reset();
                        return false;
                    }
                }

                return true;
            }

            bool StaticEchoTunnel::NextTimeout() noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<StaticEchoDatagarmSocket> socket = static_echo_sockets_[0];
                if (NULLPTR == socket) {
                    return false;
                }

                bool opened = socket->is_open(true);
                if (!opened) {
                    return false;
                }

                AppConfigurationPtr configuration = configuration_;
                int min = std::max<int>(0, configuration->udp.static_.keep_alived[0]);
                int max = std::max<int>(0, configuration->udp.static_.keep_alived[1]);
                if (min == 0) {
                    min = PPP_UDP_KEEP_ALIVED_MIN_TIMEOUT;
                }

                if (max == 0) {
                    max = PPP_UDP_KEEP_ALIVED_MAX_TIMEOUT;
                }

                if (min > max) {
                    std::swap(min, max);
                }

                uint64_t tick = Executors::GetTickCount();
                min = std::max<int>(1, min) * 1000;
                max = std::max<int>(1, max) * 1000;

                if (min == max) {
                    static_echo_timeout_.store(tick + min, std::memory_order_relaxed);
                }
                else {
                    uint64_t next = RandomNext(min, max + 1);
                    static_echo_timeout_.store(tick + next, std::memory_order_relaxed);
                }

                return true;
            }

            bool StaticEchoTunnel::PacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept {
                if (NULLPTR == packet || packet->AddressesFamily != AddressFamily::InterNetwork) {
                    return false;
                }

                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = configuration_;
                if (NULLPTR == configuration) {
                    return false;
                }

                int session_id = static_echo_session_id_.load(std::memory_order_relaxed);
                if (session_id < 1) {
                    return false;
                }

                int message_length = -1;
                std::shared_ptr<Byte> messages = VirtualEthernetPacket::Pack(configuration,
                    configuration->GetBufferAllocator(),
                    VirtualEthernetPacket::SessionCiphertext([this](int) noexcept { return static_echo_protocol_; }),
                    VirtualEthernetPacket::SessionCiphertext([this](int) noexcept { return static_echo_transport_; }),
                    session_id,
                    packet,
                    message_length);
                return PacketToRemoteExchanger(messages, message_length);
            }

            bool StaticEchoTunnel::PacketToRemoteExchanger(const UdpFramePtr& frame) noexcept {
                if (NULLPTR == frame || frame->AddressesFamily != AddressFamily::InterNetwork) {
                    return false;
                }

                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = configuration_;
                if (NULLPTR == configuration) {
                    return false;
                }

                int session_id = static_echo_session_id_.load(std::memory_order_relaxed);
                if (session_id < 1) {
                    return false;
                }

                std::shared_ptr<ppp::net::packet::BufferSegment> payload_buffers = frame->Payload;
                if (NULLPTR == payload_buffers) {
                    return false;
                }

                int packet_length = -1;
                uint32_t source_ip = frame->Source.GetAddress();
                uint32_t destination_ip = frame->Destination.GetAddress();
                std::shared_ptr<Byte> packet = VirtualEthernetPacket::Pack(configuration,
                    configuration->GetBufferAllocator(),
                    VirtualEthernetPacket::SessionCiphertext([this](int) noexcept { return static_echo_protocol_; }),
                    VirtualEthernetPacket::SessionCiphertext([this](int) noexcept { return static_echo_transport_; }),
                    session_id,
                    source_ip,
                    frame->Source.Port,
                    destination_ip,
                    frame->Destination.Port,
                    payload_buffers->Buffer.get(),
                    payload_buffers->Length,
                    packet_length);
                return PacketToRemoteExchanger(packet, packet_length);
            }

            bool StaticEchoTunnel::PacketToRemoteExchanger(const BytePtr& packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<StaticEchoDatagarmSocket> socket = static_echo_sockets_[0];
                if (NULLPTR == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                boost::asio::ip::udp::endpoint serverEP = GetRemoteEndPoint();
                if (int serverPort = serverEP.port(); serverPort > IPEndPoint::MinPort && serverPort <= IPEndPoint::MaxPort) {
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    std::shared_ptr<ppp::transmissions::ITransmissionStatistics> statistics;
                    if (switcher) {
                        statistics = switcher->GetStatistics();
                    }
                    boost::asio::post(socket->get_executor(),
                        [statistics, socket, packet, packet_length, serverEP]() noexcept {
                            boost::system::error_code ec;
                            socket->send_to(boost::asio::buffer(packet.get(), packet_length), serverEP,
                                boost::asio::socket_base::message_end_of_record, ec);

                            if (ec == boost::system::errc::success) {
                                if (NULLPTR != statistics) {
                                    statistics->AddOutgoingTraffic(packet_length);
                                }
                            }
                        });
                    return true;
                }

                return false;
            }

            StaticEchoTunnel::VirtualEthernetPacketPtr StaticEchoTunnel::ReadPacket(const void* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return NULLPTR;
                }

                if (disposed_.load(std::memory_order_relaxed)) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = configuration_;
                if (NULLPTR == configuration) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration->GetBufferAllocator();
                return VirtualEthernetPacket::Unpack(configuration,
                    allocator,
                    VirtualEthernetPacket::SessionCiphertext([this](int) noexcept { return static_echo_protocol_; }),
                    VirtualEthernetPacket::SessionCiphertext([this](int) noexcept { return static_echo_transport_; }),
                    packet,
                    packet_length);
            }

            bool StaticEchoTunnel::PacketInput(const VirtualEthernetPacketPtr& packet) noexcept {
                if (NULLPTR == packet || disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (!switcher) {
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = configuration_;
                if (NULLPTR == configuration) {
                    return false;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration->GetBufferAllocator();
                static_echo_input_.store(true, std::memory_order_relaxed);

                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    auto tap = switcher->GetTap();
                    if (NULLPTR == tap) {
                        return false;
                    }

                    std::shared_ptr<ppp::net::packet::UdpFrame> frame = packet->GetUdpPacket();
                    if (NULLPTR == frame) {
                        return false;
                    }

                    std::shared_ptr<ppp::net::packet::IPFrame> ip = frame->ToIp(allocator);
                    if (NULLPTR == ip) {
                        return false;
                    }

                    if (configuration->udp.dns.cache && frame->Source.Port == PPP_DNS_SYS_PORT) {
                        auto payload = frame->Payload;
                        if (NULLPTR != payload) {
                            ppp::net::asio::vdns::AddCache(payload->Buffer.get(), payload->Length);
                        }
                    }

                    return switcher->Output(ip.get());
                }
                elif(packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    std::shared_ptr<ppp::net::packet::IPFrame> frame = packet->GetIPPacket(allocator);
                    if (NULLPTR == frame) {
                        return false;
                    }

                    if (frame->ProtocolType == ppp::net::native::ip_hdr::IP_PROTO_ICMP) {
                        if (frame->Source == IPEndPoint::LoopbackAddress) {
                            int ack_id = ntohl(frame->Destination);
                            if (ack_id == 0 || ack_id == STATIC_ECHO_KEEP_ALIVED_ID) {
                                return false;
                            }

                            return switcher->ERORTE(ack_id);
                        }
                    }

                    return switcher->Output(frame.get());
                }
                else {
                    return false;
                }
            }

            int StaticEchoTunnel::YieldReceiveForm(Byte* incoming_packet, int incoming_traffic) noexcept {
                std::shared_ptr<VirtualEthernetPacket> packet = ReadPacket(incoming_packet, incoming_traffic);
                if (NULLPTR != packet) {
                    PacketInput(packet);
                }

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (switcher) {
                    auto statistics = switcher->GetStatistics();
                    if (NULLPTR != statistics) {
                        statistics->AddIncomingTraffic(incoming_traffic);
                    }
                }

                return incoming_traffic;
            }

            bool StaticEchoTunnel::LoopbackSocket(const std::shared_ptr<StaticEchoDatagarmSocket>& socket) noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                bool openped = socket->is_open();
                if (!openped) {
                    return false;
                }

                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                auto self = shared_from_this();
                if (switcher) {
                    if (std::shared_ptr<ppp::transmissions::ITransmissionQoS> qos = switcher->GetQoS(); NULLPTR != qos) {
                        return qos->BeginRead(
                            [self, this, socket, qos]() noexcept {
                                socket->async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), static_echo_source_ep_,
                                    [self, this, qos, socket](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                        int bytes_transferred = std::max<int>(-1, ec ? -1 : (int)sz);
                                        if (bytes_transferred > 0) {
                                            qos->EndRead(YieldReceiveForm(buffer_.get(), bytes_transferred));
                                        }

                                        LoopbackSocket(socket);
                                    });
                            });
                    }
                }

                socket->async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), static_echo_source_ep_,
                    [self, this, socket](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        int bytes_transferred = std::max<int>(-1, ec ? -1 : (int)sz);
                        if (bytes_transferred > 0) {
                            YieldReceiveForm(buffer_.get(), bytes_transferred);
                        }

                        LoopbackSocket(socket);
                    });
                return true;
            }

            bool StaticEchoTunnel::AddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept {
                boost::asio::ip::udp::endpoint destinationEP = Ipep::V4ToV6(remoteEP);
                boost::asio::ip::address destinationIP = destinationEP.address();
                if (!destinationIP.is_v6()) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                auto r = static_echo_server_ep_set_.emplace(destinationEP);
                if (!r.second) {
                    return false;
                }

                static_echo_server_ep_balances_.emplace_back(destinationEP);
                return true;
            }

            boost::asio::ip::udp::endpoint StaticEchoTunnel::GetRemoteEndPoint() noexcept {
                std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                if (switcher) {
                    std::shared_ptr<aggligator::aggligator> aggligator = switcher->GetAggligator();
                    if (NULLPTR != aggligator) {
#if !defined(_ANDROID) && !defined(_IPHONE)
                        auto ni = switcher->GetUnderlyingNetowrkInterface();
                        if (NULLPTR != ni) {
                            boost::asio::ip::udp::endpoint ep = aggligator->client_endpoint(ni->IPAddress);
                            return Ipep::V4ToV6(ep);
                        }
#endif
                        return aggligator->client_endpoint(boost::asio::ip::address_v6::loopback());
                    }
                }

                boost::asio::ip::udp::endpoint destinationEP;
                for (SynchronizedObjectScope scope(syncobj_);;) {
                    auto tail = static_echo_server_ep_balances_.begin();
                    auto endl = static_echo_server_ep_balances_.end();
                    if (tail == endl) {
                        destinationEP = boost::asio::ip::udp::endpoint(server_remoteEP_.address(), static_echo_remote_port_.load(std::memory_order_relaxed));
                        break;
                    }

                    std::size_t server_addrsss_num = static_echo_server_ep_set_.size();
                    if (server_addrsss_num == 1) {
                        destinationEP = *static_echo_server_ep_balances_.begin();
                    }
                    else {
                        destinationEP = *tail;
                        static_echo_server_ep_balances_.erase(tail);
                        static_echo_server_ep_balances_.emplace_back(destinationEP);
                    }

                    break;
                }

                return Ipep::V4ToV6(destinationEP);
            }

            bool StaticEchoTunnel::OpenAsynchronousSocket(StaticEchoDatagarmSocket& socket, YieldContext& y) noexcept {
                if (disposed_.load(std::memory_order_relaxed)) {
                    return false;
                }

                bool opened = socket.is_open(true);
                if (opened) {
                    return true;
                }

                if (server_port_ <= IPEndPoint::MinPort || server_port_ > IPEndPoint::MaxPort) {
                    return false;
                }

                AppConfigurationPtr configuration = configuration_;
                if (NULLPTR == configuration) {
                    return false;
                }

                opened = ppp::coroutines::asio::async_open<boost::asio::ip::udp::socket>(y, socket, boost::asio::ip::udp::v6()) && !disposed_.load(std::memory_order_relaxed);
                if (!opened) {
                    return false;
                }

                bool ok = false;
                for (;;) {
                    opened = Socket::OpenSocket(socket, boost::asio::ip::address_v6::any(), IPEndPoint::MinPort, opened);
                    if (!opened) {
                        break;
                    }
                    else {
                        Socket::SetWindowSizeIfNotZero(socket.native_handle(), configuration->udp.cwnd, configuration->udp.rwnd);
                    }

#if defined(_ANDROID)
                    std::shared_ptr<VEthernetNetworkSwitcher> switcher = switcher_.lock();
                    if (switcher) {
                        std::shared_ptr<aggligator::aggligator> aggligator = switcher->GetAggligator();
                        if (NULLPTR == aggligator) {
                            auto protector_network = switcher->GetProtectorNetwork();
                            if (NULLPTR != protector_network) {
                                opened = protector_network->Protect(socket.native_handle(), y);
                                if (!opened) {
                                    break;
                                }
                            }
                        }
                    }
#endif
                    // Mark that the socket has been opened.
                    socket.opened = opened;

                    // Set the timeout period for closing and re-opening the socket next-timed.
                    ok = NextTimeout();
                    break;
                }

                if (!ok) {
                    Socket::Closesocket(socket);
                }

                return ok;
            }
        }
    }
}
