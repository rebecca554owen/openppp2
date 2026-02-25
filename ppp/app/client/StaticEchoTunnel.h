#pragma once

#include <atomic>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/Int128.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/threading/Timer.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/auxiliary/UriAuxiliary.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetNetworkSwitcher;

            class StaticEchoTunnel : public std::enable_shared_from_this<StaticEchoTunnel> {
            public:
                static constexpr int STATIC_ECHO_KEEP_ALIVED_ID = ppp::net::IPEndPoint::NoneAddress - 1;

            public:
                typedef std::shared_ptr<Byte>                                           BytePtr;
                typedef std::shared_ptr<ppp::configurations::AppConfiguration>         AppConfigurationPtr;
                typedef std::shared_ptr<ppp::threading::BufferswapAllocator>           BufferAllocatorPtr;
                typedef std::shared_ptr<boost::asio::io_context>                       ContextPtr;
                typedef std::shared_ptr<ppp::cryptography::Ciphertext>                 CiphertextPtr;
                typedef std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>     VirtualEthernetPacketPtr;
                typedef std::shared_ptr<ppp::net::packet::IPFrame>                     IPFramePtr;
                typedef std::shared_ptr<ppp::net::packet::UdpFrame>                    UdpFramePtr;
                typedef std::weak_ptr<VEthernetNetworkSwitcher>                         VEthernetNetworkSwitcherWeakPtr;
                typedef std::shared_ptr<VEthernetNetworkSwitcher>                       VEthernetNetworkSwitcherPtr;
                typedef ppp::coroutines::YieldContext                                   YieldContext;
                typedef std::mutex                                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                             SynchronizedObjectScope;

            private:
                class StaticEchoDatagarmSocket final : public boost::asio::ip::udp::socket {
                public:
                    StaticEchoDatagarmSocket(boost::asio::io_context& context) noexcept
                        : basic_datagram_socket(context)
                        , opened(false) {

                    }
                    virtual ~StaticEchoDatagarmSocket() noexcept {
                        boost::asio::ip::udp::socket* my = this;
                        destructor_invoked(my);
                    }

                public:
                    bool                                                                is_open(bool only_native = false) noexcept { return only_native ? basic_datagram_socket::is_open() : opened && basic_datagram_socket::is_open(); }

                public:
                    bool                                                                opened = false;
                };

            public:
                StaticEchoTunnel(
                    const VEthernetNetworkSwitcherPtr&                                  switcher,
                    const AppConfigurationPtr&                                          configuration,
                    const ContextPtr&                                                   context,
                    const std::shared_ptr<Byte>&                                        buffer,
                    const CiphertextPtr&                                                protocol,
                    const CiphertextPtr&                                                transport,
                    const boost::asio::ip::tcp::endpoint&                               remoteEP,
                    int                                                                 port,
                    ppp::auxiliary::UriAuxiliary::ProtocolType                         protocol_type) noexcept;
                virtual ~StaticEchoTunnel() noexcept;

            public:
                void                                                                    Clean() noexcept;
                bool                                                                    Allocated() noexcept;
                bool                                                                    AllocatedToRemoteExchanger(YieldContext& y) noexcept;
                bool                                                                    SwapAsynchronousSocket() noexcept;
                bool                                                                    NextTimeout() noexcept;
                bool                                                                    GatewayServer(int ack_id) noexcept;
                int                                                                     YieldReceiveForm(Byte* incoming_packet, int incoming_traffic) noexcept;
                bool                                                                    LoopbackSocket(const std::shared_ptr<StaticEchoDatagarmSocket>& socket) noexcept;
                bool                                                                    OpenAsynchronousSocket(StaticEchoDatagarmSocket& socket, YieldContext& y) noexcept;
                bool                                                                    PacketToRemoteExchanger(const BytePtr& packet, int packet_length) noexcept;
                bool                                                                    PacketToRemoteExchanger(const ppp::net::packet::IPFrame* packet) noexcept;
                bool                                                                    PacketToRemoteExchanger(const UdpFramePtr& frame) noexcept;
                bool                                                                    PacketInput(const VirtualEthernetPacketPtr& packet) noexcept;
                VirtualEthernetPacketPtr                                                ReadPacket(const void* packet, int packet_length) noexcept;
                bool                                                                    AddRemoteEndPoint(boost::asio::ip::udp::endpoint& remoteEP) noexcept;
                boost::asio::ip::udp::endpoint                                          GetRemoteEndPoint() noexcept;

            public:
                bool                                                                    GetInput() noexcept { return static_echo_input_.load(std::memory_order_relaxed); }
                void                                                                    SetInput(bool value) noexcept { static_echo_input_.store(value, std::memory_order_relaxed); }
                int                                                                     GetSessionId() noexcept { return static_echo_session_id_.load(std::memory_order_relaxed); }
                void                                                                    SetSessionId(int value) noexcept { static_echo_session_id_.store(value, std::memory_order_relaxed); }
                int                                                                     GetRemotePort() noexcept { return static_echo_remote_port_.load(std::memory_order_relaxed); }
                void                                                                    SetRemotePort(int value) noexcept { static_echo_remote_port_.store(value, std::memory_order_relaxed); }
                bool                                                                    IsDisposed() noexcept { return disposed_.load(std::memory_order_relaxed); }

            private:
                SynchronizedObject                                                      syncobj_;
                std::atomic<bool>                                                      disposed_ = false;
                std::atomic<bool>                                                      static_echo_input_ = false;
                std::atomic<uint64_t>                                                  static_echo_timeout_ = UINT64_MAX;
                std::atomic<int>                                                       static_echo_session_id_ = 0;
                std::atomic<int>                                                       static_echo_remote_port_ = ppp::net::IPEndPoint::MinPort;
                BytePtr                                                                 buffer_;
                VEthernetNetworkSwitcherWeakPtr                                         switcher_;
                AppConfigurationPtr                                                    configuration_;
                ContextPtr                                                              context_;
                CiphertextPtr                                                           static_echo_protocol_;
                CiphertextPtr                                                           static_echo_transport_;
                std::shared_ptr<StaticEchoDatagarmSocket>                               static_echo_sockets_[2];
                boost::asio::ip::udp::endpoint                                          static_echo_source_ep_;
                ppp::list<boost::asio::ip::udp::endpoint>                               static_echo_server_ep_balances_;
                ppp::unordered_set<boost::asio::ip::udp::endpoint>                      static_echo_server_ep_set_;
                boost::asio::ip::tcp::endpoint                                          server_remoteEP_;
                int                                                                     server_port_;
                ppp::auxiliary::UriAuxiliary::ProtocolType                             server_protocol_type_;
            };
        }
    }
}
