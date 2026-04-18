#pragma once

/**
 * @file VirtualEthernetExchanger.h
 * @brief Declares the per-session virtual ethernet exchanger on server side.
 * @author OPENPPP2 Team
 * @license GPL-3.0
 */

#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/mux/vmux_net.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Firewall.h>
#include <ppp/threading/Timer.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetManagedServer;
            class VirtualEthernetSwitcher;
            class VirtualEthernetDatagramPort;
            class VirtualEthernetDatagramPortStatic;
            class VirtualInternetControlMessageProtocol;
            class VirtualInternetControlMessageProtocolStatic;

            /**
             * @brief Handles one client session's L2/L3 forwarding, NAT and control operations.
             */
            class VirtualEthernetExchanger : public ppp::app::protocol::VirtualEthernetLinklayer {
                friend class                                                                VirtualInternetControlMessageProtocolStatic;
                friend class                                                                VirtualEthernetSwitcher;
                friend class                                                                VirtualEthernetDatagramPort;
                friend class                                                                VirtualEthernetDatagramPortStatic;

            public:
                /** @brief Base information packet alias. */
                typedef ppp::app::protocol::VirtualEthernetInformation                      VirtualEthernetInformation;
                /** @brief Extended information packet alias. */
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions            VirtualEthernetInformationExtensions;
                /** @brief Shared pointer alias for switcher owner. */
                typedef std::shared_ptr<VirtualEthernetSwitcher>                            VirtualEthernetSwitcherPtr;
                /** @brief Shared pointer alias for UDP datagram port wrapper. */
                typedef std::shared_ptr<VirtualEthernetDatagramPort>                        VirtualEthernetDatagramPortPtr;
                /** @brief Shared pointer alias for managed server bridge. */
                typedef std::shared_ptr<VirtualEthernetManagedServer>                       VirtualEthernetManagedServerPtr;
                /** @brief Static echo allocation context alias. */
                typedef VirtualEthernetSwitcher::VirtualEthernetStaticEchoAllocatedContext  VirtualEthernetStaticEchoAllocatedContext;
                /** @brief Shared pointer alias for static echo allocation context. */
                typedef std::shared_ptr<VirtualEthernetStaticEchoAllocatedContext>          VirtualEthernetStaticEchoAllocatedContextPtr;

            private:    
                typedef std::mutex                                                          SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>                                 SynchronizedObjectScope;
                typedef ppp::threading::Timer                                               Timer;
                typedef std::shared_ptr<Timer>                                              TimerPtr;
                typedef ppp::net::Firewall                                                  Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>                                 FirewallPtr;
                typedef Timer::TimeoutEventHandlerPtr                                       TimeoutEventHandlerPtr;
                typedef ppp::unordered_map<void*, TimeoutEventHandlerPtr>                   TimeoutEventHandlerTable;
                typedef ppp::transmissions::ITransmissionStatistics                         ITransmissionStatistics;
                typedef std::shared_ptr<ITransmissionStatistics>                            ITransmissionStatisticsPtr;
                typedef ppp::net::Ipep                                                      Ipep;
                typedef ppp::app::protocol::VirtualEthernetLogger                           VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>                              VirtualEthernetLoggerPtr;
                typedef ppp::unordered_map<boost::asio::ip::udp::endpoint,  
                    VirtualEthernetDatagramPortPtr>                                         VirtualEthernetDatagramPortTable;
                typedef std::shared_ptr<VirtualInternetControlMessageProtocol>              VirtualInternetControlMessageProtocolPtr;
                typedef ppp::app::protocol::VirtualEthernetMappingPort                      VirtualEthernetMappingPort;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                         VirtualEthernetMappingPortPtr;
                typedef ppp::unordered_map<uint32_t, VirtualEthernetMappingPortPtr>         VirtualEthernetMappingPortTable;
                typedef std::shared_ptr<VirtualEthernetDatagramPortStatic>                  VirtualEthernetDatagramPortStaticPtr;
                typedef ppp::unordered_map<uint64_t, VirtualEthernetDatagramPortStaticPtr>  VirtualEthernetDatagramPortStaticTable;

            public:
                /**
                 * @brief Creates a virtual exchanger bound to one transmission session.
                 * @param switcher Parent switcher that manages all exchangers.
                 * @param configuration Runtime configuration snapshot.
                 * @param transmission Session transport channel.
                 * @param id Session identifier.
                 */
                VirtualEthernetExchanger(
                    const VirtualEthernetSwitcherPtr&                                       switcher,
                    const AppConfigurationPtr&                                              configuration, 
                    const ITransmissionPtr&                                                 transmission,
                    const Int128&                                                           id) noexcept;
                /** @brief Releases all session resources. */
                virtual ~VirtualEthernetExchanger() noexcept;   
    
            public:
                /** @brief Runs periodic maintenance for ports, mappings and keepalive. */
                virtual bool                                                                Update(UInt64 now) noexcept;
                /** @brief Initializes echo/static components for this session. */
                virtual bool                                                                Open() noexcept;
                /** @brief Asynchronously disposes this exchanger on its io context. */
                virtual void                                                                Dispose() noexcept;
                /** @brief Gets whether exchanger has been disposed. */
                bool                                                                        IsDisposed() noexcept       { return disposed_; }
                /** @brief Gets parent switcher reference. */
                VirtualEthernetSwitcherPtr                                                  GetSwitcher() noexcept      { return switcher_; }
                /** @brief Gets current transmission reference. */
                ITransmissionPtr                                                            GetTransmission() noexcept  { return transmission_; }
                /** @brief Gets managed-server bridge reference. */
                VirtualEthernetManagedServerPtr                                             GetManagedServer() noexcept { return managed_server_; }
                /** @brief Gets traffic statistics object in use. */
                ITransmissionStatisticsPtr                                                  GetStatistics() noexcept    { return statistics_; }
                /** @brief Gets current VMUX instance when enabled. */
                std::shared_ptr<vmux::vmux_net>                                             GetMux() noexcept           { return mux_; }
                /** @brief Gets preferred TUN fd hint used by lower forwarding layer. */
                int                                                                         GetPreferredTunFd() noexcept;
                /** @brief Sets preferred TUN fd hint used by lower forwarding layer. */
                void                                                                        SetPreferredTunFd(int fd) noexcept;

            protected:  
                /** @brief Handles client LAN announcement and NAT binding registration. */
                virtual bool                                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept override;
                /** @brief Handles NAT packet from client and forwards to destination peer/transit. */
                virtual bool                                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Rejects legacy information message to prevent protocol abuse. */
                virtual bool                                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept override;
                /** @brief Handles extended information message (primarily IPv6 request exchange). */
                virtual bool                                                                OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept override;
                /** @brief Rejects direct push command for security hardening. */
                virtual bool                                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Rejects direct connect command for security hardening. */
                virtual bool                                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override;
                /** @brief Rejects connect-ack command for security hardening. */
                virtual bool                                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override;
                /** @brief Rejects direct disconnect command for security hardening. */
                virtual bool                                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept override;
                /** @brief Handles echo ack command from client. */
                virtual bool                                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept override;
                /** @brief Handles ICMP echo packet from client. */
                virtual bool                                                                OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles UDP sendto command from client. */
                virtual bool                                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles static-echo session allocation request. */
                virtual bool                                                                OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept override;
                /** @brief Rejects client-side static-echo control packet for security hardening. */
                virtual bool                                                                OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept override;
                /** @brief Handles VMUX configuration request from client. */
                virtual bool                                                                OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept override;

            protected:  
                /** @brief Returns firewall used for this exchanger session. */
                virtual FirewallPtr                                                         GetFirewall() noexcept override;
                /** @brief Creates ICMP echo forwarding helper bound to transmission. */
                virtual VirtualInternetControlMessageProtocolPtr                            NewEchoTransmissions(const ITransmissionPtr& transmission) noexcept;
                /** @brief Creates UDP datagram proxy port for a source endpoint. */
                virtual VirtualEthernetDatagramPortPtr                                      NewDatagramPort(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /** @brief Finds existing datagram proxy port by source endpoint. */
                virtual VirtualEthernetDatagramPortPtr                                      GetDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /** @brief Releases datagram proxy port ownership by source endpoint. */
                virtual VirtualEthernetDatagramPortPtr                                      ReleaseDatagramPort(const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
    
            private:    
                /** @brief Performs synchronous resource finalization and switcher deregistration. */
                void                                                                        Finalize() noexcept;
                /** @brief Removes a DNS redirect timeout entry by native key. */
                bool                                                                        DeleteTimeout(void* k) noexcept;
                /** @brief Resolves configured DNS redirect host and dispatches redirect send task. */
                bool                                                                        INTERNAL_RedirectDnsQuery(
                    const ITransmissionPtr&                                                 transmission, 
                    const boost::asio::ip::udp::endpoint&                                   sourceEP,
                    const boost::asio::ip::udp::endpoint&                                   destinationEP,
                    Byte*                                                                   packet, 
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;
                /** @brief Sends one DNS query to redirect endpoint and relays asynchronous response. */
                bool                                                                        INTERNAL_RedirectDnsQuery(
                    ITransmissionPtr                                                        transmission,
                    boost::asio::ip::udp::endpoint                                          redirectEP,
                    boost::asio::ip::udp::endpoint                                          sourceEP,
                    boost::asio::ip::udp::endpoint                                          destinationEP,
                    std::shared_ptr<Byte>                                                   packet,
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;
                /** @brief Handles DNS redirect policy and returns redirect status code. */
                int                                                                         RedirectDnsQuery(
                    const ITransmissionPtr&                                                 transmission, 
                    const boost::asio::ip::udp::endpoint&                                   sourceEP, 
                    const boost::asio::ip::udp::endpoint&                                   destinationEP, 
                    Byte*                                                                   packet, 
                    int                                                                     packet_length,
                    bool                                                                    static_transit) noexcept;
    
            private:    
                /** @brief Uploads per-session traffic deltas to managed server bridge. */
                bool                                                                        UploadTrafficToManagedServer() noexcept;
                /** @brief Runs VMUX polling/update and tears down failed VMUX instance. */
                bool                                                                        DoMuxEvents() noexcept;
                /** @brief Registers NAT information based on announced LAN address/mask. */
                bool                                                                        Arp(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask) noexcept;
                /** @brief Forwards IPv4 NAT packet to peer exchanger inside managed subnet. */
                bool                                                                        ForwardNatPacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Forwards IPv6 packet to local peer exchanger or transit gateway. */
                bool                                                                        ForwardIPv6PacketToDestination(Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Parses and forwards ICMP echo packet to echo subsystem. */
                bool                                                                        SendEchoToDestination(const ITransmissionPtr& transmission, Byte* packet, int packet_length) noexcept;
                /** @brief Forwards UDP payload to destination via per-source datagram port. */
                bool                                                                        SendPacketToDestination(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
    
            private:    
                /** @brief Allocates static-echo relay session and returns assignment to client. */
                bool                                                                        StaticEcho(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Releases a static-echo UDP source port mapping. */
                bool                                                                        StaticEchoReleasePort(uint32_t source_ip, int source_port) noexcept;
                /** @brief Forwards static-echo UDP packet to destination. */
                bool                                                                        StaticEchoSendToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet) noexcept;
                /** @brief Handles static-echo ICMP packet forwarding path. */
                bool                                                                        StaticEchoEchoToDestination(const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
    
            private:    
                /** @brief Finds existing FRP mapping port by direction/protocol/port key. */
                VirtualEthernetMappingPortPtr                                               GetMappingPort(bool in, bool tcp, int remote_port) noexcept;
                /** @brief Creates FRP mapping port object for one remote port key. */
                VirtualEthernetMappingPortPtr                                               NewMappingPort(bool in, bool tcp, int remote_port) noexcept;
                /** @brief Opens and registers FRP mapping port in mapping table. */
                bool                                                                        RegisterMappingPort(bool in, bool tcp, int remote_port) noexcept;
    
            private:    
                /** @brief Extends base keepalive and disposes session on timeout. */
                virtual bool                                                                DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept override;
                /** @brief Handles FRP entry notification from client. */
                virtual bool                                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept override;
                /** @brief Handles FRP UDP data packet from client. */
                virtual bool                                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept override;
                /** @brief Handles FRP TCP connect-ack packet from client. */
                virtual bool                                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept override;
                /** @brief Handles FRP TCP disconnect notification from client. */
                virtual bool                                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept override;
                /** @brief Handles FRP TCP stream payload from client. */
                virtual bool                                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept override;
    
            private:    
                SynchronizedObject                                                          syncobj_;
                bool                                                                        disposed_ = false;
                uint32_t                                                                    address_  = 0;
                int                                                                         preferred_tun_fd_ = -1;
                VirtualEthernetSwitcherPtr                                                  switcher_;
                std::shared_ptr<Byte>                                                       buffer_;
                FirewallPtr                                                                 firewall_;
                TimeoutEventHandlerTable                                                    timeouts_;
                VirtualInternetControlMessageProtocolPtr                                    echo_;
                VirtualEthernetDatagramPortTable                                            datagrams_;
                ITransmissionPtr                                                            transmission_;
                VirtualEthernetManagedServerPtr                                             managed_server_;
                ITransmissionStatisticsPtr                                                  statistics_last_;
                VirtualEthernetMappingPortTable                                             mappings_;
                ITransmissionStatisticsPtr                                                  statistics_;
                std::shared_ptr<vmux::vmux_net>                                             mux_;

                SynchronizedObject                                                          static_echo_syncobj_;
                std::shared_ptr<VirtualInternetControlMessageProtocolStatic>                static_echo_;
                VirtualEthernetStaticEchoAllocatedContextPtr                                static_allocated_context_;
                boost::asio::ip::udp::endpoint                                              static_echo_source_ep_;
                std::atomic<int>                                                            static_echo_session_id_ = 0;
                VirtualEthernetDatagramPortStaticTable                                      static_echo_datagram_ports_;
            };
        }
    }
}
