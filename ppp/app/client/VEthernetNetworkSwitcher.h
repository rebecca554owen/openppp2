 #pragma once

/**
 * @file VEthernetNetworkSwitcher.h
 * @brief Client-side virtual Ethernet network switcher declarations.
 *
 * @details
 * VEthernetNetworkSwitcher is the **top-level client runtime coordinator**.
 * It extends VEthernet (which manages the TAP/TUN device and lwIP stack) and
 * orchestrates all client-side services:
 *
 *  - Creates and owns a VEthernetExchanger (remote server session).
 *  - Manages local HTTP and SOCKS proxy listeners.
 *  - Installs and removes OS routing table entries.
 *  - Loads RIB/FIB IP-list files and builds the bypass/route decision table.
 *  - Handles DNS redirection based on configurable rule sets (three-tier lookup).
 *  - Manages ICMP probe tracking and echo reply / TTL exceeded generation.
 *  - Optionally enables QUIC blocking, VMUX, static-mode, and traffic aggligator.
 *
 * ### Threading model
 * All callbacks (`OnPacketInput`, `OnTick`, `OnUpdate`, `OnInformation`) are
 * invoked from the single Boost.Asio io_context thread. The `prdr_` mutex
 * serializes access to the default-route guard worker on non-mobile platforms.
 *
 * ### Lifecycle
 * 1. Construct with io_context, lwip/vnet/mta flags, and configuration.
 * 2. Call Open(tap) to initialize all services and start the exchanger.
 * 3. Packet input flows: TAP → OnPacketInput → Exchanger/Nat/UDP/ICMP handlers.
 * 4. Call Dispose() to tear down all services and remove routes.
 *
 * Licensed under GPL-3.0.
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
             * @brief Top-level client runtime that coordinates the TAP interface, remote session,
             *        proxy listeners, routing, and DNS redirection.
             *
             * @details
             * VEthernetNetworkSwitcher derives from ppp::ethernet::VEthernet and is responsible for:
             *
             *  - **Session management**: Owns a single VEthernetExchanger connected to the server.
             *  - **Packet routing**: Dispatches inbound TAP packets to NAT, UDP relay, or ICMP handlers.
             *  - **Proxy services**: Starts optional HTTP and SOCKS5 local proxy listeners.
             *  - **Route management**: Adds/removes OS routing table entries on Open()/Dispose().
             *  - **DNS redirection**: Intercepts DNS UDP datagrams and rewrites them to configured
             *    servers according to three-tier rule sets (relative, full-host, regexp).
             *  - **ICMP emulation**: Synthesizes Echo Reply and TTL Exceeded ICMP responses.
             *  - **Traffic shaping**: Optionally applies QoS and collects traffic statistics.
             *  - **IPv6 assignment**: Applies server-assigned IPv6 addresses to the local interface.
             *
             * ### Platform-specific features
             *  - **Windows**: PaperAirplaneController LSP for per-process socket protection.
             *  - **Linux**: ProtectorNetwork for marking sockets to bypass VPN routes.
             *  - **Android/iOS**: Bypass IP-list string parsed from JNI configuration.
             *
             * @note
             * Only one instance is created per process, held by PppApplication.
             */
            class VEthernetNetworkSwitcher : public ppp::ethernet::VEthernet {
            private:
                friend class                                                        VEthernetExchanger;
                friend class                                                        VEthernetDatagramPort;

            private:
                /**
                 * @brief Cached ICMP probe packet record with expiration timestamp.
                 *
                 * @details
                 * Used to match outbound ICMP Echo Requests with inbound Echo Replies.
                 * Records expire after a configurable interval to prevent stale entries.
                 */
                typedef struct {    
                    UInt64                                                          datetime;  ///< Tick count when the probe was sent.
                    IPFrame::IPFramePtr                                             packet;    ///< Original IP frame containing the ICMP echo.
                }                                                                   VEthernetIcmpPacket;

                /** @brief Map from ICMP identifier to pending probe record. */
                typedef ppp::unordered_map<int, VEthernetIcmpPacket>                VEthernetIcmpPacketTable;
                /** @brief Shared pointer alias for DNS rule entries. */
                typedef ppp::app::client::dns::Rule::Ptr                            DNSRulePtr;
                /** @brief Map from host/pattern string to DNS rule. */
                typedef ppp::unordered_map<ppp::string, DNSRulePtr>                 DNSRuleTable;
                /** @brief Timer alias. */
                typedef ppp::threading::Timer                                       Timer;
                /** @brief Shared pointer alias for timer event handler. */
                typedef Timer::TimeoutEventHandlerPtr                                TimeoutEventHandlerPtr;
                /** @brief Map from opaque key to timeout event handler. */
                typedef ppp::unordered_map<void*, TimeoutEventHandlerPtr>            TimeoutEventHandlerTable;
                /** @brief Vector of (file-path, gateway-ip) pairs for IP-list loading. */
                typedef ppp::vector<std::pair<ppp::string, uint32_t>/**/>           LoadIPListFileVector;
                /** @brief Shared pointer alias for IP-list vector. */
                typedef std::shared_ptr<LoadIPListFileVector>                       LoadIPListFileVectorPtr;
                /** @brief Vector of DNS server addresses for a single NIC. */
                typedef ppp::vector<boost::asio::ip::address>                       NicDnsServerAddresses;
                /** @brief Map from interface index to its DNS server addresses. */
                typedef ppp::unordered_map<int, NicDnsServerAddresses>              AllNicDnsServerAddresses;
                /** @brief Proxy forwarding interface alias. */
                typedef ppp::transmissions::proxys::IForwarding                     IForwarding;
                /** @brief Shared pointer alias for proxy forwarding interface. */
                typedef std::shared_ptr<IForwarding>                                IForwardingPtr;

            public: 
                /** @brief Base server information type alias. */
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                /** @brief Extended server information type alias. */
                typedef ppp::app::protocol::VirtualEthernetInformationExtensions    VirtualEthernetInformationExtensions;
                /** @brief HTTP proxy switcher type alias. */
                typedef ppp::app::client::proxys::VEthernetHttpProxySwitcher        VEthernetHttpProxySwitcher;
                /** @brief Shared pointer alias for HTTP proxy switcher. */
                typedef std::shared_ptr<VEthernetHttpProxySwitcher>                 VEthernetHttpProxySwitcherPtr;
                /** @brief SOCKS proxy switcher type alias. */
                typedef ppp::app::client::proxys::VEthernetSocksProxySwitcher       VEthernetSocksProxySwitcher;
                /** @brief Shared pointer alias for SOCKS proxy switcher. */
                typedef std::shared_ptr<VEthernetSocksProxySwitcher>                VEthernetSocksProxySwitcherPtr;
                /** @brief Periodic tick event handler callback signature. */
                typedef ppp::function<void(VEthernetNetworkSwitcher*, UInt64)>      VEthernetTickEventHandler;
                /** @brief Traffic statistics interface alias. */
                typedef ppp::transmissions::ITransmissionStatistics                 ITransmissionStatistics;
                /** @brief Shared pointer alias for traffic statistics. */
                typedef std::shared_ptr<ITransmissionStatistics>                    ITransmissionStatisticsPtr;
                /** @brief IPv6 client assignment state alias. */
                using IPv6AppliedState                                              = ppp::ipv6::auxiliary::ClientState;

                /**
                 * @brief Lightweight snapshot of a network interface used for route and DNS operations.
                 *
                 * @details
                 * Populated once during Open() from the host OS network stack and cached for
                 * route management. On Windows the Description field identifies the adapter;
                 * on macOS DefaultRoutes tracks the pre-VPN default route entries.
                 */
                class NetworkInterface {    
                public: 
                    ppp::string                                                     Name;       ///< Interface name (e.g. "eth0", "utun2").
#if !defined(_MACOS)    
                    ppp::string                                                     Id;         ///< Interface GUID string (Windows) or sysfs id (Linux).
#endif  
                    int                                                             Index = -1; ///< OS interface index; -1 when unknown.
                    ppp::vector<boost::asio::ip::address>                           DnsAddresses; ///< DNS servers associated with this interface.

                public: 
                    /**
                     * @brief Initializes all interface metadata to safe defaults.
                     */
                    NetworkInterface() noexcept;

                    /**
                     * @brief Default virtual destructor.
                     */
                    virtual ~NetworkInterface() noexcept = default;

                public: 
                    boost::asio::ip::address                                        IPAddress;      ///< Interface primary IPv4 address.
                    boost::asio::ip::address                                        GatewayServer;  ///< Default gateway for this interface.
                    boost::asio::ip::address                                        SubmaskAddress; ///< Subnet mask for this interface.

#if defined(_WIN32) 
                public: 
                    ppp::string                                                     Description;  ///< Windows adapter description string.
#elif defined(_MACOS)   
                    ppp::unordered_map<uint32_t, uint32_t>                          DefaultRoutes; ///< Pre-VPN default route entries (macOS only).
#endif  
                };

                /** @brief Route information base type alias. */
                typedef ppp::net::native::RouteInformationTable                     RouteInformationTable;
                /** @brief Shared pointer alias for RIB. */
                typedef std::shared_ptr<RouteInformationTable>                      RouteInformationTablePtr;
                /** @brief Forward information base type alias. */
                typedef ppp::net::native::ForwardInformationTable                   ForwardInformationTable;
                /** @brief Shared pointer alias for FIB. */
                typedef std::shared_ptr<ForwardInformationTable>                    ForwardInformationTablePtr;
                /** @brief Map from IP-list URL to local file path for vBGP routing. */
                typedef ppp::unordered_map<ppp::string, ppp::string>                RouteIPListTable;
                /** @brief Shared pointer alias for route IP-list table. */
                typedef std::shared_ptr<RouteIPListTable>                           RouteIPListTablePtr;

#if defined(_WIN32)
                /** @brief Windows PaperAirplane LSP controller type alias. */
                typedef lsp::PaperAirplaneController                                PaperAirplaneController;
                /** @brief Shared pointer alias for PaperAirplane controller. */
                typedef std::shared_ptr<PaperAirplaneController>                    PaperAirplaneControllerPtr;
#elif defined(_LINUX)   
                /** @brief Linux socket-protection network type alias. */
                typedef ppp::net::ProtectorNetwork                                  ProtectorNetwork;
                /** @brief Shared pointer alias for Linux protector network. */
                typedef std::shared_ptr<ProtectorNetwork>                           ProtectorNetworkPtr;
#endif

            public: 
                /**
                 * @brief Optional callback invoked on each periodic tick.
                 *
                 * @details
                 * Registered by the application layer to receive notifications at every
                 * switcher tick event (approximately once per second). Used for UI refresh
                 * and traffic statistics sampling.
                 */
                VEthernetTickEventHandler                                           TickEvent;

            public:
                /**
                 * @brief Constructs a virtual Ethernet network switcher instance.
                 *
                 * @param context        Boost.Asio io_context for all async operations.
                 * @param lwip           If true, use lwIP TCP/IP stack; otherwise use native stack.
                 * @param vnet           If true, enable virtual network mode.
                 * @param mta            If true, enable multi-thread accelerated packet dispatch.
                 * @param configuration  Shared application configuration snapshot.
                 */
                VEthernetNetworkSwitcher(const std::shared_ptr<boost::asio::io_context>& context, bool lwip, bool vnet, bool mta, const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept;

                /**
                 * @brief Destroys the switcher, releasing all owned services and routes.
                 *
                 * @note Calls Finalize() to ensure cleanup even if Dispose() was not called.
                 */
                virtual ~VEthernetNetworkSwitcher() noexcept;

            public:
#if defined(_WIN32)
                /**
                 * @brief Gets the optional Windows PaperAirplane LSP controller.
                 * @return Shared PaperAirplaneController; null if not created.
                 */
                PaperAirplaneControllerPtr                                          GetPaperAirplaneController() noexcept { return paper_airplane_ctrl_; }

                /**
                 * @brief Applies the local HTTP proxy endpoint to Windows system proxy settings.
                 * @return true if the system proxy was updated; false otherwise.
                 */
                virtual bool                                                        SetHttpProxyToSystemEnv()    noexcept;

                /**
                 * @brief Clears Windows system proxy settings applied by this switcher.
                 * @return true if cleared; false otherwise.
                 */
                virtual bool                                                        ClearHttpProxyToSystemEnv()  noexcept;

#elif defined(_LINUX)   
                /**
                 * @brief Gets the optional Linux socket-protection network helper.
                 * @return Shared ProtectorNetwork; null if not created.
                 */
                ProtectorNetworkPtr                                                 GetProtectorNetwork()        noexcept { return protect_network_; }
#endif  

                /**
                 * @brief Gets the active runtime configuration.
                 * @return Shared AppConfiguration snapshot.
                 */
                std::shared_ptr<ppp::configurations::AppConfiguration>              GetConfiguration()           noexcept { return configuration_; }

                /**
                 * @brief Gets the remote exchanger associated with this switcher.
                 * @return Shared VEthernetExchanger; null before Open() or after Dispose().
                 */
                std::shared_ptr<VEthernetExchanger>                                 GetExchanger()               noexcept { return exchanger_; }

                /**
                 * @brief Sets the preferred IPv6 address to request from the remote server.
                 * @param value  IPv6 address string in textual notation.
                 */
                void                                                                RequestedIPv6(const ppp::string& value) noexcept { requested_ipv6_ = value; }

                /**
                 * @brief Gets the preferred IPv6 address requested from the remote server.
                 * @return IPv6 address string; empty if not configured.
                 */
                ppp::string                                                         RequestedIPv6() noexcept { return requested_ipv6_; }

                /**
                 * @brief Returns the last IPv6 address successfully applied to the local NIC.
                 *
                 * @details Populated inside ApplyAssignedIPv6() on every successful apply.
                 *          Callers such as SendRequestedIPv6Configuration() use this as a
                 *          sticky hint so a reconnect can re-request the same address when
                 *          the user has not configured an explicit RequestedIPv6() preference.
                 *
                 * @return The last-applied IPv6 address, or a default-constructed (unspecified)
                 *         address when no assignment has ever been applied.
                 * @note   Thread-safe only when called from the same IO-context strand as
                 *         ApplyAssignedIPv6().  Do not call from an unrelated thread without
                 *         external synchronisation.
                 */
                boost::asio::ip::address                                            LastAssignedIPv6() noexcept { return last_assigned_ipv6_; }

                /**
                 * @brief Gets the QoS controller used by transport channels.
                 * @return Shared ITransmissionQoS; null if QoS is not enabled.
                 */
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>               GetQoS()                     noexcept { return qos_; }

                /**
                 * @brief Gets the traffic statistics collector.
                 * @return Shared ITransmissionStatistics instance.
                 */
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>        GetStatistics()              noexcept { return statistics_; }

                /**
                 * @brief Gets the latest server information received from the exchanger.
                 * @return Shared VirtualEthernetInformation; null before first server response.
                 */
                std::shared_ptr<VirtualEthernetInformation>                         GetInformation()             noexcept;

                /**
                 * @brief Gets the last received extended information from the server.
                 * @return Copy of VirtualEthernetInformationExtensions; zero-initialized before first response.
                 */
                VirtualEthernetInformationExtensions                                GetInformationExtensions()   noexcept { return information_extensions_; }

                /**
                 * @brief Gets the local HTTP proxy switcher.
                 * @return Shared VEthernetHttpProxySwitcher; null if HTTP proxy is disabled.
                 */
                VEthernetHttpProxySwitcherPtr                                       GetHttpProxy()               noexcept { return http_proxy_; }

                /**
                 * @brief Gets the local SOCKS proxy switcher.
                 * @return Shared VEthernetSocksProxySwitcher; null if SOCKS proxy is disabled.
                 */
                VEthernetSocksProxySwitcherPtr                                      GetSocksProxy()              noexcept { return socks_proxy_; }

                /**
                 * @brief Gets the loaded route information base (RIB).
                 * @return Shared RouteInformationTable; null if not yet loaded.
                 */
                RouteInformationTablePtr                                            GetRib()                     noexcept { return rib_; }

                /**
                 * @brief Gets the loaded forward information base (FIB).
                 * @return Shared ForwardInformationTable; null if not yet loaded.
                 */
                ForwardInformationTablePtr                                          GetFib()                     noexcept { return fib_; }

                /**
                 * @brief Gets the optional proxy-forwarding helper.
                 * @return Shared IForwarding; null if forwarding is not configured.
                 */
                IForwardingPtr                                                      GetForwarding()              noexcept { return forwarding_; }

                /**
                 * @brief Gets the optional static-mode bandwidth aggligator.
                 * @return Shared aggligator instance; null if static mode is disabled.
                 */
                std::shared_ptr<aggligator::aggligator>                             GetAggligator()              noexcept { return aggligator_; }

                /**
                 * @brief Gets the vBGP URL-to-file mapping table.
                 * @return Shared RouteIPListTable; null if vBGP is not configured.
                 */
                RouteIPListTablePtr                                                 GetVbgp()                    noexcept { return vbgp_; }

                /**
                 * @brief Returns whether outbound QUIC (UDP port 443) traffic is blocked.
                 * @return true if QUIC blocking is enabled; false otherwise.
                 */
                bool                                                                IsBlockQUIC()                noexcept { return block_quic_; }

                /**
                 * @brief Returns whether VMUX multiplexing is enabled.
                 * @return true if mux_ > 0; false otherwise.
                 */
                bool                                                                IsMuxEnabled()               noexcept { return mux_ > 0; }

                /**
                 * @brief Checks whether the given IP address should bypass the VPN route path.
                 *
                 * @param ip  IP address to test against the bypass/RIB table.
                 * @return true if the address is in the bypass list and must use direct routing.
                 */
                bool                                                                IsBypassIpAddress(const boost::asio::ip::address& ip) noexcept;

            public: 
                /**
                 * @brief Loads DNS rules from a file path or inline rule text string.
                 *
                 * @param rules               File path or inline DNS rule content.
                 * @param load_file_or_string  true to load from file; false to parse inline text.
                 * @return true if at least one rule was loaded; false on error.
                 */
                virtual bool                                                        LoadAllDnsRules(const ppp::string& rules, bool load_file_or_string) noexcept;

                /**
                 * @brief Gets or sets the static transmission mode flag.
                 *
                 * @param static_mode  Pointer to new value; pass null to query only.
                 * @return Current (or previous) static-mode value.
                 */
                bool                                                                StaticMode(bool* static_mode) noexcept;

                /**
                 * @brief Gets or sets the VMUX connection count.
                 *
                 * @param mux  Pointer to new count; pass null to query only.
                 * @return Current (or previous) mux count.
                 */
                uint16_t                                                            Mux(uint16_t* mux) noexcept;

                /**
                 * @brief Gets or sets the VMUX acceleration bitmap.
                 *
                 * @param mux_acceleration  Pointer to new flags; pass null to query only.
                 * @return Current (or previous) acceleration flags.
                 */
                uint8_t                                                             MuxAcceleration(uint8_t* mux_acceleration) noexcept;

#if defined(_ANDROID) || defined(_IPHONE)
                /**
                 * @brief Sets the bypass IP-list text used on mobile platforms.
                 *
                 * @param bypass_ip_list  Newline-separated CIDR entries to bypass VPN.
                 * @note Android/iOS only. Replaces the OS routing table approach.
                 */
                void                                                                SetBypassIpList(ppp::string&& bypass_ip_list) noexcept;
#else   
#if defined(_LINUX)
                /**
                 * @brief Gets or sets Linux socket-protect mode.
                 *
                 * @param protect_mode  Pointer to new value; pass null to query only.
                 * @return Current (or previous) protect-mode value.
                 */
                bool                                                                ProtectMode(bool* protect_mode) noexcept;
#endif
                /**
                 * @brief Gets the TAP-side network interface snapshot.
                 * @return Shared NetworkInterface for the virtual NIC; null before Open().
                 */
                std::shared_ptr<NetworkInterface>                                   GetTapNetworkInterface()        noexcept { return tun_ni_; }

                /**
                 * @brief Gets the underlying physical network interface snapshot.
                 * @return Shared NetworkInterface for the physical adapter; null before Open().
                 */
                std::shared_ptr<NetworkInterface>                                   GetUnderlyingNetworkInterface() noexcept { return underlying_ni_; }

                /**
                 * @brief Sets the preferred physical default gateway for route management.
                 *
                 * @param gw  Gateway IP address to prefer when installing VPN routes.
                 */
                virtual void                                                        PreferredNgw(const boost::asio::ip::address& gw) noexcept;

                /**
                 * @brief Sets the preferred physical NIC name for interface auto-selection.
                 *
                 * @param nic  NIC name string (e.g. "eth0"); empty to auto-detect.
                 */
                virtual void                                                        PreferredNic(const ppp::string& nic) noexcept;

                /**
                 * @brief Registers one IP-list source entry for deferred route loading.
                 *
                 * @param path  Local file path for caching the downloaded IP-list.
                 * @param gw    Gateway IP address for routes in this list.
                 * @param url   Download URL of the IP-list file.
                 * @return true if the entry was accepted; false on validation failure.
                 */
                virtual bool                                                        AddLoadIPList(
                    const ppp::string&                                              path, 
#if defined(_LINUX) 
                    const ppp::string&                                              nic,
#endif  
                    const boost::asio::ip::address&                                 gw,
                    const ppp::string&                                              url) noexcept;

                /**
                 * @brief Gets the formatted URI string of the remote server endpoint.
                 * @return Human-readable server URI (e.g. "wss://vpn.example.com:443/ws").
                 */
                virtual ppp::string                                                 GetRemoteUri() noexcept;
#endif  

            public: 
                /**
                 * @brief Opens the switcher and initializes all runtime services.
                 *
                 * @param tap  Shared TAP/TUN interface to bind to.
                 * @return true if all services started; false on any initialization failure.
                 * @note Calls base VEthernet::Open(), then creates exchanger, proxies, routes, etc.
                 */
                virtual bool                                                        Open(const std::shared_ptr<ITap>& tap) noexcept override;

                /**
                 * @brief Disposes the switcher and releases all runtime services.
                 *
                 * @note Removes OS routes, stops proxy listeners, and disposes the exchanger.
                 *       Safe to call multiple times; subsequent calls are no-ops.
                 */
                virtual void                                                        Dispose() noexcept override;

                /**
                 * @brief Returns the active buffer swap allocator.
                 * @return Shared BufferswapAllocator from the parent VEthernet context.
                 */
                virtual std::shared_ptr<ppp::threading::BufferswapAllocator>        GetBufferAllocator() noexcept override;

                /**
                 * @brief Enables or disables outgoing QUIC packet blocking.
                 *
                 * @param value  true to drop outbound UDP port-443 (QUIC) datagrams.
                 * @return true if the setting was applied; false on error.
                 */
                virtual bool                                                        BlockQUIC(bool value) noexcept;

            protected:  
                /**
                 * @brief Handles a raw IPv4 packet from the TAP device (native path).
                 *
                 * @param packet         Pointer to the raw ip_hdr structure.
                 * @param packet_length  Total IP packet length in bytes.
                 * @param header_length  IP header length in bytes.
                 * @param proto          IP protocol number (TCP=6, UDP=17, ICMP=1, etc.).
                 * @param vnet           true if packet originated from virtual-network mode.
                 * @return true if the packet was consumed; false to drop.
                 */
                virtual bool                                                        OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept override;

                /**
                 * @brief Handles a raw IPv6 packet from the TAP device.
                 *
                 * @param packet         Pointer to the raw IPv6 packet bytes.
                 * @param packet_length  Packet length in bytes.
                 * @param vnet           true if packet originated from virtual-network mode.
                 * @return true if the packet was consumed; false to drop.
                 */
                virtual bool                                                        OnPacketInput(Byte* packet, int packet_length, bool vnet) noexcept override;

                /**
                 * @brief Handles a fully-parsed IPv4 IP frame from the TAP device.
                 *
                 * @param packet  Parsed IPFrame shared pointer.
                 * @return true if the packet was consumed; false to drop.
                 */
                virtual bool                                                        OnPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept override;

                /**
                 * @brief Handles the periodic tick event (approximately 1 Hz).
                 *
                 * @param now  Current tick count in milliseconds.
                 * @return true to continue ticking; false to stop.
                 * @note Invokes TickEvent callback and performs ICMP probe expiration.
                 */
                virtual bool                                                        OnTick(uint64_t now) noexcept override;

                /**
                 * @brief Handles the periodic update event from the base VEthernet class.
                 *
                 * @param now  Current tick count in milliseconds.
                 * @return true to continue; false to stop.
                 */
                virtual bool                                                        OnUpdate(uint64_t now) noexcept override;

                /**
                 * @brief Handles the basic server information callback (without extensions).
                 *
                 * @param information  Parsed server information message.
                 * @return true if applied; false on error.
                 */
                virtual bool                                                        OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information) noexcept;

                /**
                 * @brief Handles the extended server information callback (with IPv6/QoS extensions).
                 *
                 * @param information  Parsed server information message.
                 * @param extensions   Extended fields including IPv6 assignment data.
                 * @return true if applied; false on error.
                 */
                virtual bool                                                        OnInformation(const std::shared_ptr<VirtualEthernetInformation>& information, const VirtualEthernetInformationExtensions& extensions) noexcept;

            protected:  
                /**
                 * @brief Creates the VEthernetExchanger instance for this switcher.
                 * @return New exchanger shared pointer; null on allocation failure.
                 * @note Override to inject a specialized exchanger subclass.
                 */
                virtual std::shared_ptr<VEthernetExchanger>                         NewExchanger() noexcept;

                /**
                 * @brief Creates the TCP/IP netstack implementation.
                 * @return New VNetstack shared pointer.
                 * @note Returns a VEthernetNetworkTcpipStack instance by default.
                 */
                virtual std::shared_ptr<ppp::ethernet::VNetstack>                   NewNetstack() noexcept override;

                /**
                 * @brief Creates the local HTTP proxy switcher bound to the given exchanger.
                 *
                 * @param exchanger  Exchanger providing configuration and tunnel context.
                 * @return New HTTP proxy switcher; null if HTTP proxy is disabled.
                 */
                virtual VEthernetHttpProxySwitcherPtr                               NewHttpProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                /**
                 * @brief Creates the local SOCKS proxy switcher bound to the given exchanger.
                 *
                 * @param exchanger  Exchanger providing configuration and tunnel context.
                 * @return New SOCKS proxy switcher; null if SOCKS proxy is disabled.
                 */
                virtual VEthernetSocksProxySwitcherPtr                              NewSocksProxy(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                /**
                 * @brief Creates the QoS controller instance.
                 * @return New ITransmissionQoS; null if QoS is disabled.
                 */
                virtual std::shared_ptr<ppp::transmissions::ITransmissionQoS>       NewQoS() noexcept;

                /**
                 * @brief Creates the traffic statistics collector.
                 * @return New ITransmissionStatistics instance.
                 */
                virtual ITransmissionStatisticsPtr                                  NewStatistics() noexcept;

#if defined(_WIN32) 
                /**
                 * @brief Creates the Windows PaperAirplane LSP controller.
                 * @return New PaperAirplaneController; null on failure.
                 */
                virtual PaperAirplaneControllerPtr                                  NewPaperAirplaneController() noexcept;
#elif defined(_LINUX)   
                /**
                 * @brief Creates the Linux socket-protection network helper.
                 * @return New ProtectorNetwork; null on failure.
                 */
                virtual ProtectorNetworkPtr                                         NewProtectorNetwork() noexcept;
#endif  

                /**
                 * @brief Injects a UDP datagram back into the local virtual network path.
                 *
                 * @param sourceEP       Source UDP endpoint (server-side or remote peer).
                 * @param destinationEP  Destination UDP endpoint (local TAP client).
                 * @param packet         UDP payload buffer.
                 * @param packet_size    Payload length in bytes.
                 * @param caching        If true, cache the frame for future reuse.
                 * @return true if the datagram was injected; false on error.
                 */
                virtual bool                                                        DatagramOutput(const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, void* packet, int packet_size, bool caching = true) noexcept;

            protected:  
#if !defined(_ANDROID) && !defined(_IPHONE)     
                /**
                 * @brief Installs VPN-specific routes into the host OS routing table.
                 * @note Desktop platforms only. Not called on Android/iOS.
                 */
                virtual void                                                        AddRoute() noexcept;

                /**
                 * @brief Removes VPN-specific routes from the host OS routing table.
                 * @note Desktop platforms only. Called during Dispose().
                 */
                virtual void                                                        DeleteRoute() noexcept;
#endif  

                /**
                 * @brief Handles a UDP frame that arrived from the TAP device.
                 *
                 * @param packet  Parsed IP frame containing the UDP datagram.
                 * @return true if consumed; false to drop.
                 * @note Performs DNS interception and routes remaining datagrams through the exchanger.
                 */
                virtual bool                                                        OnUdpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;

                /**
                 * @brief Handles an ICMP frame that arrived from the TAP device.
                 *
                 * @param packet  Parsed IP frame containing the ICMP message.
                 * @return true if consumed; false to drop.
                 * @note Handles echo-to-gateway and echo-to-remote paths.
                 */
                virtual bool                                                        OnIcmpPacketInput(const std::shared_ptr<IPFrame>& packet) noexcept;

            private:    
#if !defined(_ANDROID) && !defined(_IPHONE) 
                /**
                 * @brief Attempts to repair the underlying NIC's default gateway route.
                 * @return true if the gateway route was successfully restored; false otherwise.
                 */
                bool                                                                FixUnderlyingNgw() noexcept;

                /**
                 * @brief Deletes all OS default routes that conflict with the VPN gateway.
                 * @return true if routes were cleaned up; false on error.
                 */
                bool                                                                DeleteAllDefaultRoute() noexcept;
#else   
                /**
                 * @brief Builds the mobile platform bypass/VPN route table from the TAP interface.
                 *
                 * @param tap  TAP interface providing address and gateway information.
                 * @return true if routes were configured; false on failure.
                 * @note Android/iOS only.
                 */
                bool                                                                AddAllRoute(const std::shared_ptr<ITap>& tap) noexcept;
#endif  

            private:
                /**
                 * @brief Checks whether a raw IPv6 packet passes firewall and scope restrictions.
                 *
                 * @param packet         Raw IPv6 packet bytes.
                 * @param packet_length  Packet length in bytes.
                 * @return true if allowed; false if the packet should be dropped.
                 */
                bool                                                                IsApprovedIPv6Packet(Byte* packet, int packet_length) noexcept;

                /**
                 * @brief Intercepts a DNS UDP packet and redirects it according to rule sets.
                 *
                 * @param exchanger  Active exchanger for tunnel forwarding.
                 * @param packet     Original IP frame.
                 * @param frame      Parsed UDP frame.
                 * @param messages   Raw DNS query payload.
                 * @return true if the DNS packet was redirected; false to forward normally.
                 */
                bool                                                                RedirectDnsServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<UdpFrame>& frame, const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;

                /**
                 * @brief Coroutine implementation of the DNS redirect exchange.
                 *
                 * @param y              Coroutine yield context.
                 * @param socket         Temporary UDP socket used for the redirect query.
                 * @param buffer         Receive buffer for the DNS response.
                 * @param serverIP       DNS server IP to forward the query to.
                 * @param frame          Original UDP frame to extract source/dest endpoints.
                 * @param messages       Raw DNS query payload.
                 * @param context        IO context for the async operations.
                 * @param destinationIP  Original DNS destination IP (for response rewriting).
                 * @return true if the redirect completed and response was injected.
                 */
                bool                                                                RedirectDnsServer(
                    ppp::coroutines::YieldContext&                                  y,
                    const std::shared_ptr<boost::asio::ip::udp::socket>&            socket,
                    const std::shared_ptr<Byte>&                                    buffer,
                    const boost::asio::ip::address&                                 serverIP,
                    const std::shared_ptr<UdpFrame>&                                frame,
                    const std::shared_ptr<ppp::net::packet::BufferSegment>&         messages,
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const boost::asio::ip::address&                                 destinationIP) noexcept;

                /**
                 * @brief Registers a timeout event handler by opaque key.
                 *
                 * @param k        Key pointer used for later removal.
                 * @param timeout  Handler to invoke on expiration.
                 * @return true if registered; false if key already exists.
                 */
                bool                                                                EmplaceTimeout(void* k, const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept;

                /**
                 * @brief Removes and cancels a timeout event handler by opaque key.
                 *
                 * @param k  Key pointer registered via EmplaceTimeout().
                 * @return true if the handler was found and removed; false otherwise.
                 */
                bool                                                                DeleteTimeout(void* k) noexcept;

            private:
                /** @brief Releases all managed runtime objects in safe order. */
                void                                                                ReleaseAllObjects() noexcept;
                /** @brief Clears all pending ICMP probe tracking records. */
                void                                                                ReleaseAllPackets() noexcept;
                /** @brief Stops and clears all registered timeout handlers. */
                void                                                                ReleaseAllTimeouts() noexcept;

            private:    
#if !defined(_ANDROID) && !defined(_IPHONE)     
#if defined(_WIN32) 
                /**
                 * @brief Starts the optional Windows PaperAirplane LSP helper.
                 * @return true if started; false if unavailable or disabled.
                 */
                bool                                                                UsePaperAirplaneController() noexcept;
#endif  
                /**
                 * @brief Adds OS route entries for configured DNS server exception addresses.
                 * @note Ensures DNS server packets bypass the VPN tunnel.
                 */
                void                                                                AddRouteWithDnsServers() noexcept;

                /**
                 * @brief Removes OS route entries for DNS server exception addresses.
                 */
                void                                                                DeleteRouteWithDnsServers() noexcept;

                /**
                 * @brief Adds one host route into the OS routing table.
                 *
                 * @param ip     Destination IP address (host byte order).
                 * @param gw     Gateway IP address (host byte order).
                 * @param prefix Prefix length (0-32).
                 * @return true if the route was added; false on OS error.
                 */
                bool                                                                AddRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;

#if defined(_WIN32) 
                /**
                 * @brief Deletes one host route from a Windows MIB_IPFORWARDTABLE snapshot.
                 *
                 * @param mib    Pre-fetched forward table snapshot.
                 * @param ip     Destination IP.
                 * @param gw     Gateway IP.
                 * @param prefix Prefix length.
                 * @return true if the route was removed; false otherwise.
                 */
                bool                                                                DeleteRoute(const std::shared_ptr<MIB_IPFORWARDTABLE>& mib, uint32_t ip, uint32_t gw, int prefix) noexcept;
#else   
                /**
                 * @brief Deletes one host route from the Unix routing table.
                 *
                 * @param ip     Destination IP.
                 * @param gw     Gateway IP.
                 * @param prefix Prefix length.
                 * @return true if removed; false on error.
                 */
                bool                                                                DeleteRoute(uint32_t ip, uint32_t gw, int prefix) noexcept;
#endif  

                /**
                 * @brief Starts the default-route guard worker to detect and repair route loss.
                 * @return true if the guard was started; false on error.
                 */
                bool                                                                ProtectDefaultRoute() noexcept;

                /**
                 * @brief Downloads and loads all configured IP-list files into the RIB.
                 *
                 * @param gw  Default gateway to associate with loaded routes.
                 * @return true if all lists were loaded; false if any failed.
                 */
                bool                                                                LoadAllIPListWithFilePaths(const boost::asio::ip::address& gw) noexcept;
#endif

                /** @brief Executes final teardown sequence: routes, objects, timeouts. */
                void                                                                Finalize() noexcept;

                /**
                 * @brief Adds the remote server endpoint to the bypass/route exception tables.
                 *
                 * @param gw  Gateway IP to use when adding the server host route.
                 * @return true if added; false on error.
                 */
                bool                                                                AddRemoteEndPointToIPList(const boost::asio::ip::address& gw) noexcept;

#if !defined(_ANDROID) && !defined(_IPHONE)
            private:    
                /**
                 * @brief Applies the server-assigned managed IPv6 configuration to the local NIC.
                 *
                 * @param extensions  Extended information containing IPv6 assignment parameters.
                 * @return true if the IPv6 configuration was applied; false otherwise.
                 */
                bool                                                                ApplyAssignedIPv6(const VirtualEthernetInformationExtensions& extensions) noexcept;

                /**
                 * @brief Restores the original IPv6 configuration if it was previously modified.
                 */
                void                                                                RestoreAssignedIPv6() noexcept;
#endif

            private:    
                /**
                 * @brief Synthesizes and injects an ICMP Echo Reply or similar response.
                 *
                 * @param packet     Original IP frame that triggered the response.
                 * @param frame      Parsed ICMP frame.
                 * @param ttl        TTL value for the synthesized response.
                 * @param allocator  Buffer allocator for the response packet.
                 * @return true if the response was injected; false on error.
                 */
                bool                                                                ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

                /**
                 * @brief Synthesizes and injects an ICMP Time Exceeded response.
                 *
                 * @param packet     Original IP frame that triggered the response.
                 * @param frame      Parsed ICMP frame.
                 * @param source     Source IPv4 address for the TTL Exceeded message.
                 * @param allocator  Buffer allocator for the response packet.
                 * @return true if the response was injected; false on error.
                 */
                bool                                                                TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

                /**
                 * @brief Processes an ICMP echo ACK callback from the remote echo path.
                 *
                 * @param ack_id  Echo ACK identifier to match against pending probes.
                 * @return true if the corresponding probe was found and completed; false otherwise.
                 */
                bool                                                                ERORTE(int ack_id) noexcept;

            private:
                /**
                 * @brief Prepares the optional static-mode traffic aggligator.
                 * @return true if the aggligator was initialized; false if disabled or failed.
                 */
                bool                                                                PreparedAggregator() noexcept;

                /**
                 * @brief Checks whether a destination IP matches the local gateway semantics.
                 *
                 * @param ip    Destination IP (network byte order).
                 * @param gw    Gateway IP (network byte order).
                 * @param mask  Subnet mask (network byte order).
                 * @return true if ip equals gw or ip is the first address in the subnet.
                 */
                bool                                                                IPAddressIsGatewayServer(UInt32 ip, UInt32 gw, UInt32 mask) noexcept { return ip == gw ? true : htonl((ntohl(gw) & ntohl(mask)) + 1) == ip; }

                /**
                 * @brief Forwards an ICMP echo packet to a non-gateway remote server.
                 *
                 * @param exchanger  Exchanger used for transmission.
                 * @param packet     IP frame containing the ICMP echo.
                 * @param allocator  Buffer allocator.
                 * @return true if forwarded; false on error.
                 */
                bool                                                                EchoOtherServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

                /**
                 * @brief Forwards an ICMP echo packet targeted at the gateway address.
                 *
                 * @param exchanger  Exchanger used for transmission.
                 * @param packet     IP frame containing the ICMP echo.
                 * @param allocator  Buffer allocator.
                 * @return true if forwarded; false on error.
                 */
                bool                                                                EchoGatewayServer(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

            private:
                /** @brief The remote session exchanger. Created in Open(), disposed in Dispose(). */
                std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                /** @brief Runtime application configuration. */
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                /** @brief Preferred IPv6 address to request from the server. */
                ppp::string                                                         requested_ipv6_;
                /** @brief Optional QoS controller for transport bandwidth shaping. */
                std::shared_ptr<ppp::transmissions::ITransmissionQoS>               qos_;
                /** @brief Traffic statistics collector. */
                std::shared_ptr<ppp::transmissions::ITransmissionStatistics>        statistics_;
                /** @brief Pending ICMP probe packet table, keyed by echo identifier. */
                VEthernetIcmpPacketTable                                            icmppackets_;
                struct {
                    int                                                             icmppackets_aid_  = 0;   ///< Auto-increment counter for ICMP probe keys.
                    bool                                                            block_quic_       = false;///< QUIC blocking state.
                    bool                                                            static_mode_      = false;///< Static (aggligator) mode flag.
                    uint16_t                                                        mux_              = 0;   ///< VMUX sub-connection count.
                    uint8_t                                                         mux_acceleration_ = 0;   ///< VMUX acceleration flags.
                };
                /** @brief Local HTTP proxy switcher. */
                VEthernetHttpProxySwitcherPtr                                       http_proxy_;
                /** @brief Local SOCKS proxy switcher. */
                VEthernetSocksProxySwitcherPtr                                      socks_proxy_;
                /** @brief Active timeout event handler table. */
                TimeoutEventHandlerTable                                            timeouts_;
                /** @brief Three-tier DNS rule sets: [0]=relative, [1]=full-host, [2]=regexp. */
                DNSRuleTable                                                        dns_ruless_[3];
                /** @brief Route information base loaded from IP-list files. */
                RouteInformationTablePtr                                            rib_;
                /** @brief Forward information base derived from the RIB. */
                ForwardInformationTablePtr                                          fib_;
                /** @brief vBGP URL-to-path mapping for dynamic route updates. */
                RouteIPListTablePtr                                                 vbgp_;
                /** @brief Cached remote server URI string for route exception registration. */
                ppp::string                                                         server_ru_;
                /** @brief Optional static-mode bandwidth aggligator. */
                std::shared_ptr<aggligator::aggligator>                             aggligator_;
                /** @brief Optional proxy forwarding helper. */
                IForwardingPtr                                                      forwarding_;
                /**
                 * @brief Last received extended server information block.
                 *
                 * @details Populated inside the exchanger coroutine on the owning
                 *          io_context strand.  All reads and writes of this field MUST
                 *          execute on that same strand; no additional mutex is required
                 *          because the strand already provides exclusive access.
                 *
                 * @warning Do NOT read this field from an unrelated thread or a different
                 *          strand without external synchronisation.  The exchanger strand
                 *          is the sole owner of this object's lifetime during the session.
                 */
                VirtualEthernetInformationExtensions                                information_extensions_;
                /** @brief Whether a server-assigned IPv6 configuration is currently applied. */
                bool                                                                ipv6_applied_ = false;
                /** @brief IPv6 assignment state used for OS-level rollback. */
                IPv6AppliedState                                                    ipv6_state_;
                /**
                 * @brief The IPv6 address most recently and successfully applied to the local NIC.
                 *
                 * @details Written by ApplyAssignedIPv6() on every successful apply.  Read by
                 *          LastAssignedIPv6() so that SendRequestedIPv6Configuration() can
                 *          supply a sticky hint on reconnect when the user has not set an
                 *          explicit RequestedIPv6() preference.  Default-initialised to the
                 *          unspecified address; callers must check is_v6() before use.
                 */
                boost::asio::ip::address                                            last_assigned_ipv6_;
                
#if !defined(_ANDROID) && !defined(_IPHONE)
                /** @brief Mutex guarding the default-route guard worker. */
                SynchronizedObject                                                  prdr_;
#if defined(_LINUX)
                /** @brief Whether Linux protect mode is active. */
                bool                                                                protect_mode_  = false;
                /** @brief Map from gateway IP to NIC name for per-NIC route management. */
                ppp::unordered_map<uint32_t, ppp::string>                           nics_;
#endif
#endif

#if defined(_LINUX)
                /** @brief Linux socket protection network helper instance. */
                ProtectorNetworkPtr                                                 protect_network_;
#endif

#if defined(_ANDROID) || defined(_IPHONE)
                /** @brief Mobile bypass IP-list text (CIDR-separated). */
                ppp::string                                                         bypass_ip_list_;
#else
                /** @brief Whether VPN routes have been added to the OS table. */
                bool                                                                route_added_   = false;
                /** @brief IP-list file sources registered for deferred loading. */
                LoadIPListFileVectorPtr                                             ribs_;

                /** @brief TAP-side network interface snapshot. */
                std::shared_ptr<NetworkInterface>                                   tun_ni_;
                /** @brief Underlying physical NIC snapshot. */
                std::shared_ptr<NetworkInterface>                                   underlying_ni_;
                /** @brief Preferred physical NIC name for interface selection. */
                ppp::string                                                         preferred_nic_;
                /** @brief Preferred physical default gateway for route operations. */
                boost::asio::ip::address                                            preferred_ngw_;
                /** @brief DNS server sets per tier (bypass/VPN/redirect). */
                ppp::unordered_set<uint32_t>                                        dns_serverss_[3];
                
#if defined(_WIN32)
                /** @brief Windows PaperAirplane LSP controller. */
                PaperAirplaneControllerPtr                                          paper_airplane_ctrl_;
                /** @brief Snapshot of Windows default routes captured before VPN start. */
                ppp::vector<MIB_IPFORWARDROW>                                       default_routes_;
                /** @brief Per-NIC DNS server addresses captured before VPN start. */
                AllNicDnsServerAddresses                                            ni_dns_servers_;
#elif defined(_LINUX)
                /** @brief Linux resolv.conf content captured before VPN start. */
                ppp::string                                                         ni_dns_servers_;
                /** @brief Linux default routes captured before VPN start. */
                RouteInformationTablePtr                                            default_routes_;
#endif
#endif
            };
        }
    }
}
