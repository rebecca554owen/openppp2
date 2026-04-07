#pragma once

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/Int128.h>
#include <ppp/net/Firewall.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

namespace ppp {
    namespace app {
        namespace protocol {
            // Address type enumeration for SOCKS-like addressing
            enum AddressType {
                None                                                        = 0,    // No address type
                IPv4                                                        = 1,    // IPv4 address
                IPv6                                                        = 2,    // IPv6 address
                Domain                                                      = 3,    // Domain name
            };

            // Structure representing an endpoint with address type, host and port
            struct AddressEndPoint {
                AddressType                                                 Type = AddressType::None;   // Type of the address
                ppp::string                                                 Host;                       // Host string (IP or domain)
                int                                                         Port = 0;                   // Port number
            };

            /* Virtual Ethernet Link Layer Protocol Handler */
            class VirtualEthernetLinklayer : public std::enable_shared_from_this<VirtualEthernetLinklayer> {
            public:
                struct                                                    InformationEnvelope {
                    VirtualEthernetInformation                            Base;
                    VirtualEthernetInformationExtensions                  Extensions;
                    ppp::string                                           ExtendedJson;
                };

            public:
                typedef ppp::configurations::AppConfiguration               AppConfiguration;           // Application configuration type
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;        // Shared pointer to configuration
                typedef ppp::transmissions::ITransmission                   ITransmission;              // Transmission interface type
                typedef std::shared_ptr<ITransmission>                      ITransmissionPtr;           // Shared pointer to transmission
                typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;                 // Shared pointer to IO context
                typedef ppp::coroutines::YieldContext                       YieldContext;               // Coroutine yield context type

            public:
                // Packet action opcodes for the virtual Ethernet protocol
                typedef enum {
                    // Information and keep-alive messages
                    PacketAction_INFO                                       = 0x7E, // Information exchange
                    PacketAction_KEEPALIVED                                 = 0x7F, // Keep-alive heartbeat

                    // FRP (Fast Reverse Proxy) related actions
                    PacketAction_FRP_ENTRY                                  = 0x20, // FRP entry registration
                    PacketAction_FRP_CONNECT                                = 0x21, // FRP connection request
                    PacketAction_FRP_CONNECTOK                              = 0x22, // FRP connection acknowledgment
                    PacketAction_FRP_PUSH                                   = 0x23, // FRP data push
                    PacketAction_FRP_DISCONNECT                             = 0x24, // FRP disconnection
                    PacketAction_FRP_SENDTO                                 = 0x25, // FRP UDP send-to

                    // VPN tunnel actions
                    PacketAction_LAN                                        = 0x28, // LAN advertisement
                    PacketAction_NAT                                        = 0x29, // NAT traversal data
                    PacketAction_SYN                                        = 0x2A, // TCP SYN (connection request)
                    PacketAction_SYNOK                                      = 0x2B, // TCP SYN+ACK (connection accepted)
                    PacketAction_PSH                                        = 0x2C, // TCP PSH (data push)
                    PacketAction_FIN                                        = 0x2D, // TCP FIN (connection close)
                    PacketAction_SENDTO                                     = 0x2E, // UDP send-to
                    PacketAction_ECHO                                       = 0x2F, // Echo request
                    PacketAction_ECHOACK                                    = 0x30, // Echo reply
                    PacketAction_STATIC                                     = 0x31, // Static route request
                    PacketAction_STATICACK                                  = 0x32, // Static route acknowledgment

                    // Multiplexing (MUX) actions
                    PacketAction_MUX                                        = 0x35, // MUX setup request
                    PacketAction_MUXON                                      = 0x36, // MUX established acknowledgment
                }                                                           PacketAction;

            public:
                // Error codes for connection outcomes
                typedef enum {
                    ERRORS_SUCCESS,                 // Connection succeeded
                    ERRORS_CONNECT_TO_DESTINATION,  // Failed to connect to destination
                    ERRORS_CONNECT_CANCEL,          // Connection was cancelled
                }                                                           ERROR_CODES;

            public:
                // Constructor initializes the link layer with configuration, context and unique ID
                VirtualEthernetLinklayer(
                    const AppConfigurationPtr&                              configuration, 
                    const ContextPtr&                                       context,
                    const Int128&                                           id) noexcept;
                virtual ~VirtualEthernetLinklayer() noexcept = default;    // Virtual destructor for safe inheritance

            public:
                // Returns a shared pointer to this instance
                std::shared_ptr<VirtualEthernetLinklayer>                   GetReference() noexcept     { return shared_from_this(); }
                // Returns the associated IO context
                ContextPtr                                                  GetContext() noexcept       { return context_; }
                // Returns the application configuration
                AppConfigurationPtr&                                        GetConfiguration() noexcept { return configuration_; }
                // Returns the unique identifier of this link layer instance
                Int128                                                      GetId() noexcept            { return id_; }

            public:
                // Main run loop: processes incoming packets from the transmission
                virtual bool                                                Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                // Generates a new unique connection ID (24-bit)
                static int                                                  NewId() noexcept;

            public:
                virtual bool                                                DoLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept;
                virtual bool                                                DoNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                virtual bool                                                DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept;
                virtual bool                                                DoInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept;
                // Send TCP data push on a connection
                virtual bool                                                DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept;
                // Send TCP connection request using hostname and port
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept;
                // Send TCP connection request using endpoint
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept;
                // Send TCP connection acknowledgment with error code
                virtual bool                                                DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept;
                // Send TCP disconnection notification
                virtual bool                                                DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept;
                // Send echo reply (acknowledgment)
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept;
                // Send echo request with payload
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                // Send UDP datagram with source and destination endpoints
                virtual bool                                                DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                // Request static route information
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                // Respond with static route information for a specific session
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept;

            public:
                // Request MUX (multiplexing) setup
                virtual bool                                                DoMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept;
                // Acknowledge MUX setup with sequence and acknowledgment numbers
                virtual bool                                                DoMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept;

            protected:
                // Handler for incoming MUX request (override in derived class)
                virtual bool                                                OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept { return false; }
                // Handler for incoming MUXON acknowledgment (override in derived class)
                virtual bool                                                OnMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept { return false; }

            public:
                // Send FRP entry registration
                virtual bool                                                DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept;
                // Send FRP UDP datagram
                virtual bool                                                DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                // Send FRP connection request
                virtual bool                                                DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                // Send FRP connection acknowledgment
                virtual bool                                                DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept;
                // Send FRP disconnection notification
                virtual bool                                                DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                // Send FRP data push
                virtual bool                                                DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length, YieldContext& y) noexcept;

            protected:
                // Handlers for FRP actions (override in derived class)
                virtual bool                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept { return true; }
                virtual bool                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept { return true; }

            protected:
                virtual bool                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept { return OnInformation(transmission, information.Base, y); }
                virtual bool                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept { return true; }

            protected:
                // Preparation hooks before performing connect or sendto
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                virtual bool                                                OnPreparedSendTo(const ITransmissionPtr& transmission, const ppp::string& sourceHost, const boost::asio::ip::udp::endpoint& sourceEP, const ppp::string& destinationHost, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                // Sends keep-alive packet if needed, based on timing
                virtual bool                                                DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept;
                
            protected:
                // Returns the firewall instance for filtering (can be overridden)
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept;
                // Processes an incoming packet from the transmission
                virtual bool                                                PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                ContextPtr                                                  context_;       // Associated IO context
                Int128                                                      id_      = 0;  // Unique identifier
                UInt64                                                      last_    = 0;  // Last activity timestamp (milliseconds)
                UInt64                                                      next_ka_ = 0;  // Next keep-alive scheduled timestamp
                AppConfigurationPtr                                         configuration_; // Application configuration
            };
        }
    }
}
