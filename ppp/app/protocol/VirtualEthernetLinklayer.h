// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file VirtualEthernetLinklayer.h
 * @brief Virtual Ethernet link-layer protocol definitions and dispatch interface.
 */

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
            /** @brief Address encoding type used by packet endpoint fields. */
            enum AddressType {
                None                                                        = 0,
                IPv4                                                        = 1,
                IPv6                                                        = 2,
                Domain                                                      = 3,
            };

            /** @brief Logical endpoint containing address type, host text, and port. */
            struct AddressEndPoint {
                AddressType                                                 Type = AddressType::None;
                ppp::string                                                 Host;
                int                                                         Port = 0;
            };

            /**
             * @brief Virtual Ethernet packet codec and dispatcher.
             *
             * This class serializes outbound protocol frames and parses inbound frames,
             * then dispatches parsed events through overridable `On*` handlers.
             */
            class VirtualEthernetLinklayer : public std::enable_shared_from_this<VirtualEthernetLinklayer> {
            public:
                /** @brief Full information payload including optional extension JSON. */
                struct                                                    InformationEnvelope {
                    VirtualEthernetInformation                            Base;
                    VirtualEthernetInformationExtensions                  Extensions;
                    ppp::string                                           ExtendedJson;
                };

            public:
                typedef ppp::configurations::AppConfiguration               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;
                typedef ppp::transmissions::ITransmission                   ITransmission;
                typedef std::shared_ptr<ITransmission>                      ITransmissionPtr;
                typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;
                typedef ppp::coroutines::YieldContext                       YieldContext;

            public:
                /** @brief Virtual Ethernet protocol action opcodes. */
                typedef enum {
                    PacketAction_INFO                                       = 0x7E,
                    PacketAction_KEEPALIVED                                 = 0x7F,
                    PacketAction_FRP_ENTRY                                  = 0x20,
                    PacketAction_FRP_CONNECT                                = 0x21,
                    PacketAction_FRP_CONNECTOK                              = 0x22,
                    PacketAction_FRP_PUSH                                   = 0x23,
                    PacketAction_FRP_DISCONNECT                             = 0x24,
                    PacketAction_FRP_SENDTO                                 = 0x25,
                    PacketAction_LAN                                        = 0x28,
                    PacketAction_NAT                                        = 0x29,
                    PacketAction_SYN                                        = 0x2A,
                    PacketAction_SYNOK                                      = 0x2B,
                    PacketAction_PSH                                        = 0x2C,
                    PacketAction_FIN                                        = 0x2D,
                    PacketAction_SENDTO                                     = 0x2E,
                    PacketAction_ECHO                                       = 0x2F,
                    PacketAction_ECHOACK                                    = 0x30,
                    PacketAction_STATIC                                     = 0x31,
                    PacketAction_STATICACK                                  = 0x32,
                    PacketAction_MUX                                        = 0x35,
                    PacketAction_MUXON                                      = 0x36,
                }                                                           PacketAction;

            public:
                /** @brief Error codes returned by connect acknowledgment actions. */
                typedef enum {
                    ERRORS_SUCCESS,
                    ERRORS_CONNECT_TO_DESTINATION,
                    ERRORS_CONNECT_CANCEL,
                }                                                           ERROR_CODES;

            public:
                /**
                 * @brief Constructs a link-layer handler.
                 * @param configuration Application configuration object.
                 * @param context IO context used by asynchronous operations.
                 * @param id Session identifier associated with this handler.
                 */
                VirtualEthernetLinklayer(
                    const AppConfigurationPtr&                              configuration, 
                    const ContextPtr&                                       context,
                    const Int128&                                           id) noexcept;
                /** @brief Virtual destructor. */
                virtual ~VirtualEthernetLinklayer() noexcept = default;

            public:
                /** @brief Returns `shared_from_this()` for this object. */
                std::shared_ptr<VirtualEthernetLinklayer>                   GetReference() noexcept     { return shared_from_this(); }
                /** @brief Returns the associated IO context. */
                ContextPtr                                                  GetContext() noexcept       { return context_; }
                /** @brief Returns the configuration object. */
                AppConfigurationPtr&                                        GetConfiguration() noexcept { return configuration_; }
                /** @brief Returns the session identifier for this link layer. */
                Int128                                                      GetId() noexcept            { return id_; }

            public:
                /**
                 * @brief Processes incoming packets until read/parse failure.
                 * @param transmission Active transport channel.
                 * @param y Coroutine yield context.
                 * @return `true` when at least one packet is processed successfully.
                 */
                virtual bool                                                Run(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Generates a protocol connection ID in 24-bit range. */
                static int                                                  NewId() noexcept;

            public:
                /** @brief Sends a LAN advertisement packet. */
                virtual bool                                                DoLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept;
                /** @brief Sends a NAT frame payload. */
                virtual bool                                                DoNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends base information payload. */
                virtual bool                                                DoInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept;
                /** @brief Sends information envelope with optional extension data. */
                virtual bool                                                DoInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept;
                /** @brief Sends TCP payload for an existing connection. */
                virtual bool                                                DoPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends TCP connect request using domain/host text. */
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& hostname, int port, YieldContext& y) noexcept;
                /** @brief Sends TCP connect request using resolved endpoint. */
                virtual bool                                                DoConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept;
                /** @brief Sends TCP connect acknowledgment with status code. */
                virtual bool                                                DoConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept;
                /** @brief Sends TCP disconnect notification. */
                virtual bool                                                DoDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept;
                /** @brief Sends echo acknowledgment by ID. */
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept;
                /** @brief Sends echo payload packet. */
                virtual bool                                                DoEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends UDP payload with destination/source endpoint descriptors. */
                virtual bool                                                DoSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Requests static mapping information from peer. */
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept;
                /** @brief Sends static mapping acknowledgment payload. */
                virtual bool                                                DoStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept;

            public:
                /** @brief Sends MUX setup request. */
                virtual bool                                                DoMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept;
                /** @brief Sends MUX setup acknowledgment. */
                virtual bool                                                DoMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept;

            protected:
                /** @brief Handles inbound MUX request. */
                virtual bool                                                OnMux(const ITransmissionPtr& transmission, uint16_t vlan, uint16_t max_connections, bool acceleration, YieldContext& y) noexcept { return false; }
                /** @brief Handles inbound MUX acknowledgment. */
                virtual bool                                                OnMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept { return false; }

            public:
                /** @brief Sends FRP mapping entry registration. */
                virtual bool                                                DoFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept;
                /** @brief Sends FRP UDP payload. */
                virtual bool                                                DoFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept;
                /** @brief Sends FRP connect request. */
                virtual bool                                                DoFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                /** @brief Sends FRP connect acknowledgment. */
                virtual bool                                                DoFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept;
                /** @brief Sends FRP disconnect notification. */
                virtual bool                                                DoFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept;
                /** @brief Sends FRP stream payload. */
                virtual bool                                                DoFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length, YieldContext& y) noexcept;

            protected:
                /** @brief Handles inbound FRP entry registration. */
                virtual bool                                                OnFrpEntry(const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP UDP payload. */
                virtual bool                                                OnFrpSendTo(const ITransmissionPtr& transmission, bool in, int remote_port, const boost::asio::ip::udp::endpoint& sourceEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP connect request. */
                virtual bool                                                OnFrpConnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP connect acknowledgment. */
                virtual bool                                                OnFrpConnectOK(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, Byte error_code, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound FRP disconnect notification. */
                virtual bool                                                OnFrpDisconnect(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port) noexcept { return true; }
                /** @brief Handles inbound FRP stream payload. */
                virtual bool                                                OnFrpPush(const ITransmissionPtr& transmission, int connection_id, bool in, int remote_port, const void* packet, int packet_length) noexcept { return true; }

            protected:
                /** @brief Handles inbound LAN advertisement. */
                virtual bool                                                OnLan(const ITransmissionPtr& transmission, uint32_t ip, uint32_t mask, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound NAT payload. */
                virtual bool                                                OnNat(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound base information payload. */
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const VirtualEthernetInformation& information, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound information envelope payload. */
                virtual bool                                                OnInformation(const ITransmissionPtr& transmission, const InformationEnvelope& information, YieldContext& y) noexcept { return OnInformation(transmission, information.Base, y); }
                /** @brief Handles inbound TCP stream payload. */
                virtual bool                                                OnPush(const ITransmissionPtr& transmission, int connection_id, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound TCP connect request. */
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound connect acknowledgment. */
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound disconnect event. */
                virtual bool                                                OnDisconnect(const ITransmissionPtr& transmission, int connection_id, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound echo acknowledgment. */
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, int ack_id, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound echo payload. */
                virtual bool                                                OnEcho(const ITransmissionPtr& transmission, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound UDP payload. */
                virtual bool                                                OnSendTo(const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound static request. */
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, YieldContext& y) noexcept { return true; }
                /** @brief Handles inbound static acknowledgment. */
                virtual bool                                                OnStatic(const ITransmissionPtr& transmission, Int128 fsid, int session_id, int remote_port, YieldContext& y) noexcept { return true; }

            protected:
                /** @brief Hook called after connect endpoint parsing and validation. */
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept { return true; }
                /** @brief Hook called after UDP endpoints parsing and validation. */
                virtual bool                                                OnPreparedSendTo(const ITransmissionPtr& transmission, const ppp::string& sourceHost, const boost::asio::ip::udp::endpoint& sourceEP, const ppp::string& destinationHost, const boost::asio::ip::udp::endpoint& destinationEP, Byte* packet, int packet_length, YieldContext& y) noexcept { return true; }
                /** @brief Sends keep-alive payload when scheduler triggers. */
                virtual bool                                                DoKeepAlived(const ITransmissionPtr& transmission, uint64_t now) noexcept;
                
            protected:
                /** @brief Returns firewall used for endpoint filtering. */
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept;
                /** @brief Decodes and dispatches one inbound protocol packet. */
                virtual bool                                                PacketInput(const ITransmissionPtr& transmission, Byte* p, int packet_length, YieldContext& y) noexcept;

            private:
                /** @brief Associated IO context. */
                ContextPtr                                                  context_;
                /** @brief Session identifier. */
                Int128                                                      id_      = 0;
                /** @brief Last successful packet activity timestamp in milliseconds. */
                UInt64                                                      last_    = 0;
                /** @brief Next keep-alive scheduled timestamp in milliseconds. */
                UInt64                                                      next_ka_ = 0;
                /** @brief Runtime configuration source. */
                AppConfigurationPtr                                         configuration_;
            };
        }
    }
}
