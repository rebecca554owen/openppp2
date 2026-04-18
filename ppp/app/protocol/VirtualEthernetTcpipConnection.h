#pragma once

/**
 * @file VirtualEthernetTcpipConnection.h
 * @brief Declares TCP/IP bridge connection between socket and transmission.
 * @author ("OPENPPP2 Team")
 * @license ("GPL-3.0")
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/net/Firewall.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace app {
        namespace protocol {
            /**
             * @brief Bridges a local TCP socket and a virtual Ethernet transmission channel.
             */
            class VirtualEthernetTcpipConnection : public std::enable_shared_from_this<VirtualEthernetTcpipConnection> {
            public:
                typedef ppp::configurations::AppConfiguration                   AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                       AppConfigurationPtr;
                typedef ppp::net::Firewall                                      Firewall;
                typedef std::shared_ptr<ppp::net::Firewall>                     FirewallPtr;
                typedef ppp::threading::Executors::StrandPtr                    StrandPtr;
                typedef std::shared_ptr<boost::asio::io_context>                ContextPtr;
                typedef ppp::coroutines::YieldContext                           YieldContext;
                typedef ppp::transmissions::ITransmission                       ITransmission;
                typedef std::shared_ptr<ITransmission>                          ITransmissionPtr;
                typedef ppp::app::protocol::VirtualEthernetLogger               VirtualEthernetLogger;
                typedef std::shared_ptr<VirtualEthernetLogger>                  VirtualEthernetLoggerPtr;
                typedef ppp::function<bool(uint32_t, uint32_t, uint32_t)>       AcceptMuxAsynchronousCallback;

#if defined(_LINUX)
            public:
                /**
                 * @brief Shared pointer type for Linux socket protection helper.
                 */
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>             ProtectorNetworkPtr;

            public:
                ProtectorNetworkPtr                                             ProtectorNetwork;
#endif

            public:
                /**
                 * @brief Initializes a TCP/IP connection bridge object.
                 * @param configuration Runtime application configuration.
                 * @param context Asio IO context.
                 * @param strand Serialized executor for callbacks.
                 * @param id Logical connection identifier.
                 * @param socket Existing TCP socket instance.
                 * @return N/A.
                 * @note The socket can be null for mux-only handshake flows.
                 */
                VirtualEthernetTcpipConnection(
                    const AppConfigurationPtr&                                  configuration,
                    const ContextPtr&                                           context,
                    const StrandPtr&                                            strand,
                    const Int128&                                               id,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&        socket) noexcept;
                /**
                 * @brief Releases connection resources.
                 * @return N/A.
                 * @note Destructor finalizes transmission and socket state.
                 */
                virtual ~VirtualEthernetTcpipConnection() noexcept;

            public:
                /** @brief Checks whether the bridge is currently linked. @return True when not disposed and connected. @note Lightweight state check. */
                bool                                                            IsLinked()          noexcept { return !disposed_ && connected_; }
                /** @brief Gets a shared self-reference. @return Shared pointer to current object. @note Requires object ownership by `shared_ptr`. */
                std::shared_ptr<VirtualEthernetTcpipConnection>                 GetReference()      noexcept { return shared_from_this(); }
                /** @brief Gets IO context. @return Context shared pointer. @note No ownership transfer. */
                ContextPtr                                                      GetContext()        noexcept { return context_; }
                /** @brief Gets strand executor. @return Strand shared pointer. @note Used to serialize internal operations. */
                StrandPtr                                                       GetStrand()         noexcept { return strand_; }
                /** @brief Gets runtime configuration. @return Configuration shared pointer. @note Read-only access pattern by convention. */
                AppConfigurationPtr                                             GetConfiguration()  noexcept { return configuration_; }
                /** @brief Gets logical connection id. @return Connection id value. @note Value is assigned during construction. */
                Int128                                                          GetId()             noexcept { return id_; }
                /** @brief Gets underlying TCP socket. @return Socket shared pointer. @note May be null after `Clear()`. */
                std::shared_ptr<boost::asio::ip::tcp::socket>                   GetSocket()         noexcept { return socket_; }
                /** @brief Gets active transmission. @return Reference to transmission shared pointer. @note Can be null before handshake completes. */
                const ITransmissionPtr&                                         GetTransmission()   noexcept { return transmission_; }

            public:
                /**
                 * @brief Clears connection references without fully disposing object.
                 * @return void.
                 * @note Primarily resets socket/transmission handles.
                 */
                void                                                            Clear() noexcept;
                /**
                 * @brief Initiates active connect handshake over transmission.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param host Destination host string.
                 * @param port Destination port.
                 * @return True when connect handshake succeeds.
                 * @note This path expects a normal connect-not-mux flow.
                 */
                virtual bool                                                    Connect(YieldContext& y, ITransmissionPtr& transmission, const ppp::string& host, int port) noexcept;
                /**
                 * @brief Accepts peer connect handshake and opens destination socket.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param logger Optional logger for connect events.
                 * @param mux Optional mux accept callback.
                 * @return True when handshake and setup succeed.
                 * @note When `mux` is provided, non-connect packets may be treated as mux handshakes.
                 */
                virtual bool                                                    Accept(YieldContext& y, ITransmissionPtr& transmission, const VirtualEthernetLoggerPtr& logger, const AcceptMuxAsynchronousCallback& mux) noexcept;

                /**
                 * @brief Initiates mux-on handshake.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param vlan Mux VLAN identifier.
                 * @param seq Sequence value.
                 * @param ack Acknowledge value.
                 * @return True on successful mux negotiation.
                 * @note Uses control-plane handshake without destination host/port.
                 */
                virtual bool                                                    ConnectMux(YieldContext& y, ITransmissionPtr& transmission, uint32_t vlan, uint32_t seq, uint32_t ack) noexcept;
                /**
                 * @brief Accepts mux-on handshake.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel to use.
                 * @param ac Callback invoked with negotiated mux fields.
                 * @return True on successful mux negotiation.
                 * @note Callback must be valid and return true to complete acceptance.
                 */
                virtual bool                                                    AcceptMux(YieldContext& y, ITransmissionPtr& transmission, const AcceptMuxAsynchronousCallback& ac) noexcept;

            public:
                /**
                 * @brief Starts bidirectional forwarding loop.
                 * @param y Coroutine yield context.
                 * @return True if at least one direction starts successfully.
                 * @note Returns after forwarding loop exits and disposal is scheduled.
                 */
                virtual bool                                                    Run(YieldContext& y) noexcept;
                /**
                 * @brief Updates activity state.
                 * @return void.
                 * @note Default implementation is empty and can be overridden.
                 */
                virtual void                                                    Update() noexcept {};
                /**
                 * @brief Schedules asynchronous disposal of this connection.
                 * @return void.
                 * @note Actual cleanup runs on configured context/strand.
                 */
                virtual void                                                    Dispose() noexcept;
                /**
                 * @brief Gets firewall policy object.
                 * @return Firewall instance or null.
                 * @note Base implementation returns null.
                 */
                virtual std::shared_ptr<ppp::net::Firewall>                     GetFirewall() noexcept { return NULLPTR; }
                /**
                 * @brief Sends a raw buffer to peer through transmission.
                 * @param y Coroutine yield context.
                 * @param packet Buffer pointer.
                 * @param packet_length Buffer size.
                 * @return True on successful write.
                 * @note Requires connected and non-disposed state.
                 */
                virtual bool                                                    SendBufferToPeer(YieldContext& y, const void* packet, int packet_length) noexcept;

            private:
                /**
                 * @brief Finalizes connection synchronously.
                 * @return void.
                 * @note Called by destructor and posted dispose path.
                 */
                void                                                            Finalize() noexcept;
                /**
                 * @brief Starts socket-read to transmission forwarding side.
                 * @return True when initial receive is armed.
                 * @note Allocates and schedules asynchronous socket reads.
                 */
                bool                                                            ReceiveTransmissionToSocket() noexcept;
                /**
                 * @brief Runs transmission-read to socket-write forwarding loop.
                 * @param y Coroutine yield context.
                 * @return True if at least one packet is forwarded.
                 * @note Loop ends on read/write failure or disposal.
                 */
                bool                                                            ForwardTransmissionToSocket(YieldContext& y) noexcept;
                /**
                 * @brief Arms asynchronous read from socket.
                 * @param buffer Receive buffer.
                 * @param buffer_size Receive buffer capacity.
                 * @return True when async read scheduling succeeds.
                 * @note Read completion forwards data to transmission.
                 */
                bool                                                            ReceiveSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept;
                /**
                 * @brief Forwards one socket chunk to transmission.
                 * @param buffer Receive buffer.
                 * @param buffer_size Buffer capacity.
                 * @param bytes_transferred Number of bytes to forward.
                 * @return True when asynchronous write is accepted.
                 * @note Completion callback decides continuation/disposal.
                 */
                bool                                                            ForwardSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size, int bytes_transferred) noexcept;
                /**
                 * @brief Handles completion of socket-to-transmission forward.
                 * @param ok True when write completed successfully.
                 * @param buffer Receive buffer.
                 * @param buffer_size Buffer capacity.
                 * @return void.
                 * @note Continues receive loop on success; otherwise disposes connection.
                 */
                void                                                            ForwardSocketToTransmissionOK(bool ok, const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept {
                    if (ok) {
                        ok = ReceiveSocketToTransmission(buffer, buffer_size);
                    }

                    if (ok) {
                        Update();
                    }
                    else {
                        Dispose();
                    }
                }

            private:
                /**
                 * @brief Shared accept-side negotiation helper.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel.
                 * @param logger Optional logger.
                 * @param accept_mux_ac Optional mux callback.
                 * @param mux_or_connect True for mux mode; false for connect mode.
                 * @return True when negotiation succeeds.
                 * @note Handles both connect and mux acceptance entry points.
                 */
                bool                                                            MuxOrAccept(
                    YieldContext&                                               y, 
                    ITransmissionPtr&                                           transmission, 
                    const VirtualEthernetLoggerPtr&                             logger,
                    const AcceptMuxAsynchronousCallback&                        accept_mux_ac, 
                    bool                                                        mux_or_connect) noexcept;
                /**
                 * @brief Shared connect-side negotiation helper.
                 * @param y Coroutine yield context.
                 * @param transmission Transmission channel.
                 * @param host Destination host for connect mode.
                 * @param port Destination port for connect mode.
                 * @param vlan VLAN value for mux mode.
                 * @param seq Sequence value for mux mode.
                 * @param ack Acknowledge value for mux mode.
                 * @param mux_or_connect True for mux mode; false for connect mode.
                 * @return True when negotiation succeeds.
                 * @note Handles both connect and mux active entry points.
                 */
                bool                                                            MuxOrConnect(
                    YieldContext&                                               y, 
                    ITransmissionPtr&                                           transmission, 
                    const ppp::string&                                          host, 
                    int                                                         port, 
                    uint32_t                                                    vlan, 
                    uint32_t                                                    seq, 
                    uint32_t                                                    ack, 
                    bool                                                        mux_or_connect) noexcept;

            private:
#if defined(_WIN32)
                std::shared_ptr<ppp::net::QoSS>                                 qoss_;
#endif
                struct {
                    bool                                                        disposed_  : 1;
                    bool                                                        connected_ : 7;
                };
                AppConfigurationPtr                                             configuration_;
                ContextPtr                                                      context_;
                StrandPtr                                                       strand_;
                Int128                                                          id_        = 0;
                std::shared_ptr<boost::asio::ip::tcp::socket>                   socket_;
                ITransmissionPtr                                                transmission_;
            };
        }
    }
}
