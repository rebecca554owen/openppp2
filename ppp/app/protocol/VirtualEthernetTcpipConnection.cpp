#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file VirtualEthernetTcpipConnection.cpp
 * @brief Implements TCP/IP connection handshake and bidirectional forwarding.
 * @author ("OPENPPP2 Team")
 * @license ("GPL-3.0")
 */

namespace ppp {
    namespace app {
        namespace protocol {
            /**
             * @brief Temporary linklayer helper used during connect/accept handshake.
             */
            class STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST final : public VirtualEthernetLinklayer {
                friend class VirtualEthernetTcpipConnection;

            public:
                /**
                 * @brief Constructs handshake helper instance.
                 * @param connection Parent TCP/IP connection bridge.
                 * @param configuration Runtime configuration.
                 * @param context IO context.
                 * @param id Logical connection id.
                 * @return N/A.
                 * @note This object captures handshake packets and exposes decoded fields.
                 */
                STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST(
                    VirtualEthernetTcpipConnection*                         connection,
                    const AppConfigurationPtr&                              configuration,
                    const ContextPtr&                                       context,
                    const Int128&                                           id) noexcept
                    : VirtualEthernetLinklayer(configuration, context, id)
                    , ConnectId(0)
                    , ConnectOK(false)
                    , ErrorCode(0)
                    , Connect(false)
                    , Sequence(0)
                    , Acknowledge(0)
                    , Vlan(0)
                    , MuxON(false)
                    , connection_(connection) {

                }

            public:
                // PROTOCOL: PREPARED_CONNECT  CONNECT  CONNECT_OK
                int                                                         ConnectId;

                // PROTOCOL: PREPARED_CONNECT
                ppp::string                                                 Host;

                // PROTOCOL: CONNECT
                bool                                                        Connect;
                boost::asio::ip::tcp::endpoint                              Destination;

                // PROTOCOL: CONNECT_OK
                bool                                                        ConnectOK;
                Byte                                                        ErrorCode;

                // PROTOCOL: MUXON
                uint32_t                                                    Sequence;
                uint32_t                                                    Acknowledge;
                uint16_t                                                    Vlan;
                bool                                                        MuxON;

            public:
                /**
                 * @brief Returns firewall object from parent bridge.
                 * @return Firewall object or null.
                 * @note Used by linklayer pipeline for access checks.
                 */
                virtual std::shared_ptr<ppp::net::Firewall>                 GetFirewall() noexcept {
                    return connection_->GetFirewall();
                }
                /**
                 * @brief Handles PREPARED_CONNECT control message.
                 * @param transmission Active transmission channel.
                 * @param connection_id Connection identifier.
                 * @param destinationHost Destination host string.
                 * @param destinationEP Destination endpoint.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Stores host for later logging.
                 */
                virtual bool                                                OnPreparedConnect(const ITransmissionPtr& transmission, int connection_id, const ppp::string& destinationHost, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override {
                    Host = destinationHost;
                    return true;
                }
                /**
                 * @brief Handles CONNECT control message.
                 * @param transmission Active transmission channel.
                 * @param connection_id Connection identifier.
                 * @param destinationEP Destination endpoint.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Marks connect request as received and caches endpoint data.
                 */
                virtual bool                                                OnConnect(const ITransmissionPtr& transmission, int connection_id, const boost::asio::ip::tcp::endpoint& destinationEP, YieldContext& y) noexcept override {
                    Connect = true;
                    ConnectId = connection_id;
                    Destination = destinationEP;
                    return true;
                }
                /**
                 * @brief Handles CONNECT_OK control message.
                 * @param transmission Active transmission channel.
                 * @param connection_id Connection identifier.
                 * @param error_code Handshake result code.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Stores status for caller-side validation.
                 */
                virtual bool                                                OnConnectOK(const ITransmissionPtr& transmission, int connection_id, Byte error_code, YieldContext& y) noexcept override {
                    ConnectOK = true;
                    ErrorCode = error_code;
                    ConnectId = connection_id;
                    return true;
                }
                /**
                 * @brief Handles MUXON control message.
                 * @param transmission Active transmission channel.
                 * @param vlan VLAN value.
                 * @param seq Sequence value.
                 * @param ack Acknowledge value.
                 * @param y Coroutine yield context.
                 * @return Always true.
                 * @note Stores mux tuple for strict handshake matching.
                 */
                virtual bool                                                OnMuxON(const ITransmissionPtr& transmission, uint16_t vlan, uint32_t seq, uint32_t ack, YieldContext& y) noexcept override {
                    MuxON = true;
                    Vlan = vlan;
                    Sequence = seq;
                    Acknowledge = ack;
                    return true;
                }

            private:
                VirtualEthernetTcpipConnection* const                       connection_;
            };

            /**
             * @brief Constructs TCP/IP bridge object.
             * @param configuration Runtime configuration.
             * @param context IO context.
             * @param strand Serialized executor.
             * @param id Logical connection id.
             * @param socket TCP socket object.
             * @return N/A.
             * @note Applies socket window/QoS hints when socket is available.
             */
            VirtualEthernetTcpipConnection::VirtualEthernetTcpipConnection(
                const AppConfigurationPtr&                              configuration,
                const ContextPtr&                                       context,
                const StrandPtr&                                        strand,
                const Int128&                                           id,
                const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket) noexcept
                : disposed_(false)
                , connected_(false)
                , configuration_(configuration)
                , context_(context)
                , strand_(strand)
                , id_(id)
                , socket_(socket) {

                if (NULLPTR != socket) {
#if defined(_WIN32)
                    if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                        if (socket->is_open()) {
                            qoss_ = ppp::net::QoSS::New(socket->native_handle());
                        }
                    }
#endif
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                }
            }

            /**
             * @brief Performs active connect handshake.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param host Destination host.
             * @param port Destination port.
             * @return True on successful handshake.
             * @note Delegates to common `MuxOrConnect` path with connect mode.
             */
            bool VirtualEthernetTcpipConnection::Connect(
                YieldContext&       y, 
                ITransmissionPtr&   transmission, 
                const ppp::string&  host, 
                int                 port) noexcept {
                    
                return MuxOrConnect(y, transmission, host, port, 0, 0, 0, false);
            }

            /**
             * @brief Performs active mux handshake.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param vlan VLAN value.
             * @param seq Sequence value.
             * @param ack Acknowledge value.
             * @return True on successful mux negotiation.
             * @note Delegates to common `MuxOrConnect` path with mux mode.
             */
            bool VirtualEthernetTcpipConnection::ConnectMux(
                YieldContext&       y, 
                ITransmissionPtr&   transmission, 
                uint32_t            vlan, 
                uint32_t            seq, 
                uint32_t            ack) noexcept {

                ppp::string default_host;
                int default_port = ppp::net::IPEndPoint::MinPort;

                return MuxOrConnect(y, transmission, default_host, default_port, vlan, seq, ack, true);
            }

            /**
             * @brief Shared implementation for connect/mux active negotiation.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param host Destination host for connect mode.
             * @param port Destination port for connect mode.
             * @param vlan VLAN value for mux mode.
             * @param seq Sequence value for mux mode.
             * @param ack Acknowledge value for mux mode.
             * @param mux_or_connect True for mux handshake, false for connect handshake.
             * @return True when negotiation succeeds.
             * @note This routine sends one request and validates one peer response packet.
             */
            bool VirtualEthernetTcpipConnection::MuxOrConnect(
                YieldContext&       y, 
                ITransmissionPtr&   transmission, 
                const ppp::string&  host, 
                int                 port, 
                uint32_t            vlan, 
                uint32_t            seq, 
                uint32_t            ack, 
                bool                mux_or_connect) noexcept {

                typedef VirtualEthernetLinklayer::ERROR_CODES ERROR_CODES;

                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionConnectAlreadyConnected);
                    return false;
                }

                if (!mux_or_connect) {
                    if (!socket_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return false;
                    }
                }

                Update();

                auto connector = make_shared_object<STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST>(this, configuration_, context_, id_);
                if (NULLPTR == connector) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionConnectorAllocFailed);
                    return false;
                }
                else {
                    // Dispatch exactly one control packet according to selected negotiation mode.
                    bool connector_dook = false;
                    if (mux_or_connect) {
                        connector_dook = connector->DoMuxON(transmission, vlan, seq, ack, y);
                    }
                    else {
                        connector_dook = connector->DoConnect(transmission, RandomNext(1, INT_MAX), host, port, y);
                    }

                    if (!connector_dook) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                        return false;
                    }
                }

                int packet_size = 0;
                std::shared_ptr<Byte> packet = transmission->Read(y, packet_size);
                if (NULLPTR == packet || packet_size < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                if (!connector->PacketInput(transmission, packet.get(), packet_size, y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                if (mux_or_connect) {
                    // For mux mode, reply must be a MUXON echo with exact tuple match.
                    if (!connector->MuxON) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }

                    if (connector->Vlan != vlan || connector->Sequence != seq || connector->Acknowledge != ack) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }
                }
                else {
                    // For connect mode, reply must be CONNECT_OK with success code.
                    if (!connector->ConnectOK) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                        return false;
                    }

                    ERROR_CODES err = (ERROR_CODES)connector->ErrorCode;
                    if (err != ERROR_CODES::ERRORS_SUCCESS) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                        return false;
                    }
                }

                connected_ = true;
                transmission_ = transmission;

                Update();
                return true;
            }

            /**
             * @brief Performs passive connect acceptance.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param logger Optional logger.
             * @param mux Optional mux callback.
             * @return True on successful acceptance.
             * @note Delegates to common `MuxOrAccept` path with connect mode.
             */
            bool VirtualEthernetTcpipConnection::Accept(
                YieldContext&                                           y, 
                ITransmissionPtr&                                       transmission, 
                const VirtualEthernetLoggerPtr&                         logger,
                const AcceptMuxAsynchronousCallback&                    mux) noexcept {

                return MuxOrAccept(y, transmission, logger, mux, false);
            }

            /**
             * @brief Performs passive mux acceptance.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param ac Mux callback.
             * @return True on successful mux acceptance.
             * @note Delegates to common `MuxOrAccept` path with mux mode.
             */
            bool VirtualEthernetTcpipConnection::AcceptMux(
                YieldContext&                           y, 
                ITransmissionPtr&                       transmission, 
                const AcceptMuxAsynchronousCallback&    ac) noexcept {

                if (NULLPTR == ac) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionAcceptMuxNullCallback);
                    return false;
                }

                return MuxOrAccept(y, transmission, NULLPTR, ac, true);
            }

            /**
             * @brief Shared implementation for connect/mux passive acceptance.
             * @param y Coroutine yield context.
             * @param transmission Transmission channel.
             * @param logger Optional logger for connect events.
             * @param accept_mux_ac Optional mux callback.
             * @param mux_or_connect True for mux-only accept path.
             * @return True when acceptance succeeds.
             * @note In connect mode this function opens/connects the local socket and returns CONNECT_OK.
             */
            bool VirtualEthernetTcpipConnection::MuxOrAccept(
                YieldContext&                                           y, 
                ITransmissionPtr&                                       transmission, 
                const VirtualEthernetLoggerPtr&                         logger,
                const AcceptMuxAsynchronousCallback&                    accept_mux_ac, 
                bool                                                    mux_or_connect) noexcept {

                typedef VirtualEthernetLinklayer::ERROR_CODES ERROR_CODES;

                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionAcceptAlreadyConnected);
                    return false;
                }

                if (!socket_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                Update();

                int packet_size = -1;
                std::shared_ptr<Byte> packet = transmission->Read(y, packet_size);
                if (NULLPTR == packet || packet_size < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                auto connector = make_shared_object<STATIC_VIRTUAL_ETHERNET_TCPIP_CONNECTOR_NEST>(this, configuration_, context_, id_);
                if (NULLPTR == connector) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionAcceptConnectorAllocFailed);
                    return false;
                }

                if (!connector->PacketInput(transmission, packet.get(), packet_size, y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                if (mux_or_connect) {
                LABEL_MUXON:
                    // Mux mode: mark linked state and hand negotiated tuple to callback.
                    if (!connector->MuxON) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }

                    connected_ = true;
                    transmission_ = transmission;
                    Update();

                    bool ok = accept_mux_ac(connector->Vlan, connector->Sequence, connector->Acknowledge);
                    if (!ok) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                        return false;
                    }
                }
                else {
                    boost::asio::ip::tcp::endpoint& destinationEP = connector->Destination;
                    if (!connector->Connect) {
                        // If first packet is not CONNECT and mux callback exists, allow mux fallback.
                        if (NULLPTR != accept_mux_ac) {
                            goto LABEL_MUXON;
                        }

                        return false;
                    }

                    boost::system::error_code ec;
                    socket_->open(destinationEP.protocol(), ec);
                    if (ec) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                        return false;
                    }

                    boost::asio::ip::address destinationIP = destinationEP.address();
#if defined(_WIN32)
                    if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                        int destinationPort = destinationEP.port();
                        qoss_ = ppp::net::QoSS::New(socket_->native_handle(), destinationIP, destinationPort);
                    }
#elif defined(_LINUX)
                    // If IPV4 is not a loop IP address, it needs to be linked to a physical network adapter. 
                    // IPV6 does not need to be linked, because VPN is IPV4, 
                    // And IPV6 does not affect the physical layer network communication of the VPN.
                    if (!destinationIP.is_loopback()) {
                        auto protector_network = ProtectorNetwork;
                        if (NULLPTR != protector_network) {
                            if (!protector_network->Protect(socket_->native_handle(), y)) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelProtectionConfigureFailed);
                                return false;
                            }
                        }
                    }
#endif

                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = GetConfiguration();
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket_->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);
                    ppp::net::Socket::AdjustSocketOptional(*socket_, destinationIP.is_v4(), configuration->tcp.fast_open, configuration->tcp.turbo);

                    // Connect to requested destination and send CONNECT_OK with precise status code.
                    bool ok = ppp::coroutines::asio::async_connect(*socket_, destinationEP, y);
                    if (NULLPTR != logger) {
                        logger->Connect(GetId(), transmission, socket_->local_endpoint(ec), destinationEP, connector->Host);
                    }

                    if (disposed_) {
                        connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_CONNECT_CANCEL, y);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    if (ok) {
                        ok = connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_SUCCESS, y);
                        if (!ok) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                            return false;
                        }
                    }
                    else {
                        connector->DoConnectOK(transmission, connector->ConnectId, ERROR_CODES::ERRORS_CONNECT_TO_DESTINATION, y);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                        return false;
                    }

                    connected_ = true;
                    transmission_ = transmission;
                    Update();
                }

                return true;
            }

            /**
             * @brief Finalizes bridge resources immediately.
             * @return void.
             * @note Closes transmission and socket; resets connected/disposed flags.
             */
            void VirtualEthernetTcpipConnection::Finalize() noexcept {
                ITransmissionPtr transmission = std::move(transmission_); 
                if (NULLPTR != transmission) {
                    transmission->Dispose();
                }

#if defined(_WIN32)
                qoss_.reset();
#endif

                disposed_ = true;
                connected_ = false;

                ppp::net::Socket::Closesocket(socket_);
            }

            /**
             * @brief Clears handles without posting async finalization.
             * @return void.
             * @note Intended for lightweight reset scenarios.
             */
            void VirtualEthernetTcpipConnection::Clear() noexcept {
                connected_ = false;

#if defined(_WIN32)
                qoss_.reset();
#endif

                socket_.reset();
                transmission_.reset();
            }

            /**
             * @brief Destroys bridge object.
             * @return N/A.
             * @note Destructor calls `Finalize()` directly.
             */
            VirtualEthernetTcpipConnection::~VirtualEthernetTcpipConnection() noexcept {
                Finalize();
            }

            /**
             * @brief Posts asynchronous finalization to context/strand.
             * @return void.
             * @note Ensures cleanup order is consistent with other strand-bound operations.
             */
            void VirtualEthernetTcpipConnection::Dispose() noexcept {
                auto self = shared_from_this();
                ppp::threading::Executors::ContextPtr context = context_;
                ppp::threading::Executors::StrandPtr strand = strand_;

                ppp::threading::Executors::Post(context, strand,
                    [self, this, context, strand]() noexcept {
                        Finalize();
                    });
            }

            /**
             * @brief Starts the bidirectional forwarding session.
             * @param y Coroutine yield context.
             * @return True when forward loop yields at least one packet.
             * @note Starts socket-read side first, then enters transmission-read loop.
             */
            bool VirtualEthernetTcpipConnection::Run(YieldContext& y) noexcept {
                if (!ReceiveTransmissionToSocket()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                    return false;
                }

                Update();
                return ForwardTransmissionToSocket(y);
            }

            /**
             * @brief Writes data to remote peer through transmission.
             * @param y Coroutine yield context.
             * @param packet Payload pointer.
             * @param packet_length Payload length.
             * @return True on successful write.
             * @note Requires connected and non-disposed state.
             */
            bool VirtualEthernetTcpipConnection::SendBufferToPeer(YieldContext& y, const void* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionSendPeerInvalidPayload);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionSendPeerNotConnected);
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                return transmission->Write(y, packet, packet_length);
            }

            /**
             * @brief Forwards one socket-read chunk into transmission.
             * @param buffer Shared receive buffer.
             * @param buffer_size Buffer capacity.
             * @param bytes_transferred Number of valid bytes.
             * @return True when async transmission write is accepted.
             * @note Completion callback decides whether to continue receive loop.
             */
            bool VirtualEthernetTcpipConnection::ForwardSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size, int bytes_transferred) noexcept {
                if (NULLPTR == buffer || buffer_size < 1 || bytes_transferred < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionForwardSocketInvalidArguments);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionForwardSocketNotConnected);
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                auto self = shared_from_this();
                return transmission->Write(buffer.get(), bytes_transferred, 
                    [self, this, buffer, buffer_size](bool ok) noexcept {
                        ForwardSocketToTransmissionOK(ok, buffer, buffer_size);
                    });
            }

            /**
             * @brief Arms asynchronous socket receive and forwards received data.
             * @param buffer Shared receive buffer.
             * @param buffer_size Buffer capacity.
             * @return True when async receive is scheduled.
             * @note Receive length is randomized by skateboarding strategy to diversify chunk sizes.
             */
            bool VirtualEthernetTcpipConnection::ReceiveSocketToTransmission(const std::shared_ptr<Byte>& buffer, int buffer_size) noexcept {
                if (NULLPTR == buffer || buffer_size < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveSocketInvalidBuffer);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveSocketNotConnected);
                    return false;
                }

                auto self = shared_from_this();
                boost::asio::post(socket_->get_executor(),
                    [self, this, buffer, buffer_size]() noexcept {
                        // Pick a dynamic read size, then chain read -> write -> next read.
                        int bytes_transferred = BufferSkateboarding(configuration_->key.sb, buffer_size, PPP_BUFFER_SIZE);
                        socket_->async_read_some(boost::asio::buffer(buffer.get(), bytes_transferred),
                            [self, this, buffer, buffer_size](const boost::system::error_code& ec, std::size_t sz) noexcept {
                                int bytes_transferred = std::max<int>(ec ? -1 : static_cast<int>(sz), -1);
                                if (bytes_transferred < 1) {
                                    Dispose();
                                }
                                elif(ForwardSocketToTransmission(buffer, buffer_size, bytes_transferred)) {
                                    Update();
                                }
                                else {
                                    Dispose();
                                }
                            });
                    });
                return true;
            }

            /**
             * @brief Initializes first socket receive cycle.
             * @return True when initial receive scheduling succeeds.
             * @note Allocates a single reusable read buffer.
             */
            bool VirtualEthernetTcpipConnection::ReceiveTransmissionToSocket() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveStartNotConnected);
                    return false;
                }

                auto allocator = configuration_->GetBufferAllocator();
                auto buffer = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, PPP_BUFFER_SIZE);
                if (NULLPTR == buffer) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionReceiveStartBufferAllocFailed);
                    return false;
                }

                return ReceiveSocketToTransmission(buffer, PPP_BUFFER_SIZE);
            }

            /**
             * @brief Reads from transmission and writes to local socket until termination.
             * @param y Coroutine yield context.
             * @return True if at least one packet is forwarded.
             * @note Loop exits on read/write failure or disposal, then schedules cleanup.
             */
            bool VirtualEthernetTcpipConnection::ForwardTransmissionToSocket(YieldContext& y) noexcept {
                if (!connected_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpipConnectionForwardTransmissionNotConnected);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool any = false;
                while (!disposed_) {
                    // Pull framed payload from transmission, then push to TCP socket.
                    ITransmissionPtr transmission = transmission_;
                    if (NULLPTR == transmission) {
                        break;
                    }

                    int packet_length = 0;
                    std::shared_ptr<Byte> packet = transmission->Read(y, packet_length);
                    if (NULLPTR == packet || packet_length < 1) {
                        break;
                    }

                    any = true;
                    Update();

                    bool ok = ppp::coroutines::asio::async_write(*socket_, boost::asio::buffer(packet.get(), packet_length), y);
                    if (ok) {
                        Update();
                    }
                    else {
                        break;
                    }
                }

                Dispose();
                return any;
            }
        }
    }
}
