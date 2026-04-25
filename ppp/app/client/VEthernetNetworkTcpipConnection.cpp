#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/protocol/templates/TVEthernetTcpipConnection.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/rinetd/RinetdConnection.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>

#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>

/**
 * @file VEthernetNetworkTcpipConnection.cpp
 * @brief Implements TCP/IP forwarding selection for virtual Ethernet sessions.
 * @license GPL-3.0
 */

namespace ppp {
    namespace app {
        namespace client {
            /** @brief Initializes session state and marks it active. */
            VEthernetNetworkTcpipConnection::VEthernetNetworkTcpipConnection(const std::shared_ptr<VEthernetExchanger>& exchanger, const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept
                : TapTcpClient(context, strand)
                , exchanger_(exchanger) {
                Update();
            }

            /** @brief Finalizes owned forwarding channels. */
            VEthernetNetworkTcpipConnection::~VEthernetNetworkTcpipConnection() noexcept {
                Finalize();
            }

            /** @brief Disposes any active VPN/rinetd/vmux connection objects. */
            void VEthernetNetworkTcpipConnection::Finalize() noexcept {
                std::shared_ptr<VirtualEthernetTcpipConnection> connection = std::move(connection_); 
                std::shared_ptr<RinetdConnection> connection_rinetd = std::move(connection_rinetd_); 
                std::shared_ptr<vmux::vmux_skt> connection_mux = std::move(connection_mux_);

                if (NULLPTR != connection) {
                    connection->Dispose();
                }

                if (NULLPTR != connection_rinetd) {
                    connection_rinetd->Dispose();
                }

                if (NULLPTR != connection_mux) {
                    connection_mux->close();
                }
            }

            /**
             * @brief Schedules cleanup on the proper executor and disposes the base client.
             */
            void VEthernetNetworkTcpipConnection::Dispose() noexcept {
                if (IsDisposed()) {
                    return;
                }

                auto self = shared_from_this();
                auto socket = GetSocket(); 

                if (NULLPTR != socket) {
                    boost::asio::post(socket->get_executor(), 
                        [self, this, socket]() noexcept {
                            Finalize();
                        });
                }
                else {
                    ppp::threading::Executors::ContextPtr context = GetContext();
                    ppp::threading::Executors::StrandPtr strand = GetStrand();

                    ppp::threading::Executors::Post(context, strand, 
                        [self, this, context, strand]() noexcept {
                            Finalize();
                        });
                }

                TapTcpClient::Dispose();
            }

            /**
             * @brief Runs whichever forwarding path is currently active.
             * @return true when forwarding loop runs successfully.
             */
            bool VEthernetNetworkTcpipConnection::Loopback(ppp::coroutines::YieldContext& y) noexcept {
                // If the connection is interrupted while the coroutine is working, 
                // Or closed during other asynchronous processes or coroutines, do not perform meaningless processing.
                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                // If rinetd local loopback link forwarding is not used, failure will be returned, 
                // Otherwise the link to the peer will be processed successfully.
                if (std::shared_ptr<RinetdConnection> connection_rinetd = connection_rinetd_; NULLPTR != connection_rinetd) {
                    return connection_rinetd->Run();
                }

                // If the link is relayed through the VPN remote switcher, then run the VPN link relay subroutine.
                if (std::shared_ptr<VirtualEthernetTcpipConnection> connection = connection_; NULLPTR != connection) {
                    bool ok = connection->Run(y);
                    IDisposable::DisposeReferences(connection);
                    return ok;
                }

                if (std::shared_ptr<vmux::vmux_skt> connection_mux = connection_mux_; NULLPTR != connection_mux) {
                    return connection_mux->run();
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                return false;
            }

            /**
             * @brief Builds forwarding to the peer using rinetd, vmux, or VPN transport.
             * @return true when one forwarding path is prepared successfully.
             */
            bool VEthernetNetworkTcpipConnection::ConnectToPeer(ppp::coroutines::YieldContext& y) noexcept {
                using VEthernetTcpipConnection = ppp::app::protocol::templates::TVEthernetTcpipConnection<TapTcpClient>;

                // Create a link and correctly establish a link between remote peers, 
                // Indicating whether to use VPN link or Rinetd local loopback forwarding.
                do {
                    std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                    if (NULLPTR == exchanger) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return false;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    std::shared_ptr<boost::asio::io_context> context = GetContext();
                    if (NULLPTR == context) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                        return false;
                    }

                    std::shared_ptr<AppConfiguration> configuration = exchanger->GetConfiguration();
                    if (NULLPTR == configuration) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = GetSocket();
                    if (NULLPTR == socket) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                        return false;
                    }

                    auto self = shared_from_this();
                    auto strand = GetStrand();
                    boost::asio::ip::tcp::endpoint remoteEP = GetRemoteEndPoint();

                    int rinetd_status = Rinetd(self, exchanger, context, strand, configuration, socket, remoteEP, connection_rinetd_, y);
                    if (rinetd_status < 1) {
                        if (rinetd_status < 0) {
                            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
                            }
                        }
                        return rinetd_status == 0;
                    }

                    int mux_status = Mux(self, exchanger, remoteEP, socket, connection_mux_, y);
                    if (mux_status < 1) {
                        if (mux_status < 0) {
                            if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                            }
                        }
                        return mux_status == 0;
                    }

                    std::shared_ptr<ppp::transmissions::ITransmission> transmission = exchanger->ConnectTransmission(context, strand, y);
                    if (NULLPTR == transmission) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                        return false;
                    }

                    std::shared_ptr<VEthernetTcpipConnection> connection =
                        make_shared_object<VEthernetTcpipConnection>(self, configuration, context, strand, exchanger->GetId(), socket);
                    if (NULLPTR == connection) {
                        IDisposable::DisposeReferences(transmission);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }

#if defined(_LINUX)
                    auto switcher = exchanger->GetSwitcher(); 
                    if (NULLPTR != switcher) {
                        connection->ProtectorNetwork = switcher->GetProtectorNetwork();
                    }
#endif

                    bool ok = connection->Connect(y, transmission, ppp::net::Ipep::ToAddressString<ppp::string>(remoteEP), remoteEP.port());
                    if (!ok) {
                        IDisposable::DisposeReferences(connection, transmission);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionOpenFailed);
                        return false;
                    }

                    connection_ = std::move(connection);
                } while (false);
                return true;
            }

#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
/**
 * @brief Applies conservative compiler optimization for coroutine-sensitive code paths.
 *
 * For older GCC versions (<= 7.5.x), O1 is used to avoid known optimizer-induced
 * crashes in this section. For newer versions, optimization is disabled here to
 * keep runtime behavior stable across toolchains.
 */
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
            /** @brief Starts established-stage forwarding coroutine execution. */
            bool VEthernetNetworkTcpipConnection::Establish() noexcept {
                return Spawn(
                    [this](ppp::coroutines::YieldContext& y) noexcept {
                        return Loopback(y);
                    });
            }

            /** @brief Starts peer setup coroutine before accept acknowledgement. */
            bool VEthernetNetworkTcpipConnection::BeginAccept() noexcept {
                return Spawn(
                    [this](ppp::coroutines::YieldContext& y) noexcept {
                        return ConnectToPeer(y) && AckAccept();
                    });
            }

            /**
             * @brief Posts a coroutine launcher to the session strand.
             * @return true when posting succeeds.
             */
            bool VEthernetNetworkTcpipConnection::Spawn(const ppp::function<bool(ppp::coroutines::YieldContext&)>& coroutine) noexcept {
                if (IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (NULLPTR == coroutine) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger->GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                    return false;
                }

                ppp::threading::Executors::ContextPtr context = GetContext();
                if (NULLPTR == context) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                    return false;
                }

                auto self = shared_from_this();
                ppp::threading::Executors::StrandPtr strand = GetStrand();

                auto post_work = 
                    [self, this, context, strand, coroutine, configuration]() noexcept {
                        auto spawn_work = 
                            [self, this, context, strand, coroutine](ppp::coroutines::YieldContext& y) noexcept {
                               bool ok = coroutine(y);
                               if (!ok) {
                                   Dispose();
                               }
                           };
                        
                        auto allocator = configuration->GetBufferAllocator();
                        bool spawned = ppp::coroutines::YieldContext::Spawn(allocator.get(), *context, strand.get(), spawn_work);
                        if (!spawned) {
                            IDisposable::Dispose(this);
                        }
                    };

                bool posted = ppp::threading::Executors::Post(context, strand, post_work);
                if (!posted) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                    return false;
                }

                return true;
            }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif

            /**
             * @brief Tunes accepted socket options and delegates to base accept end.
             */
            bool VEthernetNetworkTcpipConnection::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
                if (NULLPTR == socket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return false;
                }

                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                if (NULLPTR == exchanger) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                std::shared_ptr<ppp::configurations::AppConfiguration> configuration = exchanger->GetConfiguration();
                if (NULLPTR == configuration) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppConfigurationMissing);
                    return false;
                }
                
                ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration->tcp.turbo);
                ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration->tcp.cwnd, configuration->tcp.rwnd);

                return TapTcpClient::EndAccept(socket, natEP);
            }
        }
    }
}
