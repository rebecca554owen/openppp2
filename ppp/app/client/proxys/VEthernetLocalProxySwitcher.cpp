#include <ppp/app/client/proxys/VEthernetLocalProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetLocalProxyConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/diagnostics/Error.h>

#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>

#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>

/**
 * @file VEthernetLocalProxySwitcher.cpp
 * @brief Implements local proxy listener setup, accept loop, and connection maintenance.
 * @author OpenPPP Contributors
 * @license GPL-3.0
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief Initializes switcher state from exchanger-owned configuration.
                 */
                VEthernetLocalProxySwitcher::VEthernetLocalProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept
                    : disposed_(false)
                    , exchanger_(exchanger)
                    , context_(ppp::threading::Executors::GetDefault())
                    , configuration_(exchanger->GetConfiguration()) {

                }

                VEthernetLocalProxySwitcher::~VEthernetLocalProxySwitcher() noexcept {
                    Finalize();
                }

                /**
                 * @brief Stops timer/acceptor, detaches all connections, and releases references.
                 */
                void VEthernetLocalProxySwitcher::Finalize() noexcept {
                    VEthernetLocalProxyConnectionTable connections;
                    for (;;) {
                        SynchronizedObjectScope scope(syncobj_);
                        connections = std::move(connections_);
                        connections_.clear();
                        break;
                    }

                    std::shared_ptr<ppp::threading::Timer> timeout = std::move(timeout_); 
                    std::shared_ptr<ppp::net::SocketAcceptor> acceptor = std::move(acceptor_); 

                    if (NULLPTR != timeout) {
                        timeout->Dispose();
                    }

                    if (NULLPTR != acceptor) {
                        acceptor->Dispose();
                    }

                    disposed_ = true;
                    ppp::collections::Dictionary::ReleaseAllObjects(connections);
                }

                /**
                 * @brief Runs periodic aging checks over tracked connections.
                 *
                 * @param now  Current tick count in milliseconds.
                 *
                 * @note  Snapshot-and-release pattern: expired connection pointers are moved
                 *        into a local vector while syncobj_ is held, the map entries are
                 *        erased, then Dispose() is called outside the lock.  This prevents a
                 *        potential re-entrant deadlock if a connection's Dispose() callback
                 *        tries to call back into VEthernetLocalProxySwitcher under syncobj_.
                 */
                void VEthernetLocalProxySwitcher::Update(UInt64 now) noexcept {
                    ppp::vector<VEthernetLocalProxyConnectionPtr> stale;

                    {
                        SynchronizedObjectScope scope(syncobj_);
                        for (auto tail = connections_.begin(); tail != connections_.end();) {
                            const VEthernetLocalProxyConnectionPtr& conn = tail->second;
                            if (NULLPTR == conn || conn->IsPortAging(now)) {
                                if (NULLPTR != conn) {
                                    stale.emplace_back(conn);
                                }

                                tail = connections_.erase(tail);
                            }
                            else {
                                ++tail;
                            }
                        }
                    }

                    // Dispose outside the lock to prevent re-entrant acquisition of syncobj_.
                    for (auto& conn : stale) {
                        IDisposable::Dispose(*conn);
                    }
                }

                /**
                 * @brief Defers switcher teardown onto the switcher context thread.
                 */
                void VEthernetLocalProxySwitcher::Dispose() noexcept {
                    auto self = shared_from_this();
                    boost::asio::post(*context_, 
                        [self, this]() noexcept {
                            Finalize();
                        });
                }

                /**
                 * @brief Opens listening socket and wires accept callback dispatching.
                 */
                bool VEthernetLocalProxySwitcher::Open() noexcept {
                    using NetworkState = VEthernetExchanger::NetworkState;

                    if (NULLPTR != acceptor_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetLocalProxySwitcherOpenAcceptorAlreadyInitialized);
                        return false;
                    }

                    std::shared_ptr<ppp::net::SocketAcceptor> acceptor;
                    if (disposed_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }
                    else {
                        int bind_port = configuration_->client.http_proxy.port;
                        boost::asio::ip::address bind_ips[] = {
                                MyLocalEndPoint(bind_port),
                                boost::asio::ip::address_v6::any(),
                                boost::asio::ip::address_v4::any()
                            };
                        if (bind_port <= ppp::net::IPEndPoint::MinPort || bind_port > ppp::net::IPEndPoint::MaxPort) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                            return false;
                        }

                        /**
                         * @brief Try preferred bind address first, then IPv6/IPv4 any-address fallbacks.
                         */
                        for (boost::asio::ip::address& interfaceIP : bind_ips) {
                            if (interfaceIP.is_multicast()) {
                                continue;
                            }

                            bool bip = interfaceIP.is_v4() || interfaceIP.is_v6();
                            if (!bip) {
                                continue;
                            }

                            if (!interfaceIP.is_unspecified() && ppp::net::IPEndPoint::IsInvalid(interfaceIP)) {
                                continue;
                            }

                            std::shared_ptr<ppp::net::SocketAcceptor> t = ppp::net::SocketAcceptor::New();
                            if (NULLPTR == t) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                                return false;
                            }

                            ppp::string address_string = ppp::net::Ipep::ToAddressString<ppp::string>(interfaceIP);
                            if (!t->Open(address_string.data(), bind_port, configuration_->tcp.backlog)) {
                                continue;
                            }

                            acceptor = std::move(t);
                            break;
                        }

                        if (NULLPTR == acceptor) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketBindFailed);
                            return false;
                        }
                    }

                    int sockfd = acceptor->GetHandle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(sockfd, false);
                    ppp::net::Socket::SetTypeOfService(sockfd);
                    ppp::net::Socket::SetSignalPipeline(sockfd, false);
                    ppp::net::Socket::SetWindowSizeIfNotZero(sockfd, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                    auto self = shared_from_this();
                    acceptor->AcceptSocket = 
                        [self, this](ppp::net::SocketAcceptor*, ppp::net::SocketAcceptor::AcceptSocketEventArgs& e) noexcept {
                            int sockfd = e.Socket;
                            ppp::diagnostics::ErrorCode error_code = ppp::diagnostics::ErrorCode::SessionDisposed;
                            
                            /**
                             * @brief Accept callback validates network readiness before scheduling per-socket work.
                             */
                            while (!disposed_) {
                                std::shared_ptr<VEthernetExchanger> exchanger = exchanger_;
                                if (NULLPTR == exchanger) {
                                    error_code = ppp::diagnostics::ErrorCode::AppContextUnavailable;
                                    break;
                                }

                                NetworkState network_state = exchanger->GetNetworkState();
                                if (network_state != NetworkState::NetworkState_Established) {
                                    error_code = ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable;
                                    break;
                                }

                                ppp::threading::Executors::ContextPtr context;
                                ppp::threading::Executors::StrandPtr strand;
                                context = ppp::threading::Executors::SelectScheduler(strand);
                                
                                if (NULLPTR == context) {
                                    error_code = ppp::diagnostics::ErrorCode::RuntimeSchedulerUnavailable;
                                    break;
                                }

                                bool posted = ppp::threading::Executors::Post(context, strand,
                                    std::bind(&VEthernetLocalProxySwitcher::ProcessAcceptSocket, self, context, strand, sockfd));
                                if (!posted) {
                                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
                                }

                                return posted;
                            }

                            ppp::net::Socket::Closesocket(sockfd);
                            ppp::diagnostics::SetLastErrorCode(error_code);
                            return false;
                        };

                    bool bok = CreateAlwaysTimeout();
                    if (!bok) {
                        acceptor->Dispose();

                        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
                        }

                        return false;
                    }

                    acceptor_ = std::move(acceptor);
                    return bok;
                }

                /**
                 * @brief Queues tracked-connection removal on the switcher executor.
                 */
                void VEthernetLocalProxySwitcher::ReleaseConnection(VEthernetLocalProxyConnection* connection) noexcept {
                    if (NULLPTR != connection) {
                        auto self = shared_from_this();
                        std::shared_ptr<boost::asio::io_context> context = GetContext();
                        boost::asio::post(*context, 
                            [self, this, connection]() noexcept {
                                RemoveConnection(connection);
                            });
                    }
                }

                /**
                 * @brief Removes one tracked connection entry by pointer identity.
                 */
                bool VEthernetLocalProxySwitcher::RemoveConnection(VEthernetLocalProxyConnection* connection) noexcept {
                    VEthernetLocalProxyConnectionPtr r; 
                    if (NULLPTR != connection) {
                        SynchronizedObjectScope scope(syncobj_);
                        r = ppp::collections::Dictionary::ReleaseObjectByKey(connections_, connection); 
                    }

                    return NULLPTR != r;
                }

                /**
                 * @brief Creates an asio socket wrapper from a native accepted descriptor.
                 */
                std::shared_ptr<boost::asio::ip::tcp::socket> VEthernetLocalProxySwitcher::NewSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept {
                    if (NULLPTR == context) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                        return NULLPTR;
                    }

                    boost::asio::ip::tcp::endpoint remoteEP = ppp::net::Socket::GetRemoteEndPoint(sockfd);
                    boost::system::error_code ec = boost::asio::error::operation_aborted;

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = strand ?
                        make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
                    try {
                        if (NULLPTR == socket) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                            return NULLPTR;
                        }
                        else {
                            socket->assign(remoteEP.protocol(), sockfd, ec);
                        }
                    }
                    catch (const std::exception&) {}

                    if (ec) {
                        ppp::net::Socket::Closesocket(sockfd);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                        return NULLPTR;
                    }
                    
                    ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo);
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                    return socket;
                }

                /**
                 * @brief Adds connection to synchronized tracking table.
                 */
                bool VEthernetLocalProxySwitcher::AddConnection(const std::shared_ptr<VEthernetLocalProxyConnection>& connection) noexcept {
                    if (NULLPTR == connection) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                        return false;
                    }
                    
                    SynchronizedObjectScope scope(syncobj_);
                    bool added = ppp::collections::Dictionary::TryAdd(connections_, connection.get(), connection);
                    if (!added) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MappingEntryConflict);
                    }
                    
                    return added;
                }

                /**
                 * @brief Builds connection object and starts its coroutine worker.
                 */
                bool VEthernetLocalProxySwitcher::ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept {
                    if (NULLPTR == context) {
                        ppp::net::Socket::Closesocket(sockfd);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
                        return false;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = NewSocket(context, strand, sockfd);
                    if (NULLPTR == socket) {
                        ppp::net::Socket::Closesocket(sockfd);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                        return false;
                    }

                    std::shared_ptr<VEthernetLocalProxyConnection> connection = NewConnection(context, strand, socket);
                    if (NULLPTR == connection) {
                        ppp::net::Socket::Closesocket(sockfd);
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }

                    bool bok = false;
                    for (;;) {
                        bok = AddConnection(connection);
                        if (!bok) {
                            break;
                        }

                        auto allocator = GetBufferAllocator();
                        auto self = shared_from_this();

                        /**
                         * @brief Spawn the session coroutine; failed runs self-dispose the connection.
                         */
                        bok = ppp::coroutines::YieldContext::Spawn(allocator.get(), *context, strand.get(),
                            [self, this, context, strand, connection](ppp::coroutines::YieldContext& y) noexcept {
                                bool bok = connection->Run(y);
                                if (!bok) {
                                    connection->Dispose();
                                }
                            });

                        break;
                    }
                    
                    if (!bok) {
                        if (RemoveConnection(connection.get())) {
                            connection->Dispose(); 
                        }

                        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                        }
                    }

                    return bok;
                }

                /**
                 * @brief Returns configured allocator used by new connection coroutines.
                 */
                std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetLocalProxySwitcher::GetBufferAllocator() noexcept {
                    std::shared_ptr<ppp::configurations::AppConfiguration> configuration = configuration_;
                    return NULLPTR != configuration ? configuration->GetBufferAllocator() : NULLPTR;
                }

                /**
                 * @brief Creates the always-on 1-second timer for periodic housekeeping.
                 */
                bool VEthernetLocalProxySwitcher::CreateAlwaysTimeout() noexcept {
                    if (disposed_) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return false;
                    }

                    auto self = shared_from_this();
                    auto timeout = make_shared_object<ppp::threading::Timer>(context_);
                    if (!timeout) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                        return false;
                    }

                    timeout->TickEvent = 
                        [self, this](ppp::threading::Timer* sender, ppp::threading::Timer::TickEventArgs& e) noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            Update(now);
                        };

                    if (!timeout->SetInterval(1000)) {
                        return false;
                    }

                    if (!timeout->Start()) {
                        return false;
                    }

                    timeout_ = timeout;
                    return true;
                }

                /**
                 * @brief Returns listener endpoint when acceptor is active.
                 */
                boost::asio::ip::tcp::endpoint VEthernetLocalProxySwitcher::GetLocalEndPoint() noexcept {
                    std::shared_ptr<ppp::net::SocketAcceptor> acceptor = acceptor_;
                    if (NULLPTR != acceptor) {
                        return ppp::net::Socket::GetLocalEndPoint(acceptor->GetHandle());
                    }

                    return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
                }
            }
        }
    }
}
