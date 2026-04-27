#pragma once

/**
 * @file VEthernetLocalProxySwitcher.h
 * @brief Declares the local proxy listener and connection manager.
 * @author OpenPPP Contributors
 * @license GPL-3.0
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/SocketAcceptor.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;

            namespace proxys {
                class VEthernetLocalProxyConnection;

                /**
                 * @brief Accepts local proxy clients and dispatches per-client handlers.
                 */
                class VEthernetLocalProxySwitcher : public std::enable_shared_from_this<VEthernetLocalProxySwitcher> {
                    friend class                                                        VEthernetLocalProxyConnection;

                private:
                    typedef std::shared_ptr<VEthernetLocalProxyConnection>              VEthernetLocalProxyConnectionPtr;
                    typedef ppp::unordered_map<void*, VEthernetLocalProxyConnectionPtr> VEthernetLocalProxyConnectionTable;
                    typedef std::mutex                                                  SynchronizedObject;
                    typedef std::lock_guard<SynchronizedObject>                         SynchronizedObjectScope;

                public:
                    /**
                     * @brief Creates a local proxy switcher using exchanger runtime context.
                     * @param exchanger Shared exchanger owner.
                     */
                    VEthernetLocalProxySwitcher(const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;
                    /**
                     * @brief Destroys the switcher and finalizes active resources.
                     */
                    virtual ~VEthernetLocalProxySwitcher() noexcept;

                public:
                    std::shared_ptr<boost::asio::io_context>&                           GetContext()         noexcept { return context_; }
                    std::shared_ptr<ppp::configurations::AppConfiguration>&             GetConfiguration()   noexcept { return configuration_; }
                    std::shared_ptr<VEthernetExchanger>&                                GetExchanger()       noexcept { return exchanger_; }
                    /**
                     * @brief Returns buffer allocator used by connection coroutines.
                     * @return Shared allocator instance from configuration.
                     */
                    std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferAllocator() noexcept;
                    /**
                     * @brief Returns the currently bound local listening endpoint.
                     * @return TCP endpoint of the active acceptor or a default empty endpoint.
                     */
                    boost::asio::ip::tcp::endpoint                                      GetLocalEndPoint()   noexcept;
                    /**
                     * @brief Opens local listening socket and starts accept pipeline.
                     * @return true if listener and timer are created successfully.
                     */
                    virtual bool                                                        Open()               noexcept;
                    /**
                     * @brief Schedules asynchronous teardown on the switcher context.
                     */
                    virtual void                                                        Dispose()            noexcept;

                protected:
                    /**
                     * @brief Resolves bind address and may adjust bind port.
                     * @param bind_port Input/output bind port.
                     * @return Address to use when creating the listener.
                     */
                    virtual boost::asio::ip::address                                    MyLocalEndPoint(int& bind_port) noexcept = 0;
                    /**
                     * @brief Periodic maintenance callback used to age idle connections.
                     * @param now Current tick count in milliseconds.
                     */
                    virtual void                                                        Update(UInt64 now) noexcept;
                    /**
                     * @brief Factory for protocol-specific local connection handlers.
                     * @param context Selected I/O context for the connection.
                     * @param strand Selected strand for serialized callbacks.
                     * @param socket Accepted client socket.
                     * @return New local proxy connection instance.
                     */
                    virtual std::shared_ptr<VEthernetLocalProxyConnection>              NewConnection(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept = 0;

                private:
                    /**
                     * @brief Performs idempotent shutdown for timer, acceptor, and connections.
                     */
                    void                                                                Finalize() noexcept;
                    /**
                     * @brief Creates the periodic timer used for connection housekeeping.
                     * @return true when timer setup and start succeed.
                     */
                    bool                                                                CreateAlwaysTimeout() noexcept;
                    /**
                     * @brief Converts an accepted native socket into a managed connection task.
                     * @param context Target scheduler context.
                     * @param strand Target strand.
                     * @param sockfd Native accepted socket handle.
                     * @return true if connection task is created and scheduled.
                     */
                    bool                                                                ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept;
                    /**
                     * @brief Requests asynchronous removal of a connection from tracking.
                     * @param connection Connection pointer key.
                     */
                    void                                                                ReleaseConnection(VEthernetLocalProxyConnection* connection) noexcept;
                    /**
                     * @brief Adds a connection object to the active connection table.
                     * @param connection Connection to track.
                     * @return true if inserted successfully.
                     */
                    bool                                                                AddConnection(const std::shared_ptr<VEthernetLocalProxyConnection>& connection) noexcept;
                    /**
                     * @brief Removes a tracked connection by raw pointer key.
                     * @param connection Connection pointer key.
                     * @return true if a tracked entry was found and removed.
                     */
                    bool                                                                RemoveConnection(VEthernetLocalProxyConnection* connection) noexcept;
                    /**
                     * @brief Wraps an accepted native socket descriptor into asio socket object.
                     * @param context Target I/O context.
                     * @param strand Optional strand.
                     * @param sockfd Native accepted descriptor.
                     * @return Wrapped socket object, or null on failure.
                     */
                    std::shared_ptr<boost::asio::ip::tcp::socket>                       NewSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand, int sockfd) noexcept;

                private:
                    SynchronizedObject                                                  syncobj_;
                    bool                                                                disposed_ = false;
                    std::shared_ptr<VEthernetExchanger>                                 exchanger_;
                    std::shared_ptr<ppp::net::SocketAcceptor>                           acceptor_;
                    std::shared_ptr<boost::asio::io_context>                            context_;
                    std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;
                    std::shared_ptr<ppp::threading::Timer>                              timeout_;
                    VEthernetLocalProxyConnectionTable                                  connections_;
                };
            }
        }
    }
}
