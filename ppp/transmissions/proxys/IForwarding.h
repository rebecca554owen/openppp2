#pragma once 

/**
 * @file IForwarding.h
 * @brief Declares the local forwarding service used to bridge accepted loopback sockets to an upstream HTTP/SOCKS proxy.
 */

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/net/rinetd/RinetdConnection.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/configurations/AppConfiguration.h>

#if defined(_WIN32)
#include <windows/ppp/net/QoSS.h>
#elif defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace transmissions {
        namespace proxys {
            /**
             * @brief Manages local accept, upstream proxy handshake, and bidirectional forwarding lifecycle.
             */
            class IForwarding : public std::enable_shared_from_this<IForwarding> {
                friend class                                                ProxyConnection;

            public:
                /** @brief Supported upstream proxy protocol types. */
                enum ProtocolType {
                    /** @brief HTTP CONNECT proxy tunnel mode. */
                    ProtocolType_HttpProxy,
                    /** @brief SOCKS5 proxy tunnel mode. */
                    ProtocolType_SocksProxy,
                };
                /** @brief Application configuration type alias. */
                typedef ppp::configurations::AppConfiguration               AppConfiguration;
                /** @brief Shared pointer to application configuration. */
                typedef std::shared_ptr<AppConfiguration>                   AppConfigurationPtr;
                /** @brief Coroutine yield context type. */
                typedef ppp::coroutines::YieldContext                       YieldContext;
                /** @brief Shared io_context pointer. */
                typedef std::shared_ptr<boost::asio::io_context>            ContextPtr;
                /** @brief Mutex type for internal synchronization. */
                typedef std::mutex                                          SynchronizedObject;
                /** @brief RAII lock guard for SynchronizedObject. */
                typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;
#if defined(_LINUX)
                /** @brief Linux socket protector for VPN bypass routing (Linux only). */
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>         ProtectorNetworkPtr;

            public:
                /** @brief Optional socket protector that prevents VPN routing loops (Linux only). */
                ProtectorNetworkPtr                                         ProtectorNetwork;
#endif

            private:
                /** @brief Internal forward declaration of the proxy connection helper class. */
                class                                                       ProxyConnection;
                /** @brief Shared proxy connection pointer. */
                typedef std::shared_ptr<ProxyConnection>                    ProxyConnectionPtr;
                /** @brief Table of active proxy connections keyed by raw pointer. */
                typedef ppp::unordered_map<void*, ProxyConnectionPtr>       ProxyConnectionTable;
                /** @brief Shared TCP socket pointer. */
                typedef std::shared_ptr<boost::asio::ip::tcp::socket>       SocketPtr;
                /** @brief Table of tracked sockets keyed by raw pointer. */
                typedef ppp::unordered_map<void*, SocketPtr>                SocketTable;
                /** @brief Timer type alias. */
                typedef ppp::threading::Timer                               Timer;
                /** @brief Shared timer pointer. */
                typedef std::shared_ptr<Timer>                              TimerPtr;
                /** @brief Table of one-shot timers keyed by raw Timer pointer. */
                typedef ppp::unordered_map<void*, TimerPtr>                 TimerTable;

            public: 
                /**
                 * @brief Constructs a forwarding service.
                 * @param context Shared I/O context used by async operations.
                 * @param configuration Application runtime configuration.
                 */
                IForwarding(        
                    const ContextPtr&                                       context, 
                    const AppConfigurationPtr&                              configuration) noexcept;
                /** @brief Releases resources and closes active forwarding objects. */
                virtual ~IForwarding() noexcept;

            public:
                /** @brief Gets the bound asynchronous context. */
                ContextPtr                                                  GetContext()                noexcept { return context_; }
                /** @brief Gets the runtime configuration object. */
                AppConfigurationPtr                                         GetConfiguration()          noexcept { return configuration_; }
                /** @brief Gets a shared reference to this forwarding instance. */
                std::shared_ptr<IForwarding>                                GetReference()              noexcept { return shared_from_this(); }
                /** @brief Gets the mutex guarding internal tables. */
                SynchronizedObject&                                         GetSynchronizedObject()     noexcept { return syncobj_; }
                /** @brief Opens and starts the local accept loop. */
                bool                                                        Open()                      noexcept;
                /** @brief Schedules asynchronous disposal of this forwarding instance. */
                void                                                        Dispose()                   noexcept;
                /** @brief Updates aging state for tracked proxy connections. */
                void                                                        Update(UInt64 now)          noexcept;
                /** @brief Gets the currently selected upstream proxy protocol. */
                ProtocolType&                                               GetProtocolType()           noexcept { return server_.protocol; }
                /** @brief Gets the parsed upstream proxy URL. */
                ppp::string&                                                GetProxyUrl()               noexcept { return server_.url; }
                /** @brief Gets the resolved upstream proxy endpoint. */
                boost::asio::ip::tcp::endpoint&                             GetProxyEndPoint()          noexcept { return server_.endpoint; }
                /** @brief Gets the loopback endpoint exposed to local clients. */
                boost::asio::ip::tcp::endpoint                              GetLocalEndPoint()          noexcept;
                /**
                 * @brief Sets the remote destination used by CONNECT/SOCKS tunneling.
                 * @param host Remote target host.
                 * @param port Remote target port.
                 * @return This object for chained calls.
                 */
                IForwarding&                                                SetRemoteEndPoint(          
                    const ppp::string&                                      host, 
                    int                                                     port)                       noexcept;
                /** @brief Gets the remote destination host. */
                ppp::string&                                                GetRemoteHost()             noexcept { return server_.host; }
                /** @brief Gets the remote destination port. */
                int&                                                        GetRemotePort()             noexcept { return server_.port; }

            private:
                /** @brief Registers a one-shot timer and tracks it in the timer table. */
                TimerPtr                                                    SetTimeoutHandler(const std::shared_ptr<boost::asio::io_context>& context, int milliseconds, const ppp::function<void()>& handler) noexcept;
                /** @brief Registers a timeout that closes the specified socket asynchronously. */
                Timer*                                                      SetTimeoutAutoClosesocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                /** @brief Performs final cleanup for sockets, timers, and proxy connections. */
                void                                                        Finalize() noexcept; 
                /** @brief Resets cached proxy/server state to defaults. */
                void                                                        ResetSS() noexcept;
                /** @brief Opens a loopback acceptor on an ephemeral port. */
                bool                                                        OpenAcceptor() noexcept;
                /** @brief Parses proxy configuration and initializes local acceptor state. */
                int                                                         OpenInternal() noexcept;
                /** @brief Starts continuous asynchronous accept on the local endpoint. */
                bool                                                        LoopAcceptSocket() noexcept;
                /** @brief Applies socket options and dispatches upstream connect flow for an accepted client. */
                bool                                                        ProcessAcceptSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                /** @brief Creates and configures a new socket for upstream proxy connection. */
                std::shared_ptr<boost::asio::ip::tcp::socket>               NewAsynchronousSocket(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand) noexcept;
                /** @brief Spawns coroutine flow to connect an accepted socket to upstream proxy. */
                bool                                                        ConnectToProxyServer(const std::shared_ptr<boost::asio::io_context>& context, const ppp::net::Socket::AsioStrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, Timer* timeout_key) noexcept;
                /** @brief Executes synchronous coroutine steps for proxy handshake and forwarding startup. */
                bool                                                        ConnectToProxyServer(
                    const std::shared_ptr<boost::asio::io_context>&         context, 
                    const ppp::net::Socket::AsioStrandPtr&                  strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    local_socket,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    proxy_socket,
                    YieldContext&                                           y,
                    bool                                                    http_or_socks_protocol) noexcept;

            private:
                /** @brief Adds a socket to the tracked socket table. */
                bool                                                        TryAdd(const SocketPtr& socket) noexcept;
                /** @brief Adds a proxy connection to the tracked connection table. */
                bool                                                        TryAdd(const ProxyConnectionPtr& connection) noexcept;
                /** @brief Adds a timer to the tracked timer table. */
                bool                                                        TryAdd(const TimerPtr& connection) noexcept;
                /** @brief Removes a socket from tracking, optionally disposing it. */
                bool                                                        TryRemove(boost::asio::ip::tcp::socket* socket, bool disposing) noexcept;
                /** @brief Removes a proxy connection from tracking, optionally disposing it. */
                bool                                                        TryRemove(ProxyConnection* connection, bool disposing) noexcept;
                /** @brief Removes a timer from tracking, optionally disposing it. */
                bool                                                        TryRemove(Timer* timer, bool disposing) noexcept;

            private:
                /** @brief Applies platform-specific processing before connecting proxy socket. */
                bool                                                        PROXY_SOCKET_SPECIAL_PROCESS(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y, ProxyConnection& proxy_connection) noexcept;
                /** @brief Performs SOCKS5 handshake with the upstream proxy. */
                bool                                                        SOCKS_Handshake(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    YieldContext&                                           y) noexcept;
                /** @brief Sends an HTTP CONNECT handshake packet to the upstream proxy. */
                bool                                                        HTTP_SendHandshakePacket(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    YieldContext&                                           y) noexcept;
                /** @brief Reads and validates an HTTP CONNECT response and captures overflow bytes. */
                bool                                                        HTTP_ReadHandshakePacket(
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
                    YieldContext&                                           y,
                    std::shared_ptr<Byte>&                                  overflow_buffer,
                    int&                                                    overflow_offset,
                    int&                                                    overflow_length) noexcept;

            private:
                /** @brief Mutex guarding sockets_, connections_, and timers_ tables. */
                SynchronizedObject                                          syncobj_;
                /**
                 * @brief Disposal flag.
                 * @note  Written inside syncobj_ in Finalize() and read with an atomic fast-path
                 *        outside the lock in IFORWARDING_TRY_ADD().  Must be std::atomic<bool> to
                 *        avoid a data race between Finalize() and concurrent TryAdd() callers.
                 */
                std::atomic<bool>                                           disposed_ = { false };
                /** @brief Shared io_context used for all async accept/connect operations. */
                ContextPtr                                                  context_;
                /** @brief Runtime configuration providing timeouts and proxy settings. */
                AppConfigurationPtr                                         configuration_;
                /** @brief Cached upstream proxy and tunnel destination settings. */
                struct {
                    /** @brief Selected upstream proxy protocol (HTTP or SOCKS). */
                    ProtocolType                                            protocol;
                    /** @brief Remote tunnel target host name. */
                    ppp::string                                             host;
                    /** @brief Remote tunnel target port. */
                    int                                                     port = 0;
                    /** @brief Upstream proxy authentication username. */
                    ppp::string                                             username;
                    /** @brief Upstream proxy authentication password. */
                    ppp::string                                             password;
                    /** @brief Full upstream proxy URL string. */
                    ppp::string                                             url;
                    /** @brief Resolved upstream proxy endpoint. */
                    boost::asio::ip::tcp::endpoint                          endpoint;
                }                                                           server_;
                /** @brief Tracked one-shot timeout timers keyed by raw Timer pointer. */
                TimerTable                                                  timers_;
                /** @brief Tracked accepted local sockets awaiting upstream connection. */
                SocketTable                                                 sockets_;
                /** @brief Active bidirectional proxy connections keyed by raw pointer. */
                ProxyConnectionTable                                        connections_;
                /** @brief Loopback TCP acceptor that receives local client connections. */
                boost::asio::ip::tcp::acceptor                              acceptor_;
                /** @brief Cached local endpoint exposed to clients after bind. */
                boost::asio::ip::tcp::endpoint                              local_endpoint_;
            };
        }
    }
}
