#pragma once

#include <ppp/stdafx.h>

/**
 * @file Socket.h
 * @brief Declares socket utility helpers used by TCP/UDP networking components.
 *
 * This header provides the @ref ppp::net::Socket class — a pure static utility
 * namespace that wraps Boost.Asio and native POSIX/Winsock operations behind a
 * uniform interface.  No instances are created; all entry points are static.
 *
 * Design notes:
 * - TCP helpers (AcceptLoopbackAsync, AdjustDefaultSocketOptional) manage
 *   connection-oriented state such as keep-alive, Nagle algorithm, and TFO.
 * - UDP helpers (OpenSocket, AdjustSocketOptional) focus on binding, broadcast,
 *   and buffer sizing.  Each UDP socket typically uses a single per-thread 64 KB
 *   receive buffer to minimise allocation overhead.
 * - Cancel() overloads provide a uniform way to abort in-flight Asio operations
 *   without throwing; all overloads are noexcept.
 * - Platform guards: SetTypeOfService() and SetSignalPipeline() are no-ops on
 *   platforms that do not expose the underlying option.
 */

namespace ppp {
    namespace net {
        /**
         * @brief Collection of static helpers for low-level socket and Boost.Asio operations.
         *
         * All members are static; this class is never instantiated.  It acts as a
         * namespaced set of utilities that cover:
         *  - Native descriptor management (open, close, shutdown, non-blocking mode).
         *  - Asio acceptor/socket lifecycle (open, bind, listen, accept loops).
         *  - Socket option tuning (TOS, TCP keep-alive, MSS, window sizes, TFO).
         *  - Asio operation cancellation (overloaded for all relevant Asio types).
         *  - Readiness polling via select/poll with configurable timeout.
         */
        class Socket final {
        public:
            /**
             * @brief Runtime and policy flags that gate socket option behavior.
             *
             * A single global instance (@ref SOCKET_RESTRICTIONS_) is populated during
             * static construction by probing the kernel for supported socket options.
             * Callers should read these flags rather than unconditionally applying
             * options that may not be available on the current kernel or platform.
             */
            class SOCKET_RESTRICTIONS final {
            public:
                /**
                 * @brief Bit-field switches for type-of-service and traffic-class behavior.
                 *
                 * Layout:
                 *   IPV6_TCLASS_ON       = bool : 1,  ///< Kernel supports IPV6_TCLASS
                 *   IP_TOS_ON            = bool : 1,  ///< Kernel supports IP_TOS
                 *   IP_TOS_DEFAULT_FLASH = bool : 7,  ///< Default TOS uses Flash precedence (0x68)
                 */
                struct {
                    bool                                                                                    IPV6_TCLASS_ON       : 1;
                    bool                                                                                    IP_TOS_ON            : 1;
                    bool                                                                                    IP_TOS_DEFAULT_FLASH : 7;
                };

            public:
                /**
                 * @brief Initializes restriction flags from platform capabilities.
                 *
                 * On Linux the constructor creates temporary raw sockets and calls
                 * ValidV4()/ValidV6() to probe whether IP_TOS and IPV6_TCLASS are
                 * accepted by the running kernel.  On other platforms, safe defaults
                 * are written without probing.
                 */
                SOCKET_RESTRICTIONS() noexcept;

#if defined(_LINUX)
            private:
                /**
                 * @brief Validates IPv4 related socket options on Linux.
                 * @param sockfd  Native socket descriptor opened with AF_INET/SOCK_DGRAM.
                 * @return        true if setsockopt(IP_TOS) succeeds on this kernel.
                 * @note          Called only from the constructor; @p sockfd is closed by caller.
                 */
                bool                                                                                    ValidV4(int sockfd) noexcept;
                /**
                 * @brief Validates IPv6 related socket options on Linux.
                 * @param sockfd  Native socket descriptor opened with AF_INET6/SOCK_DGRAM.
                 * @return        true if setsockopt(IPV6_TCLASS) succeeds on this kernel.
                 * @note          Called only from the constructor; @p sockfd is closed by caller.
                 */
                bool                                                                                    ValidV6(int sockfd) noexcept;
#endif
            };

            /** @brief Shared pointer to a TCP socket object managed by Boost.Asio. */
            typedef std::shared_ptr<boost::asio::ip::tcp::socket>                                       AsioTcpSocket;
            /** @brief Shared pointer to an Asio IO context used as the event loop executor. */
            typedef std::shared_ptr<boost::asio::io_context>                                            AsioContext;
            /** @brief Strand bound to the IO context executor; serializes handler invocations. */
            typedef boost::asio::strand<boost::asio::io_context::executor_type>                         AsioStrand;
            /** @brief Shared pointer to an Asio strand for lifetime-managed serialized dispatch. */
            typedef std::shared_ptr<AsioStrand>                                                         AsioStrandPtr;
            /** @brief Shared pointer to a TCP acceptor used to listen for inbound connections. */
            typedef std::shared_ptr<boost::asio::ip::tcp::acceptor>                                     AsioTcpAcceptor;
            /** @brief Shared pointer to a UDP socket for datagram-oriented communication. */
            typedef std::shared_ptr<boost::asio::ip::udp::socket>                                       AsioUdpSocket;
            /**
             * @brief Callback that returns an IO context for asynchronous work.
             *
             * Returned context is used to post completion handlers for newly accepted
             * connections.  Returning NULLPTR causes the accept loop to close the socket.
             */
            typedef ppp::function<AsioContext()>                                                        GetContextCallback;
            /**
             * @brief Callback for loopback receive processing.
             *
             * @param buffer  Shared byte buffer containing the received datagram.
             * @param length  Number of valid bytes in @p buffer.
             * @return        true to continue the receive loop; false to stop it.
             */
            typedef ppp::function<bool(const std::shared_ptr<Byte>&, int)>                              ReceiveFromLoopbackCallback;
            /**
             * @brief Callback invoked when a loopback connection is accepted.
             *
             * @param context IO context assigned to the new connection.
             * @param socket  Newly accepted TCP socket.
             * @return        true if the connection is taken; false to close it.
             */
            typedef ppp::function<bool(const AsioContext&, const AsioTcpSocket&)>                       AcceptLoopbackCallback;
            /**
             * @brief Callback invoked for scheduled loopback acceptance with strand support.
             *
             * @param context IO context assigned to the new connection.
             * @param strand  Strand serializing handlers for the new connection.
             * @param socket  Newly accepted TCP socket.
             * @return        true if the connection is taken; false to close it.
             */
            typedef ppp::function<bool(const AsioContext&, const AsioStrandPtr&, const AsioTcpSocket&)> AcceptLoopbackSchedulerCallback;

        public:
            /**
             * @brief Poll event category for socket readiness checks.
             *
             * Passed to @ref Poll / @ref PolH to select which readiness condition is tested.
             */
            enum SelectMode {
                SelectMode_SelectRead,  ///< Wait until data is available for reading.
                SelectMode_SelectWrite, ///< Wait until the socket can accept a write without blocking.
                SelectMode_SelectError, ///< Wait until an exceptional or error condition is pending.
            };

            /**
             * @brief Waits for a socket descriptor state with microsecond precision.
             * @param s            Native socket descriptor to poll.
             * @param microSeconds Maximum wait time in microseconds; 0 returns immediately.
             * @param mode         Readiness condition to test (read, write, or error).
             * @return             true when the descriptor satisfies @p mode before timeout.
             * @note               Wraps select(2) / WSAPoll internally.  Not suitable for
             *                     production-scale I/O; used in initialization paths only.
             */
            static bool                                                                                 PolH(int s, int64_t microSeconds, SelectMode mode) noexcept;

            /**
             * @brief Waits for a socket descriptor state with millisecond precision.
             * @param s            Native socket descriptor to poll.
             * @param milliSeconds Maximum wait time in milliseconds; 0 returns immediately.
             * @param mode         Readiness condition to test.
             * @return             true when the descriptor satisfies @p mode before timeout.
             * @note               Convenience wrapper around @ref PolH with millisecond granularity.
             */
            static bool                                                                                 Poll(int s, int milliSeconds, SelectMode mode) noexcept;

        public:
            /**
             * @brief Shuts down both send and receive directions of a native socket descriptor.
             * @param fd  Native socket descriptor; invalid values are silently ignored.
             * @note      Equivalent to shutdown(fd, SHUT_RDWR) but suppresses all errors.
             */
            static void                                                                                 Shutdown(int fd) noexcept;

            /**
             * @brief Closes a native socket descriptor, releasing kernel resources.
             * @param fd  Native socket descriptor; invalid values are silently ignored.
             */
            static void                                                                                 Closesocket(int fd) noexcept;

            /**
             * @brief Gets the local endpoint bound to a native socket descriptor.
             * @param fd  Native socket descriptor.
             * @return    Local TCP endpoint; default-constructed endpoint on failure.
             */
            static boost::asio::ip::tcp::endpoint                                                       GetLocalEndPoint(int fd) noexcept;

            /**
             * @brief Gets the remote endpoint connected to a native socket descriptor.
             * @param fd  Native socket descriptor.
             * @return    Remote TCP endpoint; default-constructed endpoint on failure.
             */
            static boost::asio::ip::tcp::endpoint                                                       GetRemoteEndPoint(int fd) noexcept;

            /**
             * @brief Enables or disables non-blocking mode for a native descriptor.
             * @param fd           Native socket descriptor.
             * @param nonblocking  true to set non-blocking; false to restore blocking mode.
             * @return             true on success; false if the underlying ioctl/fcntl fails.
             */
            static bool                                                                                 SetNonblocking(int fd, bool nonblocking) noexcept;

            /**
             * @brief Applies project default TCP socket options to an Asio TCP socket.
             * @param socket  Asio TCP socket to configure.
             * @param turbo   true to apply low-latency options (TCP_NODELAY, disable Nagle).
             * @return        true when all option calls succeed; false on first failure.
             * @note          Always called immediately after a TCP connection is established.
             */
            static bool                                                                                 AdjustDefaultSocketOptional(boost::asio::ip::tcp::socket& socket, bool turbo) noexcept;

        public:
            /**
             * @brief Starts asynchronous loopback accepting using shared acceptor/context wrappers.
             *
             * Posts an async_accept loop on the executor associated with @p acceptor.
             * Each accepted connection invokes @p callback; if @p context is provided,
             * the returned context is used to assign a per-connection executor.
             *
             * @param acceptor  Shared TCP acceptor already bound and listening.
             * @param callback  Handler called with (context, socket) for each new connection.
             * @param context   Optional factory returning a per-connection IO context.
             * @return          true if the first async_accept call is successfully posted.
             */
            static bool                                                                                 AcceptLoopbackAsync(
                const AsioTcpAcceptor&                                                                  acceptor,
                const AcceptLoopbackCallback&                                                           callback,
                const GetContextCallback&                                                               context = NULLPTR) noexcept;

            /**
             * @brief Starts asynchronous loopback accepting for a raw Asio acceptor.
             *
             * Overload for callers that hold a raw (non-shared) acceptor reference.
             *
             * @param acceptor  Raw TCP acceptor already bound and listening.
             * @param callback  Handler called with (context, socket) for each new connection.
             * @param context   Optional factory returning a per-connection IO context.
             * @return          true if the first async_accept call is successfully posted.
             */
            static bool                                                                                 AcceptLoopbackAsync(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const AcceptLoopbackCallback&                                                           callback,
                const GetContextCallback&                                                               context = NULLPTR) noexcept;

            /**
             * @brief Starts scheduled asynchronous loopback acceptance with strand dispatching.
             *
             * Similar to @ref AcceptLoopbackAsync but creates a strand per accepted connection
             * and passes it to @p callback, enabling strand-serialized handler execution.
             *
             * @param acceptor  Raw TCP acceptor already bound and listening.
             * @param callback  Handler called with (context, strand, socket) for each connection.
             * @return          true if the first async_accept call is successfully posted.
             */
            static bool                                                                                 AcceptLoopbackSchedulerAsync(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const AcceptLoopbackSchedulerCallback&                                                  callback) noexcept;

            /**
             * @brief Opens, configures, and binds a TCP acceptor for listening.
             * @param acceptor    Raw TCP acceptor to configure.
             * @param listenIP    Local IP address to bind (IPv4 or IPv6).
             * @param listenPort  Local port to bind; must be in [1, 65535].
             * @param backlog     Maximum length of pending connection queue.
             * @param fastOpen    true to enable TCP Fast Open (TFO) where supported.
             * @param noDelay     true to disable the Nagle algorithm (TCP_NODELAY).
             * @return            true if all configuration steps succeed; false otherwise.
             * @note              Sets SO_REUSEADDR, SO_REUSEPORT (Linux), and SO_KEEPALIVE
             *                    in addition to the caller-specified options.
             */
            static bool                                                                                 OpenAcceptor(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort,
                int                                                                                     backlog,
                bool                                                                                    fastOpen,
                bool                                                                                    noDelay) noexcept;

            /**
             * @brief Opens and binds a UDP socket with default opened state handling.
             *
             * Convenience overload that passes `opened = false`, meaning the socket
             * will be opened by this function before binding.
             *
             * @param socket      UDP socket to configure.
             * @param listenIP    Local IP address to bind.
             * @param listenPort  Local port to bind; 0 lets the OS choose.
             * @return            true on success; false if open or bind fails.
             */
            static bool                                                                                 OpenSocket(
                const boost::asio::ip::udp::socket&                                                     socket,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort) noexcept { return OpenSocket(socket, listenIP, listenPort, false); }

            /**
             * @brief Opens and binds a UDP socket with explicit opened state handling.
             * @param socket      UDP socket to configure.
             * @param listenIP    Local IP address to bind.
             * @param listenPort  Local port to bind; 0 lets the OS choose.
             * @param opened      true when the socket is already opened and should not be
             *                    re-opened (only bind will be attempted).
             * @return            true on success; false on any failure.
             */
            static bool                                                                                 OpenSocket(
                const boost::asio::ip::udp::socket&                                                     socket,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort,
                bool                                                                                    opened) noexcept;

        public:
            /**
             * @brief Cancels pending operations on a deadline timer.
             * @param socket  Timer to cancel; already-expired timers are unaffected.
             */
            static void                                                                                 Cancel(const boost::asio::deadline_timer& socket) noexcept;
            /**
             * @brief Cancels pending operations on a UDP socket.
             * @param socket  UDP socket whose outstanding async operations are cancelled.
             */
            static void                                                                                 Cancel(const boost::asio::ip::udp::socket& socket) noexcept;
            /**
             * @brief Cancels pending operations on a TCP socket.
             * @param socket  TCP socket whose outstanding async operations are cancelled.
             */
            static void                                                                                 Cancel(const boost::asio::ip::tcp::socket& socket) noexcept;
            /**
             * @brief Cancels pending operations on a TCP acceptor.
             * @param acceptor  Acceptor whose outstanding async_accept is cancelled.
             */
            static void                                                                                 Cancel(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            /**
             * @brief Cancels pending operations on a UDP resolver.
             * @param resolver  Resolver whose outstanding async_resolve is cancelled.
             */
            static void                                                                                 Cancel(const boost::asio::ip::udp::resolver& resolver) noexcept;
            /**
             * @brief Cancels pending operations on a TCP resolver.
             * @param resolver  Resolver whose outstanding async_resolve is cancelled.
             */
            static void                                                                                 Cancel(const boost::asio::ip::tcp::resolver& resolver) noexcept;
            
        public:
            /**
             * @brief Cancels pending operations on a shared UDP socket.
             * @param socket  Shared UDP socket; null pointer is silently ignored.
             */
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            /**
             * @brief Cancels pending operations on a shared TCP socket.
             * @param socket  Shared TCP socket; null pointer is silently ignored.
             */
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            /**
             * @brief Cancels pending operations on a shared TCP acceptor.
             * @param acceptor  Shared TCP acceptor; null pointer is silently ignored.
             */
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            /**
             * @brief Closes a POSIX stream descriptor wrapper.
             * @param stream  Raw pointer to stream descriptor; null is silently ignored.
             * @return        true if the descriptor was open and is now closed; false otherwise.
             * @note          Calls cancel() then close() on the descriptor.
             */
            static bool                                                                                 Closestream(boost::asio::posix::stream_descriptor* stream) noexcept;
            /**
             * @brief Closes a shared POSIX stream descriptor wrapper.
             * @param stream  Shared stream descriptor; empty shared_ptr is silently ignored.
             * @return        true if the descriptor was open and is now closed; false otherwise.
             */
            static bool                                                                                 Closestream(const std::shared_ptr<boost::asio::posix::stream_descriptor>& stream) noexcept { return Closestream(stream.get()); }

        public:
            /**
             * @brief Closes a shared UDP socket.
             * @param socket  Shared UDP socket; null is silently ignored.
             * @return        true if the socket was open and is now closed; false otherwise.
             */
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            /**
             * @brief Closes a shared TCP socket.
             * @param socket  Shared TCP socket; null is silently ignored.
             * @return        true if the socket was open and is now closed; false otherwise.
             */
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            /**
             * @brief Closes a shared TCP acceptor.
             * @param acceptor  Shared TCP acceptor; null is silently ignored.
             * @return          true if the acceptor was open and is now closed; false otherwise.
             */
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            template <class TSocket>
            /**
             * @brief Gets local bound port from a socket-like object.
             * @tparam TSocket  Any type that exposes `local_endpoint(error_code&)`.
             * @param socket    Socket-like instance (TCP or UDP socket).
             * @return          Bound port number in host order, or 0 when the call fails.
             * @note            Thread-safe as long as the socket is not concurrently closed.
             */
            static int                                                                                  LocalPort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                auto ep = constantof(socket).local_endpoint(ec);
                return ec ? 0 : ep.port();
            }
            
            template <class TSocket>
            /**
             * @brief Gets remote connected port from a socket-like object.
             * @tparam TSocket  Any type that exposes `remote_endpoint(error_code&)`.
             * @param socket    Socket-like instance; typically a connected TCP socket.
             * @return          Remote port number in host order, or 0 when the call fails.
             */
            static int                                                                                  RemotePort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                auto ep = constantof(socket).remote_endpoint(ec);
                return ec ? 0 : ep.port();
            }

            /**
             * @brief Resolves the best local interface IPv4 for a destination IPv4.
             * @param destination  Target IPv4 address in network byte order.
             * @return             Best-match local interface address in network byte order,
             *                     or INADDR_ANY on failure.
             * @note               On Windows delegates to GetBestInterface(); on Linux reads
             *                     /proc/net/route or uses a connected UDP socket trick.
             */
            static uint32_t                                                                             GetBestInterfaceIP(uint32_t destination) noexcept;

        public:
            /**
             * @brief Applies default socket option profile to a native descriptor.
             * @param sockfd  Native descriptor.
             * @param in4     true for IPv4 (AF_INET); false for IPv6 (AF_INET6).
             * @note          Sets SO_SNDBUF, SO_RCVBUF, IP_TOS / IPV6_TCLASS, and
             *                SO_REUSEADDR according to @ref SOCKET_RESTRICTIONS_.
             */
            static void                                                                                 AdjustDefaultSocketOptional(int sockfd, bool in4) noexcept;

            /**
             * @brief Applies TCP socket options to an Asio TCP socket.
             * @param socket    Target TCP socket (must be open).
             * @param in4       true for IPv4; false for IPv6.
             * @param fastOpen  true to request TCP Fast Open support.
             * @param noDealy   true to set TCP_NODELAY (note: parameter name typo preserved).
             */
            static void                                                                                 AdjustSocketOptional(const boost::asio::ip::tcp::socket& socket, bool in4, bool fastOpen, bool noDealy) noexcept;

            /**
             * @brief Applies UDP socket options to an Asio UDP socket.
             * @param socket  Target UDP socket (must be open).
             * @param in4     true for IPv4; false for IPv6.
             * @note          Sets SO_BROADCAST, SO_RCVBUF, and TOS/TCLASS options.
             */
            static void                                                                                 AdjustSocketOptional(const boost::asio::ip::udp::socket& socket, bool in4) noexcept;

            /**
             * @brief Sets send/receive window sizes when non-zero values are provided.
             * @param sockfd  Native socket descriptor.
             * @param cwnd    Desired send buffer size in bytes; 0 leaves unchanged.
             * @param rwnd    Desired receive buffer size in bytes; 0 leaves unchanged.
             * @return        true if all requested size changes succeed; false on any failure.
             */
            static bool                                                                                 SetWindowSizeIfNotZero(int sockfd, int cwnd, int rwnd) noexcept;

        public:
            /**
             * @brief Gets process default IP time-to-live value.
             * @return  Default TTL stored in @ref ppp::net::packet::IPFrame::DefaultTtl.
             */
            static int                                                                                  GetDefaultTTL() noexcept;

            /**
             * @brief Queries TCP MSS from a native descriptor.
             * @param fd  Connected TCP socket descriptor.
             * @return    MSS value in bytes, or -1 on failure.
             */
            static int                                                                                  GetTcpMss(int fd) noexcept;

            /**
             * @brief Sets TCP MSS on a native descriptor.
             * @param fd   Connected TCP socket descriptor.
             * @param mss  Desired MSS value in bytes.
             * @return     true on success; false if setsockopt fails.
             */
            static bool                                                                                 SetTcpMss(int fd, int mss) noexcept;

            /**
             * @brief Enables/disables and configures TCP keep-alive probes.
             * @param fd               Native socket descriptor.
             * @param enable           true to enable SO_KEEPALIVE; false to disable.
             * @param idle_seconds     Idle time before first keep-alive probe (default: 60).
             * @param interval_seconds Interval between consecutive probes (default: 15).
             * @param probe_count      Maximum number of unacknowledged probes (default: 4).
             * @return                 true if all setsockopt calls succeed; false otherwise.
             */
            static bool                                                                                 SetKeepAlive(int fd, bool enable, int idle_seconds = 60, int interval_seconds = 15, int probe_count = 4) noexcept;

            /**
             * @brief Reports whether flash TOS is enabled by default.
             * @return  Value of @ref SOCKET_RESTRICTIONS_::IP_TOS_DEFAULT_FLASH.
             */
            static bool                                                                                 IsDefaultFlashTypeOfService() noexcept { return SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH; }

            /**
             * @brief Sets whether flash TOS should be used by default.
             * @param value  true to enable flash TOS (DSCP 0x68) on new frames.
             */
            static void                                                                                 SetDefaultFlashTypeOfService(bool value) noexcept { SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH = value; } 

            /**
             * @brief Sets packet type-of-service on a native descriptor.
             * @param fd   Native socket descriptor.
             * @param tos  TOS / DSCP value; pass ~0 to use the project default flash value.
             * @return     true on success; false if unsupported or setsockopt fails.
             * @note       No-op when @ref SOCKET_RESTRICTIONS_::IP_TOS_ON is false.
             */
            static bool                                                                                 SetTypeOfService(int fd, int tos = ~0) noexcept;

            /**
             * @brief Controls SIGPIPE behavior where supported.
             * @param fd      Native socket descriptor.
             * @param sigpipe true to restore default SIGPIPE delivery; false to suppress it
             *                (sets SO_NOSIGPIPE or MSG_NOSIGNAL equivalent).
             * @return        true on success; false if the platform does not support the option.
             */
            static bool                                                                                 SetSignalPipeline(int fd, bool sigpipe) noexcept;

            /**
             * @brief Enables or disables address reuse on a native descriptor.
             * @param fd     Native socket descriptor.
             * @param reuse  true to set SO_REUSEADDR (and SO_REUSEPORT on Linux).
             * @return       true on success; false if setsockopt fails.
             */
            static bool                                                                                 ReuseSocketAddress(int fd, bool reuse) noexcept;

        public:
            /**
             * @brief Gets native descriptor handle from an Asio TCP acceptor.
             * @param acceptor  TCP acceptor (must be open).
             * @return          Native handle; -1 (INVALID_SOCKET on Windows) on failure.
             */
            static int                                                                                  GetHandle(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            /**
             * @brief Gets native descriptor handle from an Asio TCP socket.
             * @param socket  TCP socket (must be open).
             * @return        Native handle; -1 (INVALID_SOCKET on Windows) on failure.
             */
            static int                                                                                  GetHandle(const boost::asio::ip::tcp::socket& socket) noexcept;
            /**
             * @brief Gets native descriptor handle from an Asio UDP socket.
             * @param socket  UDP socket (must be open).
             * @return        Native handle; -1 (INVALID_SOCKET on Windows) on failure.
             */
            static int                                                                                  GetHandle(const boost::asio::ip::udp::socket& socket) noexcept;

        public:
            /**
             * @brief Closes an Asio TCP acceptor.
             * @param acceptor  TCP acceptor to close.
             * @return          true if the acceptor was open and is now successfully closed.
             */
            static bool                                                                                 Closesocket(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            /**
             * @brief Closes an Asio TCP socket.
             * @param socket  TCP socket to close.
             * @return        true if the socket was open and is now successfully closed.
             */
            static bool                                                                                 Closesocket(const boost::asio::ip::tcp::socket& socket) noexcept;
            /**
             * @brief Closes an Asio UDP socket.
             * @param socket  UDP socket to close.
             * @return        true if the socket was open and is now successfully closed.
             */
            static bool                                                                                 Closesocket(const boost::asio::ip::udp::socket& socket) noexcept;
        
        private:
            /**
             * @brief Global restriction flags used by option-setting helpers.
             *
             * Populated once during static initialization by the @ref SOCKET_RESTRICTIONS
             * constructor.  All public flag-reading functions delegate to this instance.
             */
            static SOCKET_RESTRICTIONS                                                                  SOCKET_RESTRICTIONS_; 
        };
    }
}
