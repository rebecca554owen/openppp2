#pragma once

#include <ppp/stdafx.h>

/**
 * @file Socket.h
 * @brief Declares socket utility helpers used by TCP/UDP networking components.
 */

namespace ppp {
    namespace net {
        /**
         * @brief Collection of static helpers for low-level socket and Boost.Asio operations.
         */
        class Socket final {
        public:
            /**
             * @brief Runtime and policy flags that gate socket option behavior.
             */
            class SOCKET_RESTRICTIONS final {
            public:
                /**
                 * @brief Bit-field switches for type-of-service and traffic-class behavior.
                 */
                struct {
                    bool                                                                                    IPV6_TCLASS_ON       : 1;
                    bool                                                                                    IP_TOS_ON            : 1;
                    bool                                                                                    IP_TOS_DEFAULT_FLASH : 7;
                };

            public:
                /**
                 * @brief Initializes restriction flags from platform capabilities.
                 */
                SOCKET_RESTRICTIONS() noexcept;

#if defined(_LINUX)
            private:
                /**
                 * @brief Validates IPv4 related socket options on Linux.
                 * @param sockfd Native socket descriptor.
                 * @return true if IPv4 option probing succeeds; otherwise false.
                 */
                bool                                                                                    ValidV4(int sockfd) noexcept;
                /**
                 * @brief Validates IPv6 related socket options on Linux.
                 * @param sockfd Native socket descriptor.
                 * @return true if IPv6 option probing succeeds; otherwise false.
                 */
                bool                                                                                    ValidV6(int sockfd) noexcept;
#endif
            };
            /** @brief Shared pointer to a TCP socket object. */
            typedef std::shared_ptr<boost::asio::ip::tcp::socket>                                       AsioTcpSocket;
            /** @brief Shared pointer to an Asio IO context. */
            typedef std::shared_ptr<boost::asio::io_context>                                            AsioContext;
            /** @brief Strand bound to the IO context executor. */
            typedef boost::asio::strand<boost::asio::io_context::executor_type>                         AsioStrand;
            /** @brief Shared pointer to an Asio strand. */
            typedef std::shared_ptr<AsioStrand>                                                         AsioStrandPtr;
            /** @brief Shared pointer to a TCP acceptor. */
            typedef std::shared_ptr<boost::asio::ip::tcp::acceptor>                                     AsioTcpAcceptor;
            /** @brief Shared pointer to a UDP socket. */
            typedef std::shared_ptr<boost::asio::ip::udp::socket>                                       AsioUdpSocket;
            /** @brief Callback that returns an IO context for asynchronous work. */
            typedef ppp::function<AsioContext()>                                                        GetContextCallback;
            /** @brief Callback for loopback receive processing. */
            typedef ppp::function<bool(const std::shared_ptr<Byte>&, int)>                              ReceiveFromLoopbackCallback;
            /** @brief Callback invoked when a loopback connection is accepted. */
            typedef ppp::function<bool(const AsioContext&, const AsioTcpSocket&)>                       AcceptLoopbackCallback;
            /** @brief Callback invoked for scheduled loopback acceptance with strand support. */
            typedef ppp::function<bool(const AsioContext&, const AsioStrandPtr&, const AsioTcpSocket&)> AcceptLoopbackSchedulerCallback;

        public:
            /**
             * @brief Poll event category for socket readiness checks.
             */
            enum SelectMode {
                SelectMode_SelectRead,
                SelectMode_SelectWrite,
                SelectMode_SelectError,
            };
            /**
             * @brief Waits for a socket descriptor state with microsecond precision.
             * @param s Native socket descriptor.
             * @param microSeconds Timeout in microseconds.
             * @param mode Desired readiness mode.
             * @return true when the descriptor is ready for the selected mode.
             */
            static bool                                                                                 PolH(int s, int64_t microSeconds, SelectMode mode) noexcept;
            /**
             * @brief Waits for a socket descriptor state with millisecond precision.
             * @param s Native socket descriptor.
             * @param milliSeconds Timeout in milliseconds.
             * @param mode Desired readiness mode.
             * @return true when the descriptor is ready for the selected mode.
             */
            static bool                                                                                 Poll(int s, int milliSeconds, SelectMode mode) noexcept;

        public:
            /** @brief Shuts down both directions of a native socket descriptor. */
            static void                                                                                 Shutdown(int fd) noexcept;
            /** @brief Closes a native socket descriptor. */
            static void                                                                                 Closesocket(int fd) noexcept;
            /** @brief Gets the local endpoint bound to a native socket descriptor. */
            static boost::asio::ip::tcp::endpoint                                                       GetLocalEndPoint(int fd) noexcept;
            /** @brief Gets the remote endpoint connected to a native socket descriptor. */
            static boost::asio::ip::tcp::endpoint                                                       GetRemoteEndPoint(int fd) noexcept;
            /** @brief Enables or disables non-blocking mode for a native descriptor. */
            static bool                                                                                 SetNonblocking(int fd, bool nonblocking) noexcept;
            /** @brief Applies project default TCP socket options. */
            static bool                                                                                 AdjustDefaultSocketOptional(boost::asio::ip::tcp::socket& socket, bool turbo) noexcept;

        public:
            /** @brief Starts asynchronous loopback accepting using shared acceptor/context wrappers. */
            static bool                                                                                 AcceptLoopbackAsync(
                const AsioTcpAcceptor&                                                                  acceptor,
                const AcceptLoopbackCallback&                                                           callback,
                const GetContextCallback&                                                               context = NULLPTR) noexcept;
            /** @brief Starts asynchronous loopback accepting for a raw Asio acceptor. */
            static bool                                                                                 AcceptLoopbackAsync(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const AcceptLoopbackCallback&                                                           callback,
                const GetContextCallback&                                                               context = NULLPTR) noexcept;
            /** @brief Starts scheduled asynchronous loopback acceptance with strand dispatching. */
            static bool                                                                                 AcceptLoopbackSchedulerAsync(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const AcceptLoopbackSchedulerCallback&                                                  callback) noexcept;
            /** @brief Opens, configures, and binds a TCP acceptor for listening. */
            static bool                                                                                 OpenAcceptor(
                const boost::asio::ip::tcp::acceptor&                                                   acceptor,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort,
                int                                                                                     backlog,
                bool                                                                                    fastOpen,
                bool                                                                                    noDelay) noexcept;
            /** @brief Opens and binds a UDP socket with default opened state handling. */
            static bool                                                                                 OpenSocket(
                const boost::asio::ip::udp::socket&                                                     socket,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort) noexcept { return OpenSocket(socket, listenIP, listenPort, false); }
            /** @brief Opens and binds a UDP socket with explicit opened state handling. */
            static bool                                                                                 OpenSocket(
                const boost::asio::ip::udp::socket&                                                     socket,
                const boost::asio::ip::address&                                                         listenIP,
                int                                                                                     listenPort,
                bool                                                                                    opened) noexcept;

        public:
            /** @brief Cancels pending operations on a deadline timer. */
            static void                                                                                 Cancel(const boost::asio::deadline_timer& socket) noexcept;
            /** @brief Cancels pending operations on a UDP socket. */
            static void                                                                                 Cancel(const boost::asio::ip::udp::socket& socket) noexcept;
            /** @brief Cancels pending operations on a TCP socket. */
            static void                                                                                 Cancel(const boost::asio::ip::tcp::socket& socket) noexcept;
            /** @brief Cancels pending operations on a TCP acceptor. */
            static void                                                                                 Cancel(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            /** @brief Cancels pending operations on a UDP resolver. */
            static void                                                                                 Cancel(const boost::asio::ip::udp::resolver& resolver) noexcept;
            /** @brief Cancels pending operations on a TCP resolver. */
            static void                                                                                 Cancel(const boost::asio::ip::tcp::resolver& resolver) noexcept;
            
        public:
            /** @brief Cancels pending operations on a shared UDP socket. */
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            /** @brief Cancels pending operations on a shared TCP socket. */
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            /** @brief Cancels pending operations on a shared TCP acceptor. */
            static void                                                                                 Cancel(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            /** @brief Closes a POSIX stream descriptor wrapper. */
            static bool                                                                                 Closestream(boost::asio::posix::stream_descriptor* stream) noexcept;
            /** @brief Closes a shared POSIX stream descriptor wrapper. */
            static bool                                                                                 Closestream(const std::shared_ptr<boost::asio::posix::stream_descriptor>& stream) noexcept { return Closestream(stream.get()); }

        public:
            /** @brief Closes a shared UDP socket. */
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept;
            /** @brief Closes a shared TCP socket. */
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
            /** @brief Closes a shared TCP acceptor. */
            static bool                                                                                 Closesocket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept;

        public:
            template <class TSocket>
            /**
             * @brief Gets local bound port from a socket-like object.
             * @tparam TSocket Socket type exposing local_endpoint(error_code).
             * @param socket Socket-like instance.
             * @return Port number, or 0 when endpoint retrieval fails.
             */
            static int                                                                                  LocalPort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                auto ep = constantof(socket).local_endpoint(ec);
                return ec ? 0 : ep.port();
            }
            
            template <class TSocket>
            /**
             * @brief Gets remote connected port from a socket-like object.
             * @tparam TSocket Socket type exposing remote_endpoint(error_code).
             * @param socket Socket-like instance.
             * @return Port number, or 0 when endpoint retrieval fails.
             */
            static int                                                                                  RemotePort(const TSocket& socket) noexcept {
                boost::system::error_code ec;
                auto ep = constantof(socket).remote_endpoint(ec);
                return ec ? 0 : ep.port();
            }

            /** @brief Resolves the best local interface IPv4 for a destination IPv4. */
            static uint32_t                                                                             GetBestInterfaceIP(uint32_t destination) noexcept;

        public:
            /** @brief Applies default socket option profile to a native descriptor. */
            static void                                                                                 AdjustDefaultSocketOptional(int sockfd, bool in4) noexcept;
            /** @brief Applies TCP socket options to an Asio TCP socket. */
            static void                                                                                 AdjustSocketOptional(const boost::asio::ip::tcp::socket& socket, bool in4, bool fastOpen, bool noDealy) noexcept;
            /** @brief Applies UDP socket options to an Asio UDP socket. */
            static void                                                                                 AdjustSocketOptional(const boost::asio::ip::udp::socket& socket, bool in4) noexcept;
            /** @brief Sets send/receive window sizes when non-zero values are provided. */
            static bool                                                                                 SetWindowSizeIfNotZero(int sockfd, int cwnd, int rwnd) noexcept;

        public:
            /** @brief Gets process default IP time-to-live value. */
            static int                                                                                  GetDefaultTTL() noexcept;
            /** @brief Queries TCP MSS from a native descriptor. */
            static int                                                                                  GetTcpMss(int fd) noexcept;
            /** @brief Sets TCP MSS on a native descriptor. */
            static bool                                                                                 SetTcpMss(int fd, int mss) noexcept;
            /** @brief Enables/disables and configures TCP keep-alive probes. */
            static bool                                                                                 SetKeepAlive(int fd, bool enable, int idle_seconds = 60, int interval_seconds = 15, int probe_count = 4) noexcept;
            /** @brief Reports whether flash TOS is enabled by default. */
            static bool                                                                                 IsDefaultFlashTypeOfService() noexcept { return SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH; }
            /** @brief Sets whether flash TOS should be used by default. */
            static void                                                                                 SetDefaultFlashTypeOfService(bool value) noexcept { SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH = value; } 
            /** @brief Sets packet type-of-service on a native descriptor. */
            static bool                                                                                 SetTypeOfService(int fd, int tos = ~0) noexcept;
            /** @brief Controls SIGPIPE behavior where supported. */
            static bool                                                                                 SetSignalPipeline(int fd, bool sigpipe) noexcept;
            /** @brief Enables or disables address reuse on a native descriptor. */
            static bool                                                                                 ReuseSocketAddress(int fd, bool reuse) noexcept;

        public:
            /** @brief Gets native descriptor handle from an Asio TCP acceptor. */
            static int                                                                                  GetHandle(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            /** @brief Gets native descriptor handle from an Asio TCP socket. */
            static int                                                                                  GetHandle(const boost::asio::ip::tcp::socket& socket) noexcept;
            /** @brief Gets native descriptor handle from an Asio UDP socket. */
            static int                                                                                  GetHandle(const boost::asio::ip::udp::socket& socket) noexcept;

        public:
            /** @brief Closes an Asio TCP acceptor. */
            static bool                                                                                 Closesocket(const boost::asio::ip::tcp::acceptor& acceptor) noexcept;
            /** @brief Closes an Asio TCP socket. */
            static bool                                                                                 Closesocket(const boost::asio::ip::tcp::socket& socket) noexcept;
            /** @brief Closes an Asio UDP socket. */
            static bool                                                                                 Closesocket(const boost::asio::ip::udp::socket& socket) noexcept;
        
        private:
            /** @brief Global restriction flags used by option-setting helpers. */
            static SOCKET_RESTRICTIONS                                                                  SOCKET_RESTRICTIONS_; 
        };
    }
}
