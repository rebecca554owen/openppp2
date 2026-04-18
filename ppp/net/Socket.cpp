/**
 * @file Socket.cpp
 * @brief Cross-platform socket utility implementations for PPP networking.
 */

// https://www-numi.fnal.gov/offline_software/srt_public_context/WebDocs/Errors/unix_system_errors.html
// #define ENOENT           2      /* No such file or directory */
// #define EAGAIN          11      /* Try again */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <iostream>
#include <assert.h>

#include <sys/types.h>

#if defined(_WIN32)
#include <stdint.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Mstcpip.h>

#pragma comment(lib, "ws2_32.lib")
#else
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#endif

#include <fcntl.h>
#include <errno.h>

#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Executors.h>

#if defined(__MUSL__)
#include <err.h>
#include <poll.h>
#else
#if defined(_MACOS)
#include <errno.h>
#include <sys/poll.h>
#elif defined(_LINUX)
#include <error.h>
#include <sys/poll.h>
#endif
#endif

#ifndef INFINITE
#define INFINITE ~0 // INFINITY
#endif

// https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/ip.h#L26
// https://man7.org/linux/man-pages/man7/ip.7.html
#if defined(_WIN32)
#define IPTOS_TOS_MASK      0x1E
#define IPTOS_TOS(tos)      ((tos) & IPTOS_TOS_MASK)
#define IPTOS_LOWDELAY      0x10
#define IPTOS_THROUGHPUT    0x08
#define IPTOS_RELIABILITY   0x04
#define IPTOS_MINCOST       0x02
#endif

namespace ppp {
    namespace net {
        /**
         * @brief Converts a native sockaddr into Boost.Asio address and endpoint.
         */
        static bool Socket_ConvertSockaddrToEndpoint(const struct sockaddr* addr, boost::asio::ip::address& address, boost::asio::ip::tcp::endpoint& endpoint) noexcept {
            const struct sockaddr_in* in4 = (const struct sockaddr_in*)addr;
            const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)addr;
            if (addr->sa_family == AF_INET) {
                address = boost::asio::ip::address_v4(ntohl(in4->sin_addr.s_addr));
                endpoint = boost::asio::ip::tcp::endpoint(address, ntohs(in4->sin_port));
                return true;
            }
            elif(addr->sa_family == AF_INET6) {
                boost::asio::ip::address_v6::bytes_type bytes;
                memcpy(bytes.data(), &in6->sin6_addr.s6_addr, bytes.size());

                address = boost::asio::ip::address_v6(bytes);
                endpoint = boost::asio::ip::tcp::endpoint(address, ntohs(in6->sin6_port));
                return true;
            }
            else {
                return false;
            }
        }

        /**
         * @brief Obtains peer or local endpoint from a file descriptor.
         * @param endpoint Output endpoint value.
         * @param fd Native socket descriptor.
         * @param getpeername_or_getsockname true for getpeername, false for getsockname.
         */
        static bool Socket_GetPeerNameOrGetSocketName(boost::asio::ip::tcp::endpoint& endpoint, int fd, bool getpeername_or_getsockname) noexcept {
            int err = -1;
            union {
                struct sockaddr_in in4;
                struct sockaddr_in6 in6;
            } address;

            socklen_t address_size = sizeof(address);
            if (getpeername_or_getsockname) {
                err = ::getpeername(fd, (struct sockaddr*)&address, &address_size);
            }
            else {
                err = ::getsockname(fd, (struct sockaddr*)&address, &address_size);
            }

            if (err != 0) {
                return false;
            }

            boost::asio::ip::address boost_address = boost::asio::ip::address_v4::any();
            return Socket_ConvertSockaddrToEndpoint((struct sockaddr*)&address, boost_address, endpoint);
        }

        /**
         * @brief Gets local endpoint information for a native socket.
         */
        boost::asio::ip::tcp::endpoint Socket::GetLocalEndPoint(int fd) noexcept {
            boost::asio::ip::tcp::endpoint endpoint;
            Socket_GetPeerNameOrGetSocketName(endpoint, fd, false);
            return endpoint;
        }

        /**
         * @brief Gets remote peer endpoint information for a native socket.
         */
        boost::asio::ip::tcp::endpoint Socket::GetRemoteEndPoint(int fd) noexcept {
            boost::asio::ip::tcp::endpoint endpoint;
            Socket_GetPeerNameOrGetSocketName(endpoint, fd, true);
            return endpoint;
        }

        /**
         * @brief Polls socket state with millisecond timeout.
         */
        bool Socket::Poll(int s, int milliSeconds, SelectMode mode) noexcept {
            int64_t microSeconds = milliSeconds;
            microSeconds *= 1000;
            return Socket::PolH(s, microSeconds, mode);
        }

        /**
         * @brief Polls socket state with microsecond timeout.
         */
        bool Socket::PolH(int s, int64_t microSeconds, SelectMode mode) noexcept {
            if (s == -1) {
                return false;
            }

#if defined(_WIN32)
            struct fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(s, &fdset);

            struct timeval tv;
            if (microSeconds < 0) {
                tv.tv_sec = (int)INFINITE;
                tv.tv_usec = (int)INFINITE;
            }
            else {
                tv.tv_sec = microSeconds / 1000000;
                tv.tv_usec = microSeconds;
            }

            int hr = -1;
            if (mode == SelectMode_SelectRead) {
                hr = select(s + 1, &fdset, NULLPTR, NULLPTR, &tv) > 0;
            }
            elif(mode == SelectMode_SelectWrite) {
                hr = select(s + 1, NULLPTR, &fdset, NULLPTR, &tv) > 0;
            }
            else {
                hr = select(s + 1, NULLPTR, NULLPTR, &fdset, &tv) > 0;
            }

            if (hr > 0) {
                return FD_ISSET(s, &fdset);
            }
#else
            struct pollfd fds[1];
            memset(fds, 0, sizeof(fds));

            int events = POLLERR;
            if (mode == SelectMode_SelectRead) {
                events = POLLIN;
            }
            elif(mode == SelectMode_SelectWrite) {
                events = POLLOUT;
            }
            else {
                events = POLLERR;
            }

            fds->fd = s;
            fds->events = events;

            int hr;
            if (microSeconds < 0) {
                int timeout_ = (int)INFINITE;
                hr = poll(fds, 1, timeout_);
            }
            else {
                int timeout_ = (int)(microSeconds / 1000);
                hr = poll(fds, 1, timeout_);
            }

            if (hr > 0) {
                if ((fds->revents & events) == events) {
                    return true;
                }
            }
#endif
            return false;
        }

        /** @brief Cancels pending asynchronous operations on UDP socket. */
        void Socket::Cancel(const boost::asio::ip::udp::socket& socket) noexcept {
            boost::asio::ip::udp::socket& s = constantof(socket);
            if (s.is_open()) {
                boost::system::error_code ec;
                try {
                    s.cancel(ec);
                }
                catch (const std::exception&) {}
            }
        }

        /** @brief Cancels pending asynchronous operations on TCP socket. */
        void Socket::Cancel(const boost::asio::ip::tcp::socket& socket) noexcept {
            boost::asio::ip::tcp::socket& s = constantof(socket);
            if (s.is_open()) {
                boost::system::error_code ec;
                try {
                    s.cancel(ec);
                }
                catch (const std::exception&) {}
            }
        }

        /** @brief Cancels pending asynchronous accept operations. */
        void Socket::Cancel(const boost::asio::ip::tcp::acceptor& acceptor) noexcept {
            boost::asio::ip::tcp::acceptor& s = constantof(acceptor);
            if (s.is_open()) {
                boost::system::error_code ec;
                try {
                    s.cancel(ec);
                }
                catch (const std::exception&) {}
            }
        }

        /** @brief Cancels pending UDP resolver operations. */
        void Socket::Cancel(const boost::asio::ip::udp::resolver& resolver) noexcept {
            boost::asio::ip::udp::resolver& s = constantof(resolver);
            try {
                s.cancel();
            }
            catch (const std::exception&) {}
        }

        /** @brief Cancels pending TCP resolver operations. */
        void Socket::Cancel(const boost::asio::ip::tcp::resolver& resolver) noexcept {
            boost::asio::ip::tcp::resolver& s = constantof(resolver);
            try {
                s.cancel();
            }
            catch (const std::exception&) {}
        }

        /** @brief Cancels pending deadline timer operations. */
        void Socket::Cancel(const boost::asio::deadline_timer& deadline_timer) noexcept {
            boost::asio::deadline_timer& t = constantof(deadline_timer);
            boost::system::error_code ec;
            try {
                t.cancel(ec);
            }
            catch (const std::exception&) {}
        }

        /** @brief Shared-pointer UDP socket cancel overload. */
        void Socket::Cancel(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept {
            if (NULLPTR != socket) {
                Cancel(*socket);
            }
        }

        /** @brief Shared-pointer TCP socket cancel overload. */
        void Socket::Cancel(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
            if (NULLPTR != socket) {
                Cancel(*socket);
            }
        }

        /** @brief Shared-pointer acceptor cancel overload. */
        void Socket::Cancel(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept {
            if (NULLPTR != acceptor) {
                Cancel(*acceptor);
            }
        }

        /** @brief Shared-pointer UDP socket close overload. */
        bool Socket::Closesocket(const std::shared_ptr<boost::asio::ip::udp::socket>& socket) noexcept {
            if (NULLPTR != socket) {
                return Closesocket(*socket);
            }
            else {
                return false;
            }
        }

        /** @brief Shared-pointer TCP socket close overload. */
        bool Socket::Closesocket(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
            if (NULLPTR != socket) {
                return Closesocket(*socket);
            }
            else {
                return false;
            }
        }

        /** @brief Shared-pointer acceptor close overload. */
        bool Socket::Closesocket(const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) noexcept {
            if (NULLPTR != acceptor) {
                return Closesocket(*acceptor);
            }
            else {
                return false;
            }
        }

        /**
         * @brief Performs half-close on native socket send channel.
         */
        void Socket::Shutdown(int fd) noexcept {
            if (fd != -1) {
                int how;
#if defined(_WIN32)
                how = SD_SEND;
#else
                how = SHUT_WR;
#endif

                ::shutdown(fd, how);
            }
        }

        /**
         * @brief Closes a native socket descriptor.
         */
        void Socket::Closesocket(int fd) noexcept {
            if (fd != -1) {
#if defined(_WIN32)
                ::closesocket(fd);
#else   
                ::close(fd);
#endif
            }
        }

        /**
         * @brief Queries system default IPv4 TTL value.
         */
        int Socket::GetDefaultTTL() noexcept {
            static constexpr int DFL_TTL = 64;

            int ttl = DFL_TTL;
            int fd = (int)socket(AF_INET, SOCK_DGRAM, 0);
            if (fd != -1) {
#if defined(_MACOS)
                socklen_t len = sizeof(ttl);
                if (getsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, &len) < 0) {
                    int mib[] = { CTL_NET, IPPROTO_IP, IPCTL_DEFTTL };
                    if (sysctl(mib, 3, &ttl, (size_t*)&len, NULLPTR, 0) < 0 || ttl < 1) {
                        ttl = DFL_TTL;
                    }
                }
                elif(ttl < 1) {
                    ttl = DFL_TTL;
                }
#else
                socklen_t len = sizeof(ttl);
                if (getsockopt(fd, SOL_IP, IP_TTL, (char*)&ttl, &len) < 0 || ttl < 1) {
                    ttl = DFL_TTL;
                }
#endif

#if defined(_WIN32)
                ::closesocket((SOCKET)fd);
#else
                ::close(fd);
#endif
            }

            return std::min<int>(ttl, UINT8_MAX);
        }
        
        using SOCKET_RESTRICTIONS = Socket::SOCKET_RESTRICTIONS;

        // If the socket function is not supported by the QEMU user mode VM, 
        // The does not apply.  
        // Otherwise, the QEMU user mode VM frantically reports error logs.
        SOCKET_RESTRICTIONS Socket::SOCKET_RESTRICTIONS_; 

        /**
         * @brief Probes platform socket option support at startup.
         */
        SOCKET_RESTRICTIONS::SOCKET_RESTRICTIONS() noexcept 
            : IPV6_TCLASS_ON(true)
            , IP_TOS_ON(true)
            , IP_TOS_DEFAULT_FLASH(true) {
#if defined(_LINUX)
            int fd = (int)socket(AF_INET, SOCK_STREAM, 0);
            if (fd != -1) {
                ValidV4(fd);
                Socket::Closesocket(fd);
            }

            fd = (int)socket(AF_INET6, SOCK_STREAM, 0);
            if (fd != -1) {
                ValidV6(fd);
                Socket::Closesocket(fd);
            }
#endif

            // When the VPN source code is compiled with jemalloc memory allocators, 
            // The default dirty_decay_ms and muzzy_decay_ms values need to be changed, 
            // Which can significantly reduce memory usage, 
            // And both values are set to 0 in Android 10. We can all just follow Google's lead.
#if defined(JEMALLOC)
            /* https://android.googlesource.com/platform/external/jemalloc_new/+/refs/heads/main/include/jemalloc/internal/arena_types.h */
            /* https://blog.csdn.net/liulilittle/article/details/137535634 */
            /* https://jemalloc.net/jemalloc.3.html */
            // 
            // /* Default decay times in milliseconds. */
            // #if defined(__ANDROID__)
            // #define DIRTY_DECAY_MS_DEFAULT	ZD(0)
            // #define MUZZY_DECAY_MS_DEFAULT	ZD(0)
            // #else
            // #define DIRTY_DECAY_MS_DEFAULT	ZD(10 * 1000)
            // #define MUZZY_DECAY_MS_DEFAULT	ZD(10 * 1000)
            // #endif

            size_t dirty_decay_ms = 0;
            size_t muzzy_decay_ms = 0;

            je_mallctl("arenas.dirty_decay_ms", NULLPTR, 0, reinterpret_cast<void*>(&dirty_decay_ms), sizeof(dirty_decay_ms));
            je_mallctl("arenas.muzzy_decay_ms", NULLPTR, 0, reinterpret_cast<void*>(&muzzy_decay_ms), sizeof(muzzy_decay_ms));
#endif
        }

#if defined(_LINUX)
        /**
         * @brief Validates IPv4 IP_TOS availability on current runtime.
         */
        bool SOCKET_RESTRICTIONS::ValidV4(int sockfd) noexcept {
            int tos = IPTOS_LOWDELAY;
            int err = ::setsockopt(sockfd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos));
            if (err > -1) {
                return true;
            }

            IP_TOS_ON = false;
            return false;
        }

        /**
         * @brief Validates IPv6 traffic-class option availability.
         */
        bool SOCKET_RESTRICTIONS::ValidV6(int sockfd) noexcept {
            int tos = IPTOS_LOWDELAY;
#if defined(IPV6_TCLASS)
            int err = ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos));
            if (err > -1) {
                return true;
            }
#endif

            IPV6_TCLASS_ON = false;
            return false;
        }
#endif  

        /**
         * @brief Applies DSCP/TOS hints to a socket.
         */
        bool Socket::SetTypeOfService(int fd, int tos) noexcept {
            if (fd == -1) {
                return false;
            }

            if (tos < 0) {
                tos = SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH ? IPTOS_LOWDELAY : 0;
            }

            bool any = false;
#if defined(_MACOS)
#if defined(IPV6_TCLASS)
            if (SOCKET_RESTRICTIONS_.IPV6_TCLASS_ON) {
                any |= ::setsockopt(fd, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
            }
#endif
            if (SOCKET_RESTRICTIONS_.IP_TOS_ON) {
                any |= ::setsockopt(fd, IPPROTO_IP, IP_TOS, (char*)&tos, sizeof(tos)) == 0;
            }
#else
#if defined(IPV6_TCLASS)
            if (SOCKET_RESTRICTIONS_.IPV6_TCLASS_ON) {
                any |= ::setsockopt(fd, SOL_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)) == 0;
            }
#endif
            if (SOCKET_RESTRICTIONS_.IP_TOS_ON) {
                any |= ::setsockopt(fd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos)) == 0;
            }
#endif
            return any;
        }

        /**
         * @brief Configures SIGPIPE behavior where supported.
         */
        bool Socket::SetSignalPipeline(int fd, bool sigpipe) noexcept {
            int err = 0;
            if (fd == -1) {
                return false;
            }

#if defined(SO_NOSIGPIPE)
            int opt = sigpipe ? 0 : 1;
            err = ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char*)&opt, sizeof(opt));
#endif
            return err == 0;
        }

        /**
         * @brief Enables or disables SO_REUSEADDR.
         */
        bool Socket::ReuseSocketAddress(int fd, bool reuse) noexcept {
            if (fd == -1) {
                return false;
            }

            int flag = reuse ? 1 : 0;
            return ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&flag, sizeof(flag)) == 0;
        }

        /* TCP MSS values – what’s changed?
         * https://blog.apnic.net/2019/07/31/tcp-mss-values-whats-changed/ 
         */
        /**
         * @brief Gets TCP maximum segment size from socket options.
         */
        int Socket::GetTcpMss(int fd) noexcept {
            if (fd == -1) {
                return -1;
            }

            int mss = 0;
            socklen_t mss_len = sizeof(mss);

            if (::getsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, (char*)&mss, &mss_len) < 0) {
                return -1;
            }

            return mss;
        }

        /**
         * @brief Sets TCP MSS with conservative min/max clamping.
         */
        bool Socket::SetTcpMss(int fd, int mss) noexcept {
            static constexpr int TCP_MIN_MSS = 536;
            static constexpr int TCP_MAX_MSS = 1460;

            if (fd == -1) {
                return false;
            }

            if (mss < TCP_MIN_MSS) {
                mss = TCP_MIN_MSS;
            }
            elif(mss > TCP_MAX_MSS) {
                mss = TCP_MAX_MSS;
            }

            int err = ::setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, (char*)&mss, sizeof(mss));
            return err == 0;
        }

        /**
         * @brief Enables TCP keepalive and optional platform-specific tunables.
         */
        bool Socket::SetKeepAlive(int fd, bool enable, int idle_seconds, int interval_seconds, int probe_count) noexcept {
            if (fd == -1) {
                return false;
            }

            int on = enable ? 1 : 0;
            if (::setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&on, sizeof(on)) != 0) {
                return false;
            }

            if (!enable) {
                return true;
            }

            idle_seconds = std::max<int>(1, idle_seconds);
            interval_seconds = std::max<int>(1, interval_seconds);
            probe_count = std::max<int>(1, probe_count);

#if defined(_WIN32)
            tcp_keepalive settings;
            memset(&settings, 0, sizeof(settings));
            settings.onoff = 1;
            settings.keepalivetime = static_cast<ULONG>(idle_seconds) * 1000UL;
            settings.keepaliveinterval = static_cast<ULONG>(interval_seconds) * 1000UL;

            DWORD returned = 0;
            return ::WSAIoctl((SOCKET)fd, SIO_KEEPALIVE_VALS,
                &settings, sizeof(settings),
                NULLPTR, 0,
                &returned, NULLPTR, NULLPTR) == 0;
#else
#if defined(TCP_KEEPIDLE)
            ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&idle_seconds, sizeof(idle_seconds));
#elif defined(TCP_KEEPALIVE)
            ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, (char*)&idle_seconds, sizeof(idle_seconds));
#endif

#if defined(TCP_KEEPINTVL)
            ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (char*)&interval_seconds, sizeof(interval_seconds));
#endif

#if defined(TCP_KEEPCNT)
            ::setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (char*)&probe_count, sizeof(probe_count));
#endif

            return true;
#endif
        }

        /**
         * @brief Applies send/receive socket buffer sizes when values are provided.
         */
        bool Socket::SetWindowSizeIfNotZero(int sockfd, int cwnd, int rwnd) noexcept {
            if (sockfd == -1) {
                return false;
            }

            if (cwnd < 1 && rwnd < 1) {
                return true;
            }

            bool any = false;
            if (cwnd > 0) {
                any |= setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char*)&cwnd, sizeof(cwnd)) > -1;  
            }

            if (rwnd > 0) {
                any |= setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&rwnd, sizeof(rwnd)) > -1;  
            }
            
            return any;
        }
        
        /**
         * @brief Applies default low-level options to a native socket handle.
         */
        void Socket::AdjustDefaultSocketOptional(int sockfd, bool in4) noexcept {
            if (sockfd != -1) {
                uint8_t tos = SOCKET_RESTRICTIONS_.IP_TOS_DEFAULT_FLASH ? IPTOS_LOWDELAY : 0;
                if (in4) {
                    if (SOCKET_RESTRICTIONS_.IP_TOS_ON) {
#if defined(_MACOS)
                        ::setsockopt(sockfd, IPPROTO_IP, IP_TOS, (char*)&tos, sizeof(tos));
#else
                        ::setsockopt(sockfd, SOL_IP, IP_TOS, (char*)&tos, sizeof(tos));
#endif
                    }

#if defined(IP_DONTFRAGMENT)
                    int dont_frag = IP_PMTUDISC_NOT_SET; // IP_PMTUDISC
                    ::setsockopt(sockfd, IPPROTO_IP, IP_DONTFRAGMENT, (char*)&dont_frag, sizeof(dont_frag));
#elif defined(IP_PMTUDISC_WANT)
                    int dont_frag = IP_PMTUDISC_WANT;
                    ::setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
                }
                else {
                    // linux-user: Add missing IP_TOS, IPV6_TCLASS and IPV6_RECVTCLASS sockopts
                    // QEMU:
                    // https://patchwork.kernel.org/project/qemu-devel/patch/20170311195906.GA13187@ls3530.fritz.box/
#if defined(IPV6_TCLASS)
                    if (SOCKET_RESTRICTIONS_.IPV6_TCLASS_ON) {
                        ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, (char*)&tos, sizeof(tos)); /* SOL_IPV6 */
                    }
#endif

#if defined(IPV6_MTU_DISCOVER) && defined(IPV6_PMTUDISC_WANT)
                    int dont_frag = IPV6_PMTUDISC_WANT;
                    ::setsockopt(sockfd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &dont_frag, sizeof(dont_frag));
#endif
                }

#if defined(SO_NOSIGPIPE)
                int no_sigpipe = 1;
                ::setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif

                /**
                 * @brief Keepalive rationale for long-idle forwarded sessions.
                 */
                // User-space forwarders such as rinetd often reclaim idle TCP
                // sessions earlier than NAT devices. Keepalive prevents VMUX
                // sub-links from being silently dropped while the mux is idle.
                SetKeepAlive(sockfd, true);
            }
        }

        // https://source.android.google.cn/devices/tech/debug/native-crash?hl=zh-cn
        // https://android.googlesource.com/platform/bionic/+/master/docs/fdsan.md
        /**
         * @brief Gracefully closes a TCP socket.
         */
        bool Socket::Closesocket(const boost::asio::ip::tcp::socket& socket) noexcept {
            boost::asio::ip::tcp::socket& s = constantof(socket);
            if (s.is_open()) {
                boost::system::error_code ec;
                try {
                    s.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
                }
                catch (const std::exception&) {}

                try {
                    s.close(ec);
                    return ec == boost::system::errc::success;
                }
                catch (const std::exception&) {}
            }
            return false;
        }

        /**
         * @brief Closes a TCP acceptor.
         */
        bool Socket::Closesocket(const boost::asio::ip::tcp::acceptor& acceptor) noexcept {
            boost::asio::ip::tcp::acceptor& s = constantof(acceptor);
            if (s.is_open()) {
                boost::system::error_code ec;
                try {
                    s.close(ec);
                    return ec == boost::system::errc::success;
                }
                catch (const std::exception&) {}
            }
            return false;
        }

        /**
         * @brief Closes a UDP socket.
         */
        bool Socket::Closesocket(const boost::asio::ip::udp::socket& socket) noexcept {
            boost::asio::ip::udp::socket& s = constantof(socket);
            if (s.is_open()) {
                boost::system::error_code ec;
                try {
                    s.close(ec);
                    return ec == boost::system::errc::success;
                }
                catch (const std::exception&) {}
            }
            return false;
        }

        /**
         * @brief Returns native handle of an open TCP socket.
         */
        int Socket::GetHandle(const boost::asio::ip::tcp::socket& socket) noexcept {
            boost::asio::ip::tcp::socket& s = constantof(socket);
            if (!socket.is_open()) {
                return -1;
            }

            try {
                int ndfs = s.native_handle();
                return ndfs;
            }
            catch (const std::exception&) {
                return -1;
            }
        }

        /**
         * @brief Returns native handle of an open TCP acceptor.
         */
        int Socket::GetHandle(const boost::asio::ip::tcp::acceptor& acceptor) noexcept {
            boost::asio::ip::tcp::acceptor& s = constantof(acceptor);
            if (!s.is_open()) {
                return -1;
            }

            try {
                int ndfs = s.native_handle();
                return ndfs;
            }
            catch (const std::exception&) {
                return -1;
            }
        }

        /**
         * @brief Returns native handle of an open UDP socket.
         */
        int Socket::GetHandle(const boost::asio::ip::udp::socket& socket) noexcept {
            boost::asio::ip::udp::socket& s = constantof(socket);
            if (!s.is_open()) {
                return -1;
            }

            try {
                int ndfs = s.native_handle();
                return ndfs;
            }
            catch (const std::exception&) {
                return -1;
            }
        }

        /**
         * @brief Starts loopback accept recursion for shared-pointer acceptor API.
         */
        bool Socket::AcceptLoopbackAsync(
            const AsioTcpAcceptor&                                  acceptor,
            const AcceptLoopbackCallback&                           callback,
            const GetContextCallback&                               context) noexcept {
            if (!acceptor || !acceptor->is_open()) {
                return false;
            }

            if (!callback) {
                Closesocket(acceptor);
                return false;
            }

            const AcceptLoopbackCallback cb = 
                [acceptor, callback](const AsioContext& context, const AsioTcpSocket& socket) noexcept {
                    return callback(context, socket);
                };

            bool opened = Socket::AcceptLoopbackAsync(*acceptor, cb, context);
            if (opened) {
                return true;
            }
            else {
                Closesocket(acceptor);
                return false;
            }
        }

        /**
         * @brief Internal accept loop implementation for callback and scheduler modes.
         */
        static bool SocketAcceptLoopbackAsync(
            const boost::asio::ip::tcp::acceptor&                   acceptor,
            const Socket::AcceptLoopbackCallback&                   callback,
            const Socket::GetContextCallback&                       context,
            const Socket::AcceptLoopbackSchedulerCallback&          scheduler) noexcept {
            if (!acceptor.is_open()) {
                return false;
            }

            Socket::AsioStrandPtr strand_;
            Socket::AsioContext context_;
            if (scheduler) {
                context_ = ppp::threading::Executors::GetScheduler();
                if (context_) {
                    strand_ = make_shared_object<ppp::threading::Executors::Strand>(boost::asio::make_strand(*context_));
                }

                if (NULLPTR == strand_) {
                    context_ = ppp::threading::Executors::GetExecutor();
                }
            }
            else {
                context_ = context ? context() : ppp::threading::Executors::GetExecutor();
            }

            if (!context_) {
                return false;
            }

            boost::asio::ip::tcp::acceptor* const acceptor_ = addressof(acceptor);
            const Socket::AsioTcpSocket           socket_   = strand_ ? make_shared_object<boost::asio::ip::tcp::socket>(*strand_) : make_shared_object<boost::asio::ip::tcp::socket>(*context_);
            if (NULLPTR == socket_) {
                return false;
            }

            boost::asio::post(acceptor_->get_executor(),
                [context_, acceptor_, callback, socket_, context, scheduler, strand_]() noexcept {
                    acceptor_->async_accept(*socket_,
                        [context_, acceptor_, callback, socket_, context, scheduler, strand_](boost::system::error_code ec) noexcept {
                            if (ec == boost::system::errc::operation_canceled) {
                                return;
                            }

                            /**
                             * @brief Complex accept path with socket setup and delegation.
                             */
                            bool success = false;
                            do { /* boost::system::errc::connection_aborted */
                                if (ec) { /* ECONNABORTED */
                                    break;
                                }

                                boost::asio::ip::tcp::endpoint lcoalEP = socket_->local_endpoint(ec);
                                if (ec) {
                                    break;
                                }

                                socket_->set_option(boost::asio::ip::tcp::no_delay(true), ec);
                                if (ec) {
                                    break;
                                }

                                int handle_ = socket_->native_handle();
                                boost::asio::ip::address lcoalIP = lcoalEP.address();

                                Socket::AdjustDefaultSocketOptional(handle_, lcoalIP.is_v4());
                                Socket::SetTypeOfService(handle_);
                                Socket::SetSignalPipeline(handle_, false);

                                /* Accept Socket?? */
                                if (scheduler) {
                                    success = scheduler(context_, strand_, socket_);
                                }
                                else {
                                    success = callback(context_, socket_);
                                }
                            } while (false);

                            // The accepted Socket should be closed if it is rejected or fails to process,
                            // But it should not be executed on the Context worker thread that does not belong to it. 
                            // It needs to be delegated to the past processing for better security and programming paradigm.
                            if (!success) {
                                boost::asio::post(*context_, 
                                    [context_, socket_]() noexcept {
                                        Socket::Closesocket(socket_);
                                    });
                            }

                            // Unable to continue to initiate the next asynchronous task accepting a Socket from an arbitrary 
                            // Network client needs to be delegated to the receiver for close processing on the context.
                            SocketAcceptLoopbackAsync(*acceptor_, callback, context, scheduler);
                        });
                });
            return true;
        }

        /**
         * @brief Starts loopback accept recursion using simple callback mode.
         */
        bool Socket::AcceptLoopbackAsync(
            const boost::asio::ip::tcp::acceptor&                   acceptor,
            const AcceptLoopbackCallback&                           callback,
            const GetContextCallback&                               context) noexcept {
            if (!callback) {
                return false;
            }

            AcceptLoopbackSchedulerCallback ac = NULLPTR;
            return SocketAcceptLoopbackAsync(acceptor, callback, context, ac);
        }

        /**
         * @brief Starts loopback accept recursion using scheduler callback mode.
         */
        bool Socket::AcceptLoopbackSchedulerAsync(const boost::asio::ip::tcp::acceptor& acceptor, const AcceptLoopbackSchedulerCallback& callback) noexcept {
            if (!callback) {
                return false;
            }

            return SocketAcceptLoopbackAsync(acceptor, NULLPTR, NULLPTR, callback);
        }

        /**
         * @brief Opens, configures, binds, and listens on a TCP acceptor.
         */
        bool Socket::OpenAcceptor(
            const boost::asio::ip::tcp::acceptor&                   acceptor,
            const boost::asio::ip::address&                         listenIP,
            int                                                     listenPort,
            int                                                     backlog,
            bool                                                    fastOpen,
            bool                                                    noDelay) noexcept {
            typedef ppp::net::IPEndPoint IPEndPoint;

            if (listenPort < IPEndPoint::MinPort || listenPort > IPEndPoint::MaxPort) {
                listenPort = IPEndPoint::MinPort;
            }

            boost::asio::ip::address address_ = listenIP;
            if (!address_.is_unspecified()) {
                if (IPEndPoint::IsInvalid(address_)) {
                    address_ = boost::asio::ip::address_v6::any();
                }
            }

            boost::asio::ip::tcp::acceptor& acceptor_ = constantof(acceptor);
            if (acceptor_.is_open()) {
                return false;
            }

            boost::system::error_code ec;
            if (address_.is_v4()) {
                acceptor_.open(boost::asio::ip::tcp::v4(), ec);
            }
            else {
                acceptor_.open(boost::asio::ip::tcp::v6(), ec);
            }

            if (ec) {
                return false;
            }

            int handle = acceptor_.native_handle();
            ppp::net::Socket::AdjustDefaultSocketOptional(handle, address_.is_v4());
            ppp::net::Socket::SetTypeOfService(handle);
            ppp::net::Socket::SetSignalPipeline(handle, false);
            ppp::net::Socket::ReuseSocketAddress(handle, true);

            acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
            if (ec) {
                return false;
            }

            acceptor_.set_option(boost::asio::ip::tcp::no_delay(noDelay), ec);
            acceptor_.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(fastOpen), ec);

            acceptor_.bind(boost::asio::ip::tcp::endpoint(address_, listenPort), ec);
            if (ec) {
                if (listenPort != IPEndPoint::MinPort) {
                    acceptor_.bind(boost::asio::ip::tcp::endpoint(address_, IPEndPoint::MinPort), ec);
                    if (ec) {
                        return false;
                    }
                }
            }

            if (backlog < 1) {
                backlog = PPP_LISTEN_BACKLOG;
            }

            acceptor_.listen(backlog, ec);
            if (ec) {
                return false;
            }

            return true;
        }

        /**
         * @brief Opens/configures/binds a UDP socket for listening.
         */
        bool Socket::OpenSocket(
            const boost::asio::ip::udp::socket&                     socket,
            const boost::asio::ip::address&                         listenIP,
            int                                                     listenPort,
            bool                                                    opened) noexcept {
            typedef ppp::net::IPEndPoint IPEndPoint;

            if (listenPort < IPEndPoint::MinPort || listenPort > IPEndPoint::MaxPort) {
                listenPort = IPEndPoint::MinPort;
            }

            boost::asio::ip::address address_ = listenIP;
            if (!address_.is_unspecified()) {
                if (IPEndPoint::IsInvalid(address_)) {
                    address_ = boost::asio::ip::address_v6::any();
                }
            }

            boost::system::error_code ec;
            boost::asio::ip::udp::socket& socket_ = constantof(socket);
            if (!opened) {
                if (socket_.is_open()) {
                    return false;
                }

                if (address_.is_v4()) {
                    socket_.open(boost::asio::ip::udp::v4(), ec);
                }
                else {
                    socket_.open(boost::asio::ip::udp::v6(), ec);
                }

                if (ec) {
                    return false;
                }
            }

            int handle = socket_.native_handle();
            ppp::net::Socket::AdjustDefaultSocketOptional(handle, address_.is_v4());
            ppp::net::Socket::SetTypeOfService(handle);
            ppp::net::Socket::SetSignalPipeline(handle, false);
            ppp::net::Socket::ReuseSocketAddress(handle, true);

            socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true), ec);
            if (ec) {
                return false;
            }

            socket_.bind(boost::asio::ip::udp::endpoint(address_, listenPort), ec);
            if (ec) {
                if (listenPort != IPEndPoint::MinPort) {
                    socket_.bind(boost::asio::ip::udp::endpoint(address_, IPEndPoint::MinPort), ec);
                    if (ec) {
                        return false;
                    }
                }
            }
            return true;
        }

        /**
         * @brief Applies default and transport-specific options to a TCP socket.
         */
        void Socket::AdjustSocketOptional(const boost::asio::ip::tcp::socket& socket, bool in4, bool fastOpen, bool noDealy) noexcept {
            boost::asio::ip::tcp::socket& s = constantof(socket);
            if (s.is_open()) {
                int handle = s.native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, in4);
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);

                boost::system::error_code ec;
                s.set_option(boost::asio::ip::tcp::no_delay(noDealy), ec);
                s.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(fastOpen), ec);
            }
        }

        /**
         * @brief Applies default options to a UDP socket.
         */
        void Socket::AdjustSocketOptional(const boost::asio::ip::udp::socket& socket, bool in4) noexcept {
            boost::asio::ip::udp::socket& s = constantof(socket);
            if (s.is_open()) {
                int handle = s.native_handle();
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, in4);
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);
            }
        }

        /**
         * @brief Toggles non-blocking mode on native descriptor.
         */
        bool Socket::SetNonblocking(int fd, bool nonblocking) noexcept {
            if (fd == -1) {
                return false;
            }

#if defined(_WIN32)
            u_long flags = nonblocking ? 1 : 0;
            return ioctlsocket(fd, FIONBIO, &flags) == 0;
#else
            int flags = fcntl(fd, F_GETFD, 0);
            if (flags == -1) {
                return false;
            }

            if (nonblocking) {
                flags |= O_NONBLOCK;
            }
            else {
                flags &= ~O_NONBLOCK;
            }

            int err = fcntl(fd, F_SETFL, flags);
            return err == 0;
#endif
        }

        /**
         * @brief Cancels and closes a POSIX stream descriptor.
         */
        bool Socket::Closestream(boost::asio::posix::stream_descriptor* stream) noexcept {
            if (NULLPTR == stream) {
                return false;
            }

            boost::system::error_code ec;
            if (stream->is_open()) {
                try {
                    stream->cancel(ec);
                }
                catch (const std::exception&) {}
            }

            try {
                stream->close(ec);
                if (ec == boost::system::errc::success) {
                    return true;
                }
            }
            catch (const std::exception&) {}
            return false;
        }

        /**
         * @brief Applies default options to an already-open TCP socket.
         */
        bool Socket::AdjustDefaultSocketOptional(boost::asio::ip::tcp::socket& socket, bool turbo) noexcept {
            bool opened = socket.is_open();
            if (!opened) {
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::tcp::endpoint localEP = socket.local_endpoint(ec);
            if (ec) {
                return false;
            }
            else {
                socket.set_option(boost::asio::ip::tcp::no_delay(turbo), ec);
                if (ec) {
                    return false;
                }
            }

            int handle = socket.native_handle();
            boost::asio::ip::address localIP = localEP.address();

            ppp::net::Socket::AdjustDefaultSocketOptional(handle, localIP.is_v4());
            ppp::net::Socket::SetTypeOfService(handle);
            ppp::net::Socket::SetSignalPipeline(handle, false);
            return true;
        }

        /**
         * @brief Determines local IPv4 source address for a destination.
         */
        uint32_t Socket::GetBestInterfaceIP(uint32_t destination) noexcept {
            int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock_fd == -1) {
                return IPEndPoint::AnyAddress;
            }

            struct sockaddr_in remote_endpoint;
            ::memset(&remote_endpoint, 0, sizeof(remote_endpoint));

            remote_endpoint.sin_family = AF_INET;
            remote_endpoint.sin_port = htons(1); 
            remote_endpoint.sin_addr.s_addr = destination;

            Socket::SetNonblocking(sock_fd, true);
            ::connect(sock_fd, reinterpret_cast<struct sockaddr*>(&remote_endpoint), sizeof(remote_endpoint));

            struct sockaddr_in local_endpoint;
            socklen_t local_endpoint_size = sizeof(local_endpoint);

            int err = ::getsockname(sock_fd, reinterpret_cast<struct sockaddr*>(&local_endpoint), &local_endpoint_size);
            Socket::Closesocket(sock_fd);

            if (err < 0) {
                return IPEndPoint::AnyAddress;
            }
            elif(local_endpoint.sin_family != AF_INET) {
                return IPEndPoint::AnyAddress;
            }
            else {
                return local_endpoint.sin_addr.s_addr;
            }
        }
    }
}
