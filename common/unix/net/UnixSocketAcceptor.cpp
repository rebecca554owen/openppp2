#include <chrono>

#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/threading/Executors.h>
#include <common/unix/net/UnixSocketAcceptor.h>

/**
 * @brief Interval between watchdog ticks. Runs on the same io_context as the acceptor.
 */
static constexpr int PPP_UNIX_ACCEPTOR_WATCHDOG_INTERVAL_MS = 5000;

/**
 * @brief Maximum silence window between accept callbacks before the watchdog
 *        treats the pending async_accept as stalled and cancels it to force
 *        the kqueue reactor to re-register the readable event.
 *
 * On macOS we observe the boost.asio kqueue reactor silently dropping readable
 * notifications for the listener fd after roughly 60s under load, even though
 * the underlying socket remains open and the io_context is healthy. Cancelling
 * the pending async_accept drives the handler to run with operation_aborted
 * which triggers a fresh Next() that re-arms the event.
 */
static constexpr int PPP_UNIX_ACCEPTOR_STALL_THRESHOLD_MS = 15000;

namespace ppp
{
    namespace net
    {
        /** @brief Returns the current steady clock in milliseconds since process start. */
        static uint64_t UnixAcceptor_NowMs() noexcept
        {
            return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }

        UnixSocketAcceptor::UnixSocketAcceptor() noexcept
            : server_(NULLPTR)
            , context_(ppp::threading::Executors::GetDefault())
            , in_(false)
        {

        }

        UnixSocketAcceptor::~UnixSocketAcceptor() noexcept
        {
            Finalize();
        }

        bool UnixSocketAcceptor::IsOpen() noexcept
        {
            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULLPTR == context)
            {
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::acceptor> server = server_;
            if (NULLPTR == server)
            {
                return false;
            }

            return server->is_open();
        }

        int UnixSocketAcceptor::GetHandle() noexcept
        {
            std::shared_ptr<boost::asio::ip::tcp::acceptor> server = server_;
            if (NULLPTR == server)
            {
                return -1;
            }

            return server->native_handle();
        }

        bool UnixSocketAcceptor::Open(const char* localIP, int localPort, int backlog) noexcept
        {
            if (localPort < IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort)
            {
                return false;
            }

            if (NULLPTR == localIP || *localIP == '\x0')
            {
                return false;
            }

            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULLPTR == context)
            {
                return false;
            }

            if (NULLPTR != server_)
            {
                return false;
            }

            if (backlog < 1)
            {
                backlog = PPP_LISTEN_BACKLOG;
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(localIP, ec);
            if (ec)
            {
                return false;
            }

            server_ = make_shared_object<boost::asio::ip::tcp::acceptor>(*context);
            if (NULLPTR == server_)
            {
                return false;
            }

            bool any = false;
            boost::asio::ip::address bind_ips[] = { address, boost::asio::ip::address_v4::any(), boost::asio::ip::address_v6::any() };
            boost::asio::ip::address bound_ip;
            for (boost::asio::ip::address& bind_ip : bind_ips)
            {
                any = Socket::OpenAcceptor(*server_, bind_ip, localPort, backlog, false, false);
                if (any)
                {
                    in_ = bind_ip.is_v4();
                    bound_ip = bind_ip;
                    break;
                }

                server_->close(ec);
                if (ec)
                {
                    return false;
                }
            }

            if (!any)
            {
                return false;
            }

            /**
             * @brief Remember the bind parameters so the watchdog can rebuild the
             *        listener with identical bind() arguments when the kqueue reactor
             *        wedges the fd in a non-reportable state.
             */
            bound_address_ = bound_ip;
            bound_port_ = localPort;
            bound_backlog_ = backlog;

            uint64_t now_ms = UnixAcceptor_NowMs();
            last_event_tick_.store(now_ms, std::memory_order_release);
            pending_since_tick_.store(0, std::memory_order_release);

            if (!Next())
            {
                return false;
            }

            ArmWatchdog();
            return true;
        }

        void UnixSocketAcceptor::Dispose() noexcept
        {
            disposed_.store(true, std::memory_order_release);

            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULLPTR != context)
            {
                auto self = shared_from_this();
                boost::asio::post(*context,
                    [self, this, context]() noexcept
                    {
                        Finalize();
                    });
            }
        }

        bool UnixSocketAcceptor::Next() noexcept
        {
            std::shared_ptr<boost::asio::ip::tcp::acceptor> server = server_;
            if (NULLPTR == server)
            {
                ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed: server missing");
                return false;
            }

            if (!server->is_open())
            {
                ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed: server closed");
                return false;
            }

            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULLPTR == context)
            {
                ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed: context missing");
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*context);
            if (NULLPTR == socket)
            {
                ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed: socket allocation failed");
                return false;
            }

            ppp::telemetry::Count("socket_acceptor.next.success", 1);
            ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept scheduled fd=%d", server->native_handle());

            pending_since_tick_.store(UnixAcceptor_NowMs(), std::memory_order_release);

            std::shared_ptr<SocketAcceptor> self = shared_from_this();
            server->async_accept(*socket,
                [self, this, server, socket](boost::system::error_code ec) noexcept
                {
                    uint64_t now_ms = UnixAcceptor_NowMs();
                    last_event_tick_.store(now_ms, std::memory_order_release);
                    pending_since_tick_.store(0, std::memory_order_release);

                    ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept callback ec=%d fd=%d", ec.value(), server->native_handle());
                    if (ec == boost::system::errc::operation_canceled) /* WSAWaitForMultipleEvents */
                    {
                        ppp::telemetry::Count("socket_acceptor.accept.canceled", 1);
                        /**
                         * @brief Watchdog-driven cancels intentionally re-arm the loop so the
                         *        kqueue reactor re-registers the readable event. Only skip the
                         *        re-arm when the acceptor itself is being disposed.
                         */
                        if (!disposed_.load(std::memory_order_acquire) && server->is_open())
                        {
                            if (!Next())
                            {
                                ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed after canceled");
                            }
                        }
                        return;
                    }
                    else if (ec)
                    {
                        ppp::telemetry::Count("socket_acceptor.accept.error", 1);
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept failed error=%d message=%s fd=%d", ec.value(), ec.message().c_str(), server->native_handle());
                        if (!Next())
                        {
                            ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                            ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed after error");
                        }
                        return;
                    }

                /* This function always fails with operation_not_supported when used on Windows versions prior to Windows 8.1. */
#if defined(_WIN32)
#pragma warning(push)
#pragma warning(disable: 4996)
#endif
                    int sockfd = socket->release(ec); // os < microsoft windows 8.1 is not supported.

#if defined(_WIN32)
#pragma warning(pop)
#endif
                    if (ec)
                    {
                        ppp::telemetry::Count("socket_acceptor.accept.release_error", 1);
                        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept release failed error=%d message=%s", ec.value(), ec.message().c_str());
                        sockfd = -1;
                    }
                    else
                    {
                        Socket::AdjustDefaultSocketOptional(sockfd, in_);
                        Socket::SetTypeOfService(sockfd);
                        Socket::SetSignalPipeline(sockfd, false);
                        Socket::ReuseSocketAddress(sockfd, true);
                    }

                    Socket::Closesocket(socket);

                    if (!Next())
                    {
                        ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                        ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed after accept fd=%d", server->native_handle());
                    }

                    if (sockfd != -1)
                    {
                        ppp::telemetry::Count("socket_acceptor.accept.raw", 1);
                        AcceptSocketEventArgs e = { sockfd };
                        OnAcceptSocket(e);
                    }
                });
            return true;
        }

        void UnixSocketAcceptor::Finalize() noexcept
        {
            disposed_.store(true, std::memory_order_release);

            std::shared_ptr<boost::asio::steady_timer> watchdog = std::move(watchdog_);
            if (NULLPTR != watchdog)
            {
                boost::system::error_code ec;
                watchdog->cancel(ec);
            }

            std::shared_ptr<boost::asio::ip::tcp::acceptor> server = std::move(server_);
            if (NULLPTR != server)
            {
                Socket::Closesocket(server);
            }
            context_.reset();
        }

        void UnixSocketAcceptor::ArmWatchdog() noexcept
        {
            if (disposed_.load(std::memory_order_acquire))
            {
                return;
            }

            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULLPTR == context)
            {
                return;
            }

            std::shared_ptr<boost::asio::steady_timer> watchdog = watchdog_;
            if (NULLPTR == watchdog)
            {
                watchdog = make_shared_object<boost::asio::steady_timer>(*context);
                if (NULLPTR == watchdog)
                {
                    return;
                }
                watchdog_ = watchdog;
            }

            boost::system::error_code ec;
            watchdog->expires_after(std::chrono::milliseconds(PPP_UNIX_ACCEPTOR_WATCHDOG_INTERVAL_MS));
            if (ec)
            {
                return;
            }

            std::shared_ptr<SocketAcceptor> self = shared_from_this();
            watchdog->async_wait(
                [self, this](const boost::system::error_code& ec2) noexcept
                {
                    if (ec2)
                    {
                        return;
                    }
                    OnWatchdogTick();
                });
        }

        void UnixSocketAcceptor::OnWatchdogTick() noexcept
        {
            if (disposed_.load(std::memory_order_acquire))
            {
                return;
            }

            std::shared_ptr<boost::asio::ip::tcp::acceptor> server = server_;
            if (NULLPTR == server || !server->is_open())
            {
                return;
            }

            uint64_t now_ms = UnixAcceptor_NowMs();
            uint64_t pending_since = pending_since_tick_.load(std::memory_order_acquire);
            uint64_t last_event = last_event_tick_.load(std::memory_order_acquire);

            /**
             * @brief Detect two distinct stalls:
             *        1) A pending async_accept has been outstanding for longer than the
             *           stall threshold without any callback.
             *        2) No accept scheduling has happened at all (pending_since=0) for
             *           longer than the stall threshold while the server is still open
             *           -- this is the "silent idle" state that should never persist
             *           when the caller expects continuous accepts.
             */
            bool stalled = false;
            uint64_t silence_ms = 0;
            if (pending_since != 0)
            {
                silence_ms = now_ms - pending_since;
                if (silence_ms >= (uint64_t)PPP_UNIX_ACCEPTOR_STALL_THRESHOLD_MS)
                {
                    stalled = true;
                }
            }
            else if (last_event != 0)
            {
                silence_ms = now_ms - last_event;
                if (silence_ms >= (uint64_t)PPP_UNIX_ACCEPTOR_STALL_THRESHOLD_MS)
                {
                    stalled = true;
                }
            }

            if (stalled)
            {
                ppp::telemetry::Count("socket_acceptor.watchdog.stall", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept watchdog stall detected silence_ms=%llu pending_since=%llu last_event=%llu fd=%d", (unsigned long long)silence_ms, (unsigned long long)pending_since, (unsigned long long)last_event, server->native_handle());

                /**
                 * @brief Observed on macOS: once the kqueue reactor stops reporting
                 *        readable for the listener fd, simply cancelling the pending
                 *        async_accept is NOT enough. The subsequent re-registered
                 *        async_accept never fires either. The only reliable recovery
                 *        is to destroy the current acceptor and create a fresh one
                 *        bound to the same port. SO_REUSEADDR is set on the listener
                 *        so re-binding the same port succeeds.
                 */
                if (!RebuildListener())
                {
                    ppp::telemetry::Count("socket_acceptor.watchdog.rebuild_failed", 1);
                    ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept watchdog rebuild failed, keeping old acceptor");
                }

                /**
                 * @brief Reset so the next tick starts a fresh silence window.
                 */
                last_event_tick_.store(now_ms, std::memory_order_release);
                pending_since_tick_.store(0, std::memory_order_release);
            }

            ArmWatchdog();
        }

        bool UnixSocketAcceptor::RebuildListener() noexcept
        {
            std::shared_ptr<boost::asio::io_context> context = context_;
            if (NULLPTR == context)
            {
                return false;
            }

            if (bound_port_ <= 0)
            {
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::acceptor> new_server = make_shared_object<boost::asio::ip::tcp::acceptor>(*context);
            if (NULLPTR == new_server)
            {
                return false;
            }

            if (!Socket::OpenAcceptor(*new_server, bound_address_, bound_port_, bound_backlog_, false, false))
            {
                boost::system::error_code ec_close;
                new_server->close(ec_close);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept rebuild OpenAcceptor failed port=%d", bound_port_);
                return false;
            }

            boost::system::error_code ec_endpoint;
            boost::asio::ip::tcp::endpoint endpoint = new_server->local_endpoint(ec_endpoint);
            if (ec_endpoint || endpoint.port() != (unsigned short)bound_port_)
            {
                boost::system::error_code ec_close;
                new_server->close(ec_close);
                ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept rebuild bound wrong port expected=%d actual=%d error=%d", bound_port_, ec_endpoint ? -1 : endpoint.port(), ec_endpoint.value());
                return false;
            }

            std::shared_ptr<boost::asio::ip::tcp::acceptor> old_server = server_;
            server_ = new_server;

            if (NULLPTR != old_server)
            {
                Socket::Closesocket(old_server);
            }

            ppp::telemetry::Count("socket_acceptor.watchdog.rebuild", 1);
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept rebuilt listener new_fd=%d port=%d", new_server->native_handle(), bound_port_);

            /**
             * @brief Arm a fresh async_accept on the new listener. Without this the
             *        rebuilt acceptor never pumps the accept loop again.
             */
            if (!Next())
            {
                ppp::telemetry::Count("socket_acceptor.watchdog.next_after_rebuild_failed", 1);
                return false;
            }

            return true;
        }
    }
}
