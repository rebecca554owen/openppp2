#include <algorithm>

#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/Socket.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/threading/Executors.h>
#include <common/unix/net/UnixSocketAcceptor.h>

namespace ppp
{
    namespace net
    {
        UnixSocketAcceptor::UnixSocketAcceptor() noexcept
            : server_(NULLPTR)
            , context_(ppp::threading::Executors::GetDefault())
            , accept_parallel_(1)
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
            for (boost::asio::ip::address& bind_ip : bind_ips) 
            {
                any = Socket::OpenAcceptor(*server_, bind_ip, localPort, backlog, false, false);
                if (any)
                {
                    in_ = bind_ip.is_v4();
                    break;
                }

                server_->close(ec);
                if (ec)
                {
                    return false;
                }
            }

            accept_parallel_ = 1;
            for (int i = 0; any && i < accept_parallel_; i++)
            {
                any = Next();
            }
            return any;
        }

        void UnixSocketAcceptor::Dispose() noexcept
        {
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
            if (accept_pending_.load(std::memory_order_acquire) >= accept_parallel_)
            {
                return true;
            }

            std::shared_ptr<boost::asio::ip::tcp::acceptor> server = server_;
            if (NULLPTR == server)
            {
                ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed: server missing");
                return false;
            }
            else if (!server->is_open())
            {
                ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed: server closed");
                return false;
            }

            ppp::telemetry::Count("socket_acceptor.next.success", 1);

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

            std::shared_ptr<SocketAcceptor> self = shared_from_this();
            {
                std::lock_guard<std::mutex> scope(accept_mutex_);
                if (!server->is_open())
                {
                    ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                    ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed: server closed");
                    return false;
                }

                if (accept_pending_.load(std::memory_order_acquire) >= accept_parallel_)
                {
                    return true;
                }

                accept_pending_.fetch_add(1, std::memory_order_acq_rel);
                int pending_after = accept_pending_.load(std::memory_order_acquire);
                ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept scheduled, pending=%d fd=%d", pending_after, server->native_handle());
                server->async_accept(*socket,
                    [self, this, server, socket](boost::system::error_code ec) noexcept
                    {
                        int pending_before = accept_pending_.load(std::memory_order_acquire);
                        accept_pending_.fetch_sub(1, std::memory_order_acq_rel);
                        int pending_after = accept_pending_.load(std::memory_order_acquire);
                        ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept callback, ec=%d pending_before=%d pending_after=%d fd=%d", ec.value(), pending_before, pending_after, server->native_handle());
                        if (ec == boost::system::errc::operation_canceled) /* WSAWaitForMultipleEvents */
                        {
                            ppp::telemetry::Count("socket_acceptor.accept.canceled", 1);
                            return;
                        }
                        else if (ec)
                        {
                            ppp::telemetry::Count("socket_acceptor.accept.error", 1);
                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "socket_acceptor", "unix accept failed error=%d message=%s pending=%d fd=%d", ec.value(), ec.message().c_str(), pending_after, server->native_handle());
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

                        if (!Next())
                        {
                            ppp::telemetry::Count("socket_acceptor.next.fail", 1);
                            ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept next failed after accept, pending=%d fd=%d", pending_after, server->native_handle());
                        }

                        if (sockfd != -1)
                        {
                            ppp::telemetry::Count("socket_acceptor.accept.raw", 1);
                            AcceptSocketEventArgs e = { sockfd };
                            OnAcceptSocket(e);
                        }
                        else
                        {
                            ppp::telemetry::Log(ppp::telemetry::Level::kDebug, "socket_acceptor", "unix accept sockfd=-1 after release, pending=%d fd=%d", pending_after, server->native_handle());
                        }
                    });
            }
            return true;
        }

        void UnixSocketAcceptor::Finalize() noexcept
        {
            std::shared_ptr<boost::asio::ip::tcp::acceptor> server = std::move(server_);
            if (NULLPTR != server)
            {
                Socket::Closesocket(server);
            }
            context_.reset();
        }
    }
}