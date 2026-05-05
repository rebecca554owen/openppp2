#pragma once

#include <atomic>
#include <mutex>

#include <ppp/net/SocketAcceptor.h>

namespace ppp
{
    namespace net
    {
        class UnixSocketAcceptor final : public ppp::net::SocketAcceptor
        {
        public:
            UnixSocketAcceptor() noexcept;
            virtual ~UnixSocketAcceptor() noexcept;

        public:
            virtual bool                                                            IsOpen() noexcept;
            virtual bool                                                            Open(const char* localIP, int localPort, int backlog) noexcept;
            virtual void                                                            Dispose() noexcept;
            virtual int                                                             GetHandle() noexcept;

        private:
            bool                                                                    Next() noexcept;
            void                                                                    Finalize() noexcept;

        private:
            std::shared_ptr<boost::asio::ip::tcp::acceptor>                         server_;
            std::shared_ptr<boost::asio::io_context>                                context_ = NULLPTR;
            std::mutex                                                              accept_mutex_;
            std::atomic<int>                                                        accept_pending_ = { 0 };
            int                                                                     accept_parallel_ = 1;
            bool                                                                    in_      = false;
        };
    }
}