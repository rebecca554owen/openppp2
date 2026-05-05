#pragma once

#include <atomic>

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
            void                                                                    ArmWatchdog() noexcept;
            void                                                                    OnWatchdogTick() noexcept;

        private:
            std::shared_ptr<boost::asio::ip::tcp::acceptor>                         server_;
            std::shared_ptr<boost::asio::io_context>                                context_ = NULLPTR;
            std::shared_ptr<boost::asio::steady_timer>                              watchdog_;
            std::atomic<uint64_t>                                                   last_event_tick_ = { 0 };
            std::atomic<uint64_t>                                                   pending_since_tick_ = { 0 };
            std::atomic<bool>                                                       disposed_ = { false };
            bool                                                                    in_      = false;
        };
    }
}