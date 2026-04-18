#pragma once

#include <ppp/threading/Timer.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file InternetControlMessageProtocol.h
 * @brief Declares asynchronous ICMP echo and translation helpers.
 */

namespace ppp {
    namespace net {
        namespace asio {
            /** @brief Forward declaration for per-request ICMP echo async context. */
            class InternetControlMessageProtocol_EchoAsynchronousContext;

            /**
             * @brief ICMP processing helper for asynchronous echo and error generation.
             *
             * The class sends raw ICMP echo probes, tracks in-flight requests, and reports
             * translated ICMP responses through the abstract output interface.
             */
            class InternetControlMessageProtocol : public std::enable_shared_from_this<InternetControlMessageProtocol> {
                friend class                                                    InternetControlMessageProtocol_EchoAsynchronousContext;

            public:
                /** @brief Timer utility used for request timeout handling. */
                typedef ppp::threading::Timer                                   Timer;
                /** @brief Timeout callback functor type. */
                typedef Timer::TimeoutEventHandler                              TimeoutEventHandler;
                /** @brief Shared timeout callback pointer type. */
                typedef Timer::TimeoutEventHandlerPtr                           TimeoutEventHandlerPtr;
                /** @brief Active timeout callback table indexed by context pointer. */
                typedef ppp::unordered_map<void*, TimeoutEventHandlerPtr>       TimeoutEventHandlerTable;
                /** @brief IPv4 packet frame type alias. */
                typedef ppp::net::packet::IPFrame                               IPFrame;
                /** @brief ICMP frame type alias. */
                typedef ppp::net::packet::IcmpFrame                             IcmpFrame;
                /** @brief Endpoint type used for output forwarding. */
                typedef ppp::net::IPEndPoint                                    IPEndPoint;

            public:
                /** @brief Maximum asynchronous ICMP wait time in milliseconds. */
                static constexpr int MAX_ICMP_TIMEOUT                           = 3000;

            public:
                /** @brief Shared allocator used for packet/frame materialization. */
                const std::shared_ptr<ppp::threading::BufferswapAllocator>      BufferAllocator;

            public:
                /** @brief Initializes ICMP protocol helper with allocator and executor context. */
                InternetControlMessageProtocol(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<boost::asio::io_context>& context) noexcept;
                /** @brief Finalizes state and releases all pending timeout handlers. */
                virtual ~InternetControlMessageProtocol() noexcept;

            public:
                /** @brief Returns the associated IO execution context. */
                std::shared_ptr<boost::asio::io_context>                        GetContext() noexcept;
                /** @brief Returns a shared reference to this protocol instance. */
                std::shared_ptr<InternetControlMessageProtocol>                 GetReference() noexcept;

            public:
                /** @brief Sends ICMP echo asynchronously and forwards translated response. */
                virtual bool                                                    Echo(
                    const std::shared_ptr<IPFrame>&                             packet,
                    const std::shared_ptr<IcmpFrame>&                           frame,
                    const IPEndPoint&                                           destinationEP) noexcept;
                /** @brief Asynchronously disposes protocol state on executor thread. */
                virtual void                                                    Dispose() noexcept;

            public:
                /** @brief Builds ICMP echo-reply packet from original request metadata. */
                static std::shared_ptr<IPFrame>                                 ER(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, int ttl, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;
                /** @brief Builds ICMP time-exceeded packet that embeds original IP payload. */
                static std::shared_ptr<IPFrame>                                 TE(const std::shared_ptr<IPFrame>& packet, const std::shared_ptr<IcmpFrame>& frame, UInt32 source, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept;

            protected:
                /** @brief Emits a generated packet to target endpoint via implementation backend. */
                virtual bool                                                    Output(
                    const IPFrame*                                              packet,
                    const IPEndPoint&                                           destinationEP) noexcept = 0;

            private:
                /** @brief Marks disposed and clears all registered timeout callbacks. */
                void                                                            Finalize() noexcept;

            private:
                /** @brief Indicates whether this instance has been disposed. */
                bool                                                            disposed_ = false;
                /** @brief Reusable endpoint receiving raw ICMP responses. */
                boost::asio::ip::udp::endpoint                                  ep_;
                /** @brief Shared receive buffer used by asynchronous response parsing. */
                std::shared_ptr<Byte>                                           buffer_;
                /** @brief IO executor used for posting state transitions. */
                std::shared_ptr<boost::asio::io_context>                        executor_;
                /** @brief Active timeout callbacks for currently tracked echo contexts. */
                TimeoutEventHandlerTable                                        timeouts_;
            };
        }
    }
}
