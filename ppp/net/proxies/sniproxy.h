/**
 * @file sniproxy.h
 * @brief SNI proxy: inspects TLS SNI or HTTP Host header and forwards to target.
 */

#pragma once

#include <ppp/stdafx.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace net {
        namespace proxies {

            /**
             * @brief SNI proxy class.
             *
             * Detects whether the incoming connection is TLS (with SNI) or HTTP (with Host header)
             * and forwards the stream to the appropriate upstream server.
             */
            class sniproxy final : public std::enable_shared_from_this<sniproxy> {
                typedef ppp::io::MemoryStream                                       MemoryStream;
                typedef ppp::threading::Timer                                       Timer;
                typedef boost::asio::strand<boost::asio::io_context::executor_type> Strand;
                typedef std::lock_guard<std::mutex>                                 SynchronizedObjectScope;

#pragma pack(push, 1)
                /**
                 * @brief TLS record header (packed).
                 */
                struct tls_hdr {                                                    // POD struct for TLS record header
                    Byte                                                            Content_Type = 0;   ///< 0x16 for Handshake
                    UInt16                                                          Version = 0;        ///< TLS version (network order)
                    UInt16                                                          Length = 0;         ///< payload length (network order)
                };
#pragma pack(pop)

                static constexpr int                                                FORWARD_MSS = 65536;   ///< Max segment size for forwarding

            public:
                /**
                 * @brief Constructor.
                 * @param cdn CDN flag.
                 * @param configuration Application configuration.
                 * @param context IO context.
                 * @param socket Client socket.
                 */
                sniproxy(int                                                        cdn,
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;

                /// Destructor.
                ~sniproxy() noexcept;

            public:
                /// Close the proxy and release all resources.
                void                                                                close() noexcept;

                /// Start the handshake process (entry point).
                bool                                                                handshake() noexcept;

            private:
                /// Cancel the handshake timeout timer.
                void                                                                clear_timeout() noexcept;

                /// (Re)start the inactivity timer.
                void                                                                reset_inactivity_timer() noexcept;

                /// Cancel the inactivity timer.
                void                                                                cancel_inactivity_timer() noexcept;

                /// Read a 2-byte big-endian integer from buffer, advance pointer.
                UInt16                                                              fetch_uint16(Byte*& data) noexcept;

                /// Read a 3-byte big-endian integer (TLS length field), advance pointer.
                int                                                                 fetch_length(Byte*& data) noexcept;

                /// Extract SNI hostname from TLS Client Hello payload.
                ppp::string                                                         fetch_sniaddr(size_t tls_payload) noexcept;

                /// Main coroutine-based handshake logic.
                bool                                                                do_handshake(ppp::coroutines::YieldContext& y) noexcept;

                /// Check if both local and remote sockets are open.
                bool                                                                socket_is_open() const noexcept;

                /// Start forwarding data from local -> remote.
                bool                                                                local_to_remote() noexcept;

                /// Start forwarding data from remote -> local.
                bool                                                                remote_to_local() noexcept;

                /// Return whether close logic already ran.
                bool                                                                is_disposed() const noexcept;

                /// Execute a callback on the socket executor to serialize state mutation.
                bool                                                                post(const ppp::function<void()>& callback) noexcept;

                /// Check if the first few bytes look like an HTTP request.
                static bool                                                         be_http(const void* p) noexcept;

                /// Check if 'host' matches 'domain' (exact match or subdomain).
                static bool                                                         be_host(ppp::string host, ppp::string domain) noexcept;

                /// Handle TLS handshake (SNI extraction and forwarding).
                bool                                                                do_tlsvd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept;

                /// Handle HTTP handshake (Host header extraction and forwarding).
                bool                                                                do_httpd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept;

                /// Trim and split host:port from HTTP Host header, supporting IPv6.
                bool                                                                do_httpd_handshake_host_trim(MemoryStream& messages_, ppp::string& host, int& port) noexcept;

                /// Extract the Host header value from HTTP request (headers only, up to \r\n\r\n).
                ppp::string                                                         do_httpd_handshake_host(MemoryStream& messages_) noexcept;

                /// Connect to target host and start bidirectional forwarding.
                bool                                                                do_connect_and_forward_to_host(ppp::coroutines::YieldContext& y,
                    const ppp::string                                               hostname_,
                    int                                                             self_websocket_port,
                    int                                                             forward_connect_port,
                    MemoryStream&                                                   messages_) noexcept;

                /// Return the WebSocket port for local loopback.
                int                                                                 do_forward_websocket_port() const noexcept;

            private:
                int                                                                 cdn_;               ///< CDN flag
                std::shared_ptr<ppp::configurations::AppConfiguration>              configuration_;    ///< App config
                std::shared_ptr<boost::asio::io_context>                            context_;           ///< IO context
                Strand                                                              strand_;            ///< Serializes proxy state
                std::shared_ptr<boost::asio::ip::tcp::socket>                       local_socket_;      ///< Client socket
                boost::asio::ip::tcp::socket                                        remote_socket_;     ///< Upstream socket
                uint64_t                                                            last_;              ///< Last activity timestamp (ms)
                std::shared_ptr<Timer>                                              timeout_;           ///< Handshake timeout timer
                std::shared_ptr<Timer>                                              inactivity_timer_;  ///< Inactivity timeout timer
                mutable std::mutex                                                  syncobj_;
                std::atomic<bool>                                                   disposed_{ false };
                char                                                                local_socket_buf_[FORWARD_MSS];  ///< Read buffer for local socket
                char                                                                remote_socket_buf_[FORWARD_MSS]; ///< Read buffer for remote socket
            };

        } // namespace proxies
    } // namespace net
} // namespace ppp
