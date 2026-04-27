/**
 * @file sniproxy.h
 * @brief SNI proxy: inspects TLS SNI or HTTP Host header and transparently
 *        forwards the TCP stream to the resolved upstream server.
 *
 * @details
 * The proxy operates in two modes:
 *  - **TLS mode**: reads the TLS Client Hello, extracts the SNI hostname from
 *    the server_name extension, then connects upstream and replays the buffered
 *    handshake bytes so the upstream sees a normal TLS stream.
 *  - **HTTP mode**: reads the first HTTP request headers, extracts the `Host`
 *    header (supporting IPv6 bracket notation and optional port), connects
 *    upstream, and replays the buffered request.
 *
 * All data-path operations are serialized by a Boost.Asio strand; no mutex is
 * needed for shared state.  The only re-entrancy guard is the atomic CAS in
 * `close()`.
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
             * @brief Transparent TLS-SNI / HTTP-Host proxy.
             *
             * Accepts a raw TCP client socket, peeks at the first bytes to decide
             * whether the connection is TLS or plain HTTP, extracts the target
             * hostname, connects to the upstream server, and then splices data
             * bidirectionally until either side closes or an inactivity timeout
             * fires.
             *
             * @note All public methods are `noexcept`.  Errors are handled
             *       internally; callers need only check the `bool` return value
             *       of `handshake()`.
             *
             * @note Lifetime is managed exclusively through `std::shared_ptr`.
             *       Never stack-allocate an instance of this class.
             */
            class sniproxy final : public std::enable_shared_from_this<sniproxy> {
                typedef ppp::io::MemoryStream                                       MemoryStream;
                typedef ppp::threading::Timer                                       Timer;
                typedef boost::asio::strand<boost::asio::io_context::executor_type> Strand;
                // NOTE: No SynchronizedObjectScope/mutex needed — all data-path
                // calls are serialized by strand_.  The disposed_ atomic CAS in
                // close() is the sole re-entrancy guard.

#pragma pack(push, 1)
                /**
                 * @brief Packed TLS record-layer header (5 bytes).
                 *
                 * Fields are in network byte order (big-endian) as received
                 * directly from the socket buffer.
                 */
                struct tls_hdr {
                    Byte    Content_Type = 0;   ///< Record content type; 0x16 = Handshake
                    UInt16  Version      = 0;   ///< TLS protocol version (network order)
                    UInt16  Length       = 0;   ///< Payload length in bytes (network order)
                };
#pragma pack(pop)

                /** @brief Maximum segment size used for the bidirectional forwarding buffers. */
                static constexpr int FORWARD_MSS = 65536;

            public:
                /**
                 * @brief Construct an sniproxy instance.
                 *
                 * @param cdn           CDN routing flag; non-zero enables CDN-aware
                 *                      WebSocket loopback port selection.
                 * @param configuration Shared application configuration (timeouts,
                 *                      port assignments, domain rules, etc.).
                 * @param context       Boost.Asio IO context that owns all async ops.
                 * @param socket        Accepted client TCP socket; ownership is shared
                 *                      with this object for its lifetime.
                 */
                sniproxy(int                                                        cdn,
                    const std::shared_ptr<ppp::configurations::AppConfiguration>&   configuration,
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept;

                /**
                 * @brief Destructor. Implicitly calls `close()` if not already called.
                 */
                ~sniproxy() noexcept;

            public:
                /**
                 * @brief Gracefully close both sockets and release all resources.
                 *
                 * May be called from any thread.  Internally posts the teardown
                 * work onto the strand to avoid data races.  Idempotent: subsequent
                 * calls after the first are no-ops.
                 */
                void close() noexcept;

                /**
                 * @brief Start the SNI/HTTP detection and forwarding handshake.
                 *
                 * Spawns a coroutine on the strand that reads initial bytes from the
                 * client socket, identifies the protocol, extracts the target host,
                 * and initiates the upstream connection.
                 *
                 * @return `true`  if the coroutine was successfully spawned.
                 * @return `false` if the object is already disposed or the spawn fails.
                 *
                 * @note Must be called at most once per instance.
                 */
                bool handshake() noexcept;

            private:
                /**
                 * @brief Cancel and destroy the handshake timeout timer.
                 */
                void clear_timeout() noexcept;

                /**
                 * @brief (Re)arm the inactivity timer.
                 *
                 * Resets `last_` to the current monotonic millisecond timestamp and
                 * schedules a timer callback that calls `close()` if no data has been
                 * transferred within the configured inactivity window.
                 */
                void reset_inactivity_timer() noexcept;

                /**
                 * @brief Cancel the inactivity timer without closing the connection.
                 */
                void cancel_inactivity_timer() noexcept;

                /**
                 * @brief Read a 2-byte big-endian unsigned integer from `data` and
                 *        advance the pointer by 2.
                 *
                 * @param data  In/out pointer into a raw byte buffer.
                 * @return      The decoded 16-bit value in host byte order.
                 */
                UInt16 fetch_uint16(Byte*& data) noexcept;

                /**
                 * @brief Read a 3-byte big-endian integer (used for TLS length fields)
                 *        from `data` and advance the pointer by 3.
                 *
                 * @param data  In/out pointer into a raw byte buffer.
                 * @return      The decoded 24-bit value as a host-order `int`.
                 */
                int fetch_length(Byte*& data) noexcept;

                /**
                 * @brief Parse the SNI `server_name` hostname from a TLS Client Hello
                 *        payload (after the 5-byte record header).
                 *
                 * @param tls_payload  Number of bytes available in the internal memory
                 *                     stream beyond the record header.
                 * @return             The extracted SNI hostname, or an empty string if
                 *                     parsing fails or no SNI extension is present.
                 */
                ppp::string fetch_sniaddr(size_t tls_payload) noexcept;

                /**
                 * @brief Main coroutine body for the handshake phase.
                 *
                 * Reads the first bytes from the client socket, dispatches to either
                 * `do_tlsvd_handshake()` or `do_httpd_handshake()`, then returns.
                 * The forwarding loops run independently after a successful handshake.
                 *
                 * @param y  Coroutine yield context provided by `boost::asio::spawn`.
                 * @return   `true` on success, `false` if any step fails.
                 */
                bool do_handshake(ppp::coroutines::YieldContext& y) noexcept;

                /**
                 * @brief Check whether both the local and remote sockets are open.
                 *
                 * @return `true` if both sockets report `is_open() == true`.
                 */
                bool socket_is_open() const noexcept;

                /**
                 * @brief Start an async read loop forwarding data from the client
                 *        (local) socket to the upstream (remote) socket.
                 *
                 * @return `true` if the forwarding loop was successfully initiated.
                 */
                bool local_to_remote() noexcept;

                /**
                 * @brief Start an async read loop forwarding data from the upstream
                 *        (remote) socket back to the client (local) socket.
                 *
                 * @return `true` if the forwarding loop was successfully initiated.
                 */
                bool remote_to_local() noexcept;

                /**
                 * @brief Query whether `close()` has already run.
                 *
                 * @return `true` if the instance has been disposed.
                 */
                bool is_disposed() const noexcept;

                /**
                 * @brief Post a callback onto the strand for serialized execution.
                 *
                 * @param callback  Callable to dispatch; must be non-null.
                 * @return          `true` if the post succeeded, `false` if disposed
                 *                  or if `callback` is empty.
                 */
                bool post(const ppp::function<void()>& callback) noexcept;

                /**
                 * @brief Heuristically determine whether a byte buffer begins with an
                 *        HTTP request verb (e.g. `GET`, `POST`, `CONNECT`).
                 *
                 * @param p  Pointer to at least the first few bytes of received data.
                 * @return   `true` if the buffer looks like an HTTP request.
                 */
                static bool be_http(const void* p) noexcept;

                /**
                 * @brief Test whether `host` matches `domain` — either as an exact
                 *        match or as a subdomain (e.g. `foo.example.com` matches
                 *        `example.com`).
                 *
                 * @param host    The hostname to test (lowercased before comparison).
                 * @param domain  The reference domain (lowercased before comparison).
                 * @return        `true` if `host` equals or is a subdomain of `domain`.
                 */
                static bool be_host(ppp::string host, ppp::string domain) noexcept;

                /**
                 * @brief TLS-mode handshake coroutine.
                 *
                 * Reads enough bytes to parse the TLS record header and Client Hello,
                 * extracts the SNI hostname via `fetch_sniaddr()`, then calls
                 * `do_connect_and_forward_to_host()`.
                 *
                 * @param y         Coroutine yield context.
                 * @param messages_ Accumulator for bytes read so far; replayed to the
                 *                  upstream after connection is established.
                 * @return          `true` on success.
                 */
                bool do_tlsvd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept;

                /**
                 * @brief HTTP-mode handshake coroutine.
                 *
                 * Reads HTTP request headers (up to the blank line), extracts the
                 * `Host` header via `do_httpd_handshake_host()`, resolves the port,
                 * then calls `do_connect_and_forward_to_host()`.
                 *
                 * @param y         Coroutine yield context.
                 * @param messages_ Accumulator for bytes read so far; replayed to the
                 *                  upstream after connection is established.
                 * @return          `true` on success.
                 */
                bool do_httpd_handshake(ppp::coroutines::YieldContext& y, MemoryStream& messages_) noexcept;

                /**
                 * @brief Parse and split the `host:port` string obtained from an HTTP
                 *        Host header, handling IPv6 bracket addresses.
                 *
                 * @param messages_  Memory stream containing the raw HTTP headers
                 *                   (used for context only; not modified).
                 * @param host       [out] Extracted hostname or IP address string.
                 * @param port       [out] Extracted port number, or the default HTTP
                 *                   port (80) if not specified.
                 * @return           `true` if a valid host was successfully extracted.
                 */
                bool do_httpd_handshake_host_trim(MemoryStream& messages_, ppp::string& host, int& port) noexcept;

                /**
                 * @brief Scan the HTTP headers in `messages_` and return the value of
                 *        the first `Host:` header field.
                 *
                 * Parsing stops at the first blank line (`\r\n\r\n`).
                 *
                 * @param messages_  Memory stream containing raw HTTP request bytes.
                 * @return           The trimmed Host header value, or an empty string
                 *                   if not found or malformed.
                 */
                ppp::string do_httpd_handshake_host(MemoryStream& messages_) noexcept;

                /**
                 * @brief Resolve `hostname_`, connect the upstream socket, replay
                 *        buffered bytes, then start bidirectional forwarding.
                 *
                 * @param y                    Coroutine yield context.
                 * @param hostname_            Target hostname or IP address string.
                 * @param self_websocket_port  Local WebSocket loopback port; non-zero
                 *                             triggers loopback routing instead of DNS
                 *                             resolution.
                 * @param forward_connect_port Target TCP port to connect to upstream.
                 * @param messages_            Buffered bytes to replay immediately after
                 *                             the upstream connection is established.
                 * @return                     `true` if forwarding was successfully
                 *                             started; `false` on any error.
                 */
                bool do_connect_and_forward_to_host(ppp::coroutines::YieldContext& y,
                    const ppp::string  hostname_,
                    int                self_websocket_port,
                    int                forward_connect_port,
                    MemoryStream&      messages_) noexcept;

                /**
                 * @brief Determine the local WebSocket loopback port to use when the
                 *        target hostname resolves to this proxy itself.
                 *
                 * @return  The configured WebSocket port, or 0 if CDN mode is disabled
                 *          or no loopback routing should be applied.
                 */
                int do_forward_websocket_port() const noexcept;

            private:
                int                                                            cdn_;               ///< CDN routing flag (non-zero = CDN mode)
                std::shared_ptr<ppp::configurations::AppConfiguration>         configuration_;     ///< Shared application configuration
                std::shared_ptr<boost::asio::io_context>                       context_;           ///< Boost.Asio IO context
                Strand                                                         strand_;            ///< Strand serializing all data-path operations
                std::shared_ptr<boost::asio::ip::tcp::socket>                  local_socket_;      ///< Client-side (downstream) TCP socket
                boost::asio::ip::tcp::socket                                   remote_socket_;     ///< Upstream TCP socket
                uint64_t                                                       last_;              ///< Monotonic timestamp (ms) of last I/O activity
                std::shared_ptr<Timer>                                         timeout_;           ///< Handshake phase timeout timer
                std::shared_ptr<Timer>                                         inactivity_timer_;  ///< Idle-connection timeout timer
                // syncobj_ removed: close() is strand-serialized; mutex was deadlock-prone.
                std::atomic<bool>                                              disposed_{ false };
                char                                                           local_socket_buf_[FORWARD_MSS];  ///< Read buffer for the local (client) socket
                char                                                           remote_socket_buf_[FORWARD_MSS]; ///< Read buffer for the remote (upstream) socket
            };

        } // namespace proxies
    } // namespace net
} // namespace ppp
