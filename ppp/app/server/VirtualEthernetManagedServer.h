#pragma once

/**
 * @file VirtualEthernetManagedServer.h
 * @brief Declares the managed-server bridge for authentication and traffic reporting.
 *
 * @details `VirtualEthernetManagedServer` connects the openppp2 server process to an
 *          optional external management backend (typically the Go companion process) over
 *          a WebSocket (plain or TLS) link.  Its responsibilities are:
 *
 *          - **Authentication**: For each new client session, the switcher calls
 *            `AuthenticationToManagedServer()`, which sends an auth request and invokes
 *            the provided callback when the backend responds.
 *          - **Traffic accounting**: `UploadTrafficToManagedServer()` queues rx/tx deltas
 *            per session; `TickAllUploadTrafficToManagedServer()` batches them and flushes
 *            on a configurable interval.
 *          - **Keep-alive**: `TickEchoToManagedServer()` sends periodic echo packets so
 *            the backend can detect dropped connections.
 *          - **Reconnection**: `RunInner()` implements a persistent reconnect loop that
 *            re-establishes the WebSocket link on disconnect.
 *
 *          Composite WebSocket abstraction (`IWebSocket`):
 *          - Wraps either a plain `websocket` or a TLS `sslwebsocket` behind a uniform
 *            interface, selected at runtime based on the configured URL scheme.
 *
 *          Lifecycle:
 *          - Constructed by `VirtualEthernetSwitcher::NewManagedServer()`.
 *          - `ConnectToManagedServer(url)` starts the persistent connection coroutine.
 *          - `Update(now)` handles echo, traffic upload, and auth timeout ticks.
 *          - `Dispose()` closes the active WebSocket and stops the reconnect loop.
 *
 *          Thread safety:
 *          - `syncobj_` guards `authentications_`, `traffics_`, and `url_`.
 *          - All WebSocket I/O runs on the internal `context_` io_context.
 *          - `aid_` (atomic) provides lock-free generation of request identifiers.
 *
 * @author  OPENPPP2 Team
 * @license GPL-3.0
 */

#include <ppp/Int128.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>
#include <ppp/net/asio/websocket.h>
#include <ppp/coroutines/YieldContext.h>
#include <chrono>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;

            /**
             * @brief Connects to the managed control backend for authentication and traffic accounting.
             *
             * @details This class is owned by `VirtualEthernetSwitcher` and acts as the sole
             *          communication channel to the Go management backend.  It serializes all
             *          interactions with the backend over a single persistent WebSocket link
             *          and exposes an async-callback API for authentication and traffic upload.
             */
            class VirtualEthernetManagedServer : public std::enable_shared_from_this<VirtualEthernetManagedServer> {
            public:
                /** @brief Virtual ethernet session information type alias. */
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                /** @brief Shared pointer alias for session information objects. */
                typedef std::shared_ptr<VirtualEthernetInformation>                 VirtualEthernetInformationPtr;
                /**
                 * @brief Callback invoked when an authentication request completes.
                 *
                 * @details Parameters:
                 *   - `bool`                       — true if authentication succeeded.
                 *   - `VirtualEthernetInformationPtr&` — session info populated by the backend.
                 */
                typedef ppp::function<void(bool, VirtualEthernetInformationPtr&)>   AuthenticationToManagedServerAsyncCallback;
                /** @brief Coroutine yield context type alias. */
                typedef ppp::coroutines::YieldContext                               YieldContext;
                /** @brief Runtime application configuration type alias. */
                typedef ppp::configurations::AppConfiguration                       AppConfiguration;
                /** @brief Shared pointer alias for the application configuration. */
                typedef std::shared_ptr<AppConfiguration>                           AppConfigurationPtr;
                /**
                 * @brief Callback invoked when a URI verification attempt completes.
                 * @details Parameter: `bool` — true if the URI is reachable and valid.
                 */
                typedef ppp::function<void(bool)>                                   TryVerifyUriAsyncCallback;
                /** @brief Timer type alias. */
                typedef ppp::threading::Timer                                       Timer;
                /** @brief Shared pointer alias for timer objects. */
                typedef std::shared_ptr<Timer>                                      TimerPtr;
                /** @brief Internal synchronization primitive type alias. */
                typedef std::mutex                                                  SynchronizedObject;
                /** @brief Lock guard alias for synchronized sections. */
                typedef std::lock_guard<SynchronizedObject>                         SynchronizedObjectScope;

            private:
                /**
                 * @brief Pending authentication callback state with absolute expiry timestamp.
                 *
                 * @details Stored in `authentications_` while the backend response is in flight.
                 *          `TickAllAuthenticationToManagedServer()` discards entries whose
                 *          `timeout` has elapsed without a response.
                 *
                 * Fields:
                 *   - timeout = uint64_t  ///< Absolute expiry tick in milliseconds.
                 *   - ac      = AuthenticationToManagedServerAsyncCallback  ///< Completion callback.
                 */
                typedef struct {
                    uint64_t                                                        timeout; ///< Absolute expiry tick in milliseconds.
                    std::chrono::steady_clock::time_point                           started_at; ///< Request start time for auth round-trip telemetry.
                    AuthenticationToManagedServerAsyncCallback                      ac;      ///< Completion callback.
                }                                                                   AuthenticationWaitable;

                /** @brief Map of pending authentication callbacks keyed by session identifier. */
                typedef ppp::unordered_map<Int128, AuthenticationWaitable>          AuthenticationWaitableTable;
                /** @brief Timer table keyed by raw implementation pointer. */
                typedef ppp::unordered_map<void*, TimerPtr>                         TimerTable;

                /**
                 * @brief Accumulated upload traffic delta for one session.
                 *
                 * @details Entries accumulate in `traffics_` until flushed by
                 *          `TickAllUploadTrafficToManagedServer()`.
                 *
                 * Fields:
                 *   - rx = int64_t  ///< Accumulated received bytes delta.
                 *   - tx = int64_t  ///< Accumulated transmitted bytes delta.
                 */
                struct UploadTrafficTask {
                    int64_t                                                         rx = 0; ///< Received bytes accumulated since last flush.
                    int64_t                                                         tx = 0; ///< Transmitted bytes accumulated since last flush.
                };

                /** @brief Map of queued traffic upload tasks keyed by session identifier. */
                typedef ppp::unordered_map<Int128, UploadTrafficTask>               UploadTrafficTaskTable;
                /** @brief Plain (non-TLS) WebSocket type alias. */
                typedef ppp::net::asio::websocket                                   WebSocket;
                /** @brief TLS WebSocket type alias. */
                typedef ppp::net::asio::sslwebsocket                                WebSocketSsl;

                /**
                 * @brief Composite WebSocket wrapper that abstracts plain and TLS transports.
                 *
                 * @details At runtime exactly one of `ws` (plain) or `wss` (TLS) is non-null.
                 *          All methods delegate to the active implementation and are no-ops when
                 *          both are null (disposed state).
                 *
                 * Fields:
                 *   - ws            = shared_ptr<WebSocket>     ///< Plain WebSocket; null when TLS is used.
                 *   - wss           = shared_ptr<WebSocketSsl>  ///< TLS WebSocket; null when plain is used.
                 *   - configuration = AppConfigurationPtr       ///< Configuration shared with the parent.
                 */
                struct IWebSocket {
                public:
                    /** @brief Asynchronous write callback type alias (forwarded from WebSocket). */
                    typedef WebSocket::AsynchronousWriteCallback                    AsynchronousWriteCallback;
                    /** @brief WebSocket handshake type alias (client or server). */
                    typedef WebSocket::HandshakeType                                HandshakeType;

                public:
                    /**
                     * @brief Disposes the active websocket implementation (plain or TLS).
                     *
                     * @details After this call `IsDisposed()` returns true and all further
                     *          operations on this wrapper are no-ops.
                     */
                    void                                                            Dispose() noexcept;

                    /**
                     * @brief Returns true if both `ws` and `wss` are null or disposed.
                     * @return Disposal state of the active implementation.
                     */
                    bool                                                            IsDisposed() noexcept;

                    /**
                     * @brief Reads exactly `length` bytes from the active websocket into `buffer`.
                     *
                     * @param buffer Destination buffer (must remain valid for the duration of the call).
                     * @param offset Byte offset into `buffer` to start writing.
                     * @param length Number of bytes to read.
                     * @param y      Coroutine yield context.
                     * @return True if all bytes are read; false on error or disconnect.
                     */
                    bool                                                            Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;

                    /**
                     * @brief Performs the WebSocket upgrade handshake.
                     *
                     * @param type Server or client handshake direction.
                     * @param host `Host` header value for the HTTP upgrade request.
                     * @param path URL path for the HTTP upgrade request.
                     * @param y    Coroutine yield context.
                     * @return True if the handshake completes successfully.
                     */
                    bool                                                            Run(HandshakeType type, const ppp::string& host, const ppp::string& path, YieldContext& y) noexcept;

                    /**
                     * @brief Writes bytes to the active websocket asynchronously.
                     *
                     * @param buffer Payload buffer.
                     * @param offset Byte offset into `buffer`.
                     * @param length Number of bytes to write.
                     * @param cb     Completion callback invoked when the write finishes.
                     * @return True if the write is posted; false if the socket is disposed.
                     */
                    bool                                                            Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept;

                public:
                    std::shared_ptr<WebSocket>                                      ws;            ///< Plain WebSocket; null when TLS is active.
                    std::shared_ptr<WebSocketSsl>                                   wss;           ///< TLS WebSocket; null when plain is active.
                    AppConfigurationPtr                                             configuration; ///< Shared configuration reference.
                };

                /** @brief Shared pointer alias for the composite WebSocket wrapper. */
                typedef std::shared_ptr<IWebSocket>                                 IWebScoketPtr;

            public:
                /**
                 * @brief Constructs the managed-server bridge.
                 *
                 * @param switcher Parent virtual ethernet switcher that owns this bridge.
                 *                 The switcher is held weakly to avoid circular ownership.
                 */
                VirtualEthernetManagedServer(const std::shared_ptr<VirtualEthernetSwitcher>& switcher) noexcept;

                /** @brief Default destructor; all cleanup is handled by `Dispose()`. */
                virtual ~VirtualEthernetManagedServer() = default;

            public:
                /** @brief Returns a shared self-reference via `shared_from_this()`. */
                std::shared_ptr<VirtualEthernetManagedServer>                       GetReference() noexcept;
                /** @brief Returns the current runtime configuration snapshot. */
                AppConfigurationPtr                                                 GetConfiguration() noexcept;
                /** @brief Returns the buffer-swap allocator used for WebSocket I/O. */
                std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferswapAllocator() noexcept;
                /** @brief Returns the internal synchronization mutex. */
                SynchronizedObject&                                                 GetSynchronizedObject() noexcept;
                /** @brief Returns the verified managed-server URI string. */
                ppp::string                                                         GetUri() noexcept;
                /** @brief Returns true if the WebSocket link to the managed server is active. */
                bool                                                                LinkIsAvailable() noexcept;
                /** @brief Returns true if a reconnect backoff cycle is currently in progress. */
                bool                                                                LinkIsReconnecting() noexcept;

                /**
                 * @brief Releases managed-server resources and closes the active WebSocket link.
                 *
                 * @details Sets `disposed_ = 1`, closes the `server_` WebSocket wrapper, and
                 *          cancels any pending authentication callbacks.
                 */
                virtual void                                                        Dispose() noexcept;

                /**
                 * @brief Asynchronously verifies and normalizes a managed-server URI.
                 *
                 * @param url URL string to verify (e.g. `"ws://host:port/path"`).
                 * @param ac  Callback invoked with `true` when the URI is reachable.
                 * @return True if the verification attempt is dispatched.
                 */
                virtual bool                                                        TryVerifyUriAsync(const ppp::string& url, const TryVerifyUriAsyncCallback& ac) noexcept;

                /**
                 * @brief Starts the persistent asynchronous managed-server connection loop.
                 *
                 * @param url WebSocket URL of the managed server.
                 * @return True if the connection coroutine is posted successfully.
                 */
                virtual bool                                                        ConnectToManagedServer(const ppp::string& url) noexcept;

                /**
                 * @brief Runs periodic maintenance: echo, traffic flush, auth timeout expiry.
                 *
                 * @param now Current monotonic tick count in milliseconds.
                 * @return True to continue ticking; false to stop.
                 */
                virtual bool                                                        Update(UInt64 now) noexcept;

                /**
                 * @brief Generates a new positive request identifier for managed-server commands.
                 *
                 * @return Atomically incremented positive integer.
                 */
                virtual int                                                         NewId() noexcept;

            public:
                /**
                 * @brief Sends an authentication request for one client session to the managed server.
                 *
                 * @param session_id Session identifier to authenticate.
                 * @param ac         Callback invoked with the authentication result.
                 * @return True if the request is sent; false if the link is unavailable or disposed.
                 */
                virtual bool                                                        AuthenticationToManagedServer(const ppp::Int128& session_id, const AuthenticationToManagedServerAsyncCallback& ac) noexcept;

                /**
                 * @brief Queues a traffic usage delta for the specified session for managed-server upload.
                 *
                 * @param session_id Session whose traffic counters should be updated.
                 * @param rx         Received bytes delta since the last upload.
                 * @param tx         Transmitted bytes delta since the last upload.
                 */
                virtual void                                                        UploadTrafficToManagedServer(const ppp::Int128& session_id, int64_t rx, int64_t tx) noexcept;

            protected:
                /**
                 * @brief Sends a managed-server command packet with an empty payload.
                 *
                 * @param session_id Session context for the command.
                 * @param cmd        Command opcode.
                 * @param id         Request identifier.
                 * @return True if the packet is written to the WebSocket.
                 */
                bool                                                                SendToManagedServer(const ppp::Int128& session_id, int cmd, int id) noexcept;

                /**
                 * @brief Sends a managed-server command packet with a string payload.
                 *
                 * @param session_id Session context for the command.
                 * @param cmd        Command opcode.
                 * @param id         Request identifier.
                 * @param data       String payload to include in the packet.
                 * @return True if the packet is written to the WebSocket.
                 */
                virtual bool                                                        SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const ppp::string& data) noexcept;

                /**
                 * @brief Sends a managed-server command packet with a JSON payload.
                 *
                 * @param session_id Session context for the command.
                 * @param cmd        Command opcode.
                 * @param id         Request identifier.
                 * @param data       JSON value to serialize as the packet payload.
                 * @return True if the packet is written to the WebSocket.
                 */
                virtual bool                                                        SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const Json::Value& data) noexcept;

            private:
                /**
                 * @brief Removes and returns the pending authentication callback for a session.
                 *
                 * @param session_id Session whose callback should be removed.
                 * @return The removed callback; default-constructed if not found.
                 */
                AuthenticationToManagedServerAsyncCallback                          DeleteAuthenticationToManagedServer(const ppp::Int128& session_id) noexcept;

                /**
                 * @brief Discards pending authentication callbacks that have exceeded their timeout.
                 *
                 * @param now Current tick count in milliseconds.
                 */
                void                                                                TickAllAuthenticationToManagedServer(UInt64 now) noexcept;

                /**
                 * @brief Sends a periodic echo packet to keep the managed-server link alive.
                 *
                 * @param now Current tick count in milliseconds.
                 */
                void                                                                TickEchoToManagedServer(UInt64 now) noexcept;

                /**
                 * @brief Runs the persistent reconnect loop until the bridge is disposed.
                 *
                 * @param url URL of the managed server to connect to.
                 * @param y   Coroutine yield context.
                 */
                void                                                                RunInner(const ppp::string& url, YieldContext& y) noexcept;

                /**
                 * @brief Resolves and validates the managed-server URI and returns endpoint parameters.
                 *
                 * @param url       Input URL string to resolve.
                 * @param host[out] Resolved hostname extracted from the URL.
                 * @param path[out] URL path component.
                 * @param remoteEP[out] Resolved TCP endpoint of the managed server.
                 * @param ssl[out]  True if the URL scheme indicates TLS (wss://).
                 * @param y         Coroutine yield context.
                 * @return Normalized URL string; empty on resolution failure.
                 */
                ppp::string                                                         GetManagedServerEndPoint(const ppp::string& url, ppp::string& host, ppp::string& path, boost::asio::ip::tcp::endpoint& remoteEP, bool& ssl, YieldContext& y) noexcept;

                /**
                 * @brief Flushes all queued traffic tasks to the managed server if the interval has elapsed.
                 *
                 * @param now Current tick count in milliseconds.
                 * @return True if the flush is performed; false if the interval has not elapsed.
                 */
                bool                                                                TickAllUploadTrafficToManagedServer(UInt64 now) noexcept;

            private:
                /**
                 * @brief Reads packets from the active WebSocket and dispatches them to handlers.
                 *
                 * @param websocket Active WebSocket wrapper to read from.
                 * @param y         Coroutine yield context.
                 */
                void                                                                Run(IWebScoketPtr& websocket, YieldContext& y) noexcept;

                /**
                 * @brief Handles an authentication acknowledgment packet from the managed server.
                 *
                 * @param json Parsed JSON response from the server.
                 * @param y    Coroutine yield context.
                 * @return True if the ack is processed and the callback is invoked.
                 */
                bool                                                                AckAuthenticationToManagedServer(Json::Value& json, YieldContext& y) noexcept;

                /**
                 * @brief Handles a traffic response packet and dispatches updates to the switcher.
                 *
                 * @param json Parsed JSON response from the server.
                 * @param y    Coroutine yield context.
                 * @return True if the response is processed.
                 */
                bool                                                                AckAllUploadTrafficToManagedServer(Json::Value& json, YieldContext& y) noexcept;

                /**
                 * @brief Opens a WebSocket, performs the transport handshake, and sends the connect command.
                 *
                 * @param url URL of the managed server.
                 * @param y   Coroutine yield context.
                 * @return Active WebSocket wrapper on success; null on failure.
                 */
                IWebScoketPtr                                                       NewWebSocketConnectToManagedServer2(const ppp::string& url, YieldContext& y) noexcept;

                /**
                 * @brief Opens a WebSocket transport and performs only the network-level handshake.
                 *
                 * @param url URL of the managed server.
                 * @param y   Coroutine yield context.
                 * @return Active WebSocket wrapper on success; null on failure.
                 */
                IWebScoketPtr                                                       NewWebSocketConnectToManagedServer(const ppp::string& url, YieldContext& y) noexcept;

            private:
                SynchronizedObject                                                  syncobj_;                       ///< Guards authentications_, traffics_, and url_.
                struct {
                    bool                                                            disposed_      : 1;             ///< True after Dispose() is called.
                    bool                                                            reconnecting_  : 7;             ///< Non-zero while RunInner() is in a reconnect cycle.
                };
                std::atomic<int>                                                    aid_           = 0;             ///< Atomic counter for request identifier generation.
                UInt64                                                              echotest_next_ = 0;             ///< Tick at which the next echo packet should be sent.
                UInt64                                                              traffics_next_ = 0;             ///< Tick at which the next traffic flush should occur.
                ppp::string                                                         url_;                           ///< Verified managed-server URL.
                std::shared_ptr<VirtualEthernetSwitcher>                            switcher_;                      ///< Parent switcher reference.
                std::shared_ptr<boost::asio::io_context>                            context_;                       ///< io_context for all WebSocket I/O.
                IWebScoketPtr                                                       server_;                        ///< Active composite WebSocket connection.
                std::shared_ptr<ppp::threading::BufferswapAllocator>                allocator_;                     ///< Buffer-swap allocator for WebSocket I/O frames.
                AppConfigurationPtr                                                 configuration_;                 ///< Immutable configuration snapshot.
                UploadTrafficTaskTable                                              traffics_;                      ///< Pending traffic upload tasks.
                AuthenticationWaitableTable                                         authentications_;               ///< Pending authentication callbacks.
            };
        }
    }
}
