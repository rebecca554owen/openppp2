#pragma once

/**
 * @file VirtualEthernetManagedServer.h
 * @brief Declares the managed-server bridge for authentication and traffic reporting.
 * @author OPENPPP2 Team
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

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;

            /**
             * @brief Connects to managed control servers for authentication and traffic accounting.
             */
            class VirtualEthernetManagedServer : public std::enable_shared_from_this<VirtualEthernetManagedServer> {
            public:
                /** @brief Virtual ethernet information type alias. */
                typedef ppp::app::protocol::VirtualEthernetInformation              VirtualEthernetInformation;
                /** @brief Shared pointer alias for virtual ethernet information. */
                typedef std::shared_ptr<VirtualEthernetInformation>                 VirtualEthernetInformationPtr;
                /** @brief Callback invoked when authentication request completes. */
                typedef ppp::function<void(bool, VirtualEthernetInformationPtr&)>   AuthenticationToManagedServerAsyncCallback;
                /** @brief Coroutine yield context alias. */
                typedef ppp::coroutines::YieldContext                               YieldContext;
                /** @brief Runtime application configuration type alias. */
                typedef ppp::configurations::AppConfiguration                       AppConfiguration;
                /** @brief Shared pointer alias for runtime application configuration. */
                typedef std::shared_ptr<AppConfiguration>                           AppConfigurationPtr;
                /** @brief Callback invoked when URI verification completes. */
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
                 * @brief Pending authentication callback state with timeout.
                 */
                typedef struct {
                    uint64_t                                                        timeout;
                    AuthenticationToManagedServerAsyncCallback                      ac;
                }                                                                   AuthenticationWaitable;
                /** @brief Table of pending authentication callbacks by session id. */
                typedef ppp::unordered_map<Int128, AuthenticationWaitable>          AuthenticationWaitableTable;
                /** @brief Timer table alias keyed by implementation pointer. */
                typedef ppp::unordered_map<void*, TimerPtr>                         TimerTable;
                /**
                 * @brief Accumulated upload traffic values for one session.
                 */
                struct UploadTrafficTask {
                    int64_t                                                         rx = 0;
                    int64_t                                                         tx = 0;
                };
                /** @brief Table of queued traffic upload tasks by session id. */
                typedef ppp::unordered_map<Int128, UploadTrafficTask>               UploadTrafficTaskTable;
                /** @brief Plain websocket alias. */
                typedef ppp::net::asio::websocket                                   WebSocket;
                /** @brief TLS websocket alias. */
                typedef ppp::net::asio::sslwebsocket                                WebSocketSsl;
                /**
                 * @brief Composite websocket wrapper for plain and TLS transports.
                 */
                struct IWebSocket {
                public:
                    /** @brief Asynchronous write callback alias. */
                    typedef WebSocket::AsynchronousWriteCallback                    AsynchronousWriteCallback;
                    /** @brief Websocket handshake type alias. */
                    typedef WebSocket::HandshakeType                                HandshakeType;

                public:
                    /** @brief Disposes the underlying active websocket implementation. */
                    void                                                            Dispose() noexcept;
                    /** @brief Checks whether the underlying websocket is disposed. */
                    bool                                                            IsDisposed() noexcept;
                    /** @brief Reads a fixed amount of bytes from the active websocket. */
                    bool                                                            Read(const void* buffer, int offset, int length, YieldContext& y) noexcept;
                    /** @brief Performs websocket handshake for the selected implementation. */
                    bool                                                            Run(HandshakeType type, const ppp::string& host, const ppp::string& path, YieldContext& y) noexcept;
                    /** @brief Writes bytes to the active websocket asynchronously. */
                    bool                                                            Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept;

                public:
                    std::shared_ptr<WebSocket>                                      ws;
                    std::shared_ptr<WebSocketSsl>                                   wss;  
                    AppConfigurationPtr                                             configuration;
                };
                /** @brief Shared pointer alias for the composite websocket wrapper. */
                typedef std::shared_ptr<IWebSocket>                                 IWebScoketPtr;

            public:
                /**
                 * @brief Creates a managed server bridge.
                 * @param switcher Parent virtual ethernet switcher.
                 */
                VirtualEthernetManagedServer(const std::shared_ptr<VirtualEthernetSwitcher>& switcher) noexcept;
                virtual ~VirtualEthernetManagedServer() = default;

            public:
                /** @brief Returns shared ownership reference to current instance. */
                std::shared_ptr<VirtualEthernetManagedServer>                       GetReference() noexcept;
                /** @brief Gets current runtime configuration. */
                AppConfigurationPtr                                                 GetConfiguration() noexcept;
                /** @brief Gets the shared buffer allocator used by this component. */
                std::shared_ptr<ppp::threading::BufferswapAllocator>                GetBufferswapAllocator() noexcept;
                /** @brief Gets the internal synchronization object. */
                SynchronizedObject&                                                 GetSynchronizedObject() noexcept;
                /** @brief Gets the current verified managed-server URI. */
                ppp::string                                                         GetUri() noexcept;
                /** @brief Checks whether managed-server websocket link is available. */
                bool                                                                LinkIsAvailable() noexcept;
                /** @brief Checks whether reconnect backoff loop is currently active. */
                bool                                                                LinkIsReconnecting() noexcept;
                /** @brief Releases managed-server resources and closes active link. */
                virtual void                                                        Dispose() noexcept;
                /** @brief Asynchronously verifies and normalizes a managed-server URI. */
                virtual bool                                                        TryVerifyUriAsync(const ppp::string& url, const TryVerifyUriAsyncCallback& ac) noexcept;
                /** @brief Starts asynchronous managed-server connection loop. */
                virtual bool                                                        ConnectToManagedServer(const ppp::string& url) noexcept;
                /** @brief Schedules periodic managed-server maintenance work. */
                virtual bool                                                        Update(UInt64 now) noexcept;
                /** @brief Generates a positive request identifier. */
                virtual int                                                         NewId() noexcept;

            public:
                /** @brief Sends authentication request for one virtual session. */
                virtual bool                                                        AuthenticationToManagedServer(const ppp::Int128& session_id, const AuthenticationToManagedServerAsyncCallback& ac) noexcept;
                /** @brief Queues traffic usage deltas for managed-server upload. */
                virtual void                                                        UploadTrafficToManagedServer(const ppp::Int128& session_id, int64_t rx, int64_t tx) noexcept;

            protected:
                /** @brief Sends a command packet with empty payload. */
                bool                                                                SendToManagedServer(const ppp::Int128& session_id, int cmd, int id) noexcept;
                /** @brief Sends a command packet with string payload. */
                virtual bool                                                        SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const ppp::string& data) noexcept;
                /** @brief Sends a command packet with JSON payload. */
                virtual bool                                                        SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const Json::Value& data) noexcept;

            private:
                /** @brief Removes and returns pending authentication callback for session id. */
                AuthenticationToManagedServerAsyncCallback                          DeleteAuthenticationToManagedServer(const ppp::Int128& session_id) noexcept;
                /** @brief Expires timed out authentication callbacks. */
                void                                                                TickAllAuthenticationToManagedServer(UInt64 now) noexcept;
                /** @brief Sends periodic echo to keep managed-server link healthy. */
                void                                                                TickEchoToManagedServer(UInt64 now) noexcept;
                /** @brief Runs the reconnect loop until disposed. */
                void                                                                RunInner(const ppp::string& url, YieldContext& y) noexcept;
                /** @brief Resolves and validates managed-server URI and endpoint parameters. */
                ppp::string                                                         GetManagedServerEndPoint(const ppp::string& url, ppp::string& host, ppp::string& path, boost::asio::ip::tcp::endpoint& remoteEP, bool& ssl, YieldContext& y) noexcept;
                /** @brief Flushes queued traffic tasks to managed server on interval. */
                bool                                                                TickAllUploadTrafficToManagedServer(UInt64 now) noexcept;

            private:
                /** @brief Reads and dispatches packets from active managed-server websocket. */
                void                                                                Run(IWebScoketPtr& websocket, YieldContext& y) noexcept;
                /** @brief Handles authentication acknowledgment packet. */
                bool                                                                AckAuthenticationToManagedServer(Json::Value& json, YieldContext& y) noexcept;
                /** @brief Handles traffic response packet and dispatches updates to switcher. */
                bool                                                                AckAllUploadTrafficToManagedServer(Json::Value& json, YieldContext& y) noexcept;
                /** @brief Opens websocket and performs protocol-level connect handshake. */
                IWebScoketPtr                                                       NewWebSocketConnectToManagedServer2(const ppp::string& url, YieldContext& y) noexcept;
                /** @brief Opens websocket transport and executes network handshake only. */
                IWebScoketPtr                                                       NewWebSocketConnectToManagedServer(const ppp::string& url, YieldContext& y) noexcept;

            private:
                SynchronizedObject                                                  syncobj_;
                struct {
                    bool                                                            disposed_      : 1;
                    bool                                                            reconnecting_  : 7;
                };
                std::atomic<int>                                                    aid_           = 0;
                UInt64                                                              echotest_next_ = 0;
                UInt64                                                              traffics_next_ = 0;
                ppp::string                                                         url_;
                std::shared_ptr<VirtualEthernetSwitcher>                            switcher_;
                std::shared_ptr<boost::asio::io_context>                            context_;
                IWebScoketPtr                                                       server_;
                std::shared_ptr<ppp::threading::BufferswapAllocator>                allocator_;
                AppConfigurationPtr                                                 configuration_;
                UploadTrafficTaskTable                                              traffics_;
                AuthenticationWaitableTable                                         authentications_;
            };
        }
    }
}
