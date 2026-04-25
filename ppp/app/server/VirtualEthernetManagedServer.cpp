#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualEthernetManagedServer.cpp
 * @brief Implements managed-server connection, authentication and traffic reporting workflows.
 * @author OPENPPP2 Team
 * @license GPL-3.0
 */

using ppp::threading::Executors;
using ppp::auxiliary::UriAuxiliary;
using ppp::auxiliary::JsonAuxiliary;
using ppp::auxiliary::StringAuxiliary;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::threading::Timer;

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Packet command identifiers and timing constants for managed-server protocol.
             */
            enum {
                PACKET_CMD_ECHO                 = 1000,
                PACKET_CMD_CONNECT              = 1001,
                PACKET_CMD_AUTHENTICATION       = 1002,
                PACKET_CMD_TRAFFIC              = 1003,

                PACKET_TIMEOUT_AUTHENTICATION   = 5000,
                PACKET_TIMEOUT_CONNECT          = 5000,
                PACKET_TIMEOUT_RECONNECT        = 5000,

                PACKET_TIMEOUT_ECHO             = 5000,
                PACKET_TIMEOUT_TRAFFIC          = PACKET_TIMEOUT_ECHO << 2,
            };

            /**
             * @brief Initializes managed-server bridge with switcher-owned runtime context.
             */
            VirtualEthernetManagedServer::VirtualEthernetManagedServer(const std::shared_ptr<VirtualEthernetSwitcher>& switcher) noexcept
                : disposed_(false)
                , reconnecting_(false)
                , aid_(RandomNext())
                , echotest_next_(0)
                , traffics_next_(0)
                , switcher_(switcher) {
                context_ = switcher->GetContext();
                configuration_ = switcher->GetConfiguration();
                allocator_ = configuration_->GetBufferAllocator();
            }

            /**
             * @brief Starts asynchronous reconnect loop toward managed server.
             */
            bool VirtualEthernetManagedServer::ConnectToManagedServer(const ppp::string& url) noexcept {
                if (url_.empty() || url.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                auto self = shared_from_this();
                auto context = context_;

                bool ok = YieldContext::Spawn(allocator_.get(), *context,
                    [self, this, url, context](YieldContext& y) noexcept {
                        RunInner(url, y);
                    });
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                }
                return ok;
            }

            /** @brief Returns currently verified managed-server URI. */
            ppp::string VirtualEthernetManagedServer::GetUri() noexcept {
                return url_;
            }

            /**
             * @brief Sends an authentication request and stores completion callback with timeout.
             */
            bool VirtualEthernetManagedServer::AuthenticationToManagedServer(const ppp::Int128& session_id, const AuthenticationToManagedServerAsyncCallback& ac) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (NULLPTR == ac) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return false;
                }

                UInt64 next = Executors::GetTickCount() + PACKET_TIMEOUT_AUTHENTICATION; {
                    SynchronizedObjectScope scope(syncobj_);
                    if (authentications_.find(session_id) != authentications_.end()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericAlreadyExists);
                        return false;
                    }

                    authentications_.emplace(session_id, AuthenticationWaitable{ next, ac });
                }

                int id = NewId();
                bool ok = SendToManagedServer(session_id, PACKET_CMD_AUTHENTICATION, id);
                if (ok) {
                    return true;
                }

                DeleteAuthenticationToManagedServer(session_id);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketWriteFailed);
                return false;
            }

            /**
             * @brief Removes pending authentication callback for a session id.
             */
            VirtualEthernetManagedServer::AuthenticationToManagedServerAsyncCallback VirtualEthernetManagedServer::DeleteAuthenticationToManagedServer(const ppp::Int128& session_id) noexcept {
                AuthenticationToManagedServerAsyncCallback f; {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = authentications_.find(session_id);
                    auto endl = authentications_.end();
                    if (tail != endl) {
                        auto& aw = tail->second;
                        f = std::move(aw.ac);
                        aw.ac = NULLPTR;
                        authentications_.erase(tail);
                    }
                }
                return f;
            }

            /**
             * @brief Expires timed-out authentication requests and triggers failure callbacks.
             */
            void VirtualEthernetManagedServer::TickAllAuthenticationToManagedServer(UInt64 now) noexcept {
                typedef struct {
                    ppp::Int128 k;
                    AuthenticationToManagedServerAsyncCallback f;
                } ReleaseInfo;

                ppp::vector<ReleaseInfo> releases; 
                for (SynchronizedObjectScope scope(syncobj_);;) {
                    for (auto&& kv : authentications_) {
                        auto& aw = kv.second;
                        if (now >= aw.timeout) {
                            releases.emplace_back(ReleaseInfo{ kv.first, std::move(aw.ac) });
                            aw.ac = NULLPTR;
                        }
                    }

                    break;
                }

                VirtualEthernetInformationPtr nullVEI;
                for (ReleaseInfo& ri : releases) {
                    AuthenticationToManagedServerAsyncCallback& f = ri.f;
                    if (f) {
                        f(false, nullVEI);
                    }

                    DeleteAuthenticationToManagedServer(ri.k);
                }
            }

            /** @brief Returns shared ownership reference for this object. */
            std::shared_ptr<VirtualEthernetManagedServer> VirtualEthernetManagedServer::GetReference() noexcept {
                return shared_from_this();
            }

            /** @brief Gets active application configuration. */
            VirtualEthernetManagedServer::AppConfigurationPtr VirtualEthernetManagedServer::GetConfiguration() noexcept {
                return configuration_;
            }

            /** @brief Gets default buffer allocator. */
            std::shared_ptr<ppp::threading::BufferswapAllocator> VirtualEthernetManagedServer::GetBufferswapAllocator() noexcept {
                return allocator_;
            }

            /** @brief Gets internal synchronization object. */
            VirtualEthernetManagedServer::SynchronizedObject& VirtualEthernetManagedServer::GetSynchronizedObject() noexcept {
                return syncobj_;
            }

            /** @brief Reports whether reconnect backoff loop is active. */
            bool VirtualEthernetManagedServer::LinkIsReconnecting() noexcept {
                if (disposed_) {
                    return false;
                }

                return reconnecting_;
            }

            /** @brief Reports whether websocket link to managed server is currently usable. */
            bool VirtualEthernetManagedServer::LinkIsAvailable() noexcept {
                if (disposed_) {
                    return false;
                }

                IWebScoketPtr websocket = server_;
                if (NULLPTR == websocket) {
                    return false;
                }

                if (websocket->IsDisposed()) {
                    return false;
                }

                return true;
            }

            /** @brief Schedules periodic maintenance tasks onto managed-server context. */
            bool VirtualEthernetManagedServer::Update(UInt64 now) noexcept {
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                boost::asio::post(*context_, 
                    [self, this, now]() noexcept {
                        TickEchoToManagedServer(now);
                        TickAllAuthenticationToManagedServer(now);
                        TickAllUploadTrafficToManagedServer(now);
                    });
                return true;
            }

            /** @brief Generates a strictly positive packet identifier. */
            int VirtualEthernetManagedServer::NewId() noexcept {
                for (;;) {
                    int id = ++aid_;
                    if (id < 1) {
                        aid_ = 0;
                        continue;
                    }
                    else {
                        return id;
                    }
                }
            }

            /** @brief Sends protocol echo packets at randomized keepalive interval. */
            void VirtualEthernetManagedServer::TickEchoToManagedServer(UInt64 now) noexcept {
                if (echotest_next_ == 0) {
                    echotest_next_ = now + RandomNext(1000, PACKET_TIMEOUT_ECHO);
                }
                elif(now >= echotest_next_) {
                    int id = NewId();
                    SendToManagedServer(0, PACKET_CMD_ECHO, id);
                    echotest_next_ = now + RandomNext(1000, PACKET_TIMEOUT_ECHO);
                }
            }

            template <typename TWebSocket, typename TWebSocketPtr, typename TData>
            /**
             * @brief Serializes and sends one managed-server packet through websocket.
             */
            static bool PACKET_SendToManagedServer(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, TWebSocketPtr websocket, const ppp::Int128& session_id, int cmd, int id, int node, const TData& data) noexcept {
                if (NULLPTR == websocket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                    return false;
                }

                char length_hex[8 + 1];
                if (websocket->IsDisposed()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                Json::Value messages;
                messages["Id"] = id;
                messages["Node"] = node;
                messages["Guid"] = StringAuxiliary::Int128ToGuidString(session_id);
                messages["Cmd"] = cmd;
                messages["Data"] = data;

                ppp::string json_string = JsonAuxiliary::ToString(messages);
                int length_dec = snprintf(length_hex, sizeof(length_hex), "%08x", (unsigned int)json_string.size());
                if (length_dec < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolEncodeFailed);
                    return false;
                }

                int packet_length = json_string.size() + length_dec;
                std::shared_ptr<Byte> packet = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, packet_length);
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }
                
                memcpy(packet.get(), length_hex, length_dec);
                memcpy(packet.get() + length_dec, json_string.data(), json_string.size());
                bool ok = websocket->Write(packet.get(), 0, packet_length,
                    [websocket, packet](bool ok) noexcept {
                        if (!ok) {
                            websocket->Dispose();
                        }
                    });
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketWriteFailed);
                }
                return ok;
            }

            template <typename TWebSocketPtr>
            /**
             * @brief Reads one length-prefixed binary packet from websocket stream.
             */
            static std::shared_ptr<Byte> PACKET_ReadBinaryPacket(std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, TWebSocketPtr& websocket, int& packet_length, ppp::coroutines::YieldContext& y) noexcept {
                char length_hex[8];
                if (!websocket->Read(length_hex, 0, sizeof(length_hex), y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketReadFailed);
                    return NULLPTR;
                }

                Int128 length_value = ppp::Int128FromString(ppp::string(length_hex, sizeof(length_hex)), 16);
                if (length_value > static_cast<Int128>(std::numeric_limits<int>::max())) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOverflow);
                    return NULLPTR;
                }

                int length_num = static_cast<int>(length_value);
                if (length_num < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return NULLPTR;
                }

                std::shared_ptr<Byte> packet = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length_num);
                if (NULLPTR == packet) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }

                if (!websocket->Read(packet.get(), 0, length_num, y)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketReadFailed);
                    return NULLPTR;
                }

                packet_length = length_num;
                return packet;
            }

            template <typename TWebSocketPtr>
            /**
             * @brief Reads one length-prefixed packet and parses it as JSON object.
             */
            static bool PACKET_ReadJsonPacket(std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, TWebSocketPtr& websocket, Json::Value& json, ppp::coroutines::YieldContext& y) noexcept {
                int packet_length = 0;
                std::shared_ptr<Byte> packet = PACKET_ReadBinaryPacket(allocator, websocket, packet_length, y);
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                    return false;
                }

                json = JsonAuxiliary::FromString((char*)packet.get(), packet_length);
                if (!json.isObject()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericParseFailed);
                }
                return json.isObject();
            }

            /** @brief Sends a command packet without additional payload. */
            bool VirtualEthernetManagedServer::SendToManagedServer(const ppp::Int128& session_id, int cmd, int id) noexcept {
                return SendToManagedServer(session_id, cmd, id, ppp::string());
            }

            /** @brief Sends a command packet with JSON payload. */
            bool VirtualEthernetManagedServer::SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const Json::Value& data) noexcept {
                auto allocator = configuration_->GetBufferAllocator();
                int node = switcher_->GetNode();
                return PACKET_SendToManagedServer<WebSocket>(allocator, server_, session_id, cmd, id, node, data);
            }

            /** @brief Sends a command packet with string payload. */
            bool VirtualEthernetManagedServer::SendToManagedServer(const ppp::Int128& session_id, int cmd, int id, const ppp::string& data) noexcept {
                auto allocator = configuration_->GetBufferAllocator();
                int node = switcher_->GetNode();
                return PACKET_SendToManagedServer<WebSocket>(allocator, server_, session_id, cmd, id, node, data);
            }

            /** @brief Asynchronously validates managed-server URI and caches normalized form. */
            bool VirtualEthernetManagedServer::TryVerifyUriAsync(const ppp::string& url, const TryVerifyUriAsyncCallback& ac) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                if (url.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return false;
                }

                if (NULLPTR == ac) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return false;
                }

                auto self = shared_from_this();
                auto context = context_;
                
                bool ok = YieldContext::Spawn(allocator_.get(), *context,
                    [self, this, ac, url, context](YieldContext& y) noexcept {
                        ppp::string host;
                        ppp::string path;
                        boost::asio::ip::tcp::endpoint remoteEP;
                        bool ssl;

                        auto url_new = GetManagedServerEndPoint(url, host, path, remoteEP, ssl, y);
                        auto verify_ok = url_new.size() > 0;
                        if (verify_ok) {
                            url_ = std::move(url_new);
                        }

                        boost::asio::post(y.GetContext(), 
                            [verify_ok, ac]() noexcept {
                                ac(verify_ok);
                            });
                    });
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                }
                return ok;
            }

            /** @brief Parses managed-server URI and resolves transport endpoint details. */
            ppp::string VirtualEthernetManagedServer::GetManagedServerEndPoint(const ppp::string& url, ppp::string& host, ppp::string& path, boost::asio::ip::tcp::endpoint& remoteEP, bool& ssl, YieldContext& y) noexcept {
                using ProtocolType = UriAuxiliary::ProtocolType;

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return "";
                }

                if (url.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                    return "";
                }

                ppp::string address;
                ppp::string server;
                int port;
                ProtocolType protocol_type = ProtocolType::ProtocolType_Http;

                ppp::string url_new = UriAuxiliary::Parse(url, host, address, path, port, protocol_type, y);
                if (url_new.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::HttpRequestFailed);
                    return "";
                }

                if (host.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return "";
                }

                if (address.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsResolveFailed);
                    return "";
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                    return "";
                }

                if (protocol_type == ProtocolType::ProtocolType_Http ||
                    protocol_type == ProtocolType::ProtocolType_WebSocket) {
                    ssl = false;
                }
                elif(protocol_type == ProtocolType::ProtocolType_HttpSSL ||
                    protocol_type == ProtocolType::ProtocolType_WebSocketSSL) {
                    ssl = true;
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkProtocolUnsupported);
                    return "";
                }

                IPEndPoint ipep(address.data(), port);
                if (IPEndPoint::IsInvalid(ipep)) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                    return "";
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return "";
                }

                remoteEP = IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(ipep);
                return url_new;
            }

            /** @brief Persistent reconnect loop for managed-server websocket session. */
            void VirtualEthernetManagedServer::RunInner(const ppp::string& url, YieldContext& y) noexcept {
                while (!disposed_) {
                    IWebScoketPtr websocket = NewWebSocketConnectToManagedServer2(url, y);
                    if (websocket) {
                        server_ = websocket; {
                            Run(websocket, y); {
                                server_.reset();
                            }
                        }
                        
                        websocket->Dispose();
                    }

                    reconnecting_ = true;
                    ppp::coroutines::asio::async_sleep(y, PACKET_TIMEOUT_RECONNECT);
                    reconnecting_ = false;
                }
            }

            /** @brief Disposes active websocket and marks component as disposed. */
            void VirtualEthernetManagedServer::Dispose() noexcept {
                IWebScoketPtr websocket = std::move(server_); 
                disposed_ = true;

                if (NULLPTR != websocket) {
                    websocket->Dispose();
                }
            }

            /** @brief Main receive loop that dispatches managed-server commands. */
            void VirtualEthernetManagedServer::Run(IWebScoketPtr& websocket, YieldContext& y) noexcept {
                int node = switcher_->GetNode();
                while (!disposed_) {
                    Json::Value json;
                    if (!PACKET_ReadJsonPacket(allocator_, websocket, json, y)) {
                        break;
                    }

                    int node_var = JsonAuxiliary::AsValue<int>(json["Node"]);
                    if (node_var != node) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                        break;
                    }

                    int cmd_var = JsonAuxiliary::AsValue<int>(json["Cmd"]);
                    if (cmd_var == PACKET_CMD_ECHO) {
                        continue;
                    }
                    elif(cmd_var == PACKET_CMD_AUTHENTICATION) {
                        AckAuthenticationToManagedServer(json, y);
                    }
                    elif(cmd_var == PACKET_CMD_TRAFFIC) {
                        AckAllUploadTrafficToManagedServer(json, y);
                    }
                    else {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                        break;
                    }
                }
            }

            /** @brief Applies traffic response entries by feeding information to switcher. */
            bool VirtualEthernetManagedServer::AckAllUploadTrafficToManagedServer(Json::Value& json, YieldContext& y) noexcept {
                Json::Value json_array = JsonAuxiliary::FromString(JsonAuxiliary::AsString(json["Data"]));
                if (!json_array.isObject()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                json_array = json_array["List"];
                if (!json_array.isArray()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                bool any = false;
                Json::ArrayIndex json_array_size = json_array.size();

                for (Json::ArrayIndex json_array_index = 0; json_array_index < json_array_size; json_array_index++) {
                    Json::Value& json_object = json_array[json_array_index];
                    if (!json_object.isObject()) {
                        continue;
                    }

                    ppp::string guid = JsonAuxiliary::AsString(json_object["Guid"]);
                    if (guid.empty()) {
                        continue;
                    }

                    std::shared_ptr<VirtualEthernetInformation> info = VirtualEthernetInformation::FromJson(json_object);
                    if (NULLPTR == info) {
                        continue;
                    }

                    Int128 session_id = StringAuxiliary::GuidStringToInt128(guid);
                    any |= switcher_->OnInformation(session_id, info, y);
                }
                return any;
            }

            /** @brief Completes one authentication waiter using response packet content. */
            bool VirtualEthernetManagedServer::AckAuthenticationToManagedServer(Json::Value& json, YieldContext& y) noexcept {
                ppp::string guid = JsonAuxiliary::AsString(json["Guid"]);
                if (guid.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionIdInvalid);
                    return false;
                }

                Int128 session_id = StringAuxiliary::GuidStringToInt128(guid);
                AuthenticationToManagedServerAsyncCallback f = DeleteAuthenticationToManagedServer(session_id);
                if (!f) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionNotFound);
                    return false;
                }

                std::shared_ptr<VirtualEthernetInformation> i;
                if (!i) {
                    Json::Value jo = json["Data"];
                    if (jo.isObject()) {
                        i = VirtualEthernetInformation::FromJson(jo);
                    }
                    elif(jo.isString()) {
                        jo = JsonAuxiliary::FromString(JsonAuxiliary::AsString(jo));
                        i = VirtualEthernetInformation::FromJson(jo);
                    }
                }

                if (!i) {
                    VirtualEthernetInformationPtr nullVEI;
                    f(false, nullVEI);
                    return true;
                }

                f(i->Valid(), i);
                return true;
            }

            /** @brief Accumulates traffic deltas for later batched upload. */
            void VirtualEthernetManagedServer::UploadTrafficToManagedServer(const ppp::Int128& session_id, int64_t rx, int64_t tx) noexcept {
                if ((session_id != 0) && (rx != 0 || tx != 0)) {
                    SynchronizedObjectScope scope(syncobj_);
                    UploadTrafficTask& task = traffics_[session_id];
                    task.rx += rx;
                    task.tx += tx;
                }
            }

            /** @brief Flushes queued traffic tasks to managed server at fixed interval. */
            bool VirtualEthernetManagedServer::TickAllUploadTrafficToManagedServer(UInt64 now) noexcept {
                if (traffics_next_ == 0) {
                    traffics_next_ = now + PACKET_TIMEOUT_TRAFFIC;
                    return true;
                }

                if (now < traffics_next_) {
                    return false;
                }

                Json::Value json;
                Json::Value& json_array = json["Tasks"];

                UploadTrafficTaskTable traffics; {
                    SynchronizedObjectScope scope(syncobj_);
                    traffics = std::move(traffics_);
                    traffics_.clear();
                }

                for (auto&& [guid, task] : traffics) {
                    Json::Value json_value;
                    json_value["Guid"] = StringAuxiliary::Int128ToGuidString(guid);
                    json_value["RX"] = stl::to_string<ppp::string>(task.tx); // server:tx = client:rx
                    json_value["TX"] = stl::to_string<ppp::string>(task.rx); // server:rx = client:tx
                    json_array.append(json_value);
                }

                traffics_next_ = now + PACKET_TIMEOUT_TRAFFIC;
                if (json_array.isArray()) {
                    int id = NewId();
                    SendToManagedServer(0, PACKET_CMD_TRAFFIC, id, JsonAuxiliary::ToString(json));
                }

                return true;
            }

            /** @brief Establishes websocket then performs protocol connect handshake. */
            VirtualEthernetManagedServer::IWebScoketPtr VirtualEthernetManagedServer::NewWebSocketConnectToManagedServer2(const ppp::string& url, YieldContext& y) noexcept {
                IWebScoketPtr websocket = NewWebSocketConnectToManagedServer(url, y);
                if (NULLPTR == websocket) {
                    if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                    }
                    return NULLPTR;
                }

                int id = NewId();
                int node = switcher_->GetNode();

                auto allocator = configuration_->GetBufferAllocator();
                bool ok = PACKET_SendToManagedServer<WebSocket>(allocator, websocket, 0, PACKET_CMD_CONNECT, id, node, configuration_->server.backend_key);

                /**
                 * @brief RAII guard that disposes websocket when handshake fails.
                 */
                class websocket_auto_destroy final {
                public:
                    websocket_auto_destroy(IWebScoketPtr& websocket, bool& ok) noexcept
                        : ws_(websocket)
                        , ok_(ok) {

                    }
                    ~websocket_auto_destroy() noexcept {
                        if (!ok_) {
                            IWebScoketPtr p = ws_;
                            if (NULLPTR != p) {
                                p->Dispose();
                            }
                        }
                    }

                private:
                    IWebScoketPtr&  ws_;
                    bool&           ok_; /* native websocket pointer. */
                } websocket_auto_destroy_(websocket, ok);

                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketWriteFailed);
                    return NULLPTR;
                }

                auto self = shared_from_this();
                std::shared_ptr<Timer> timeout = Timer::Timeout(context_, PACKET_TIMEOUT_CONNECT,
                    [self, this, websocket](Timer*) noexcept {
                        websocket->Dispose();
                    });
                if (NULLPTR == timeout) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerCreateFailed);
                    return NULLPTR;
                }

                Json::Value json;
                ok = PACKET_ReadJsonPacket(allocator_, websocket, json, y);

                timeout->Dispose();
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketReadFailed);
                    return NULLPTR;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return NULLPTR;
                }

                int cmd = JsonAuxiliary::AsValue<int>(json["Cmd"]);
                if (cmd != PACKET_CMD_CONNECT) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    return NULLPTR;
                }

                int node_value = JsonAuxiliary::AsValue<int>(json["Node"]);
                if (node_value != node) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    return NULLPTR;
                }

                ppp::string data = JsonAuxiliary::AsString(json["Data"]);
                if (!ToBoolean(data.data())) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionAuthFailed);
                }
                return ToBoolean(data.data()) ? websocket : NULLPTR;
            }

            /** @brief Opens TCP/TLS websocket transport and completes network handshake. */
            VirtualEthernetManagedServer::IWebScoketPtr VirtualEthernetManagedServer::NewWebSocketConnectToManagedServer(const ppp::string& url, YieldContext& y) noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return NULLPTR;
                }
                
                ppp::string host;
                ppp::string path;
                boost::asio::ip::tcp::endpoint remoteEP;
                bool ssl;

                auto url_new = GetManagedServerEndPoint(url, host, path, remoteEP, ssl, y);
                if (url_new.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                    return NULLPTR;
                }

                auto socket = make_shared_object<boost::asio::ip::tcp::socket>(*context_);
                if (NULLPTR == socket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketCreateFailed);
                    return NULLPTR;
                }

                boost::system::error_code ec;
                socket->open(remoteEP.protocol(), ec);
                if (ec) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                    return NULLPTR;
                }
                
                boost::asio::ip::address remoteIP = remoteEP.address();
                ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                ppp::net::Socket::AdjustSocketOptional(*socket, remoteIP.is_v4(), configuration_->tcp.fast_open, configuration_->tcp.turbo);

                bool connect_ok = ppp::coroutines::asio::async_connect(*socket, remoteEP, y);
                if (!connect_ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                    return NULLPTR;
                }

                bool binary = false;
                auto websocket = make_shared_object<IWebSocket>();
                if (NULLPTR == websocket) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                    return NULLPTR;
                }

                ppp::threading::Executors::StrandPtr strand;
                if (ssl) {
                    auto wss = make_shared_object<WebSocketSsl>(context_, strand, socket, binary);
                    if (NULLPTR == wss) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                        return NULLPTR;
                    }

                    websocket->wss = std::move(wss);
                }
                else {
                    auto ws = make_shared_object<WebSocket>(context_, strand, socket, binary);
                    if (NULLPTR == ws) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                        return NULLPTR;
                    }

                    websocket->ws = std::move(ws);
                }

                bool running = websocket->Run(WebSocket::HandshakeType_Client, host, path, y);
                if (!running) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                    return NULLPTR;
                }

                if (disposed_) {
                    websocket->Dispose();
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return NULLPTR;
                }
                else {
                    return websocket;
                }
            }

            /** @brief Disposes the active plain/TLS websocket endpoint. */
            void VirtualEthernetManagedServer::IWebSocket::Dispose() noexcept {
                if (std::shared_ptr<WebSocket> p = std::move(ws); NULLPTR != p) {
                    p->Dispose();
                }

                if (std::shared_ptr<WebSocketSsl> p = std::move(wss); NULLPTR != p) {
                    p->Dispose();
                }
            }

            /** @brief Returns whether current websocket endpoint is disposed. */
            bool VirtualEthernetManagedServer::IWebSocket::IsDisposed() noexcept {
                if (auto p = ws; NULLPTR != p) {
                    return p->IsDisposed();
                }

                if (auto p = wss; NULLPTR != p) {
                    return p->IsDisposed();
                }

                return true;
            }

            /** @brief Reads bytes from whichever websocket backend is active. */
            bool VirtualEthernetManagedServer::IWebSocket::Read(const void* buffer, int offset, int length, YieldContext& y) noexcept {
                if (auto p = ws; NULLPTR != p) {
                    return p->Read(buffer, offset, length, y);
                }

                if (auto p = wss; NULLPTR != p) {
                    return p->Read(buffer, offset, length, y);
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                return false;
            }

            /** @brief Executes websocket handshake for plain or TLS backend. */
            bool VirtualEthernetManagedServer::IWebSocket::Run(HandshakeType type, const ppp::string& host, const ppp::string& path, YieldContext& y) noexcept {
                if (auto p = ws; NULLPTR != p) {
                    return p->Run(type, host, path, y);
                }

                // Do not verify SSL server and only perform one-way authentication instead of mutual authentication, 
                // As the server's certificate may have expired or it could be a private certificate. 
                // There is no need for SSL/TLS mutual authentication in this cases.
                if (auto p = wss; NULLPTR != p) {
                    std::string ssl_certificate_file;
                    std::string ssl_certificate_key_file;
                    std::string ssl_certificate_chain_file;
                    std::string ssl_certificate_key_password;
                    std::string ssl_ciphersuites = GetDefaultCipherSuites();
                    bool verify_peer = false;

                    return p->Run(type, host, path, verify_peer,
                        ssl_certificate_file,
                        ssl_certificate_key_file,
                        ssl_certificate_chain_file,
                        ssl_certificate_key_password,
                        ssl_ciphersuites,
                        y);
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                return false;
            }

            /** @brief Writes bytes to whichever websocket backend is active. */
            bool VirtualEthernetManagedServer::IWebSocket::Write(const void* buffer, int offset, int length, const AsynchronousWriteCallback& cb) noexcept {
                if (auto p = ws; NULLPTR != p) {
                    return p->Write(buffer, offset, length, cb);
                }

                if (auto p = wss; NULLPTR != p) {
                    return p->Write(buffer, offset, length, cb);
                }

                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                return false;
            }
        }
    }
}
