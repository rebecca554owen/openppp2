#include <ppp/app/protocol/VirtualEthernetTcpipConnection.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/app/client/VEthernetNetworkTcpipConnection.h>
#include <ppp/app/client/proxys/VEthernetSocksProxySwitcher.h>
#include <ppp/app/client/proxys/VEthernetSocksProxyConnection.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VEthernetSocksProxyConnection.cpp
 * @brief Implements SOCKS5 handshake and request processing for local proxy clients.
 */

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief SOCKS5 protocol version.
                 */
                static constexpr int SOCKS_VER                  = 5;
                /**
                 * @brief SOCKS5 "no authentication" method id.
                 */
                static constexpr int SOCKS_METHOD_NONE          = 0;
                /**
                 * @brief SOCKS5 username/password authentication method id.
                 */
                static constexpr int SOCKS_METHOD_AUTH          = 2;
                /**
                 * @brief SOCKS5 "no acceptable methods" marker.
                 */
                static constexpr int SOCKS_METHOD_RSVD          = 255;
                /**
                 * @brief Internal error return code for transport failures.
                 */
                static constexpr int SOCKS_ERR_ER               = -1;
                /**
                 * @brief Success return code.
                 */
                static constexpr int SOCKS_ERR_OK               = 0;
                /**
                 * @brief Generic protocol rejection return code.
                 */
                static constexpr int SOCKS_ERR_NO               = 1;
                /**
                 * @brief SOCKS reply code for unsupported command.
                 */
                static constexpr int SOCKS_ERR_CMD              = 7;
                /**
                 * @brief SOCKS reply code for unsupported address type.
                 */
                static constexpr int SOCKS_ERR_ATYPE            = 8;
                /**
                 * @brief Username/password sub-protocol failure status.
                 */
                static constexpr int SOCKS_ERR_FF               = 255;
                /**
                 * @brief Username/password sub-protocol version.
                 */
                static constexpr int SOCKS_PROTO_AUTH           = 1;
                /**
                 * @brief SOCKS address type id for IPv4 addresses.
                 */
                static constexpr int SOCKS_ATYPE_IPV4           = 1;
                /**
                 * @brief SOCKS address type id for IPv6 addresses.
                 */
                static constexpr int SOCKS_ATYPE_IPV6           = 4;
                /**
                 * @brief SOCKS address type id for domain names.
                 */
                static constexpr int SOCKS_ATYPE_DOMAIN         = 3;
                /**
                 * @brief SOCKS command id for CONNECT.
                 */
                static constexpr int SOCKS_CMD_CONNECT          = 1;
                /**
                 * @brief SOCKS command id for UDP ASSOCIATE.
                 */
                static constexpr int SOCKS_CMD_UDP              = 3;

                /**
                 * @brief Constructs a SOCKS proxy connection instance.
                 * @param proxy Parent SOCKS switcher that owns this connection.
                 * @param exchanger Shared exchanger used to establish remote bridge channels.
                 * @param context I/O context used by asynchronous operations.
                 * @param strand Strand that serializes callbacks.
                 * @param socket Accepted client TCP socket.
                 */
                VEthernetSocksProxyConnection::VEthernetSocksProxyConnection(
                    const VEthernetSocksProxySwitcherPtr&                           proxy,
                    const VEthernetExchangerPtr&                                    exchanger, 
                    const std::shared_ptr<boost::asio::io_context>&                 context,
                    const ppp::threading::Executors::StrandPtr&                     strand,
                    const std::shared_ptr<boost::asio::ip::tcp::socket>&            socket) noexcept 
                    : VEthernetLocalProxyConnection(proxy, exchanger, context, strand, socket) {
                
                }
                
                /**
                 * @brief Sends a SOCKS5 request-reply packet containing local bind endpoint.
                 * @param socket Connected client socket.
                 * @param rep SOCKS reply code.
                 * @param y Coroutine yield context.
                 * @return true if the packet is written successfully; otherwise false.
                 * @note The address in the reply is derived from the socket local endpoint.
                 */
                static bool SendSocksRequestReply(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, Byte rep, ppp::coroutines::YieldContext& y) noexcept {
                    if (NULLPTR == socket || !socket->is_open()) {
                        return false;
                    }

                    Byte data[32];
                    int packet_length = 0;
                    data[packet_length++] = SOCKS_VER;
                    data[packet_length++] = rep;
                    data[packet_length++] = 0;

                    boost::system::error_code ec;
                    boost::asio::ip::tcp::endpoint local_endpoint = socket->local_endpoint(ec);
                    if (ec) {
                        local_endpoint = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), 0);
                    }
                    else {
                        local_endpoint = ppp::net::Ipep::V6ToV4(local_endpoint);
                    }

                    boost::asio::ip::address local_ip = local_endpoint.address();
                    if (local_ip.is_v4()) {
                        data[packet_length++] = SOCKS_ATYPE_IPV4;
                        auto bytes = local_ip.to_v4().to_bytes();
                        memcpy(data + packet_length, bytes.data(), bytes.size());
                        packet_length += bytes.size();
                    }
                    elif(local_ip.is_v6()) {
                        data[packet_length++] = SOCKS_ATYPE_IPV6;
                        auto bytes = local_ip.to_v6().to_bytes();
                        memcpy(data + packet_length, bytes.data(), bytes.size());
                        packet_length += bytes.size();
                    }
                    else {
                        data[packet_length++] = SOCKS_ATYPE_IPV4;
                        memset(data + packet_length, 0, 4);
                        packet_length += 4;
                    }

                    int local_port = local_endpoint.port();
                    data[packet_length++] = (Byte)(local_port >> 8);
                    data[packet_length++] = (Byte)(local_port);

                    return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, packet_length), y);
                }

                /**
                 * @brief Executes the full SOCKS5 handshake and target bridge setup.
                 * @param y Coroutine yield context.
                 * @return true when handshake and bridge connection both succeed.
                 */
                bool VEthernetSocksProxyConnection::Handshake(YieldContext& y) noexcept {
                    int method = SOCKS_METHOD_NONE;
                    int status = SelectMethod(y, method); 
                    if (status <= SOCKS_ERR_ER) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                        return false;
                    }
                    elif(status >= SOCKS_ERR_NO) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthChallengeFailed);
                        Replay(y, SOCKS_VER, SOCKS_METHOD_RSVD);
                        return false;
                    }
                    elif(!Replay(y, SOCKS_VER, method)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                        return false;
                    }
                    elif(method == SOCKS_METHOD_AUTH) {
                        status = Authentication(y);
                        if (status <= SOCKS_ERR_ER) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                            return false;
                        }
                        elif(status >= SOCKS_ERR_NO) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthCredentialInvalid);
                            Replay(y, SOCKS_PROTO_AUTH, SOCKS_ERR_FF);
                            return false;
                        }
                        elif(!Replay(y, SOCKS_PROTO_AUTH, SOCKS_ERR_OK)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                            return false;
                        }
                    }

                    int port = ppp::net::IPEndPoint::MinPort;
                    ppp::string host;
                    ppp::app::protocol::AddressType address_type = ppp::app::protocol::AddressType::Domain;

                    int command_status = Requirement(y, host, port, address_type);
                    if (command_status != SOCKS_ERR_OK) {
                        ppp::diagnostics::SetLastErrorCode(command_status == SOCKS_ERR_ATYPE ?
                            ppp::diagnostics::ErrorCode::NetworkAddressInvalid :
                            ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                        SendSocksRequestReply(GetSocket(), (Byte)command_status, y);
                        return false;
                    }

                    std::shared_ptr<ppp::app::protocol::AddressEndPoint> address_endpoint = make_shared_object<ppp::app::protocol::AddressEndPoint>();
                    if (NULLPTR == address_endpoint) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    }

                    address_endpoint->Type = address_type;
                    address_endpoint->Host = host;
                    address_endpoint->Port = port;

                    if (!ConnectBridgeToPeer(address_endpoint, y)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TcpConnectFailed);
                        SendSocksRequestReply(GetSocket(), SOCKS_ERR_NO, y);
                        return false;
                    }

                    return true;
                }

                /**
                 * @brief Validates SOCKS username/password credentials.
                 * @param y Coroutine yield context.
                 * @return SOCKS_ERR_OK when credentials match configuration; otherwise an error code.
                 * @note Credentials are read using SOCKS5 username/password sub-negotiation framing.
                 */
                int VEthernetSocksProxyConnection::Authentication(YieldContext& y) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    if (NULLPTR == socket || !socket->is_open()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return SOCKS_ERR_ER;
                    }

                    AppConfigurationPtr& configuration = GetConfiguration();
                    auto& socks_proxy = configuration->client.socks_proxy;

                    Byte data[256];
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                        return SOCKS_ERR_ER;
                    }

                    if (data[0] != SOCKS_PROTO_AUTH) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthChallengeFailed);
                        return SOCKS_ERR_NO;
                    }

                    ppp::string strings[2];
                    for (int i = 0; i < arraysizeof(strings); i++) {
                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                            return SOCKS_ERR_ER;
                        }

                        int string_size = data[0];
                        if (string_size > 0) {
                            if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, string_size), y)) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                                return SOCKS_ERR_ER;
                            }

                            data[string_size] = '\x0';
                            strings[i] = reinterpret_cast<char*>(data);
                        }
                    }

                    if (socks_proxy.username != strings[0] || socks_proxy.password != strings[1]) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthCredentialInvalid);
                        return SOCKS_ERR_NO;
                    }

                    return SOCKS_ERR_OK;
                }

                /**
                 * @brief Sends a two-byte protocol reply message.
                 * @param y Coroutine yield context.
                 * @param k First reply byte.
                 * @param v Second reply byte.
                 * @return true if write succeeds; otherwise false.
                 */
                bool VEthernetSocksProxyConnection::Replay(YieldContext& y, int k, int v) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    if (NULLPTR == socket || !socket->is_open()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketDisconnected);
                    }

                    if (IsDisposed()) {
                        return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SessionDisposed);
                    }

                    Byte data[2] = { (Byte)k, (Byte)v };
                    return ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, sizeof(data)), y);
                }

                /**
                 * @brief Negotiates SOCKS5 authentication method with the client.
                 * @param y Coroutine yield context.
                 * @param method Output negotiated method.
                 * @return SOCKS status code for success, protocol rejection, or transport error.
                 */
                int VEthernetSocksProxyConnection::SelectMethod(YieldContext& y, int& method) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    method = SOCKS_METHOD_NONE;

                    if (NULLPTR == socket || !socket->is_open()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return SOCKS_ERR_ER;
                    }

                    Byte data[256];
                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                        return SOCKS_ERR_ER;
                    }

                    int nver = data[0];
                    if (nver != SOCKS_VER) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthChallengeFailed);
                        return SOCKS_ERR_NO;
                    }

                    int nmethod = data[1];
                    AppConfigurationPtr& configuration = GetConfiguration();
                    auto& socks_proxy = configuration->client.socks_proxy;
                    bool no_auth = socks_proxy.username.empty() && socks_proxy.password.empty();

                    if (nmethod == SOCKS_METHOD_NONE) {
                        if (!no_auth) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthCredentialMissing);
                        }
                        return no_auth ? SOCKS_ERR_OK : SOCKS_ERR_NO;
                    }
                    elif(nmethod < SOCKS_METHOD_NONE) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AuthChallengeFailed);
                        return SOCKS_ERR_NO;
                    }

                    if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, nmethod), y)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                        return SOCKS_ERR_ER;
                    }

                    for (int i = 0; i < nmethod; i++) {
                        Byte m = data[i];
                        if (m == SOCKS_METHOD_RSVD) {
                            continue;
                        }
                        elif(m == SOCKS_METHOD_NONE) {
                            if (no_auth) {
                                return SOCKS_ERR_OK;
                            }
                        }
                        elif(m == SOCKS_METHOD_AUTH) {
                            if (!no_auth) {
                                method = m;
                            }

                            return SOCKS_ERR_OK;
                        }
                    }

                    return no_auth ? SOCKS_ERR_OK : SOCKS_ERR_NO;
                }
            
                /**
                 * @brief Parses SOCKS5 CONNECT request and replies with bind endpoint information.
                 * @param y Coroutine yield context.
                 * @param address Output destination host string.
                 * @param port Output destination port in host order.
                 * @param address_type Output parsed address type.
                 * @return SOCKS status code indicating request parse and reply result.
                 * @note This routine both parses input request and writes the required request reply.
                 */
                int VEthernetSocksProxyConnection::Requirement(YieldContext& y, ppp::string& address, int& port, ppp::app::protocol::AddressType& address_type) noexcept {
                    std::shared_ptr<boost::asio::ip::tcp::socket>& socket = GetSocket();
                    address.clear();

                    port = ppp::net::IPEndPoint::MinPort;
                    address_type = ppp::app::protocol::AddressType::Domain;

                    if (NULLPTR == socket || !socket->is_open()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketDisconnected);
                        return SOCKS_ERR_ER;
                    }

                    if (IsDisposed()) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                        return SOCKS_ERR_ER;
                    }
                    
                    Byte cmd = SOCKS_ERR_CMD;
                    Byte data[256];

                    /**
                     * @brief Parse request header, destination address, and destination port.
                     */
                    for (;;) {
                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 4), y)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                            return SOCKS_ERR_ER;
                        }

                        if (data[0] != SOCKS_VER) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                            return SOCKS_ERR_CMD;
                        }

                        if (data[1] != SOCKS_CMD_CONNECT) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                            return SOCKS_ERR_CMD;
                        }

                        int address_type = data[3];
                        int address_length = 0;
                        if (address_type == SOCKS_ATYPE_IPV4) {
                            address_length = 4;
                            address_type = ppp::app::protocol::AddressType::IPv4;
                        }
                        elif(address_type == SOCKS_ATYPE_IPV6) {
                            address_length = 16;
                            address_type = ppp::app::protocol::AddressType::IPv6;
                        }
                        elif(address_type == SOCKS_ATYPE_DOMAIN) {
                            if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 1), y)) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                                return SOCKS_ERR_ER;
                            }

                            address_length = data[0];
                            address_type = ppp::app::protocol::AddressType::Domain;
                        }
                        else {
                            cmd = SOCKS_ERR_ATYPE;
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                            return SOCKS_ERR_ATYPE;
                        }

                        if (address_length < 1) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkAddressInvalid);
                            return SOCKS_ERR_ATYPE;
                        }

                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, address_length), y)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                            return SOCKS_ERR_ER;
                        }

                        switch (address_type) {
                        case SOCKS_ATYPE_IPV4: {
                                boost::asio::ip::address_v4::bytes_type bytes;
                                memset(bytes.data(), 0, bytes.size());
                                memcpy(bytes.data(), data, address_length);

                                address = boost::asio::ip::address_v4(bytes).to_string();
                            }
                            break;
                        case SOCKS_ATYPE_IPV6: {
                                boost::asio::ip::address_v6::bytes_type bytes;
                                memset(bytes.data(), 0, bytes.size());
                                memcpy(bytes.data(), data, address_length);

                                address = boost::asio::ip::address_v6(bytes).to_string();
                            }
                            break;
                        default: {
                                data[address_length] = '\x0';
                                address = reinterpret_cast<char*>(data);
                            }
                            break;
                        };

                        if (!ppp::coroutines::asio::async_read(*socket, boost::asio::buffer(data, 2), y)) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketReadFailed);
                            return SOCKS_ERR_ER;
                        }

                        cmd = SOCKS_ERR_OK;
                        port = data[0] << 8 | data[1];
                        break;
                    }

                    /**
                     * @brief Build and send the SOCKS5 request-reply packet to acknowledge CONNECT.
                     */
                    for (;;) {
                        int packet_length = 0;
                        data[packet_length++] = SOCKS_VER;
                        data[packet_length++] = cmd;
                        data[packet_length++] = 0;

                        boost::system::error_code ec;
                        boost::asio::ip::tcp::endpoint local_endpoint = socket->local_endpoint(ec);
                        if (ec) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                            return SOCKS_ERR_ER;
                        }
                        else {
                            local_endpoint = ppp::net::Ipep::V6ToV4(local_endpoint);
                        }
                    
                        boost::asio::ip::address local_ip = local_endpoint.address();
                        if (local_ip.is_v4()) {
                            data[packet_length++] = SOCKS_ATYPE_IPV4;

                            boost::asio::ip::address_v4 in4 = local_ip.to_v4();
                            boost::asio::ip::address_v4::bytes_type bytes = in4.to_bytes();
                            memcpy(data + packet_length, bytes.data(), bytes.size());

                            packet_length += bytes.size();
                        }
                        elif(local_ip.is_v6()) {
                            data[packet_length++] = SOCKS_ATYPE_IPV6;

                            boost::asio::ip::address_v6 in6 = local_ip.to_v6();
                            boost::asio::ip::address_v6::bytes_type bytes = in6.to_bytes();
                            memcpy(data + packet_length, bytes.data(), bytes.size());
                            
                            packet_length += bytes.size();
                        }
                        else {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketAddressInvalid);
                            return SOCKS_ERR_ER;
                        }

                        int local_port = local_endpoint.port();
                        data[packet_length++] = (Byte)(local_port >> 8);
                        data[packet_length++] = (Byte)(local_port);

                        bool writed = ppp::coroutines::asio::async_write(*socket, boost::asio::buffer(data, packet_length), y);
                        if (!writed) {
                            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketWriteFailed);
                            return SOCKS_ERR_ER;
                        }

                        return SOCKS_ERR_OK;
                    }
                }
            }
        }
    }
}
