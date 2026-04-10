#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>
#include <ppp/IDisposable.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>

namespace ppp {
    namespace app {
        namespace protocol {
            // Maximum buffer size for UDP packets
            static constexpr int PPP_UDP_BUFFER_SIZE = 65000;
            // Maximum buffer size for TCP packets (same as UDP for simplicity)
            static constexpr int PPP_TCP_BUFFER_SIZE = PPP_UDP_BUFFER_SIZE;

            // Constructor: initializes the mapping port with given parameters
            VirtualEthernetMappingPort::VirtualEthernetMappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept
                : disposed_(FALSE)                      // Initially not disposed
                , linklayer_(linklayer)                 // Store linklayer reference
                , transmission_(transmission)           // Store transmission reference
                , tcp_(tcp)                             // Store protocol type (TCP/UDP)
                , in_(in)                               // Store IP version (IPv4/IPv6)
                , remote_port_(remote_port)             // Store remote port
                , context_(linklayer->GetContext()) {   // Get IO context from linklayer
                configuration_ = linklayer->GetConfiguration();   // Get app configuration
                buffer_allocator_ = configuration_->GetBufferAllocator(); // Get buffer allocator
            }

            // Destructor: ensures final cleanup
            VirtualEthernetMappingPort::~VirtualEthernetMappingPort() noexcept {
                Finalize();     // Release all resources
            }

            // Returns the associated IO context
            std::shared_ptr<boost::asio::io_context> VirtualEthernetMappingPort::GetContext() noexcept {
                return context_;
            }

            // Returns the linklayer instance
            std::shared_ptr<VirtualEthernetLinklayer> VirtualEthernetMappingPort::GetLinklayer() noexcept {
                return linklayer_;
            }

            // Returns the transmission instance
            VirtualEthernetMappingPort::ITransmissionPtr VirtualEthernetMappingPort::GetTransmission() noexcept {
                return transmission_;
            }

            // Returns true if the network protocol is TCP
            bool VirtualEthernetMappingPort::ProtocolIsTcpNetwork() noexcept {
                return tcp_;
            }

            // Returns true if the network protocol is UDP
            bool VirtualEthernetMappingPort::ProtocolIsUdpNetwork() noexcept {
                return !tcp_;
            }

            // Returns true if the network IP version is IPv4
            bool VirtualEthernetMappingPort::ProtocolIsNetworkV4() noexcept {
                return in_;
            }

            // Returns true if the network IP version is IPv6
            bool VirtualEthernetMappingPort::ProtocolIsNetworkV6() noexcept {
                return !in_;
            }

            // Returns the remote port number
            int VirtualEthernetMappingPort::GetRemotePort() noexcept {
                return remote_port_;
            }

            // Finalizes the mapping port: closes sockets and clears dictionaries
            void VirtualEthernetMappingPort::Finalize() noexcept {
                int disposed = disposed_.exchange(TRUE);   // Atomically set disposed flag to TRUE and get previous value
                transmission_.reset();                     // Release transmission reference

                if (disposed != TRUE) {                    // If not already disposed
                    std::shared_ptr<Server> server = std::move(server_);   // Take ownership of server
                    std::shared_ptr<Client> client = std::move(client_);   // Take ownership of client

                    if (NULLPTR != server) {               // If server exists
                        // Close UDP and TCP sockets
                        ppp::net::Socket::Closesocket(server->socket_udp_);
                        ppp::net::Socket::Closesocket(server->socket_tcp_);
                        // Release all connection objects
                        ppp::collections::Dictionary::ReleaseAllObjects(server->socket_connections_);
                    }

                    if (NULLPTR != client) {               // If client exists
                        // Release all connection and datagram port objects
                        ppp::collections::Dictionary::ReleaseAllObjects(client->socket_connections_);
                        ppp::collections::Dictionary::ReleaseAllObjects(client->socket_datagram_ports_);
                    }
                }
            }

            // Public dispose method calls Finalize
            void VirtualEthernetMappingPort::Dispose() noexcept {
                Finalize();
            }

#if defined(VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET)
#error "Compiler macro "OPENNETWORKSOCKET" definition conflict found, please check the project C/C++ code implementation for problems."
#else
// Helper macro to open a network socket (TCP or UDP) for the server
#define VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(SERVER_OBJ, PROTOCOL, SOCKET_OBJECT)           \
                auto& socket = SOCKET_OBJECT;                                                              \
                if (socket.is_open()) {                                                                    \
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                boost::system::error_code ec;                                                              \
                boost::asio::ip::address address;                                                          \
                if (in_) {                                                                                 \
                    address = boost::asio::ip::address_v4::any();                                          \
                    socket.open(PROTOCOL::v4(), ec);                                                       \
                }                                                                                          \
                else {                                                                                     \
                    address = boost::asio::ip::address_v6::any();                                          \
                    socket.open(PROTOCOL::v6(), ec);                                                       \
                }                                                                                          \
                                                                                                           \
                if (ec) {                                                                                  \
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                int handle = socket.native_handle();                                                       \
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, address.is_v4());                    \
                ppp::net::Socket::SetTypeOfService(handle);                                                \
                ppp::net::Socket::SetSignalPipeline(handle, false);                                        \
                ppp::net::Socket::ReuseSocketAddress(handle, remote_port_);                                \
                ppp::net::Socket::SetWindowSizeIfNotZero(handle,                                           \
                    configuration_->tcp.cwnd, configuration_->tcp.rwnd);                                   \
                                                                                                           \
                socket.set_option(PROTOCOL::socket::reuse_address(true), ec);                              \
                if (ec) {                                                                                  \
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                socket.set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec);          \
                socket.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(  \
                    configuration_->tcp.fast_open), ec);                                                   \
                                                                                                           \
                socket.bind(PROTOCOL::endpoint(address, remote_port_), ec);                                \
                if (ec) {                                                                                  \
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                auto local_ep = socket.local_endpoint(ec);                                                 \
                if (local_ep.port() != remote_port_) {                                                     \
                    return false;                                                                          \
                }                                                                                          \
                                                                                                           \
                SERVER_OBJ->socket_endpoint_ =                                                             \
                    ppp::net::IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(                                \
                            ppp::net::IPEndPoint::ToEndPoint(local_ep));

            // Opens a UDP socket for the server (datagram mode)
            bool VirtualEthernetMappingPort::OpenNetworkSocketDatagram() noexcept {
                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {                     // Server must exist
                    return false;
                }

                // Use the macro to open UDP socket
                VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(server, boost::asio::ip::udp, server->socket_udp_);
                return true;
            }

            // Opens a TCP acceptor for the server (stream mode)
            bool VirtualEthernetMappingPort::OpenNetworkSocketStream() noexcept {
                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {                     // Server must exist
                    return false;
                }

                // Use the macro to open TCP socket
                VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET(server, boost::asio::ip::tcp, server->socket_tcp_);
                return true;
            }
#undef VIRTUALETHERNETMAPPINGPORT_SOCKET_OPENNETWORKSOCKET
#endif

            // Opens the FRP server side (listening for incoming FRP connections)
            bool VirtualEthernetMappingPort::OpenFrpServer(const VirtualEthernetLoggerPtr& logger) noexcept {
                // Validate remote port range
                if (remote_port_ <= ppp::net::IPEndPoint::MinPort || remote_port_ > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                if (disposed_) {                             // Already disposed
                    return false;
                }

                if (client_) {                               // Cannot be both client and server
                    return false;
                }

                if (server_) {                               // Already a server
                    return false;
                }
                
                // Create a new server instance
                std::shared_ptr<Server> server = make_shared_object<Server>(this);
                if (!server) {
                    return false;
                }
                
                ITransmissionPtr transmission = transmission_;
                if (NULLPTR == transmission) {               // Need a valid transmission
                    return false;
                }

                if (tcp_) {                                  // TCP (stream) mode
                    bool opened = OpenNetworkSocketStream(); // Open TCP acceptor
                    if (!opened) {
                        return false;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::tcp::acceptor& acceptor = server->socket_tcp_;
                    acceptor.listen(configuration_->tcp.backlog, ec);   // Start listening

                    if (ec) {
                        ppp::net::Socket::Closesocket(acceptor);
                        return false;
                    }

                    // Start asynchronous accept loop
                    std::shared_ptr<VirtualEthernetMappingPort> self = shared_from_this();
                    bool accepted = ppp::net::Socket::AcceptLoopbackAsync(acceptor, 
                        [self, this, server](const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept {
                            return Server_AcceptFrpUserSocket(server, context, socket);
                        });
                    if (!accepted) {
                        ppp::net::Socket::Closesocket(acceptor);
                        return false;
                    }
                }
                else {                                       // UDP (datagram) mode
                    bool opened = OpenNetworkSocketDatagram(); // Open UDP socket
                    if (!opened) {
                        return false;
                    }

                    if (!LoopbackFrpServer()) {              // Start receive loop
                        ppp::net::Socket::Closesocket(server->socket_udp_);
                        return false;
                    }
                }

                server_ = server;                       // Publish only for the open/listen sequence
                logger_ = logger;                       // Store logger after successful startup
                return true;
            }

            // Returns the bound endpoint of the FRP server (if any)
            boost::asio::ip::tcp::endpoint VirtualEthernetMappingPort::BoundEndPointOfFrpServer() noexcept {
                std::shared_ptr<Server> server = server_;
                if (server) {
                    return server->socket_endpoint_;         // Return stored endpoint
                }

                // Return a dummy endpoint if no server
                return boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
            }

            // Starts the UDP receive loop for the server (datagram mode)
            bool VirtualEthernetMappingPort::LoopbackFrpServer() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return false;
                }

                bool opened = server->socket_udp_.is_open();
                if (!opened) {
                    return false;
                }

                // Asynchronously receive UDP datagrams
                std::shared_ptr<VirtualEthernetMappingPort> self = shared_from_this();
                server->socket_udp_.async_receive_from(boost::asio::buffer(server->socket_source_buf_.get(), PPP_UDP_BUFFER_SIZE), server->socket_source_ep_,
                    [self, this, server](boost::system::error_code ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::success) {
                            if (sz > 0) {
                                // Convert IPv6-mapped IPv4 to pure IPv4 if needed
                                boost::asio::ip::udp::endpoint natEP = ppp::net::Ipep::V6ToV4(server->socket_source_ep_);
                                Server_SendToFrpClient(server->socket_source_buf_.get(), sz, natEP);
                            }
                        }

                        LoopbackFrpServer();   // Continue receiving
                    });
                return true;
            }

            // Updates the mapping port: cleans up timed-out connections
            bool VirtualEthernetMappingPort::Update(UInt64 now) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;                            // Already disposed
                }

                std::shared_ptr<Server> server = server_; 
                if (NULLPTR != server) {
                    // Update all server-side connections
                    ppp::collections::Dictionary::UpdateAllObjects(server->socket_connections_, now);
                }

                std::shared_ptr<Client> client = client_; 
                if (NULLPTR != client) {
                    // Update all client-side connections and datagram ports
                    ppp::collections::Dictionary::UpdateAllObjects(client->socket_connections_, now);
                    ppp::collections::Dictionary::UpdateAllObjects(client->socket_datagram_ports_, now);
                }

                return true;
            }

            // Generates a new unique connection ID
            int VirtualEthernetMappingPort::NewId() noexcept {
                static std::atomic<unsigned int> aid = /*ATOMIC_FLAG_INIT*/RandomNext();   // Start with random value

                for (;;) {
                    int id = ++aid;        // Increment atomically
                    if (id != 0) {         // Zero is reserved as invalid
                        return id;
                    }
                }
            }

            // Server::Connection constructor
            VirtualEthernetMappingPort::Server::Connection::Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Server>& server, int connection_id, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept
                : IAsynchronousWriteIoQueue(mapping_port->buffer_allocator_)   // Base class initialization
                , connection_stated_(0)                   // Initial state: 0 = not connected
                , server_(server)                         // Store parent server
                , connection_id_(connection_id)           // Store connection ID
                , mapping_port_(mapping_port)             // Store parent mapping port
                , socket_(socket)                         // Store TCP socket
                , timeout_(0) {                           // Timeout will be set by Update()
                linklayer_ = mapping_port->linklayer_;     // Get linklayer reference
                configuration_ = mapping_port->configuration_; // Get configuration
                Update();                                 // Set initial timeout
            }

            // Server::Connection destructor
            VirtualEthernetMappingPort::Server::Connection::~Connection() noexcept {
                Finalize(false);                           // Clean up without sending disconnect
            }

            // Initiates connection to the FRP client (remote side)
            bool VirtualEthernetMappingPort::Server::Connection::ConnectToFrpClient() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 0) {               // Must be in initial state
                    return false;
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return false;
                }

                // Ask linklayer to establish FRP connection to the client
                bool ok = linklayer_->DoFrpConnect(transmission,
                    connection_id_, 
                    mapping_port_->in_, 
                    mapping_port_->remote_port_,
                    nullof<YieldContext>());

                if (!ok) {
                    transmission->Dispose();               // Clean up transmission on failure
                    return false;
                }

                connection_stated_.exchange(1);            // State 1 = connecting
                return true;
            }

            // Sends data to the FRP client (remote side)
            bool VirtualEthernetMappingPort::Server::Connection::SendToFrpClient(const void* packet, int packet_size) noexcept {
                if (NULLPTR == packet || packet_size < 1) {
                    return false;
                }

                int connection_state = connection_stated_.load();
                if (connection_state != 3) {               // Must be in active state (3)
                    return false;
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return false;
                }

                // Push data to FRP client via linklayer
                bool ok = linklayer_->DoFrpPush(transmission, 
                    connection_id_, 
                    mapping_port_->in_,
                    mapping_port_->remote_port_,
                    packet, 
                    packet_size, 
                    nullof<YieldContext>());

                if (ok) {
                    Update();                              // Refresh timeout on success
                }
                else {
                    transmission->Dispose();               // Clean up on failure
                }

                return ok;
            }

            // Sends data to the FRP user (local TCP client)
            bool VirtualEthernetMappingPort::Server::Connection::SendToFrpUser(const void* packet, int packet_size) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {               // Must be active
                    return false;
                }

                // Copy packet data to a shared buffer
                std::shared_ptr<Byte> messages = Copy(mapping_port_->buffer_allocator_, packet, packet_size);
                if (NULLPTR == messages) {
                    return false;
                }

                auto self = shared_from_this();
                // Queue asynchronous write to the TCP socket
                return WriteBytes(messages, packet_size, 
                    [self, this](bool ok) noexcept {
                        if (ok) {
                            Update();                      // Refresh timeout on success
                        }
                        else {
                            Dispose();                     // Close on failure
                        }
                    });
            }

            // Implements the actual asynchronous write operation
            bool VirtualEthernetMappingPort::Server::Connection::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {               // Must be active
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                // Perform async write on the TCP socket
                std::shared_ptr<IAsynchronousWriteIoQueue> self = shared_from_this();
                boost::asio::async_write(*socket_, boost::asio::buffer((Byte*)packet.get() + offset, packet_length),
                    [self, this, packet, packet_length, cb](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool ok = ec == boost::system::errc::success;
                        if (cb) {
                            cb(ok);
                        }
                    });
                return true;
            }

            // Finalizes the server connection: closes socket and removes from dictionary
            void VirtualEthernetMappingPort::Server::Connection::Finalize(bool disconnect) noexcept {
                int connection_state = connection_stated_.exchange(4);   // Set state to 4 (dead)
                if (connection_state != 4) {               // If not already finalizing
                    if (!disconnect && connection_state == 3) {   // If active and not forced disconnect
                        ITransmissionPtr transmission = mapping_port_->GetTransmission();
                        if (NULLPTR != transmission) {
                            // Notify FRP client that we are disconnecting
                            bool ok = linklayer_->DoFrpDisconnect(transmission, 
                                connection_id_, 
                                mapping_port_->in_, 
                                mapping_port_->remote_port_,
                                nullof<YieldContext>());

                            if (!ok) {
                                transmission->Dispose();
                            }
                        }
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
                    std::shared_ptr<Server> server = std::move(server_);

                    if (NULLPTR != socket) {
                        ppp::net::Socket::Closesocket(socket);   // Close TCP socket
                    }

                    if (NULLPTR != server) {
                        // Remove connection from server's dictionary
                        ppp::collections::Dictionary::TryRemove(server->socket_connections_, connection_id_);
                    }
                }
            }

            // Callback when connection to FRP client is successfully established
            bool VirtualEthernetMappingPort::Server::Connection::OnConnectOK(Byte error_code) noexcept {
                int except = 1;                              // Expected state: connecting (1)
                if (!connection_stated_.compare_exchange_strong(except, 2)) {   // Transition to state 2 (connected)
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return false;
                }

                if (error_code != 0) {                       // Connection failed
                    return false;
                }

                except = 2;
                if (!connection_stated_.compare_exchange_strong(except, 3)) {   // Transition to state 3 (active)
                    return false;
                }

                Update();                                    // Set timeout for active state
                // Allocate read buffer
                buffer_chunked_ = ppp::threading::BufferswapAllocator::MakeByteArray(mapping_port_->buffer_allocator_, PPP_TCP_BUFFER_SIZE);

                if (NULLPTR == buffer_chunked_) {
                    return false;
                }

                // Start forwarding data from FRP user to FRP client
                return ForwardFrpUserToFrpClient();
            }

            // Starts asynchronous reading from the local TCP socket (FRP user) and forwards to FRP client
            bool VirtualEthernetMappingPort::Server::Connection::ForwardFrpUserToFrpClient() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                // Async read from TCP socket
                socket->async_read_some(boost::asio::buffer(buffer_chunked_.get(), PPP_TCP_BUFFER_SIZE),
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        bool ok = false;
                        if (ec == boost::system::errc::success && sz > 0) {
                            ok = SendToFrpClient(buffer_chunked_.get(), sz);   // Forward data
                            if (ok) {
                                ForwardFrpUserToFrpClient();   // Continue reading
                            }
                        }

                        if (ok) {
                            Update();                        // Refresh timeout
                        }
                        else {
                            Dispose();                       // Close on error
                        }
                    });
                return true;
            }

            // Finds a mapping port by its properties in the given dictionary
            std::shared_ptr<VirtualEthernetMappingPort> VirtualEthernetMappingPort::FindMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept {
                uint32_t key = GetHashCode(in, tcp, remote_port);
                Ptr ptr;

                ppp::collections::Dictionary::TryGetValue(mappings, key, ptr);
                return ptr;
            }

            // Deletes a mapping port from the dictionary and returns it
            std::shared_ptr<VirtualEthernetMappingPort> VirtualEthernetMappingPort::DeleteMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept {
                uint32_t key = GetHashCode(in, tcp, remote_port);
                Ptr ptr;

                ppp::collections::Dictionary::TryRemove(mappings, key, ptr);
                return ptr;
            }

            // Adds a mapping port to the dictionary
            bool VirtualEthernetMappingPort::AddMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port, const Ptr& mapping_port) noexcept {
                if (NULLPTR == mapping_port) {
                    return false;
                }

                uint32_t key = GetHashCode(in, tcp, remote_port);
                return ppp::collections::Dictionary::TryAdd(mappings, key, mapping_port);
            }

            // Helper template to retrieve a connection from a dictionary by ID (common for server and client)
            template <typename TConnectionPtr, typename TDisposed, typename TConnectionTable>
            static inline TConnectionPtr MAPPINGPORT_GetConnection(TDisposed& disposed_, TConnectionTable& table_, int connection_id) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return NULLPTR;
                }

                auto table = table_;
                if (NULLPTR == table) {
                    return NULLPTR;
                }

                TConnectionPtr connection;
                if (!ppp::collections::Dictionary::TryGetValue(table->socket_connections_, connection_id, connection)) {
                    return NULLPTR;
                }

                if (NULLPTR != connection) {
                    return connection;
                }

                // Remove invalid entry
                ppp::collections::Dictionary::TryRemove(table->socket_connections_, connection_id);
                return NULLPTR;
            }

            // Retrieves a server-side connection by ID
            VirtualEthernetMappingPort::Server::ConnectionPtr VirtualEthernetMappingPort::Server_GetConnection(int connection_id) noexcept {
                return MAPPINGPORT_GetConnection<Server::ConnectionPtr>(disposed_, server_, connection_id);
            }

            // Retrieves a client-side connection by ID
            VirtualEthernetMappingPort::Client::ConnectionPtr VirtualEthernetMappingPort::Client_GetConnection(int connection_id) noexcept {
                return MAPPINGPORT_GetConnection<Client::ConnectionPtr>(disposed_, client_, connection_id);
            }

            // Retrieves a client-side datagram port by NAT endpoint key
            VirtualEthernetMappingPort::Client::DatagramPortPtr VirtualEthernetMappingPort::Client_GetDatagramPort(const boost::asio::ip::udp::endpoint& nat_key) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return NULLPTR;
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return NULLPTR;
                }

                Client::DatagramPortPtr datagram_port;
                if (!ppp::collections::Dictionary::TryGetValue(client->socket_datagram_ports_, nat_key, datagram_port)) {
                    return NULLPTR;
                }
                
                if (NULLPTR != datagram_port) {
                    return datagram_port;
                }

                // Remove invalid entry
                ppp::collections::Dictionary::TryRemove(client->socket_datagram_ports_, nat_key);
                return NULLPTR;
            }

            // Server constructor: initializes sockets and buffer
            VirtualEthernetMappingPort::Server::Server(VirtualEthernetMappingPort* owner) noexcept
                : socket_udp_(*owner->context_)      // UDP socket with owner's IO context
                , socket_tcp_(*owner->context_) {    // TCP acceptor with owner's IO context
                // Get a cached buffer for UDP receive
                socket_source_buf_ = ppp::threading::Executors::GetCachedBuffer(owner->context_);
            }

            // Called when FRP server receives a successful connection acknowledgment
            bool VirtualEthernetMappingPort::Server_OnFrpConnectOK(int connection_id, Byte error_code) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return false;
                }

                bool ok = connection->OnConnectOK(error_code);
                if (!ok) {
                    connection->Dispose();             // Clean up if callback fails
                }

                return ok;
            }

            // Called when FRP server receives a disconnect request
            bool VirtualEthernetMappingPort::Server_OnFrpDisconnect(int connection_id) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return false;
                }

                connection->OnDisconnect();            // Notify connection of disconnect
                return true;
            }

            // Called when FRP server receives a data push from the client
            bool VirtualEthernetMappingPort::Server_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept {
                Server::ConnectionPtr connection = Server_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return false;
                }

                bool ok = connection->SendToFrpUser(packet, packet_length);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
            }

            // Called when FRP server needs to send a UDP datagram to a remote endpoint
            bool VirtualEthernetMappingPort::Server_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                std::shared_ptr<Server> server = server_;
                if (NULLPTR == server) {
                    return false;
                }

                bool opened = server->socket_udp_.is_open();
                if (!opened) {
                    return false;
                }

                boost::system::error_code ec;
                // Send UDP datagram, converting IP version if necessary
                if (in_) {
                    server->socket_udp_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V6ToV4(sourceEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    server->socket_udp_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V4ToV6(sourceEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    return false;
                }

                return true;
            }

            // Accepts a new incoming TCP connection from an FRP user (local client)
            bool VirtualEthernetMappingPort::Server_AcceptFrpUserSocket(const std::shared_ptr<Server>& server, const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }
                // FIXED: changed 'elif' to 'else if'
                else if (!ppp::net::Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo)) {
                    return false;
                }
                else {
                    // Set TCP window sizes
                    ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                }

                ITransmissionPtr transmission = transmission_;
                if (!transmission) {
                    return false;
                }

                auto self = shared_from_this();
                auto& connections = server->socket_connections_;
                // Try to find a free connection ID
                for (int i = ppp::net::IPEndPoint::MinPort; i < ppp::net::IPEndPoint::MaxPort; i++) {
                    int connection_id = NewId();
                    if (ppp::collections::Dictionary::ContainsKey(connections, connection_id)) {
                        continue;
                    }

                    // Create a new connection object
                    auto connection = make_shared_object<Server::Connection>(self, server, connection_id, socket);
                    if (NULLPTR == connection) {
                        return false;
                    }

                    bool ok = connection->ConnectToFrpClient();   // Initiate FRP connection
                    if (ok) {
                        ok = ppp::collections::Dictionary::TryAdd(connections, connection_id, connection);
                        while (ok) {
                            VirtualEthernetLoggerPtr logger = logger_;
                            if (NULLPTR == logger) {
                                break;
                            }

                            // Log the connection (local and remote endpoints)
                            boost::system::error_code ec;
                            boost::asio::ip::tcp::endpoint localEP = socket->local_endpoint(ec);
                            if (ec) {
                                ok = false;
                                break;
                            }

                            boost::asio::ip::tcp::endpoint remoteEP = socket->remote_endpoint(ec);
                            if (ec) {
                                ok = false;
                                break;
                            }

                            logger->MPConnect(linklayer_->GetId(), transmission, localEP, remoteEP);
                            break;
                        }
                    }

                    if (!ok) {
                        connection->Dispose();    // Clean up on failure
                    }

                    return ok;
                }

                return false;   // No free connection ID found
            }

            // Sends a UDP packet to the FRP client (remote side) via linklayer
            bool VirtualEthernetMappingPort::Server_SendToFrpClient(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                std::shared_ptr<VirtualEthernetLinklayer> linklayer = linklayer_;
                if (NULLPTR == linklayer) {
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (!transmission) {
                    return false;
                }

                // Ask linklayer to send UDP datagram to FRP client
                bool ok = linklayer->DoFrpSendTo(transmission,
                    in_,
                    remote_port_,
                    sourceEP,
                    (Byte*)packet,
                    packet_length,
                    nullof<YieldContext>());

                if (ok) {
                    return ok;
                }

                transmission->Dispose();
                return false;
            }

            // Opens the FRP client side (connects to local destination)
            bool VirtualEthernetMappingPort::OpenFrpClient(const boost::asio::ip::address& local_ip, int local_port) noexcept {
                // Validate ports
                if (remote_port_ <= ppp::net::IPEndPoint::MinPort || remote_port_ > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                if (local_port <= ppp::net::IPEndPoint::MinPort || local_port > ppp::net::IPEndPoint::MaxPort) {
                    return false;
                }

                if (server_) {          // Cannot be both server and client
                    return false;
                }

                if (client_) {          // Already a client
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                if (local_ip.is_multicast()) {   // Multicast not allowed
                    return false;
                }

                if (ppp::net::IPEndPoint::IsInvalid(local_ip)) {   // Invalid IP
                    return false;
                }

                ITransmissionPtr transmission = transmission_;
                if (!transmission) {
                    return false;
                }

                // Create client object
                std::shared_ptr<Client> client = make_shared_object<Client>();
                if (!client) {
                    return false;
                }

                client->local_in_ = local_ip.is_v4();   // Store IP version
                client->local_ep_ = boost::asio::ip::udp::endpoint(local_ip, local_port);

                // Register this mapping port with the linklayer (FRP entry)
                bool ok = linklayer_->DoFrpEntry(transmission,
                    tcp_,
                    in_,
                    remote_port_,
                    nullof<YieldContext>());

                if (ok) {
                    client_ = client;
                    return true;
                }

                transmission->Dispose();
                return false;
            }

            // Client::Connection constructor
            VirtualEthernetMappingPort::Client::Connection::Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, int connection_id) noexcept
                : IAsynchronousWriteIoQueue(mapping_port->buffer_allocator_)   // Base class init
                , connection_stated_(0)                   // Initial state
                , client_(client)                         // Parent client
                , mapping_port_(mapping_port)             // Parent mapping port
                , connection_id_(connection_id)           // Unique ID
                , timeout_(0) {
                linklayer_ = mapping_port->linklayer_;
                configuration_ = mapping_port->configuration_;
                transmission_ = mapping_port->transmission_;
                Update();                                 // Set initial timeout
            }

            // Client::Connection destructor
            VirtualEthernetMappingPort::Client::Connection::~Connection() noexcept {
                Finalize(false);
            }

            // Connects to the destination server (local TCP service)
            bool VirtualEthernetMappingPort::Client::Connection::ConnectToDestinationServer() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 0) {               // Must be initial
                    return false;
                }

                if (socket_) {                             // Socket already exists
                    return false;
                }

                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return false;
                }

                // Create a new TCP socket
                std::shared_ptr<boost::asio::ip::tcp::socket> socket = make_shared_object<boost::asio::ip::tcp::socket>(*mapping_port_->context_);
                if (NULLPTR == socket) {
                    return false;
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = client->local_ep_.address();
                // Open socket with appropriate IP version
                if (local_ip.is_v4()) {
                    socket->open(boost::asio::ip::tcp::v4(), ec);
                }
                else {
                    socket->open(boost::asio::ip::tcp::v6(), ec);
                }

                if (ec) {
                    return false;
                }

                int handle = socket->native_handle();
                // Apply socket options
                ppp::net::Socket::AdjustDefaultSocketOptional(handle, local_ip.is_v4());
                ppp::net::Socket::SetTypeOfService(handle);
                ppp::net::Socket::SetSignalPipeline(handle, false);
                ppp::net::Socket::ReuseSocketAddress(handle, true);
                ppp::net::Socket::SetWindowSizeIfNotZero(handle, configuration_->tcp.cwnd, configuration_->tcp.rwnd);

                socket->set_option(boost::asio::ip::tcp::socket::reuse_address(true), ec);
                if (ec) {
                    return false;
                }

                socket->set_option(boost::asio::ip::tcp::no_delay(configuration_->tcp.turbo), ec);
                socket->set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(configuration_->tcp.fast_open), ec);

                socket_ = socket;
                connection_stated_.exchange(1);            // State 1 = connecting

                auto self = shared_from_this();
                // Asynchronously connect to the local destination
                socket->async_connect(boost::asio::ip::tcp::endpoint(local_ip, client->local_ep_.port()),
                    [self, this](boost::system::error_code ec) noexcept {
                        bool ok = OnConnectedOK(ec == boost::system::errc::success);
                        if (!ok) {
                            Dispose();
                        }
                    });
                return true;
            }

            // Finalizes the client connection: closes socket and removes from dictionary
            void VirtualEthernetMappingPort::Client::Connection::Finalize(bool disconnect) noexcept {
                std::shared_ptr<ITransmission> transmission = std::move(transmission_);
     
                int connection_state = connection_stated_.exchange(4);   // Set state to dead
                if (connection_state != 4) {
                    if (!disconnect && connection_state == 3) {   // If active and not forced disconnect
                        if (NULLPTR != transmission) {
                            // Notify FRP server of disconnect
                            bool ok = linklayer_->DoFrpDisconnect(transmission, 
                                connection_id_, 
                                mapping_port_->in_, 
                                mapping_port_->remote_port_, 
                                nullof<YieldContext>());

                            if (!ok) {
                                transmission->Dispose();
                            }
                        }
                    }

                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
                    std::shared_ptr<Client> client = std::move(client_);
     
                    if (NULLPTR != socket) {
                        ppp::net::Socket::Closesocket(socket);   // Close TCP socket
                    }

                    if (NULLPTR != client) {
                        // Remove connection from client's dictionary
                        ppp::collections::Dictionary::TryRemove(client->socket_connections_, connection_id_);
                    }
                }
            }

            // Callback when connection to destination server succeeds or fails
            bool VirtualEthernetMappingPort::Client::Connection::OnConnectedOK(bool ok) noexcept {
                int except = 1;                                  // Expected state: connecting
                if (!connection_stated_.compare_exchange_strong(except, 2)) {   // Transition to state 2 (connected)
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return false;
                }
                else {
                    ITransmissionPtr transmission = transmission_;
                    if (NULLPTR != transmission) {
                        Byte error_code = ok ? 0 : 255;          // 0 = success, 255 = failure
                        // Notify FRP server of connection result
                        bool ok = linklayer_->DoFrpConnectOK(transmission,
                            connection_id_,
                            mapping_port_->in_,
                            mapping_port_->remote_port_,
                            error_code,
                            nullof<YieldContext>());

                        if (!ok) {
                            transmission->Dispose();
                            return false;
                        }
                    }
                }

                except = 2;
                if (!connection_stated_.compare_exchange_strong(except, 3)) {   // Transition to state 3 (active)
                    return false;
                }

                if (!ok) {                                      // Connection failed
                    return false;
                }

                Update();                                       // Set active timeout
                // Allocate read buffer
                buffer_chunked_ = ppp::threading::BufferswapAllocator::MakeByteArray(mapping_port_->buffer_allocator_, PPP_TCP_BUFFER_SIZE);

                if (NULLPTR == buffer_chunked_) {
                    return false;
                }

                // Start reading from destination server socket
                return Loopback();
            }

            // Starts asynchronous reading from the destination server socket and forwards to FRP server
            bool VirtualEthernetMappingPort::Client::Connection::Loopback() noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                // Async read from destination server
                socket->async_read_some(boost::asio::buffer(buffer_chunked_.get(), PPP_TCP_BUFFER_SIZE),
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        bool ok = false;
                        if (ec == boost::system::errc::success && sz > 0) {
                            ITransmissionPtr transmission = transmission_;
                            if (NULLPTR != transmission) {
                                // Push data to FRP server
                                ok = linklayer_->DoFrpPush(
                                    transmission,
                                    connection_id_,
                                    mapping_port_->in_,
                                    mapping_port_->remote_port_,
                                    buffer_chunked_.get(),
                                    sz,
                                    nullof<YieldContext>());

                                if (ok) {
                                    ok = Loopback();            // Continue reading
                                }
                                else {
                                    transmission->Dispose();
                                }
                            }
                        }

                        if (ok) {
                            Update();                           // Refresh timeout
                        }
                        else {
                            Dispose();                          // Close on error
                        }
                    });
                return true;
            }

            // Sends data to the destination server (local TCP service)
            bool VirtualEthernetMappingPort::Client::Connection::SendToDestinationServer(const void* packet, int packet_size) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {                    // Must be active
                    return false;
                }

                // Copy packet to shared buffer
                std::shared_ptr<Byte> messages = Copy(mapping_port_->buffer_allocator_, packet, packet_size);
                if (NULLPTR == messages) {
                    return false;
                }

                auto self = shared_from_this();
                // Queue asynchronous write
                return WriteBytes(messages, packet_size, 
                    [self, this](bool ok) noexcept {
                        if (ok) {
                            Update();
                        }
                        else {
                            Dispose();
                        }
                    });
            }

            // Implements the actual asynchronous write for client connection
            bool VirtualEthernetMappingPort::Client::Connection::DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept {
                int connection_state = connection_stated_.load();
                if (connection_state != 3) {
                    return false;
                }

                std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
                if (NULLPTR == socket) {
                    return false;
                }

                bool opened = socket->is_open();
                if (!opened) {
                    return false;
                }

                std::shared_ptr<IAsynchronousWriteIoQueue> self = shared_from_this();
                boost::asio::async_write(*socket_, boost::asio::buffer((Byte*)packet.get() + offset, packet_length),
                    [self, this, packet, packet_length, cb](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool ok = ec == boost::system::errc::success;
                        if (cb) {
                            cb(ok);
                        }
                    });
                return true;
            }

            // Called when FRP client receives a connection request
            bool VirtualEthernetMappingPort::Client_OnFrpConnect(int connection_id) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULLPTR != connection) {
                    return false;                            // Already exists
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return false;
                }
                else {
                    auto self = shared_from_this();
                    // Create a new client connection object
                    connection = make_shared_object<Client::Connection>(self, client, connection_id);
                    if (NULLPTR == connection) {
                        return false;
                    }
                }

                bool ok = connection->ConnectToDestinationServer();   // Connect to local destination
                if (ok) {
                    ok = ppp::collections::Dictionary::TryAdd(client->socket_connections_, connection_id, connection);
                }

                if (!ok) {
                    connection->Dispose();
                }
                return ok;
            }

            // Called when FRP client receives a disconnect request
            bool VirtualEthernetMappingPort::Client_OnFrpDisconnect(int connection_id) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return false;
                }

                connection->OnDisconnect();
                return true;
            }

            // Called when FRP client receives a data push from the server
            bool VirtualEthernetMappingPort::Client_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept {
                Client::ConnectionPtr connection = Client_GetConnection(connection_id);
                if (NULLPTR == connection) {
                    return false;
                }

                bool ok = connection->SendToDestinationServer(packet, packet_length);
                if (!ok) {
                    connection->Dispose();
                }

                return ok;
            }

            // Called when FRP client needs to send a UDP datagram to a remote endpoint
            bool VirtualEthernetMappingPort::Client_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return false;
                }

                // Try to get an existing datagram port for this NAT endpoint
                Client::DatagramPortPtr datagram_port = Client_GetDatagramPort(sourceEP);
                if (NULLPTR != datagram_port) {
                    return datagram_port->SendTo(packet, packet_length, client->local_ep_);
                }
                else {
                    auto self = shared_from_this();
                    // Create a new datagram port
                    datagram_port = make_shared_object<Client::DatagramPort>(self, client, sourceEP);
                    if (NULLPTR == datagram_port) {
                        return false;
                    }
                }

                bool ok = datagram_port->Open();             // Open UDP socket and start loopback
                if (!ok) {
                    datagram_port->Dispose();
                    return false;
                }

                ok = ppp::collections::Dictionary::TryAdd(client->socket_datagram_ports_, sourceEP, datagram_port);
                if (ok) {
                    ok = datagram_port->SendTo(packet, packet_length, client->local_ep_);
                    if (ok) {
                        return true;
                    }
                }

                datagram_port->Dispose();
                return false;
            }

            // Client constructor: initializes default values
            VirtualEthernetMappingPort::Client::Client() noexcept
                : local_in_(false) {
                // Empty
            }

            // Client::DatagramPort constructor
            VirtualEthernetMappingPort::Client::DatagramPort::DatagramPort(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, const boost::asio::ip::udp::endpoint& natEP) noexcept
                : disposed_(FALSE)
                , socket_(*mapping_port->context_)         // UDP socket with owner's IO context
                , timeout_(0)
                , configuration_(mapping_port->configuration_)
                , mapping_port_(mapping_port)
                , client_(client)
                , linklayer_(mapping_port->linklayer_)
                , transmission_(mapping_port->transmission_) {
                nat_ep_ = natEP;                           // Store NAT endpoint
                buffer_chunked_ = ppp::threading::Executors::GetCachedBuffer(mapping_port->context_);   // Allocate buffer
                Update();                                  // Set initial timeout
            }

            // DatagramPort destructor
            VirtualEthernetMappingPort::Client::DatagramPort::~DatagramPort() noexcept {
                Dispose();
            }

            // Disposes the datagram port: closes socket and removes from dictionary
            void VirtualEthernetMappingPort::Client::DatagramPort::Dispose() noexcept {
                int disposed = disposed_.exchange(TRUE);
                if (disposed != TRUE) {
                    std::shared_ptr<Client> client = std::move(client_); 
                    if (NULLPTR != client) {
                        // Remove from client's dictionary
                        ppp::collections::Dictionary::TryRemove(client->socket_datagram_ports_, nat_ep_);
                    }

                    ppp::net::Socket::Closesocket(socket_);   // Close UDP socket
                }
            }

            // Sends a UDP packet to the destination server (via FRP)
            bool VirtualEthernetMappingPort::Client::DatagramPort::SendToDestinationServer(const void* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }
                
                ITransmissionPtr transmission = mapping_port_->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                // Ask linklayer to send UDP datagram to FRP server
                bool ok = linklayer_->DoFrpSendTo(transmission,
                    mapping_port_->in_,
                    mapping_port_->remote_port_,
                    nat_ep_,
                    (Byte*)packet,
                    packet_length,
                    nullof<YieldContext>());

                if (!ok) {
                    transmission->Dispose();
                }

                return ok;
            }

            // Starts the asynchronous receive loop on the UDP socket
            bool VirtualEthernetMappingPort::Client::DatagramPort::Loopback() noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    return false;
                }

                std::shared_ptr<DatagramPort> self = shared_from_this();
                // Async receive UDP datagram
                socket_.async_receive_from(boost::asio::buffer(buffer_chunked_.get(), PPP_UDP_BUFFER_SIZE), source_ep_,
                    [self, this](boost::system::error_code ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::success) {
                            bool ok = false;
                            if (sz > 0) {
                                ok = SendToDestinationServer(buffer_chunked_.get(), sz);
                            }

                            if (ok) {
                                Update();                // Refresh timeout on success
                            }
                            else {
                                Dispose();               // Clean up on failure
                            }
                        }

                        Loopback();                      // Continue receiving
                    });
                return true;
            }

            // Opens the UDP socket and starts the loopback
            bool VirtualEthernetMappingPort::Client::DatagramPort::Open() noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (opened) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return false;
                }

                boost::asio::ip::address local_ip = client->local_ep_.address();
                // Open UDP socket bound to any address on an ephemeral port
                if (local_ip.is_v4()) {
                    opened = ppp::net::Socket::OpenSocket(socket_, boost::asio::ip::address_v4::any(), ppp::net::IPEndPoint::MinPort);
                }
                else {
                    opened = ppp::net::Socket::OpenSocket(socket_, boost::asio::ip::address_v6::any(), ppp::net::IPEndPoint::MinPort);
                }

                if (opened) {
                    // Set UDP window sizes
                    ppp::net::Socket::SetWindowSizeIfNotZero(
                        socket_.native_handle(), 
                        configuration_->udp.cwnd, 
                        configuration_->udp.rwnd);
                    opened = Loopback();   // Start receive loop
                }
                
                return opened;
            }

            // Sends a UDP packet to the remote endpoint (local network) via the UDP socket
            bool VirtualEthernetMappingPort::Client::DatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                int disposed = disposed_.load();
                if (disposed != FALSE) {
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    return false;
                }

                std::shared_ptr<Client> client = client_;
                if (NULLPTR == client) {
                    return false;
                }

                boost::system::error_code ec;
                // Send UDP datagram, converting IP version if needed
                if (client->local_in_) {
                    socket_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V6ToV4(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    socket_.send_to(boost::asio::buffer(packet, packet_length),
                        ppp::net::Ipep::V4ToV6(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    return false;
                }

                Update();    // Refresh timeout on success
                return true;
            }
        }
    }
}