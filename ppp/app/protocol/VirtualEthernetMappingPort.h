#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/app/protocol/VirtualEthernetLogger.h>
#include <ppp/app/protocol/VirtualEthernetLinklayer.h>
#include <ppp/app/protocol/VirtualEthernetMappingPort.h>

namespace ppp {
    namespace app {
        namespace protocol {
            // Forward declaration of the main mapping port class
            class VirtualEthernetMappingPort : public std::enable_shared_from_this<VirtualEthernetMappingPort> {
            public:
                // Type aliases for convenience
                typedef ppp::coroutines::YieldContext                                       YieldContext;
                typedef ppp::transmissions::ITransmission                                   ITransmission;
                typedef std::shared_ptr<ITransmission>                                      ITransmissionPtr;
                typedef ppp::configurations::AppConfiguration                               AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>                                   AppConfigurationPtr;
                typedef std::shared_ptr<VirtualEthernetMappingPort>                         Ptr;
                typedef std::shared_ptr<VirtualEthernetLogger>                              VirtualEthernetLoggerPtr;

            public:
                // Constructor: initializes the mapping port with linklayer, transmission, protocol type, IP version, and remote port
                VirtualEthernetMappingPort(const std::shared_ptr<VirtualEthernetLinklayer>& linklayer, const ITransmissionPtr& transmission, bool tcp, bool in, int remote_port) noexcept;
                // Destructor: cleans up resources
                virtual ~VirtualEthernetMappingPort() noexcept;

            public:
                // Returns the associated IO context
                std::shared_ptr<boost::asio::io_context>                                    GetContext() noexcept;
                // Returns the linklayer instance
                std::shared_ptr<VirtualEthernetLinklayer>                                   GetLinklayer() noexcept;
                // Returns the transmission instance
                ITransmissionPtr                                                            GetTransmission() noexcept;
                // Checks if the network protocol is TCP
                bool                                                                        ProtocolIsTcpNetwork() noexcept;
                // Checks if the network protocol is UDP
                bool                                                                        ProtocolIsUdpNetwork() noexcept;
                // Checks if the network IP version is IPv4
                bool                                                                        ProtocolIsNetworkV4() noexcept;
                // Checks if the network IP version is IPv6
                bool                                                                        ProtocolIsNetworkV6() noexcept;
                // Returns the remote port number
                int                                                                         GetRemotePort() noexcept;
                // Returns the logger instance
                VirtualEthernetLoggerPtr                                                    GetLogger() noexcept { return logger_; }
                // Returns the buffer allocator
                std::shared_ptr<ppp::threading::BufferswapAllocator>                        GetBufferAllocator() noexcept { return buffer_allocator_; }
                
            public:
                // Computes a hash key from IP version, protocol type, and port
                static constexpr uint32_t                                                   GetHashCode(bool in, bool tcp, int remote_port) noexcept {
                    uint32_t key = (in ? 1 : 0) << 24;   // bit 24: IPv4=1, IPv6=0
                    key |= (tcp ? 1 : 0) << 16;          // bit 16: TCP=1, UDP=0
                    key |= remote_port & 0xffff;         // lower 16 bits: port number
                    return key;
                }

            public:
                // Returns the bound endpoint of the FRP server (if any)
                boost::asio::ip::tcp::endpoint                                              BoundEndPointOfFrpServer() noexcept;
                // Opens the FRP server side (listening for incoming FRP connections)
                virtual bool                                                                OpenFrpServer(const VirtualEthernetLoggerPtr& logger) noexcept;
                // Opens the FRP client side (connecting to a local destination)
                virtual bool                                                                OpenFrpClient(const boost::asio::ip::address& local_ip, int local_port) noexcept;
                // Disposes the mapping port, releasing all resources
                virtual void                                                                Dispose() noexcept;
                // Updates internal state and cleans up timed-out connections
                virtual bool                                                                Update(UInt64 now) noexcept;
                // Generates a new unique connection ID
                static int                                                                  NewId() noexcept;

            public:
                // Finds a mapping port by its properties in a given dictionary
                static std::shared_ptr<VirtualEthernetMappingPort>                          FindMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept;
                // Adds a mapping port to a dictionary
                static bool                                                                 AddMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port, const Ptr& mapping_port) noexcept;
                // Deletes a mapping port from a dictionary and returns it
                static std::shared_ptr<VirtualEthernetMappingPort>                          DeleteMappingPort(ppp::unordered_map<uint32_t, Ptr>& mappings, bool in, bool tcp, int remote_port) noexcept;

            public:
                // Called when FRP server receives a successful connection acknowledgment
                bool                                                                        Server_OnFrpConnectOK(int connection_id, Byte error_code) noexcept;
                // Called when FRP server receives a disconnect request
                bool                                                                        Server_OnFrpDisconnect(int connection_id) noexcept;
                // Called when FRP server receives a data push from the client
                bool                                                                        Server_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept;
                // Called when FRP server needs to send a UDP datagram to a remote endpoint
                bool                                                                        Server_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            public:
                // Called when FRP client receives a disconnect request
                bool                                                                        Client_OnFrpDisconnect(int connection_id) noexcept;
                // Called when FRP client receives a data push from the server
                bool                                                                        Client_OnFrpPush(int connection_id, const void* packet, int packet_length) noexcept;
                // Called when FRP client receives a connection request
                bool                                                                        Client_OnFrpConnect(int connection_id) noexcept;
                // Called when FRP client needs to send a UDP datagram to a remote endpoint
                bool                                                                        Client_OnFrpSendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;

            private:
                // Inner class representing the server side (listening for incoming FRP connections)
                class Server final {
                public:
                    // Inner class representing a single TCP connection on the server side
                    class Connection final : public ppp::net::asio::IAsynchronousWriteIoQueue {
                    public:
                        // Constructor: initializes a server connection
                        Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Server>& server, int connection_id, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept;
                        // Destructor: cleans up the connection
                        ~Connection() noexcept;

                    public:
                        // Disposes the connection
                        void                                                                Dispose() noexcept { Finalize(false); }
                        // Initiates connection to the FRP client (remote side)
                        bool                                                                ConnectToFrpClient() noexcept;
                        // Sends data to the FRP user (local TCP client)
                        bool                                                                SendToFrpUser(const void* packet, int packet_size) noexcept;
                        // Sends data to the FRP client (remote side)
                        bool                                                                SendToFrpClient(const void* packet, int packet_size) noexcept;
                        // Updates the timeout timestamp based on current state
                        void                                                                Update() noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            if (connection_stated_.load() < 3) {
                                timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;   // connection phase timeout
                            }
                            else {
                                timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;  // established phase timeout
                            }
                        }
                        // Checks if the connection has aged (timed out)
                        bool                                                                IsPortAging(UInt64 now) noexcept { return connection_stated_.load() > 3 || now >= timeout_; }

                    public:
                        // Callback when connection to FRP client is successfully established
                        bool                                                                OnConnectOK(Byte error_code) noexcept;
                        // Callback when disconnect occurs
                        void                                                                OnDisconnect() noexcept { Finalize(true); }

                    private:
                        // Finalizes and releases resources, optionally notifying remote side
                        void                                                                Finalize(bool disconnect) noexcept;
                        // Starts forwarding data from FRP user (local TCP) to FRP client (remote)
                        bool                                                                ForwardFrpUserToFrpClient() noexcept;
                        // Implements asynchronous write operation for the IO queue
                        virtual bool                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                    private:
                        std::atomic<int>                                                    connection_stated_;          // 0=init,1=connecting,2=connected,3=active,4=dead
                        std::shared_ptr<Server>                                             server_;                     // Parent server object
                        int                                                                 connection_id_;              // Unique ID for this connection
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;               // Parent mapping port
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;                  // Link layer for FRP operations
                        std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;                     // TCP socket to local user
                        UInt64                                                              timeout_;                    // Expiration timestamp
                        AppConfigurationPtr                                                 configuration_;              // App configuration
                        std::shared_ptr<Byte>                                               buffer_chunked_;             // Read buffer for socket
                    };
                    typedef std::shared_ptr<Connection>                                     ConnectionPtr;

                public:
                    std::shared_ptr<Byte>                                                   socket_source_buf_;          // Buffer for UDP receive
                    boost::asio::ip::udp::endpoint                                          socket_source_ep_;           // Endpoint of UDP sender
                    boost::asio::ip::udp::socket                                            socket_udp_;                 // UDP socket (for datagram mode)
                    boost::asio::ip::tcp::acceptor                                          socket_tcp_;                 // TCP acceptor (for stream mode)
                    boost::asio::ip::tcp::endpoint                                          socket_endpoint_;            // Bound endpoint of the server
                    ppp::unordered_map<int, ConnectionPtr>                                  socket_connections_;         // Map from connection ID to connection object

                public:
                    // Constructor: initializes the server with the owning mapping port
                    Server(VirtualEthernetMappingPort* owner) noexcept;
                };
                // Helper to retrieve a server-side connection by ID
                Server::ConnectionPtr                                                       Server_GetConnection(int connection_id) noexcept;

            private:
                // Inner class representing the client side (connecting to local destination)
                class Client final {
                public:
                    // Inner class representing a single TCP connection on the client side
                    class Connection final : public ppp::net::asio::IAsynchronousWriteIoQueue {
                    public:
                        // Constructor: initializes a client connection
                        Connection(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, int connection_id) noexcept;
                        // Destructor: cleans up the connection
                        ~Connection() noexcept;

                    public:
                        // Connects to the destination server (local TCP service)
                        bool                                                                ConnectToDestinationServer() noexcept;
                        // Updates timeout timestamp based on state
                        void                                                                Update() noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            if (connection_stated_.load() < 3) {
                                timeout_ = now + (UInt64)configuration_->tcp.connect.timeout * 1000;
                            }
                            else {
                                timeout_ = now + (UInt64)configuration_->tcp.inactive.timeout * 1000;
                            }
                        }
                        // Checks if connection has aged
                        bool                                                                IsPortAging(UInt64 now) noexcept { return connection_stated_.load() > 3 || now >= timeout_; }
                        // Disposes the connection
                        void                                                                Dispose() noexcept { Finalize(false); }
                        // Sends data to the destination server
                        bool                                                                SendToDestinationServer(const void* packet, int packet_size) noexcept;

                    public:
                        // Callback when connection to destination server succeeds or fails
                        bool                                                                OnConnectedOK(bool ok) noexcept;
                        // Callback when disconnect occurs
                        void                                                                OnDisconnect() noexcept { Finalize(true); }

                    private:
                        // Finalizes and releases resources
                        void                                                                Finalize(bool disconnect) noexcept;
                        // Starts loopback reading from the destination server socket
                        bool                                                                Loopback() noexcept;
                        // Implements asynchronous write operation
                        virtual bool                                                        DoWriteBytes(std::shared_ptr<Byte> packet, int offset, int packet_length, const AsynchronousWriteBytesCallback& cb) noexcept;

                    private:
                        std::atomic<int>                                                    connection_stated_ = FALSE;  // 0=init,1=connecting,2=connected,3=active,4=dead
                        std::shared_ptr<Client>                                             client_;                     // Parent client object
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;               // Parent mapping port
                        int                                                                 connection_id_     = 0;     // Unique ID
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;                  // Link layer
                        std::shared_ptr<boost::asio::ip::tcp::socket>                       socket_;                     // TCP socket to destination
                        UInt64                                                              timeout_           = 0;     // Expiration timestamp
                        AppConfigurationPtr                                                 configuration_;              // App config
                        ITransmissionPtr                                                    transmission_;               // Transmission object
                        std::shared_ptr<Byte>                                               buffer_chunked_;             // Read buffer
                    };
                    typedef std::shared_ptr<Connection>                                     ConnectionPtr;

                public:
                    // Inner class representing a UDP NAT port (for datagram forwarding)
                    class DatagramPort final : public std::enable_shared_from_this<DatagramPort> {
                    public:
                        // Constructor: initializes a datagram port for a specific NAT endpoint
                        DatagramPort(const std::shared_ptr<VirtualEthernetMappingPort>& mapping_port, const std::shared_ptr<Client>& client, const boost::asio::ip::udp::endpoint& natEP) noexcept;
                        // Destructor: cleans up the datagram port
                        ~DatagramPort() noexcept;

                    public:
                        // Sends a UDP packet to the remote endpoint (via FRP)
                        bool                                                                SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                        // Updates the timeout timestamp
                        void                                                                Update() noexcept {
                            UInt64 now = ppp::threading::Executors::GetTickCount();
                            timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                        }
                        // Opens the underlying UDP socket and starts loopback
                        bool                                                                Open() noexcept;
                        // Checks if the port has aged
                        bool                                                                IsPortAging(UInt64 now) noexcept { return disposed_.load() != FALSE || now >= timeout_; }
                        // Disposes the datagram port
                        void                                                                Dispose() noexcept;

                    private:
                        // Starts the asynchronous receive loop on the UDP socket
                        bool                                                                Loopback() noexcept;
                        // Forwards received UDP data to the destination server (via FRP)
                        bool                                                                SendToDestinationServer(const void* packet, int packet_length) noexcept;

                    private:
                        std::atomic<int>                                                    disposed_ = FALSE;           // Disposal flag
                        boost::asio::ip::udp::socket                                        socket_;                     // UDP socket for local communication
                        uint64_t                                                            timeout_  = 0;               // Expiration timestamp
                        AppConfigurationPtr                                                 configuration_;              // App config
                        std::shared_ptr<VirtualEthernetMappingPort>                         mapping_port_;               // Parent mapping port
                        std::shared_ptr<Byte>                                               buffer_chunked_;             // Receive buffer
                        boost::asio::ip::udp::endpoint                                      source_ep_;                  // Endpoint of last received packet
                        boost::asio::ip::udp::endpoint                                      nat_ep_;                     // NAT endpoint (remote peer)
                        std::shared_ptr<Client>                                             client_;                     // Parent client object
                        std::shared_ptr<VirtualEthernetLinklayer>                           linklayer_;                  // Link layer
                        ITransmissionPtr                                                    transmission_;               // Transmission object
                    };
                    typedef std::shared_ptr<DatagramPort>                                   DatagramPortPtr;

                public:
                    boost::asio::ip::udp::endpoint                                          local_ep_;                   // Local endpoint to bind to
                    bool                                                                    local_in_;                   // True if local IP is IPv4
                    ppp::unordered_map<int, ConnectionPtr>                                  socket_connections_;         // Map from connection ID to connection object
                    ppp::unordered_map<boost::asio::ip::udp::endpoint, DatagramPortPtr>     socket_datagram_ports_;      // Map from NAT endpoint to datagram port
                    
                public:
                    // Constructor: initializes an empty client
                    Client() noexcept;
                };
                // Helper to retrieve a client-side connection by ID
                Client::ConnectionPtr                                                       Client_GetConnection(int connection_id) noexcept;
                // Helper to retrieve a datagram port by NAT endpoint
                Client::DatagramPortPtr                                                     Client_GetDatagramPort(const boost::asio::ip::udp::endpoint& nat_key) noexcept;

            private:
                // Sends a UDP packet to the FRP client (remote side)
                bool                                                                        Server_SendToFrpClient(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                // Accepts a new incoming TCP connection from an FRP user
                bool                                                                        Server_AcceptFrpUserSocket(const std::shared_ptr<Server>& server, const ppp::net::Socket::AsioContext& context, const ppp::net::Socket::AsioTcpSocket& socket) noexcept;

            private:
                // Finalizes the entire mapping port
                void                                                                        Finalize() noexcept;
                // Starts the UDP receive loop for the server (datagram mode)
                bool                                                                        LoopbackFrpServer() noexcept;
                // Opens the TCP acceptor socket (stream mode)
                bool                                                                        OpenNetworkSocketStream() noexcept;
                // Opens the UDP socket (datagram mode)
                bool                                                                        OpenNetworkSocketDatagram() noexcept;

            private:
                std::atomic<int>                                                            disposed_     = FALSE;      // Disposal flag
                std::shared_ptr<VirtualEthernetLinklayer>                                   linklayer_;                  // Link layer reference
                ITransmissionPtr                                                            transmission_;               // Transmission reference

                struct {
                    bool                                                                    tcp_          : 1;          // True for TCP, false for UDP
                    bool                                                                    in_           : 7;          // True for IPv4, false for IPv6
                };

                int                                                                         remote_port_  = 0;          // Remote port number
                std::shared_ptr<boost::asio::io_context>                                    context_;                    // Asio IO context
                std::shared_ptr<Server>                                                     server_;                     // Server instance (if acting as server)
                std::shared_ptr<Client>                                                     client_;                     // Client instance (if acting as client)
                AppConfigurationPtr                                                         configuration_;              // App configuration
                VirtualEthernetLoggerPtr                                                    logger_;                     // Logger instance
                std::shared_ptr<ppp::threading::BufferswapAllocator>                        buffer_allocator_;           // Buffer allocator for memory management
            };
        }
    }
}