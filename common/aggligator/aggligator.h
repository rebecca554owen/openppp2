#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/configurations/AppConfiguration.h>

#if defined(_LINUX)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace aggligator
{
    using Byte                                                              = ppp::Byte;                                            // 8-bit unsigned byte
    using acceptor                                                          = std::shared_ptr<boost::asio::ip::tcp::acceptor>;      // TCP acceptor shared pointer
    using deadline_timer                                                    = std::shared_ptr<boost::asio::deadline_timer>;         // Deadline timer shared pointer
    using YieldContext                                                      = ppp::coroutines::YieldContext;                        // Coroutine yield context

    using string = ppp::string;                                             // String type alias

    template <class TValue>
    using unordered_set = ppp::unordered_set<TValue>;                       // Unordered set

    template <class TKey, class TValue>
    using unordered_map = ppp::unordered_map<TKey, TValue>;                 // Unordered map

    template <class TValue>
    using list = ppp::list<TValue>;                                         // Linked list

    template <class TValue>
    using queue = list<TValue>;                                             // Queue (linked list based)

    template <class TValue>
    using vector = ppp::vector<TValue>;                                     // Dynamic array

    template <typename _TKey, typename _TValue, typename _Pr>
    using map_pr = std::map<_TKey, _TValue, _Pr, ppp::allocator<std::pair<const _TKey, _TValue>>>; // Sorted map (red-black tree)

    // Timeout constants (seconds)
    static constexpr int AGGLIGATOR_RECONNECT_TIMEOUT = 5;                  // Delay before reconnecting after failure
    static constexpr int AGGLIGATOR_CONNECT_TIMEOUT = 5;                    // Timeout for TCP connection establishment
    static constexpr int AGGLIGATOR_INACTIVE_TIMEOUT = 72;                  // Inactivity timeout before closing client

    // Main aggregator class, manages both server and client modes
    class aggligator : public std::enable_shared_from_this<aggligator>
    {
        class server;                                                       // Forward declaration of server implementation
        typedef std::shared_ptr<server> server_ptr;                         // Server shared pointer

        class client;                                                       // Forward declaration of client implementation
        typedef std::shared_ptr<client> client_ptr;                         // Client shared pointer

        class connection;                                                   // Forward declaration of connection (TCP stream)
        typedef std::shared_ptr<connection> connection_ptr;                 // Connection shared pointer

        class convergence;                                                  // Forward declaration of convergence (sequencing & reassembly)
        typedef std::shared_ptr<convergence> convergence_ptr;               // Convergence shared pointer

        typedef std::shared_ptr<aggligator> ptr;                            // Self shared pointer

        // Structure representing a packet queued for sending over one TCP connection
        struct send_packet final
        {
            uint32_t                seq;                                    // Sequence number (used for ordering in map)
            std::shared_ptr<Byte>   packet;                                 // Raw packet data (including length header and sequence)
            int                     length;                                 // Total length of the packet
        };

    public:
        // Statistics and status information structure
        class information final
        {
        public:
            uint64_t                                                    rx;               // Total received bytes
            uint64_t                                                    tx;               // Total transmitted bytes
            uint64_t                                                    rx_pps;           // Received packets count
            uint64_t                                                    tx_pps;           // Transmitted packets count
            uint32_t                                                    client_count;     // Number of active clients (server mode only)
            uint32_t                                                    connection_count; // Total TCP connections established
            uint32_t                                                    establish_count;  // Number of connections that completed handshake
            unordered_set<int>                                          bind_ports;       // Local TCP ports we are listening on
            unordered_set<boost::asio::ip::tcp::endpoint>               server_endpoints; // Remote server endpoints (client mode)
        };

    public:
        aggligator(boost::asio::io_context& context, const std::shared_ptr<Byte>& buffer, int buffer_size, int congestions) noexcept;
        ~aggligator() noexcept;

#if defined(_LINUX)
    public:
        typedef std::shared_ptr<ppp::net::ProtectorNetwork>                 ProtectorNetworkPtr; // Linux VPN protect interface
    public:
        ProtectorNetworkPtr                                                 ProtectorNetwork;    // Network protector (e.g., for VPN)
#endif

    public:
        typedef std::shared_ptr<ppp::threading::BufferswapAllocator>        BufferswapAllocatorPtr; // Memory pool allocator
        typedef std::shared_ptr<ppp::configurations::AppConfiguration>      AppConfigurationPtr;    // Global configuration

    public:
        AppConfigurationPtr AppConfiguration;                               // Application configuration (socket buffers)
        BufferswapAllocatorPtr BufferswapAllocator;                         // Allocator for shared byte arrays

    public:
        ppp::function<void()> Exit;                                         // Callback invoked when aggregator is fully closed
        ppp::function<void(uint64_t)> Tick;                                 // Periodic tick callback (every 10ms)

    public:
        void                                                                close() noexcept;                                               // Gracefully close all resources
        bool                                                                server_open(const unordered_set<int>& bind_ports, const boost::asio::ip::address& destination_ip, int destination_port) noexcept; // Start in server mode
        bool                                                                client_open(                                                    // Start in client mode
            int connections,
            const unordered_set<boost::asio::ip::tcp::endpoint>& servers) noexcept;
        uint64_t                                                            now() noexcept { return now_; }                                         // Current monotonic timestamp in milliseconds
        void                                                                update(uint64_t now) noexcept;                                          // Update internal timers and check timeouts
        bool                                                                info(information& i) noexcept;                                          // Fill statistics structure
        bool                                                                server_mode() noexcept { return server_mode_; }                         // Returns true if in server mode
        boost::asio::ip::udp::endpoint                                      client_endpoint(const boost::asio::ip::address& interface_ip) noexcept; // Get UDP endpoint for sending back to client
        void                                                                client_fetch_concurrency(int& servers, int& channels) noexcept;         // Retrieve concurrency parameters

    public:
        enum link_status                                                    // Link status enumeration
        {
            link_status_none = 0,                                           // Not applicable (server mode)
            link_status_unknown = 1,                                        // Unable to determine
            link_status_connecting = 2,                                     // Some TCP connections not yet established
            link_status_reconnecting = 3,                                   // All connections lost, reconnecting
            link_status_established = 4,                                    // All TCP connections ready
        };
        link_status                                                         status() noexcept;               // Get current link status
        link_status                                                         status(information& i) noexcept; // Get status based on provided info

    public:                                                     
        static void                                                         deadline_timer_cancel(deadline_timer& t) noexcept;                  // Cancel and reset a deadline timer
        static void                                                         socket_close(boost::asio::ip::udp::socket& socket) noexcept;        // Close UDP socket safely
        static void                                                         socket_close(boost::asio::ip::tcp::socket& socket) noexcept;        // Close TCP socket safely
        static bool                                                         ip_is_invalid(const boost::asio::ip::address& address) noexcept;    // Check if IP address is unusable
        static boost::asio::ip::udp::endpoint                               ip_v6_to_v4(const boost::asio::ip::udp::endpoint& ep) noexcept;     // Convert UDP endpoint from IPv6 to IPv4 if possible
        static boost::asio::ip::tcp::endpoint                               ip_v6_to_v4(const boost::asio::ip::tcp::endpoint& ep) noexcept;     // Convert TCP endpoint from IPv6 to IPv4
        static boost::asio::ip::udp::endpoint                               ip_v4_to_v6(const boost::asio::ip::udp::endpoint& ep) noexcept;     // Convert UDP endpoint from IPv4 to IPv6 (mapped)
        static boost::asio::ip::tcp::endpoint                               ip_v4_to_v6(const boost::asio::ip::tcp::endpoint& ep) noexcept;     // Convert TCP endpoint from IPv4 to IPv6 (mapped)
        virtual std::shared_ptr<Byte>                                       make_shared_bytes(int length) noexcept;                             // Allocate shared byte array using configured allocator

    private:
        // Socket option helpers (template to avoid code duplication)
        template <typename T>
        bool                                                                aggligator_socket_adjust(T& socket) noexcept     // Adjust common socket options
        {
            boost::system::error_code ec;                                   // Error code placeholder
            if (!socket.is_open())                                          // Socket must be open
            {
                return false;
            }

            int sockfd = socket.native_handle();                            // Get native file descriptor
            if (sockfd == -1)                                               // Invalid descriptor
            {
                return false;
            }

            auto ep = socket.local_endpoint(ec);                            // Try to get local endpoint
            if (ec)                                                         // If failed, assume IPv4
            {
                socket_adjust(sockfd, true);
            }
            else
            {
                boost::asio::ip::address ip = ep.address();                 // Extract IP address
                socket_adjust(sockfd, ip.is_v4());                          // Adjust based on address family
            }

            return true;
        }

        template <typename T>
        bool                                                                aggligator_tcp_socket_adjust(T& socket) noexcept // TCP specific adjustments
        {
            if (aggligator_socket_adjust(socket))                           // Apply common adjustments first
            {
                boost::system::error_code ec;                               // Error code
                socket.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec); // Allow address reuse
                socket.set_option(boost::asio::ip::tcp::no_delay(true), ec);                // Disable Nagle's algorithm
                socket.set_option(boost::asio::detail::socket_option::boolean<IPPROTO_TCP, TCP_FASTOPEN>(true), ec); // Enable TCP Fast Open
                return true;
            }

            return false;
        }

        void                                                                socket_adjust(int sockfd, bool in4) noexcept;                   // Low-level socket options (SO_RCVBUF, SO_SNDBUF, TOS)
        bool                                                                socket_adjust(boost::asio::ip::tcp::socket& socket) noexcept;   // Adjust TCP socket
        bool                                                                socket_adjust(boost::asio::ip::udp::socket& socket) noexcept;   // Adjust UDP socket
        bool                                                                socket_adjust(boost::asio::ip::tcp::acceptor& socket) noexcept; // Adjust TCP acceptor

    private:                                                                
        bool                                                                client_reopen(client* client) noexcept;                        // Attempt to reconnect after failure
        bool                                                                server_closed(client* client) noexcept;                        // Called when a server-side client is closed
        bool                                                                server_accept(const acceptor& acceptor) noexcept;              // Start async accept on a listener
        bool                                                                server_accept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, YieldContext& y) noexcept; // Handle new incoming TCP connection
        bool                                                                create_timeout() noexcept;                                     // Create the main tick timer
        bool                                                                nawait_timeout() noexcept;                                     // Non-waiting timeout loop (10ms interval)

    private:
        boost::asio::io_context&                                            context_;           // ASIO io_context (execution context)
        std::shared_ptr<Byte>                                               buffer_;            // Shared buffer for UDP receive
        int                                                                 buffer_size_;       // Size of the UDP buffer
        int                                                                 congestions_;       // Max out-of-order packets allowed in receive queue
        bool                                                                server_mode_;       // True if running as server, false as client
        uint32_t                                                            last_;              // Last second counter (for tick)
        uint64_t                                                            now_;               // Current timestamp in milliseconds
        uint64_t                                                            rx_;                // Total received bytes
        uint64_t                                                            tx_;                // Total transmitted bytes
        uint64_t                                                            rx_pps_;            // Total received packets
        uint64_t                                                            tx_pps_;            // Total transmitted packets
        server_ptr                                                          server_;            // Server instance (non-null in server mode)
        client_ptr                                                          client_;            // Client instance (non-null in client mode)
        deadline_timer                                                      reopen_;            // Timer for reconnection delay
        deadline_timer                                                      timeout_;           // Main tick timer
    };
}