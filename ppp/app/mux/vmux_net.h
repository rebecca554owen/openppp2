#pragma once

/**
 * @file vmux_net.h
 * @brief Core vmux network session and packet scheduler.
 * @license GPL-3.0
 */

#include "vmux.h"

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetNetworkTcpipConnection;
        }

        namespace client {
            class VEthernetNetworkTcpipConnection;
        }
    }
}

namespace vmux {
    class vmux_skt;

    /**
     * @brief Multiplexed transport controller for vmux sockets.
     * @details Owns connection maps, packet queues, link layers, and heartbeat
     * management for one vmux transport session.
     */
    class vmux_net final : public std::enable_shared_from_this<vmux_net> {
    public:
        /** @brief Callback used when an async connect attempt finishes. */
        typedef ppp::function<void(vmux_skt*, bool)>                                ConnectAsynchronousCallback;
        /** @brief Underlying virtual-ethernet TCP/IP connection interface. */
        typedef ppp::app::protocol::VirtualEthernetTcpipConnection                  VirtualEthernetTcpipConnection;
        /** @brief Shared pointer wrapper for @ref VirtualEthernetTcpipConnection. */
        typedef std::shared_ptr<VirtualEthernetTcpipConnection>                     VirtualEthernetTcpipConnectionPtr;
        /** @brief Shared pointer to transmission metadata object. */
        typedef std::shared_ptr<ppp::transmissions::ITransmission>                  ITransmissionPtr;

        std::shared_ptr<ppp::threading::BufferswapAllocator>                        BufferAllocator;    ///< Shared byte-buffer pool used for packet allocation.
        std::shared_ptr<ppp::configurations::AppConfiguration>                      AppConfiguration;   ///< Application-wide runtime configuration snapshot.
        std::shared_ptr<ppp::app::protocol::VirtualEthernetLogger>                  Logger;             ///< Diagnostic and audit event logger.
        uint16_t                                                                    Vlan;               ///< VLAN identifier assigned to this session.
        std::shared_ptr<ppp::net::Firewall>                                         Firewall;           ///< Optional firewall rule evaluator.

        typedef std::shared_ptr<vmux_skt>                                           vmux_skt_ptr;
        /**
         * @brief Pair of vmux protocol connection and server-side transport wrapper.
         */
        typedef struct {
            VirtualEthernetTcpipConnectionPtr                                       connection;
            std::shared_ptr<
                ppp::app::server::VirtualEthernetNetworkTcpipConnection>            server;
        }                                                                           vmux_linklayer;

        typedef std::shared_ptr<vmux_linklayer>                                     vmux_linklayer_ptr;
        /** @brief Callback executed before finalizing successful link-layer add. */
        typedef ppp::function<bool()>                                               vmux_native_add_linklayer_after_success_before_callback;
        /** @brief Atomic integer alias used for state flags. */
        typedef std::atomic<int>                                                    atomic_int;
        /** @brief Atomic boolean alias represented by integer semantics. */
        typedef atomic_int                                                          atomic_boolean;

#if defined(_LINUX)
    public:
        typedef std::shared_ptr<ppp::net::ProtectorNetwork>                         ProtectorNetworkPtr;

    public:
        ProtectorNetworkPtr                                                         ProtectorNetwork;
#endif

    private:
        friend class                                                                vmux_skt;

        template <typename _Tp>
        struct packet_less {
            /**
             * @brief Compare wrapped 32-bit sequence values.
             * @param seq1 Left sequence number.
             * @param seq2 Right sequence number.
             * @return true when @p seq1 is considered before @p seq2.
             * @details Uses signed subtraction on explicitly-cast values to
             * avoid implementation-defined behavior during wrap handling.
             */
            static constexpr bool                                                   before(uint32_t seq1, uint32_t seq2) noexcept {
                return static_cast<int32_t>(seq1) - static_cast<int32_t>(seq2) < 0;
            }

            /**
             * @brief Compare wrapped 32-bit sequence values in reverse order.
             */
            static constexpr bool                                                   after(uint32_t seq2, uint32_t seq1) noexcept {
                return before(seq1, seq2);
            }

            /** @brief Functor adapter for ordered containers. */
            constexpr bool                                                          operator()(const _Tp& __x, const _Tp& __y) const noexcept {
                return before(__x, __y);
            }
        };

#pragma pack(push, 1)
        /**
         * @brief Packed vmux packet header prepended to every vmux frame.
         *
         * Layout (9 bytes, no padding):
         *   - seq           (4 bytes) – monotonically increasing frame sequence number.
         *   - cmd           (1 byte)  – vmux command identifier (see anonymous enum below).
         *   - connection_id (4 bytes) – logical connection this frame belongs to.
         *
         * @note All fields are in host byte order within the vmux subsystem;
         *       callers must not apply htonl/ntohs unless crossing a protocol boundary.
         */
        typedef struct 
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((packed)) 
#endif
        {
            uint32_t                                                                seq;           ///< Frame sequence number used for ordered delivery.
            uint8_t                                                                 cmd;           ///< vmux command byte (one of the cmd_* constants).
            uint32_t                                                                connection_id; ///< Logical connection identifier within this session.
        }                                                                           vmux_hdr;
#pragma pack(pop)

        /**
         * @brief vmux protocol command byte constants and packet-size limits.
         *
         * Command values are contiguous starting from `('E' - 1)` so that the
         * wire protocol is trivially distinguishable from arbitrary byte streams.
         */
        enum {
            cmd_none         = ('E' - 1), ///< Sentinel — no command / uninitialized.
            cmd_syn,                      ///< SYN — request to open a new logical connection.
            cmd_syn_ok,                   ///< SYN-OK — server acknowledges the connection request.
            cmd_push,                     ///< PUSH — carry application payload.
            cmd_fin,                      ///< FIN — close the logical connection gracefully.
            cmd_keep_alived,              ///< KEEP-ALIVE — heartbeat probe frame.
            cmd_acceleration,             ///< ACCELERATION — enable/disable fast-path flag.
            cmd_max,                      ///< Sentinel — one past the last valid command.

            max_buffers_size = UINT16_MAX - sizeof(vmux_hdr), ///< Maximum payload bytes per vmux frame.
        };

        /** @brief Internal completion callback for post operations. */
        typedef ppp::function<void(bool)>                                           PostInternalAsynchronousCallback;
        /**
         * @brief Receive packet holder used by the ordered RX reorder queue.
         *
         * Buffers a single vmux payload fragment identified by its sequence number.
         */
        struct rx_packet {
            std::shared_ptr<Byte>                                                   buffer; ///< Shared byte buffer holding the raw payload.
            int                                                                     length = 0; ///< Valid payload length in bytes.
        };

        /**
         * @brief Transmit packet holder with an optional async completion callback.
         *
         * Extends @ref rx_packet with a post-send acknowledgment callback.
         */
        struct tx_packet : rx_packet {
            PostInternalAsynchronousCallback                                        ac; ///< Optional callback invoked after the packet is sent.
        };

        typedef vmux::list<vmux_linklayer_ptr>                                      vmux_linklayer_list;
        typedef vmux::vector<vmux_linklayer_ptr>                                    vmux_linklayer_vector;

        typedef vmux::list<tx_packet>                                               tx_packet_ssqueue;
        typedef vmux::map_pr<uint32_t, rx_packet, packet_less<uint32_t>>            rx_packet_ssqueue;

        typedef vmux::unordered_map<uint32_t, vmux_skt_ptr>                         vmux_skt_map;

    public:
        /**
         * @brief Construct a vmux network session.
         * @param context Execution context.
         * @param strand Serialized execution strand.
         * @param max_connections Maximum logical socket count.
         * @param server_mode true for server-side role.
         * @param acceleration true to enable acceleration by default.
         */
        vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, bool server_mode, bool acceleration) noexcept;
        /** @brief Destroy the session and release all managed resources. */
        ~vmux_net() noexcept;

    public:
        const StrandPtr&                                                            get_strand()          noexcept { return strand_; }
        const ContextPtr&                                                           get_context()         noexcept { return context_; }
        uint16_t                                                                    get_max_connections() noexcept { return status_.max_connections; }
        uint64_t                                                                    get_last()            noexcept { return status_.last_; }
        const uint32_t&                                                             get_tx_seq()          noexcept { return status_.tx_seq_; }
        const uint32_t&                                                             get_rx_ack()          noexcept { return status_.rx_ack_; }
        bool                                                                        is_disposed()         noexcept { return base_.disposed_; }
        bool                                                                        is_established()      noexcept { return !base_.disposed_ && base_.established_; }

        /** @brief Handle fast transport training/control frame. */
        bool                                                                        ftt(uint32_t seq, uint32_t ack) noexcept;
        /** @brief Generate pseudo-random aid value in given range. */
        static uint32_t                                                             ftt_random_aid(int min, int max) noexcept;

        /** @brief Close the session in executor context. */
        void                                                                        close_exec() noexcept;
        /** @brief Drive periodic maintenance and heartbeat updates. */
        bool                                                                        update() noexcept;
        /**
         * @brief Add a new link-layer endpoint.
         * @param connection Underlying virtual ethernet connection.
         * @param linklayer Receives created link-layer object on success.
         * @param cb Callback executed before final commit.
         */
        bool                                                                        add_linklayer(
            const VirtualEthernetTcpipConnectionPtr&                                connection, 
            vmux_linklayer_ptr&                                                     linklayer,
            const vmux_native_add_linklayer_after_success_before_callback&          cb) noexcept;

        /**
         * @brief Connect to a remote host and return logical vmux socket.
         */
        bool                                                                        connect_yield(
            ppp::coroutines::YieldContext&                                          y,
            const ContextPtr&                                                       context, 
            const StrandPtr&                                                        strand,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&                    sk, 
            const template_string&                                                  host, 
            int                                                                     port,
            const std::shared_ptr<vmux_skt_ptr>&                                    return_connection) noexcept;

    public:
        template <typename YieldHandler>
        /**
         * @brief Execute handler on vmux strand and wait via coroutine yield.
         * @tparam YieldHandler Callable type returning bool-compatible value.
         * @param y Coroutine yield context.
         * @param h Handler executed on vmux executor.
         * @return Handler result.
         */
        bool                                                                        do_yield(ppp::coroutines::YieldContext& y, YieldHandler&& h) noexcept {
            bool ok = false;
            vmux_post_exec(context_, strand_,
                [&y, &ok, h]() noexcept {
                    ok = h();
                    y.R();
                });

            y.Suspend();
            return ok;
        }

        /**
         * @brief Allocate a shared byte array through the configured allocator.
         */
        std::shared_ptr<Byte>                                                       make_byte_array(int array_size) noexcept {
            return ppp::threading::BufferswapAllocator::MakeByteArray(BufferAllocator, array_size);
        }
        
        /** @brief Generate a globally unique vmux connection identifier. */
        static uint32_t                                                             generate_id() noexcept;

        /** @brief Return current monotonic tick count in milliseconds. */
        static uint64_t                                                             now_tick() noexcept { return ppp::threading::Executors::GetTickCount(); }

    private:
        /** @brief Send packet to one specific underlying link-layer endpoint. */
        bool                                                                        underlyin_sent(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& packet, int packet_length, const PostInternalAsynchronousCallback& posted_ac) noexcept;

        /** @brief Find logical socket by connection id. */
        vmux_skt_ptr                                                                get_connection(uint32_t connection_id) noexcept;
        /** @brief Remove and return connection when pointer identity matches. */
        vmux_skt_ptr                                                                release_connection(uint32_t connection_id, vmux_skt* refer_pointer) noexcept;

        /** @brief Insert or process out-of-order inbound packet. */
        bool                                                                        packet_input_unorder(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept;
        /** @brief Parse and dispatch one inbound vmux command payload. */
        bool                                                                        packet_input(Byte cmd, Byte* buffer, int buffer_size, uint64_t now) noexcept;

        /** @brief Route inbound payload to target logical connection. */
        void                                                                        packet_input_read(uint32_t connection_id, Byte* buffer, int buffer_size, uint64_t now) noexcept;

        /** @brief Process SYN request and create connecting vmux socket state. */
        bool                                                                        process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept;

        /** @brief Refresh activity timestamp when session is alive. */
        void                                                                        active(uint64_t now) noexcept { 
            if (!base_.disposed_) {
                status_.last_ = now; 
            }
        }

        /** @brief Refresh activity timestamp using current tick. */
        void                                                                        active() noexcept { 
            uint64_t now = now_tick();
            active(now);
        }

        /** @brief Post a vmux command using default acceleration behavior. */
        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id) noexcept {
            return post(cmd, packet, packet_length, connection_id, true);
        }
        /** @brief Post a vmux command with explicit acceleration switch. */
        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, bool acceleration) noexcept {
            PostInternalAsynchronousCallback null_expr;
            return post(cmd, packet, packet_length, connection_id, acceleration, null_expr);
        }
        /** @brief Post a vmux command with optional completion callback. */
        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
            bool successing = post_internal(cmd, packet, packet_length, connection_id, acceleration, posted_ac);
            if (!successing) {
                close_exec();
            }

            return successing;
        }
        /** @brief Build and enqueue one vmux framed packet. */
        bool                                                                        post_internal(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept;
        /** @brief Enqueue prebuilt vmux framed packet. */
        bool                                                                        post_internal(const std::shared_ptr<Byte>& packet, int packet_length, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept;
        
        /** @brief Drain all queued transmit packets to available link layers. */
        bool                                                                        process_tx_all_packets() noexcept;
        /** @brief Final cleanup routine for session shutdown. */
        void                                                                        finalize() noexcept;

        /** @brief Get one active underlying virtual-ethernet connection. */
        VirtualEthernetTcpipConnectionPtr                                           get_linklayer() noexcept;

        /** @brief Validate and post outgoing connect request command. */
        bool                                                                        connect_require(
            const std::shared_ptr<boost::asio::ip::tcp::socket>&                    sk, 
            const template_string&                                                  host, 
            int                                                                     port) noexcept;

        /** @brief Perform protocol handshake on specified link-layer. */
        bool                                                                        handshake(const vmux_linklayer_ptr& linklayer, uint16_t connection_id, ppp::coroutines::YieldContext& y) noexcept;
        /** @brief Forward frames between network link-layer and vmux core. */
        bool                                                                        forwarding(const vmux_linklayer_ptr& linklayer, ppp::coroutines::YieldContext& y) noexcept;
        
        /** @brief Recompute and schedule next heartbeat timeout threshold. */
        void                                                                        switch_to_next_heartbeat_timeout() noexcept;
        /** @brief Mark at least one link-layer as established. */
        void                                                                        linklayer_established() noexcept;
        /** @brief Touch/update link-layer usage order for load balancing. */
        void                                                                        linklayer_update(const vmux_linklayer_ptr& linklayer) noexcept;

        /** @brief Connect helper that reports result through callback. */
        bool                                                                        connect(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept;

    private:
        /** @brief Core boolean state flags for vmux session lifecycle. */
        struct {
            bool                                                                    disposed_          : 1; ///< Set when session is finalized.
            bool                                                                    ftt_               : 1; ///< Fast transport training frame received.
            bool                                                                    established_       : 1; ///< At least one link-layer is established.
            bool                                                                    server_or_client_  : 1; ///< true = server role; false = client role.
            bool                                                                    acceleration_      : 4; ///< Acceleration enabled flags (multi-bit).
        }                                                                           base_;

        /** @brief Runtime counters, sequence values, and heartbeat timestamps. */
        struct {
            uint16_t                                                                max_connections    = 0; ///< Maximum allowed logical connections.
            uint16_t                                                                opened_connections = 0; ///< Currently active logical connection count.

            uint32_t                                                                rx_ack_            = 0; ///< Last acknowledged inbound sequence number.
            uint32_t                                                                tx_seq_            = 0; ///< Next outbound sequence number to use.

            uint64_t                                                                last_              = 0; ///< Monotonic tick of last received packet.
            uint64_t                                                                last_heartbeat_    = 0; ///< Monotonic tick of last heartbeat sent.

            uint64_t                                                                heartbeat_timeout_ = 0; ///< Deadline tick beyond which session is considered dead.
        }                                                                           status_;

        SynchronizationObject                                                       syncobj_;           ///< Mutex protecting shared connection map.

        vmux_skt_map                                                                skts_;              ///< Active logical socket map keyed by connection_id.
        StrandPtr                                                                   strand_;            ///< Serialized strand for vmux event loop.
        ContextPtr                                                                  context_;           ///< ASIO execution context.

        tx_packet_ssqueue                                                           tx_queue_;          ///< Pending outbound packet queue.
        rx_packet_ssqueue                                                           rx_queue_;          ///< Out-of-order inbound packet reorder queue.

        vmux_linklayer_vector                                                       rx_links_;          ///< All link-layer endpoints available for inbound.
        vmux_linklayer_list                                                         tx_links_;          ///< Link-layer endpoints ordered by transmit usage.
    };
}
