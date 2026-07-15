#pragma once

/**
 * @file vmux_net.h
 * @brief Core vmux network session and packet scheduler.
 * @license GPL-3.0
 */

#include "vmux.h"
#include <ppp/app/mux/MuxRuntimeState.h>

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
        typedef struct vmux_linklayer {
            VirtualEthernetTcpipConnectionPtr                                       connection;
            std::shared_ptr<
                ppp::app::server::VirtualEthernetNetworkTcpipConnection>            server;
            uint16_t                                                                id_ = 0; ///< Server-assigned carrier-link id used by MUXON handshake; 0 means unassigned. Strand-affine.
            uint64_t                                                                last_active_ = 0; ///< Tick of the most recent inbound frame on this link; turbo's approximate "best link" signal (recency, NOT RTT). Strand-affine.
            int                                                                     inflight_ = 0;    ///< In-flight async writes issued on this link and not yet completed. Strand-affine. Used by runtime link removal (turbo dynamic pool): a link is only retired once inflight_ reaches 0 so a late write completion never touches a retired link's scheduling state.
            bool                                                                    handshake_complete_ = false; ///< True only after the carrier handshake succeeds. Protected by syncobj_.
            bool                                                                    retiring_ = false; ///< Set when this link is being drained for runtime removal; it stops receiving new frames and is removed once inflight_ hits 0. Strand-affine.
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
            cmd_mux_mode_set,             ///< MUX-MODE-SET — debug-only request to switch the peer's scheduler mode.
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

        /**
         * @brief Per-connection receive ordering context (flow v2).
         *
         * Holds one connection's independent DSN delivery state: the next
         * expected per-flow DSN, a bounded reorder buffer keyed by DSN, the
         * tick the oldest buffered frame was queued (gap timeout base), the
         * current buffered byte total (memory bound), a priming flag, and a
         * fin-seen flag used to release the context after the FIN is delivered.
         */
        struct flow_rx_context {
            uint32_t                                                                flow_rx_next_         = 0;     ///< Next expected per-flow DSN.
            rx_packet_ssqueue                                                       flow_reorder_;                ///< Bounded reorder buffer keyed by DSN (packet_less handles wraparound).
            uint64_t                                                                oldest_buffered_tick_ = 0;     ///< Tick the oldest buffered frame was queued; 0 = no active gap timer.
            size_t                                                                  buffered_bytes_       = 0;     ///< Sum of buffered frame lengths (memory bound).
            bool                                                                    primed_               = false; ///< True once flow_rx_next_ has been initialized from the first frame.
            bool                                                                    fin_seen_             = false; ///< True once a cmd_fin has been delivered for this connection.
        };

        typedef vmux::unordered_map<uint32_t, vmux_skt_ptr>                         vmux_skt_map;
        typedef vmux::unordered_map<uint32_t, flow_rx_context>                      vmux_flow_map;
    public:
        enum mux_mode {
            mux_mode_compat  = 0,
            mux_mode_flow    = 1,
            mux_mode_balance = 2,
            mux_mode_stripe  = 3,
        };

        /**
         * @brief Negotiated receiver-side ordering mode (flow v2).
         *
         * ordering_compat keeps the existing single global tx_seq_/rx_ack_
         * delivery (today's behavior). ordering_flow_v2 delivers each
         * connection independently (per-flow DSN) so one slow link cannot
         * head-of-line block other connections. Negotiated via the MUX frame's
         * ordering_caps byte; defaults to compat and never upgrades unless both
         * peers explicitly agree.
         */
        enum receiver_ordering_mode {
            ordering_compat  = 0,
            ordering_flow_v2 = 1,
        };

        /** @brief MUX capability bit advertised in the handshake (bit0 = FLOW_V2). */
        enum {
            ordering_caps_flow_v2 = 0x01,
        };

    public:
        /**
         * @brief Construct a vmux network session.
         * @param context Execution context.
         * @param strand Serialized execution strand.
         * @param max_connections Maximum logical socket count.
         * @param server_mode true for server-side role.
         * @param acceleration true to enable acceleration by default.
         */
        vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, bool server_mode, bool acceleration, mux_mode mode = mux_mode_compat) noexcept;
        /** @brief Destroy the session and release all managed resources. */
        ~vmux_net() noexcept;

    public:
        const StrandPtr&                                                            get_strand()          noexcept { return strand_; }
        const ContextPtr&                                                           get_context()         noexcept { return context_; }
        uint16_t                                                                    get_max_connections() noexcept { return status_.max_connections; }
        uint64_t                                                                    get_last()            noexcept { return status_.last_; }
        mux_mode                                                                    get_mode()            noexcept { return mode_; }
        /** @brief Current absolute carrier-link ceiling (turbo dynamic pool). */
        uint16_t                                                                    get_pool_hard_max()   noexcept { return status_.pool_hard_max; }
        /** @brief Raise the carrier-link ceiling for turbo before establishment.
         *  @param hard_max New ceiling; clamped to be >= max_connections. No-op after
         *         establishment (the base/ceiling are fixed once links are built). */
        void                                                                        set_pool_hard_max(uint16_t hard_max) noexcept;
        /**
         * @brief Consume the turbo controller's pending "add N carrier links" request.
         * @return Number of links the exchanger should connect+ConnectMux+add now
         *         through add_linklayer's established-session path. Resets the
         *         pending counter to 0.
         * @note Strand-affine; called by the client exchanger's periodic mux pump.
         */
        int                                                                         take_turbo_pending_grow() noexcept;
        static mux_mode                                                             parse_mode(const ppp::string& mode) noexcept;
        /** @brief Map a wire mode byte to a valid scheduler mode (unknown -> compat). */
        static mux_mode                                                             parse_mode_byte(Byte mode_value) noexcept;
        static const char*                                                          mode_name(mux_mode mode) noexcept;
        /** @brief Switch the active scheduler mode at runtime (strand-affine). */
        void                                                                        set_mode(mux_mode mode) noexcept;
        /** @brief Returns the negotiated receiver-side ordering mode. */
        receiver_ordering_mode                                                      get_ordering_mode()   noexcept { return ordering_mode_; }
        /**
         * @brief Set the negotiated receiver ordering mode (flow v2).
         * @param m Negotiated mode.
         * @note Only takes effect before the session is established; a call
         *       after establishment is a no-op (no hot compat<->flow-v2 switch).
         */
        void                                                                        set_ordering_mode(receiver_ordering_mode m) noexcept;
        /** @brief Applies peer capability negotiation before establishment. */
        void                                                                        apply_negotiation(bool local_supports_flow_v2, bool peer_supports_flow_v2) noexcept;
        /** @brief Returns the latest observable scheduler/link state. */
        ppp::app::mux::MuxRuntimeState                                               get_runtime_state() const noexcept;
        /** @brief True for session-level control frames (keep-alive / mux-mode-set). */
        static bool                                                                 is_session_control(Byte cmd) noexcept {
            return cmd == cmd_keep_alived || cmd == cmd_mux_mode_set;
        }
        /** @brief True for connection-level control frames (syn / syn-ok / acceleration). */
        static bool                                                                 is_connection_control(Byte cmd) noexcept {
            return cmd == cmd_syn || cmd == cmd_syn_ok || cmd == cmd_acceleration;
        }
        /** @brief True for per-flow data frames carrying a per-connection DSN (push / fin). */
        static bool                                                                 is_per_flow_data(Byte cmd) noexcept {
            return cmd == cmd_push || cmd == cmd_fin;
        }
        /**
         * @brief True when this scheduler configuration uses negotiated per-flow
         *        receiver ordering (flow v2 / per-flow DSN).
         * @details balance spreads one session's frames across links by competition
         *          (any free link sends any frame) and relies on the receiver
         *          reordering each connection independently by per-flow DSN, so
         *          cross-link reordering is not mistaken for loss. stripe (legacy,
         *          experimental) likewise needs per-flow reordering. flow only needs
         *          it when turbo is enabled, so turbo can add best-link-first and
         *          prewarmed carriers without reintroducing cross-flow HoL blocking.
         */
        static bool                                                                 mode_requires_flow_v2(mux_mode mode, bool turbo) noexcept {
            return mode == mux_mode_balance || mode == mux_mode_stripe || (mode == mux_mode_flow && turbo);
        }
        static bool                                                                 mode_requires_flow_v2(mux_mode mode) noexcept {
            return mode_requires_flow_v2(mode, false);
        }
        /**
         * @brief Push a debug-only mux-mode change request to the peer.
         * @param mode  Desired scheduler mode for the remote endpoint.
         * @return true when the control frame was queued for transmit.
         * @note No-op unless a non-empty `mux.debug.key` is configured locally.
         */
        bool                                                                        post_mux_mode_set(mux_mode mode) noexcept;
        const uint32_t&                                                             get_tx_seq()          noexcept { return status_.tx_seq_; }
        const uint32_t&                                                             get_rx_ack()          noexcept { return status_.rx_ack_; }
        bool                                                                        is_disposed()         noexcept { return base_.disposed_.load(std::memory_order_acquire); }
        bool                                                                        is_established()      noexcept { return !base_.disposed_.load(std::memory_order_acquire) && base_.established_; }

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
         * @brief Begin retiring one carrier link at runtime (turbo dynamic pool
         *        shrink, C-B4). Strand-affine.
         * @return true when a link was marked for retirement.
         * @details Picks the least-recently-active non-retiring link, marks it
         *          retiring_ and removes it from tx_links_ so it takes no new frames.
         *          The link object stays in rx_links_ until its in-flight writes
         *          drain to 0, at which point reap_retired_linklayers() disposes it.
         *          Never retires below max_connections (the base must always stand).
         */
        bool                                                                        retire_linklayer_runtime() noexcept;
        /** @brief Dispose links that finished retiring (inflight_ == 0). Strand-affine; called from update(). */
        void                                                                        reap_retired_linklayers() noexcept;
        /**
         * @brief Turbo pool controller step (C-B5). Strand-affine; called from update().
         * @param now Current tick.
         * @details Derives a target pool size from link quality (a recency/backlog
         *          proxy — worse quality => larger pool, per the design) within
         *          [max_connections, pool_hard_max], then moves the live pool one
         *          step toward it (grow via turbo_pending_grow_ for the exchanger to
         *          act on; shrink via retire_linklayer_runtime), rate-limited by a
         *          cooldown for hysteresis. No-op unless turbo is on.
         */
        void                                                                        turbo_controller_tick(uint64_t now) noexcept;

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

            // Guard Suspend() behind the post result: if the executor is unavailable the
            // lambda (and the y.R() inside it) will never run, so calling Suspend() would
            // park the coroutine with no future Resume() – a permanent coroutine leak.
            bool posted = vmux_post_exec(context_, strand_,
                [&y, &ok, h]() noexcept {
                    ok = h();
                    y.R();
                });

            if (!posted) {
                return false;
            }

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

        /** @brief Validate and apply a debug-only cmd_mux_mode_set control frame. */
        void                                                                        packet_input_mux_mode_set(const Byte* buffer, int buffer_size) noexcept;

        /** @brief Per-flow (flow v2) receive path: independent per-connection DSN delivery. */
        bool                                                                        packet_input_flow(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept;
        /** @brief Deliver one framed packet (push/fin) to its logical connection. */
        bool                                                                        deliver_one(Byte cmd, vmux_hdr* h, int length, uint64_t now) noexcept;
        /** @brief Periodically advance per-flow contexts whose gap timed out. */
        void                                                                        flow_evict_expired(uint64_t now) noexcept;
        /** @brief Skip the current gap of one flow and replay contiguous buffered frames. */
        void                                                                        flow_force_advance(uint32_t connection_id, flow_rx_context& fx, uint64_t now) noexcept;
        /** @brief Release a flow context once its FIN was delivered and buffer drained. */
        void                                                                        maybe_release_flow(uint32_t connection_id, flow_rx_context& fx) noexcept;

        /** @brief Process SYN request and create connecting vmux socket state. */
        bool                                                                        process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept;

        /** @brief Refresh activity timestamp when session is alive. */
        void                                                                        active(uint64_t now) noexcept { 
            if (!base_.disposed_.load(std::memory_order_acquire)) {
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
        /** @brief True when an underlying link-layer endpoint is usable. */
        static bool                                                                 is_linklayer_active(const vmux_linklayer_ptr& linklayer) noexcept;
        /** @brief Pick or refresh the primary link-layer endpoint for flow mode. */
        vmux_linklayer_ptr                                                          select_primary_linklayer() noexcept;
        /** @brief Pick a least-loaded active link-layer (balance link selection). */
        vmux_linklayer_ptr                                                          select_balanced_linklayer() noexcept;
        /** @brief Pick the sticky link-layer bound to a connection, binding one if needed. */
        vmux_linklayer_ptr                                                          select_affinity_linklayer(uint32_t connection_id) noexcept;
        /** @brief Pick the next active link-layer round-robin (stripe distribution). */
        vmux_linklayer_ptr                                                          select_striped_linklayer() noexcept;
        /** @brief Pick the most-recently-active link for a turbo first packet.
         *  @details Approximate "best link" by recency of inbound traffic
         *           (last_active_), NOT RTT — a cheap signal that reuses existing
         *           per-link activity with no extra control frames. Used only for a
         *           new connection's first packet under turbo; the connection is NOT
         *           bound to this link (later frames return to the competition pool). */
        vmux_linklayer_ptr                                                          select_turbo_linklayer() noexcept;
        /** @brief Return true when a carrier id is already assigned to another link. */
        bool                                                                        linklayer_id_in_use(uint16_t id, const vmux_linklayer_ptr& except) noexcept;
        /** @brief Allocate a non-zero carrier id in [1, pool_hard_max], reusing retired ids. */
        uint16_t                                                                    allocate_linklayer_id(const vmux_linklayer_ptr& linklayer) noexcept;
        /** @brief Read the connection_id stored in a queued vmux frame buffer. */
        static uint32_t                                                             peek_connection_id(const std::shared_ptr<Byte>& packet, int packet_length) noexcept;

        /** @brief Drain queued transmit packets using the legacy scheduler. */
        bool                                                                        process_tx_compat_packets() noexcept;
        /** @brief Drain the high-priority control-frame queue first (flow v2).
         *  @return false on a hard send failure, true otherwise.
         *  @details Control frames (syn/syn_ok/acceleration/keep_alived/mux_mode_set)
         *           carry seq=0 under flow v2 and are delivered inline by the
         *           receiver (not DSN-gated), so they may be sent ahead of data on
         *           any free link. This keeps new-connection setup and heartbeats
         *           alive even when tx_queue_ is backlogged. No-op under compat,
         *           where global ordering forbids reordering control ahead of data. */
        bool                                                                        process_tx_ctrl_packets() noexcept;
        /** @brief Drain queued transmit packets through one primary link. */
        bool                                                                        process_tx_flow_packets() noexcept;
        /** @brief Drain queued transmit packets using the competition scheduler
         *  for balance mode. Identical send-side policy to compat (any free link
         *  sends the next queued frame — no per-connection binding); the difference
         *  is that balance negotiates per-flow receiver ordering (flow v2) so each
         *  connection is reordered independently on receive, removing cross-flow
         *  head-of-line blocking without pinning connections to links. */
        bool                                                                        process_tx_balance_packets() noexcept;
        /** @brief Drain queued transmit packets striped round-robin across links. */
        bool                                                                        process_tx_stripe_packets() noexcept;

        
        /** @brief Drain all queued transmit packets to available link layers. */
        bool                                                                        process_tx_all_packets() noexcept;
        /** @brief Final cleanup routine for session shutdown. */
        void                                                                        finalize() noexcept;

        /** @brief Get one active underlying virtual-ethernet connection. */
        VirtualEthernetTcpipConnectionPtr                                           get_linklayer() noexcept;
        /** @brief Remove one link-layer endpoint from scheduling tables. */
        void                                                                        remove_linklayer(const vmux_linklayer_ptr& linklayer) noexcept;

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
        void                                                                        refresh_runtime_active_links() noexcept;

        /** @brief Connect helper that reports result through callback. */
        bool                                                                        connect(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept;

    private:
        /** @brief Core boolean state flags for vmux session lifecycle. */
        struct {
            bool                                                                    ftt_               : 1; ///< Fast transport training frame received.
            bool                                                                    established_       : 1; ///< At least one link-layer is established.
            bool                                                                    server_or_client_  : 1; ///< true = server role; false = client role.
            bool                                                                    acceleration_      : 4; ///< Acceleration enabled flags (multi-bit).

            /**
             * @brief Session-finalized flag (atomic).
             *
             * Read from multiple threads (the per-link forwarding strands, the
             * vmux strand drain, and send/read completion callbacks) and written
             * by finalize(). Kept as a standalone std::atomic<bool> — NOT a
             * bit-field — so the teardown guard has a well-defined happens-before
             * and writing it never read-modify-writes the neighbouring flags.
             */
            std::atomic<bool>                                                       disposed_;             ///< Set when session is finalized.
        }                                                                           base_;

        /** @brief Runtime counters, sequence values, and heartbeat timestamps. */
        struct {
            uint16_t                                                                max_connections    = 0; ///< Initial/established carrier-link target (= --tun-mux base). Established fires at this count; unchanged on the wire.
            uint16_t                                                                pool_hard_max      = 0; ///< Absolute upper bound on carrier links (turbo dynamic pool). Equals max_connections when turbo is off; base*factor when on. add_linklayer quota uses this.
            uint16_t                                                                pool_current       = 0; ///< Current runtime target pool size (turbo controller), in [max_connections, pool_hard_max]. Equals max_connections when turbo off.
            uint16_t                                                                opened_connections = 0; ///< Successful base-pool handshakes used to mark initial establishment; runtime carrier ids are allocated from free slots, not by incrementing this counter.

            uint32_t                                                                rx_ack_            = 0; ///< Last acknowledged inbound sequence number.
            uint32_t                                                                tx_seq_            = 0; ///< Next outbound sequence number to use.

            uint64_t                                                                last_              = 0; ///< Monotonic tick of last received packet.
            uint64_t                                                                last_heartbeat_    = 0; ///< Monotonic tick of last heartbeat sent.

            uint64_t                                                                heartbeat_timeout_ = 0; ///< Deadline tick beyond which session is considered dead.
        }                                                                           status_;

        SynchronizationObject                                                       syncobj_;           ///< Mutex protecting shared connection map.
        mutable std::mutex                                                          runtime_state_mutex_;
        ppp::app::mux::MuxRuntimeState                                               runtime_state_;

        vmux_skt_map                                                                skts_;              ///< Active logical socket map keyed by connection_id.
        StrandPtr                                                                   strand_;            ///< Serialized strand for vmux event loop.
        ContextPtr                                                                  context_;           ///< ASIO execution context.

        tx_packet_ssqueue                                                           tx_queue_;          ///< Pending outbound data packet queue.
        tx_packet_ssqueue                                                           tx_ctrl_queue_;     ///< High-priority control-frame queue (flow v2 only); drained before tx_queue_ so new-connection SYN / heartbeats are never starved by a data backlog.
        rx_packet_ssqueue                                                           rx_queue_;          ///< Out-of-order inbound packet reorder queue.

        mux_mode                                                                    mode_               = mux_mode_compat; ///< Transmit scheduler policy.
        vmux_linklayer_ptr                                                          primary_linklayer_; ///< Primary link used by flow mode.
        bool                                                                        mux_mode_set_pushed_ = false; ///< One-shot guard for the debug mux-mode-set push.
        vmux::unordered_map<uint32_t, vmux_linklayer_ptr>                           affinity_links_;    ///< connection_id -> sticky link-layer (balance mode).
        size_t                                                                      stripe_cursor_ = 0; ///< Round-robin cursor over rx_links_ (stripe mode).

        receiver_ordering_mode                                                      ordering_mode_ = ordering_compat; ///< Negotiated receiver ordering mode (flow v2).
        vmux_flow_map                                                               flows_;             ///< connection_id -> per-flow receive context (flow v2 only).
        vmux::unordered_map<uint32_t, uint32_t>                                     tx_flow_seq_;       ///< connection_id -> next per-flow DSN to send (flow v2 only).
        size_t                                                                      flow_reorder_cap_bytes_ = 0; ///< Per-connection reorder buffer byte cap (from config).
        uint64_t                                                                    flow_reorder_timeout_   = 0; ///< Per-connection gap wait timeout in ms (from config).
        uint64_t                                                                    tx_backlog_since_       = 0; ///< Tick the data tx queue first stayed at/over high-water (0 = not backlogged); drives the D11 stall watchdog.
        size_t                                                                      tx_queue_high_water_    = (size_t)PPP_MUX_TX_QUEUE_HIGH_WATER; ///< Data tx-queue high-water depth (from config; D11 backpressure).
        uint64_t                                                                    tx_backlog_stall_ms_    = (uint64_t)PPP_MUX_TX_BACKLOG_STALL_TIMEOUT; ///< Backlog stall timeout in ms (from config; D11 watchdog).
        bool                                                                        turbo_                  = false; ///< flow-mode turbo enabled (from config; best-link-first first packet).
        uint64_t                                                                    turbo_last_adjust_      = 0;     ///< Tick of the last turbo pool grow/shrink step (cooldown base).
        int                                                                         turbo_pending_grow_     = 0;     ///< Carrier links the turbo controller wants the exchanger to add (consumed by client DoMuxEvents). Strand-affine.

        vmux_linklayer_vector                                                       rx_links_;          ///< All link-layer endpoints available for inbound.
        vmux_linklayer_list                                                         tx_links_;          ///< Link-layer endpoints ordered by transmit usage.
    };
}
