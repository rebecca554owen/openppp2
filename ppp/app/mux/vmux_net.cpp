#include "vmux.h"
#include "vmux_net.h"
#include "vmux_skt.h"
#include <ppp/configurations/AppConfiguration.h>
#include <chrono>
#include <openssl/crypto.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include "ppp/app/client/VEthernetNetworkTcpipConnection.h"
#include "ppp/app/server/VirtualEthernetNetworkTcpipConnection.h"
#include "ppp/collections/Dictionary.h"

/**
 * @file vmux_net.cpp
 * @brief Implements vmux network multiplexing, handshake, and packet forwarding.
 * @license GPL-3.0
 */

namespace vmux {
    /**
     * @brief Parses a textual MUX scheduler mode.
     */
    vmux_net::mux_mode vmux_net::parse_mode(const ppp::string& mode) noexcept {
        ppp::string value = ppp::ToLower<ppp::string>(ppp::LTrim(ppp::RTrim(mode)));
        if (value == "flow" || value == "flow-v1" || value == "primary" || value == "primary-link") {
            return mux_mode_flow;
        }

        if (value == "balance" || value == "balanced" || value == "lb" || value == "load-balance") {
            return mux_mode_balance;
        }

        if (value == "stripe" || value == "striped" || value == "striping") {
            return mux_mode_stripe;
        }

        return mux_mode_compat;
    }

    /**
     * @brief Maps a wire mode byte to a valid scheduler mode.
     * @return The mode for known values; mux_mode_compat for anything else.
     */
    vmux_net::mux_mode vmux_net::parse_mode_byte(Byte mode_value) noexcept {
        switch (mode_value) {
        case mux_mode_flow:
            return mux_mode_flow;
        case mux_mode_balance:
            return mux_mode_balance;
        case mux_mode_stripe:
            return mux_mode_stripe;
        default:
            return mux_mode_compat;
        }
    }

    /**
     * @brief Returns the stable text name for a scheduler mode.
     */
    const char* vmux_net::mode_name(mux_mode mode) noexcept {
        switch (mode) {
        case mux_mode_flow:
            return "flow";
        case mux_mode_balance:
            return "balance";
        case mux_mode_stripe:
            return "stripe";
        default:
            return "compat";
        }
    }

    /**
     * @brief Switches the active scheduler mode at runtime.
     * @details Must run on the vmux strand. Resets per-mode scheduling state
     *          (primary link, affinity map, stripe cursor) so the next drain
     *          re-picks links under the new policy.
     */
    void vmux_net::set_mode(mux_mode mode) noexcept {
        mux_mode normalized = mode;
        switch (normalized) {
        case mux_mode_flow:
        case mux_mode_balance:
        case mux_mode_stripe:
            break;
        default:
            normalized = mux_mode_compat;
            break;
        }

        if (mode_ == normalized) {
            return;
        }

        mode_ = normalized;
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            runtime_state_.effective_mode = mode_name(mode_);
        }
        primary_linklayer_.reset();
        affinity_links_.clear();
        stripe_cursor_ = 0;
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "scheduler mode switched to %s", mode_name(mode_));
    }

    /**
     * @brief Applies the negotiated receiver ordering mode (flow v2).
     * @details Effective only before the session is established (no hot switch
     *          between compat and flow-v2). Also latches the per-connection
     *          reorder bounds from AppConfiguration when entering flow-v2.
     */
    void vmux_net::set_ordering_mode(receiver_ordering_mode m) noexcept {
        if (base_.established_) {
            return; // session-level, immutable after establishment.
        }

        receiver_ordering_mode normalized = (m == ordering_flow_v2) ? ordering_flow_v2 : ordering_compat;
        ordering_mode_ = normalized;
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            runtime_state_.receiver_ordering = normalized == ordering_flow_v2 ? "flow_v2" : "compat";
        }

        // Latch send-side backpressure / watchdog bounds from config (applies to
        // all modes; AppConfiguration is set by the exchanger before establishment).
        if (NULLPTR != AppConfiguration) {
            int qmax = AppConfiguration->mux.tx.queue.max;
            int qstall = AppConfiguration->mux.tx.queue.stall;
            tx_queue_high_water_ = (qmax > 0) ? (size_t)qmax : (size_t)PPP_MUX_TX_QUEUE_HIGH_WATER;
            tx_backlog_stall_ms_ = (qstall > 0) ? (uint64_t)qstall : (uint64_t)PPP_MUX_TX_BACKLOG_STALL_TIMEOUT;
            // flow turbo: only meaningful under flow mode; harmless to latch always.
            turbo_ = AppConfiguration->mux.turbo && (mode_ == mux_mode_flow);
        }

        if (normalized == ordering_flow_v2) {
            // Latch bounded-reorder limits from config (AppConfiguration is set
            // by the exchanger before establishment); fall back to safe defaults.
            int cap_bytes = (NULLPTR != AppConfiguration) ? AppConfiguration->mux.flow.reorder.bytes : 0;
            int timeout_ms = (NULLPTR != AppConfiguration) ? AppConfiguration->mux.flow.reorder.timeout : 0;
            flow_reorder_cap_bytes_ = (cap_bytes > 0) ? (size_t)cap_bytes : (size_t)PPP_MUX_FLOW_REORDER_BYTES;
            flow_reorder_timeout_   = (timeout_ms > 0) ? (uint64_t)timeout_ms : (uint64_t)PPP_MUX_FLOW_REORDER_TIMEOUT;
        }

        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "ordering mode=%s",
            normalized == ordering_flow_v2 ? "flow-v2" : "compat");
    }

    void vmux_net::apply_negotiation(bool local_supports_flow_v2, bool peer_supports_flow_v2) noexcept {
        ppp::app::mux::MuxRuntimeState state;
        {
            std::lock_guard<std::mutex> scope(runtime_state_mutex_);
            state = ppp::app::mux::NegotiateMuxRuntimeState(
                runtime_state_.requested_mode,
                local_supports_flow_v2,
                peer_supports_flow_v2,
                runtime_state_.active_links);
            runtime_state_ = state;
        }
        set_mode(parse_mode(ppp::string(state.effective_mode.data(), state.effective_mode.size())));
        set_ordering_mode(state.receiver_ordering == "flow_v2" ? ordering_flow_v2 : ordering_compat);
    }

    ppp::app::mux::MuxRuntimeState vmux_net::get_runtime_state() const noexcept {
        std::lock_guard<std::mutex> scope(runtime_state_mutex_);
        return runtime_state_;
    }

    void vmux_net::refresh_runtime_active_links() noexcept {
        std::size_t active_links = 0;
        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (NULLPTR != linklayer && ppp::app::mux::IsMuxLinkActive(
                    linklayer->handshake_complete_, linklayer->retiring_)) {
                ++active_links;
            }
        }
        std::lock_guard<std::mutex> scope(runtime_state_mutex_);
        runtime_state_.active_links = static_cast<std::uint16_t>(
            std::min<std::size_t>(active_links, UINT16_MAX));
    }

    /**
     * @brief Raises the carrier-link ceiling for turbo before establishment.
     */
    void vmux_net::set_pool_hard_max(uint16_t hard_max) noexcept {
        if (base_.established_) {
            return; // base/ceiling are fixed once the initial links are built.
        }

        if (hard_max < status_.max_connections) {
            hard_max = status_.max_connections;
        }

        status_.pool_hard_max = hard_max;
        // pool_current stays at the base until the controller moves it.
        if (status_.pool_current < status_.max_connections) {
            status_.pool_current = status_.max_connections;
        }
    }

    /**
     * @brief Consumes the turbo controller's pending grow request.
     */
    int vmux_net::take_turbo_pending_grow() noexcept {
        int n = turbo_pending_grow_;
        turbo_pending_grow_ = 0;
        return n;
    }

    /**
     * @brief Debug-only wire payload for cmd_mux_mode_set.
     *
     * Layout: [mode:1][key_len:1][key:key_len]. The key authorizes the change;
     * the receiver applies the mode only when the key matches its own non-empty
     * mux.debug.key. No new per-frame header field is introduced.
     */
    bool vmux_net::post_mux_mode_set(mux_mode mode) noexcept {
        if (NULLPTR == AppConfiguration) {
            return false;
        }

        const ppp::string& debug_key = AppConfiguration->mux.debug.key;
        if (debug_key.empty()) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set ignored: no local debug key configured");
            return false;
        }

        size_t key_length = debug_key.size();
        if (key_length > 255) {
            key_length = 255;
        }

        ppp::vector<Byte> payload(2 + key_length);
        payload[0] = static_cast<Byte>(mode);
        payload[1] = static_cast<Byte>(key_length);
        if (key_length > 0) {
            memcpy(payload.data() + 2, debug_key.data(), key_length);
        }

        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set requesting peer mode=%s", mode_name(mode));
        return post(cmd_mux_mode_set, payload.data(), static_cast<int>(payload.size()), 0);
    }

    using ppp::telemetry::Level;

    /**
     * @brief Constructs a vmux network core with runtime mode/capacity settings.
     */
    vmux_net::vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, bool server_mode, bool acceleration, mux_mode mode) noexcept {
        assert(max_connections > 0 && "The value of max_connections must be greater than 0.");

        vmux_net* const m             = this;
        m->Vlan                       = 0;
   
        m->base_.server_or_client_    = server_mode;
        m->base_.disposed_.store(false, std::memory_order_release);
        m->base_.ftt_                 = false;
        m->base_.established_         = false;
        m->base_.acceleration_        = acceleration;
        
        m->status_.max_connections    = max_connections;
        m->status_.pool_hard_max      = max_connections; // raised by turbo via set_pool_hard_max() before establishment.
        m->status_.pool_current       = max_connections; // runtime target; equals base until the turbo controller moves it.
        m->status_.opened_connections = 0;

        m->status_.rx_ack_            = 0;
        m->status_.tx_seq_            = 0;

        m->mode_                      = mode;
        switch (m->mode_) {
        case mux_mode_flow:
        case mux_mode_balance:
        case mux_mode_stripe:
            break;
        default:
            m->mode_                  = mux_mode_compat;
            break;
        }
        m->runtime_state_.requested_mode = mode_name(m->mode_);
        m->runtime_state_.effective_mode = mode_name(m->mode_);
        m->runtime_state_.receiver_ordering = "compat";

        ppp::telemetry::Log(Level::kInfo, "mux", "mode=%s", mode_name(m->mode_));
        uint64_t now                  = now_tick();
        m->status_.last_              = now;
        m->status_.last_heartbeat_    = now;
        m->status_.heartbeat_timeout_ = 0;

        m->strand_                    = strand;
        m->context_                   = context;
    }

    /**
     * @brief Destroys the vmux network and releases runtime resources.
     */
    vmux_net::~vmux_net() noexcept {
        // finalize without relying on shared_from_this() (destructor
        // context may not have shared ownership). Prefer callers to
        // invoke close_exec() which posts finalize onto the strand.
        finalize();
    }

    /**
     * @brief Finalizes queues, sockets, and linklayers, then marks disposed.
     */
    void vmux_net::finalize() noexcept {
        vmux_linklayer_vector rx_links;
        tx_packet_ssqueue tx_queue;
        rx_packet_ssqueue rx_queue;
        vmux_skt_map skts;
        std::shared_ptr<boost::asio::ip::tcp::resolver> tx_resolver;

        for (;;) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (!base_.disposed_.load(std::memory_order_acquire)) {
                base_.disposed_.store(true, std::memory_order_release);
                status_.last_ = now_tick(); 
            }

            rx_links = std::move(rx_links_);
            tx_queue = std::move(tx_queue_);
            rx_queue = std::move(rx_queue_);

            skts = std::move(skts_);
            skts_.clear();

            tx_queue_.clear();
            tx_ctrl_queue_.clear();
            rx_queue_.clear();
            rx_links_.clear();
            refresh_runtime_active_links();
            tx_links_.clear();
            primary_linklayer_.reset();
            affinity_links_.clear();
            stripe_cursor_ = 0;
            flows_.clear();
            tx_flow_seq_.clear();
            break;
        }

        for (const std::pair<uint32_t, vmux_skt_ptr>& kv : skts) {
            const vmux_skt_ptr& skt = kv.second;
            skt->close(); // There is no need to send any data because the underlying link will be interrupted.
        }

        for (vmux_linklayer_ptr& linklayer : rx_links) {
            ppp::telemetry::Log(Level::kInfo, "mux", "link close");
            ppp::telemetry::Count("mux.link.close", 1);

            VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
            connection->Dispose();

            if (auto server = std::move(linklayer->server); NULLPTR != server) {
                server->Dispose();
            }
        }

        if (NULLPTR != tx_resolver) {
            vmux_post_exec(context_, strand_,
                [tx_resolver]() noexcept {
                    ppp::net::Socket::Cancel(*tx_resolver);
                });
        }
    }

    /** @brief Returns the first active linklayer connection, if available. */
    vmux_net::VirtualEthernetTcpipConnectionPtr vmux_net::get_linklayer() noexcept {
        vmux_linklayer_vector::iterator tail = rx_links_.begin();
        vmux_linklayer_vector::iterator endl = rx_links_.end();
        return tail != endl ? (*tail)->connection : NULLPTR;
    }

    /** @brief Removes one link-layer endpoint from receive/transmit scheduling state. */
    void vmux_net::remove_linklayer(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR == linklayer) {
            return;
        }

        for (vmux_linklayer_vector::iterator it = rx_links_.begin(); it != rx_links_.end();) {
            if (*it == linklayer) {
                it = rx_links_.erase(it);
            }
            else {
                ++it;
            }
        }
        refresh_runtime_active_links();

        for (vmux_linklayer_list::iterator it = tx_links_.begin(); it != tx_links_.end();) {
            if (*it == linklayer) {
                it = tx_links_.erase(it);
            }
            else {
                ++it;
            }
        }

        if (primary_linklayer_ == linklayer) {
            primary_linklayer_.reset();
        }

        for (auto it = affinity_links_.begin(); it != affinity_links_.end();) {
            if (it->second == linklayer) {
                it = affinity_links_.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    /**
     * @brief Performs first-time-transfer sequence initialization/validation.
     */
    bool vmux_net::ftt(uint32_t seq, uint32_t ack) noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }
        
        if (!base_.ftt_) {
            base_.ftt_ = true;
            status_.tx_seq_ = seq;
            status_.rx_ack_ = ack;
        }

        return (status_.tx_seq_ == seq) && (status_.rx_ack_ == ack);
    }

    /** @brief Produces a randomized signed identifier encoded as uint32_t. */
    uint32_t vmux_net::ftt_random_aid(int min, int max) noexcept {
        int a = ppp::RandomNext();
        int b = a & 1;
        if (b != 0) {
            return (uint32_t)-ppp::RandomNext(min, max);
        }
        else {
            return (uint32_t)ppp::RandomNext(min, max);
        }
    }

    /** @brief Posts deferred close/finalize work onto the vmux strand. */
    void vmux_net::close_exec() noexcept {
        std::shared_ptr<vmux_net> self = shared_from_this();
        vmux_post_exec(context_, strand_,
            [self, this]() noexcept {
                finalize();
            });
    }

    /**
     * @brief Writes a packet via transmission and dispatches completion on vmux strand.
     */
    static bool transmission_write(
        std::shared_ptr<vmux_net>                                           self,
        const vmux_net::ITransmissionPtr&                                   transmission, 
        const std::shared_ptr<Byte>&                                        packet, 
        int                                                                 packet_length,
        const ppp::transmissions::ITransmission::AsynchronousWriteCallback& ac) noexcept {

        ContextPtr context = transmission->GetContext();
        StrandPtr strand = transmission->GetStrand();

        const ppp::function<void(bool)> on_completely = 
            [self, ac](bool successed) noexcept {
                vmux_post_exec(self->get_context(), self->get_strand(), 
                    [self, successed, ac]() noexcept {
                        ac(successed);
                    });
            };

        bool posted = vmux_post_exec(context, strand,
            [self, transmission, context, strand, packet, packet_length, on_completely]() noexcept {
                bool forwarding =
                    transmission->Write(packet.get(), packet_length,
                        [self, context, strand, on_completely](bool ok) noexcept {
                            on_completely(ok);
                        });

                if (!forwarding) {
                    on_completely(false);
                }
            });

        if (!posted) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
        }

        return posted;
    }
    
    /**
     * @brief Sends one packet through the specified underlying linklayer.
     */
    bool vmux_net::underlyin_sent(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& packet, int packet_length, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULLPTR == packet || packet_length < sizeof(vmux_hdr)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }
        
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
        if (!connection->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        ITransmissionPtr transmission = connection->GetTransmission();
        if (NULLPTR == transmission) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        ppp::telemetry::Count("mux.link.send", 1);
        // Track in-flight writes per link (strand-affine) so runtime link removal
        // (turbo dynamic pool) can retire a link only after its last write
        // completes — a late completion must never touch a freed/retired link's
        // scheduling state.
        linklayer->inflight_++;
        return transmission_write(self, transmission, packet, packet_length, 
            [self, this, linklayer, posted_ac](bool ok) noexcept {
                // Decrement in-flight first; this completion is accounted regardless
                // of what follows. Runtime removal checks inflight_ == 0 to retire.
                if (linklayer->inflight_ > 0) {
                    linklayer->inflight_--;
                }

                if (NULLPTR != posted_ac) {
                    posted_ac(ok);
                }

                // Teardown guard: a send may complete after the session has been
                // finalized (link flap, idle timeout, or peer close). finalize()
                // clears tx_links_/tx_queue_ under syncobj_; touching them again
                // from this strand callback (emplace_back / erase / re-drain) would
                // race the teardown and operate on freed list nodes. Once disposed,
                // drop the completion: there is nothing left to schedule.
                if (base_.disposed_.load(std::memory_order_acquire)) {
                    return;
                }

                // A link being retired for runtime removal stops taking new frames;
                // do not re-credit it. Once its in-flight drains to 0 the periodic
                // maintenance path removes it. Re-drive the scheduler so queued
                // frames continue on the remaining links.
                if (linklayer->retiring_) {
                    process_tx_all_packets();
                    return;
                }

                if (ok) {
                    // stripe picks a link per packet (round-robin), so on completion
                    // it returns this link's credit and re-runs the scheduler to
                    // route the next frame by policy. compat / flow / balance all use
                    // the competition drain (driven from the free-link list): they
                    // keep sending the next queued frame on this same just-freed link.
                    bool per_packet_policy_drain = (mode_ == mux_mode_stripe);
                    if (per_packet_policy_drain) {
                        tx_links_.emplace_back(linklayer);
                        ok = process_tx_all_packets();
                    }
                    else {
                        tx_packet_ssqueue::iterator packet_tail = tx_queue_.begin();
                        tx_packet_ssqueue::iterator packet_endl = tx_queue_.end();
                        if (packet_tail == packet_endl) {
                            tx_links_.emplace_back(linklayer);
                        }
                        else {
                            tx_packet packet = *packet_tail;
                            tx_queue_.erase(packet_tail);

                            ok = underlyin_sent(linklayer, packet.buffer, packet.length, packet.ac);
                        }
                    }
                }

                if (!ok) {
                    close_exec();
                }
            });
    }

    /**
     * @brief Periodically updates timeout state and closes stale sockets.
     */
    bool vmux_net::update() noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        bool posted = vmux_post_exec(context_, strand_,
            [self, this]() noexcept {
                list<vmux_skt_ptr> release_skts;

                uint64_t max_tcp_inactive_timeout = ((uint64_t)AppConfiguration->tcp.inactive.timeout) * 1000ULL;
                uint64_t max_tcp_connect_timeout = ((uint64_t)AppConfiguration->tcp.connect.timeout) * 1000ULL;

                uint64_t now = now_tick();
                if (base_.established_) {
                    for (const std::pair<uint32_t, vmux_skt_ptr>& kv : skts_) {
                        bool is_port_aging = false;
                        const vmux_skt_ptr& skt = kv.second;

                        uint64_t delta_time = now - skt->last_;
                        if (skt->status_.connected_) {
                            is_port_aging = delta_time >= max_tcp_inactive_timeout;
                        }
                        else {
                            is_port_aging = delta_time >= max_tcp_connect_timeout;
                        }

                        if (is_port_aging) {
                            release_skts.emplace_back(skt);
                        }
                    }
                }

                /**
                 * @brief Complex maintenance step:
                 * - close per-socket idle/connect-timeout entries,
                 * - enforce global mux inactivity timeout,
                 * - schedule heartbeat keepalive when established.
                 */
                uint64_t max_mux_inactive_timeout = ((uint64_t)AppConfiguration->mux.inactive.timeout) * 1000ULL;
                uint64_t max_mux_connect_timeout = ((uint64_t)AppConfiguration->mux.connect.timeout) * 1000ULL;

                if ((now - status_.last_) >= (base_.established_ ? max_mux_inactive_timeout : max_mux_connect_timeout)) {
                    close_exec();
                }
                elif(base_.established_ && (now - status_.last_heartbeat_) >= status_.heartbeat_timeout_) {
                    if (post(cmd_keep_alived, NULLPTR, 0, ftt_random_aid(1, INT32_MAX))) {
                        status_.last_heartbeat_ = now;
                        switch_to_next_heartbeat_timeout();
                    }
                }

                for (vmux_skt_ptr& skt : release_skts) {
                    skt->close();
                }

                /**
                 * @brief Debug-only one-shot mux-mode push.
                 *
                 * Once the session is established, if a transient
                 * `--mux-mode-set` request and a non-empty `--debug-key` are
                 * configured locally, push the requested scheduler mode to the
                 * peer exactly once. The peer applies it only when its own
                 * debug key matches (see packet_input_mux_mode_set).
                 */
                if (base_.established_ && !mux_mode_set_pushed_ && NULLPTR != AppConfiguration) {
                    const ppp::string& set_mode = AppConfiguration->mux.debug.set_mode;
                    if (!set_mode.empty() && !AppConfiguration->mux.debug.key.empty()) {
                        if (post_mux_mode_set(parse_mode(set_mode))) {
                            mux_mode_set_pushed_ = true;
                        }
                    }
                    else {
                        mux_mode_set_pushed_ = true; // Nothing to push; do not re-check every tick.
                    }
                }

                /**
                 * @brief Scheduler observability (Phase 2 telemetry):
                 * publish the active scheduler mode together with the transmit
                 * queue depth, the out-of-order reorder queue depth, and the
                 * number of attached link-layers. These run on the vmux strand,
                 * so reading the queues/link containers here is race-free.
                 */
                if (!base_.disposed_.load(std::memory_order_acquire)) {
                    // flow-v2: advance any per-connection gap whose wait timed out so a
                    // permanently lost frame cannot stall that connection's delivery.
                    flow_evict_expired(now);

                    // turbo dynamic pool: dispose any carrier link that finished
                    // retiring (its in-flight writes drained to 0) since last tick.
                    reap_retired_linklayers();

                    // turbo dynamic pool controller: move the pool one step toward
                    // the quality-derived target (grow request / shrink retire).
                    turbo_controller_tick(now);

                    // D11 stall watchdog: if the data tx queue stays at/over the
                    // high-water mark for longer than the stall timeout, the send
                    // side is wedged (carrier not draining; new connections starve)
                    // and cannot self-heal. Tear the session down so it is rebuilt,
                    // rather than hang forever serving nothing. Control frames have
                    // their own priority queue, so this only triggers on a genuine
                    // data-path wedge.
                    size_t tx_depth = tx_queue_.size();
                    if (tx_depth >= tx_queue_high_water_) {
                        if (tx_backlog_since_ == 0) {
                            tx_backlog_since_ = now;
                        }
                        elif((now - tx_backlog_since_) >= tx_backlog_stall_ms_) {
                            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux",
                                "tx backlog stall watchdog: depth=%d held >= %dms, rebuilding session",
                                (int)tx_depth, (int)tx_backlog_stall_ms_);
                            ppp::telemetry::Count("mux.tx.backlog.stall", 1);
                            close_exec();
                        }
                    }
                    else {
                        tx_backlog_since_ = 0;
                    }

                    ppp::telemetry::Gauge("mux.sched.mode", static_cast<int64_t>(mode_));
                    ppp::telemetry::Gauge("mux.tx.queue.depth", static_cast<int64_t>(tx_queue_.size()));
                    ppp::telemetry::Gauge("mux.rx.reorder.depth", static_cast<int64_t>(rx_queue_.size()));
                    ppp::telemetry::Gauge("mux.link.count", static_cast<int64_t>(rx_links_.size()));
                }
            });

        if (!posted) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
        }

        return posted;
    }

    /** @brief Selects the next randomized heartbeat timeout window. */
    void vmux_net::switch_to_next_heartbeat_timeout() noexcept {
        int min = std::max<int>(0, AppConfiguration->mux.keep_alived[0]);
        int max = std::max<int>(0, AppConfiguration->mux.keep_alived[1]);
        if (min > max) {
            std::swap(min, max);
        }

        if (max == 0) {
            max = AppConfiguration->mux.connect.timeout;
        }

        min = std::max<int>(1, min) * 1000;
        max = std::max<int>(1, max) * 1000;
        status_.heartbeat_timeout_ = ppp::RandomNext(min, max + 1);
    }

    /**
     * @brief Processes in-order/out-of-order packets and advances ACK state.
     */
    bool vmux_net::packet_input_unorder(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept {
        // Prepare the ack frames.
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        ppp::telemetry::Count("mux.link.recv", 1);

        uint32_t seq = ntohl(h->seq);
        if (status_.rx_ack_ == seq) {
                if (packet_input(h->cmd, (Byte*)h, length, now)) {
                    status_.rx_ack_++;
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                    return false;
                }

            for (;;) {
                rx_packet_ssqueue::iterator packet_tail = rx_queue_.begin();
                rx_packet_ssqueue::iterator packet_endl = rx_queue_.end();
                if (packet_tail != packet_endl && status_.rx_ack_ == packet_tail->first) {
                    rx_packet i = packet_tail->second;
                    vmux_hdr* p = (vmux_hdr*)i.buffer.get();
                    rx_queue_.erase(packet_tail);

                    if (packet_input(p->cmd, (Byte*)p, i.length, now)) {
                        status_.rx_ack_++;
                    }
                    else {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                        return false;
                    }
                }
                else {
                    break;
                }
            }

            active(now);
            linklayer_update(linklayer);
            return true;
        }
        elif(packet_less<uint32_t>::after(seq, status_.rx_ack_)) {
            /**
             * @brief Complex reorder path:
             * buffers future packets by sequence and replays contiguous packets once
             * the missing sequence is received.
             */
            // Protect against absurd packet sizes and allocate within limit.
            // 'length' here includes the vmux_hdr; ensure it's at least a header
            // and does not exceed header + max_buffers_size.
            if (length < sizeof(vmux_hdr) || length > (sizeof(vmux_hdr) + max_buffers_size)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return false;
            }

            std::shared_ptr<Byte> buf = make_byte_array(length);
            if (NULLPTR == buf) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetReorderPacketBufferAllocFailed);
                return false;
            }

            rx_packet packet = { buf, length };
            memcpy(buf.get(), h, length);

            bool inserted = rx_queue_.emplace(std::make_pair(seq, packet)).second;
            if (!inserted) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MappingEntryConflict);
            }

            return inserted;
        }
        else {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }
    }

    /** @brief Delivers payload data to one logical vmux socket. */
    void vmux_net::packet_input_read(uint32_t connection_id, Byte* buffer, int buffer_size, uint64_t now) noexcept {
        vmux_skt_ptr skt = get_connection(connection_id);
        if (NULLPTR != skt) {
            if (skt->input(buffer, buffer_size)) {
                skt->active(now);
            }
            else {
                skt->close();
            }
        }
    }

    /**
     * @brief Dispatches an incoming vmux command frame to its handler.
     */
    bool vmux_net::packet_input(Byte cmd, Byte* buffer, int buffer_size, uint64_t now) noexcept {
        buffer_size -= sizeof(vmux_hdr);
        if (buffer_size < 0) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)buffer;
        buffer = (Byte*)(h + 1);

        uint32_t connection_id = ntohl(h->connection_id);
        if (cmd == cmd_push) {
            packet_input_read(connection_id, buffer, buffer_size, now);
        }
        elif(cmd == cmd_fin) {
            packet_input_read(connection_id, NULLPTR, 0, now);
        }
        elif(cmd == cmd_syn) {
            std::shared_ptr<vmux_skt> sk;
            bool successed = process_rx_connecting(sk, connection_id, (char*)buffer, buffer_size);

            if (NULLPTR != sk) {
                if (successed) {
                    sk->active(now);
                }
                else {
                    sk->close();
                }
            }
        }
        elif(cmd == cmd_syn_ok) {
            vmux_skt_ptr skt = get_connection(connection_id);
            if (NULLPTR != skt) {
                bool successed = false;
                if (buffer_size > 0) {
                    const Byte err = static_cast<Byte>(*buffer);
                    successed = skt->connect_ok(err == 'A');
                }

                if (successed) {
                    skt->active(now);
                }
                else {
                    skt->close();
                }
            }
        }
        elif(cmd == cmd_acceleration) {
            vmux_skt_ptr skt = get_connection(connection_id);
            if (NULLPTR != skt) {
                bool acceleration = true;
                if (buffer_size > 0) {
                    acceleration = static_cast<Byte>(*buffer) != FALSE;
                }

                if (skt->tx_acceleration(acceleration)) {
                    skt->active(now);
                }
                else {
                    skt->close();
                }
            }
        }
        elif(cmd == cmd_keep_alived) {
            active(now);
        }
        elif(cmd == cmd_mux_mode_set) {
            packet_input_mux_mode_set(buffer, buffer_size);
            active(now);
        }
        else {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
            return false;
        }

        return true;
    }

    /**
     * @brief Handles a debug-only cmd_mux_mode_set control frame.
     *
     * Applies the requested scheduler mode only when remote control is enabled
     * locally (non-empty mux.debug.key) and the key carried in the frame matches
     * exactly. Mismatches are logged and ignored; the session is never closed,
     * so a malformed/forged frame cannot disrupt traffic.
     */
    void vmux_net::packet_input_mux_mode_set(const Byte* buffer, int buffer_size) noexcept {
        if (NULLPTR == AppConfiguration) {
            return;
        }

        const ppp::string& debug_key = AppConfiguration->mux.debug.key;
        if (debug_key.empty()) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set rejected: remote control disabled (no debug key)");
            return;
        }

        if (NULLPTR == buffer || buffer_size < 2) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set rejected: malformed control frame");
            return;
        }

        Byte requested = buffer[0];
        int key_length = static_cast<int>(buffer[1]);
        if (key_length <= 0 || (2 + key_length) > buffer_size) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set rejected: invalid key length");
            return;
        }

        bool key_matched =
            key_length == static_cast<int>(debug_key.size()) &&
            CRYPTO_memcmp(buffer + 2, debug_key.data(), key_length) == 0;
        if (!key_matched) {
            ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set rejected: debug key mismatch");
            return;
        }

        mux_mode mode = parse_mode_byte(requested);
        ppp::telemetry::Log(ppp::telemetry::Level::kInfo, "mux", "mux-mode-set accepted from peer: mode=%s", mode_name(mode));

        // Apply to the live session and record a lock-free runtime override on the
        // shared runtime config so the change survives mux session rebuilds (link
        // flap, idle/heartbeat timeout). The exchanger reconstructs a vmux_net via
        // AppConfiguration->GetEffectiveMuxMode() on reconnect; without this the
        // pushed mode would be lost and silently revert to the configured value.
        // A plain atomic is used (not the mux.mode string) to avoid a data race
        // with the exchanger thread that reads the mode during rebuilds.
        AppConfiguration->SetMuxModeRuntimeOverride(static_cast<int>(mode));
        set_mode(mode);
    }

    /**
     * @brief Delivers one framed data packet (push/fin) to its logical connection.
     * @details Mirrors the per-command routing of packet_input() for the two
     *          per-flow data commands. cmd_push forwards the payload; cmd_fin
     *          delivers an end-of-stream (NULL payload) to the connection.
     */
    bool vmux_net::deliver_one(Byte cmd, vmux_hdr* h, int length, uint64_t now) noexcept {
        int buffer_size = length - (int)sizeof(vmux_hdr);
        if (buffer_size < 0) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }

        Byte* payload = (Byte*)(h + 1);
        uint32_t connection_id = ntohl(h->connection_id);
        if (cmd == cmd_push) {
            packet_input_read(connection_id, payload, buffer_size, now);
        }
        else { // cmd_fin
            packet_input_read(connection_id, NULLPTR, 0, now);
        }

        return true;
    }

    /**
     * @brief Releases a flow context once its FIN has been delivered and drained.
     */
    void vmux_net::maybe_release_flow(uint32_t connection_id, flow_rx_context& fx) noexcept {
        if (fx.fin_seen_ && fx.flow_reorder_.empty()) {
            flows_.erase(connection_id);
            tx_flow_seq_.erase(connection_id);
        }
    }

    /**
     * @brief Skips the current gap of one flow and replays contiguous buffered frames.
     * @details Advances flow_rx_next_ to the smallest buffered DSN (acknowledging
     *          the gap data as lost), then replays the contiguous run from there.
     *          Used both on reorder-buffer overflow and on gap timeout. Each call
     *          that actually skips increments the mux.rx.flow.evict telemetry once.
     */
    void vmux_net::flow_force_advance(uint32_t connection_id, flow_rx_context& fx, uint64_t now) noexcept {
        rx_packet_ssqueue::iterator it = fx.flow_reorder_.begin();
        if (it == fx.flow_reorder_.end()) {
            fx.oldest_buffered_tick_ = 0;
            return;
        }

        fx.flow_rx_next_ = it->first; // jump over the missing gap to the next buffered DSN.
        ppp::telemetry::Count("mux.rx.flow.evict", 1);

        for (;;) {
            rx_packet_ssqueue::iterator j = fx.flow_reorder_.begin();
            if (j != fx.flow_reorder_.end() && j->first == fx.flow_rx_next_) {
                rx_packet pk = j->second;
                vmux_hdr* ph = (vmux_hdr*)pk.buffer.get();
                Byte pcmd = ph->cmd;
                fx.flow_reorder_.erase(j);
                fx.buffered_bytes_ -= pk.length;
                if (pcmd == cmd_fin) {
                    fx.fin_seen_ = true;
                }
                deliver_one(pcmd, ph, pk.length, now);
                fx.flow_rx_next_++;
            }
            else {
                break;
            }
        }

        fx.oldest_buffered_tick_ = fx.flow_reorder_.empty() ? 0 : now;
    }

    /**
     * @brief Per-flow (flow v2) receive path: independent per-connection DSN delivery.
     * @details Control frames bypass the DSN gate entirely. Per-flow data frames
     *          (push/fin) are delivered in per-connection DSN order, buffering
     *          future frames in a bounded reorder buffer. One slow link cannot
     *          head-of-line block other connections because each connection_id
     *          has its own flow_rx_next_ and reorder buffer.
     */
    bool vmux_net::packet_input_flow(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        ppp::telemetry::Count("mux.link.recv", 1);

        Byte cmd = h->cmd;

        // Control frames are not gated by any per-flow DSN; handle them inline.
        if (is_session_control(cmd) || is_connection_control(cmd)) {
            if (!packet_input(cmd, (Byte*)h, length, now)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                return false;
            }

            active(now);
            linklayer_update(linklayer);
            return true;
        }

        // Any other non per-flow-data command is invalid on the flow path.
        if (!is_per_flow_data(cmd)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
            return false;
        }

        uint32_t cid = ntohl(h->connection_id);
        uint32_t seq = ntohl(h->seq);

        flow_rx_context& fx = flows_[cid];
        if (!fx.primed_) {
            fx.primed_ = true;
            fx.flow_rx_next_ = seq; // prime from the first observed DSN.
        }

        if (seq == fx.flow_rx_next_) {
            // In-order: deliver immediately, then replay any contiguous buffered frames.
            if (cmd == cmd_fin) {
                fx.fin_seen_ = true;
            }

            if (!deliver_one(cmd, h, length, now)) {
                return false;
            }
            fx.flow_rx_next_++;

            for (;;) {
                rx_packet_ssqueue::iterator it = fx.flow_reorder_.begin();
                if (it != fx.flow_reorder_.end() && it->first == fx.flow_rx_next_) {
                    rx_packet pk = it->second;
                    vmux_hdr* ph = (vmux_hdr*)pk.buffer.get();
                    Byte pcmd = ph->cmd;
                    fx.flow_reorder_.erase(it);
                    fx.buffered_bytes_ -= pk.length;
                    if (pcmd == cmd_fin) {
                        fx.fin_seen_ = true;
                    }
                    if (!deliver_one(pcmd, ph, pk.length, now)) {
                        return false;
                    }
                    fx.flow_rx_next_++;
                }
                else {
                    break;
                }
            }

            if (fx.flow_reorder_.empty()) {
                fx.oldest_buffered_tick_ = 0;
            }

            maybe_release_flow(cid, fx);
            active(now);
            linklayer_update(linklayer);
            return true;
        }
        elif(packet_less<uint32_t>::after(seq, fx.flow_rx_next_)) {
            // Future frame: buffer it (bounded by bytes), unless it is itself too large.
            if (length < (int)sizeof(vmux_hdr) || length > (int)(sizeof(vmux_hdr) + max_buffers_size)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return false;
            }

            // A single frame larger than the whole per-connection cap can never be
            // buffered; treat it as a gap and advance past it to preserve the bound.
            if ((size_t)length > flow_reorder_cap_bytes_) {
                if (packet_less<uint32_t>::after(seq, fx.flow_rx_next_)) {
                    // Skip forward to (seq + 1) so we do not wait forever on a frame we cannot hold.
                    fx.flow_rx_next_ = seq + 1;
                    // Replay anything now contiguous.
                    for (;;) {
                        rx_packet_ssqueue::iterator it = fx.flow_reorder_.begin();
                        if (it != fx.flow_reorder_.end() && it->first == fx.flow_rx_next_) {
                            rx_packet pk = it->second;
                            vmux_hdr* ph = (vmux_hdr*)pk.buffer.get();
                            Byte pcmd = ph->cmd;
                            fx.flow_reorder_.erase(it);
                            fx.buffered_bytes_ -= pk.length;
                            if (pcmd == cmd_fin) {
                                fx.fin_seen_ = true;
                            }
                            deliver_one(pcmd, ph, pk.length, now);
                            fx.flow_rx_next_++;
                        }
                        else {
                            break;
                        }
                    }
                    if (fx.flow_reorder_.empty()) {
                        fx.oldest_buffered_tick_ = 0;
                    }
                }
                active(now);
                linklayer_update(linklayer);
                return true;
            }

            // Evict oldest gaps until this frame fits within the per-connection cap.
            while (fx.buffered_bytes_ + (size_t)length > flow_reorder_cap_bytes_ && !fx.flow_reorder_.empty()) {
                flow_force_advance(cid, fx, now);
                // If forcing advance made seq become the next expected, fall through is
                // not needed; re-check below by comparing again on next loop iteration.
                if (seq == fx.flow_rx_next_ || packet_less<uint32_t>::before(seq, fx.flow_rx_next_)) {
                    break;
                }
            }

            // After eviction the frame might now be in-order or stale; re-classify.
            if (seq == fx.flow_rx_next_) {
                if (cmd == cmd_fin) {
                    fx.fin_seen_ = true;
                }
                if (!deliver_one(cmd, h, length, now)) {
                    return false;
                }
                fx.flow_rx_next_++;
                for (;;) {
                    rx_packet_ssqueue::iterator it = fx.flow_reorder_.begin();
                    if (it != fx.flow_reorder_.end() && it->first == fx.flow_rx_next_) {
                        rx_packet pk = it->second;
                        vmux_hdr* ph = (vmux_hdr*)pk.buffer.get();
                        Byte pcmd = ph->cmd;
                        fx.flow_reorder_.erase(it);
                        fx.buffered_bytes_ -= pk.length;
                        if (pcmd == cmd_fin) {
                            fx.fin_seen_ = true;
                        }
                        if (!deliver_one(pcmd, ph, pk.length, now)) {
                            return false;
                        }
                        fx.flow_rx_next_++;
                    }
                    else {
                        break;
                    }
                }
                if (fx.flow_reorder_.empty()) {
                    fx.oldest_buffered_tick_ = 0;
                }
                maybe_release_flow(cid, fx);
                active(now);
                linklayer_update(linklayer);
                return true;
            }
            elif(packet_less<uint32_t>::before(seq, fx.flow_rx_next_)) {
                active(now);
                return true; // became stale after eviction; drop.
            }

            std::shared_ptr<Byte> buf = make_byte_array(length);
            if (NULLPTR == buf) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetReorderPacketBufferAllocFailed);
                return false;
            }

            rx_packet packet = { buf, length };
            memcpy(buf.get(), h, length);

            bool inserted = fx.flow_reorder_.emplace(std::make_pair(seq, packet)).second;
            if (inserted) {
                fx.buffered_bytes_ += length;
                if (fx.oldest_buffered_tick_ == 0) {
                    fx.oldest_buffered_tick_ = now;
                }
            }
            // Duplicate future DSN: keep the original, drop the duplicate, not an error.

            active(now);
            linklayer_update(linklayer);
            return true;
        }
        else {
            // Stale/duplicate (before flow_rx_next_): drop, not an error.
            active(now);
            return true;
        }
    }

    /**
     * @brief Periodically advances per-flow contexts whose gap has timed out.
     * @details Runs only under flow-v2. For each flow with a non-empty reorder
     *          buffer whose oldest buffered frame is older than the timeout, skip
     *          the missing gap so a permanently lost frame cannot stall the flow.
     */
    void vmux_net::flow_evict_expired(uint64_t now) noexcept {
        if (ordering_mode_ != ordering_flow_v2) {
            return;
        }

        for (vmux_flow_map::iterator it = flows_.begin(); it != flows_.end(); ++it) {
            flow_rx_context& fx = it->second;
            if (!fx.flow_reorder_.empty() && fx.oldest_buffered_tick_ != 0 &&
                (now - fx.oldest_buffered_tick_) > flow_reorder_timeout_) {
                flow_force_advance(it->first, fx, now);
            }
        }
    }
    
    /**
     * @brief Handles remote SYN by creating and accepting a vmux socket instance.
     */
    bool vmux_net::process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        vmux_skt_map::iterator tail = skts_.find(connection_id);
        vmux_skt_map::iterator endl = skts_.end();
        if (tail != endl) {
            skt = tail->second;
            if (NULLPTR != skt) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetProcessRxConnectingIdConflict);
                return false;
            }
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        skt = ppp::make_shared_object<vmux_skt>(self, connection_id);

        if (NULLPTR == skt) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetProcessRxConnectingSocketAllocFailed);
            return false;
        }

        skts_[connection_id] = skt;
        return skt->accept(template_string(host, host_size));
    }

    /** @brief Generates a non-zero vmux connection identifier. */
    uint32_t vmux_net::generate_id() noexcept {
        static std::atomic<uint32_t> aid = ftt_random_aid(1, INT32_MAX);

        for (;;) {
            uint32_t n = ++aid;
            if (n != 0) {
                return n;
            }
        }
    }

    /** @brief Looks up a vmux socket by logical connection identifier. */
    vmux_net::vmux_skt_ptr vmux_net::get_connection(uint32_t connection_id) noexcept {
        vmux_skt_ptr skt;
        if (connection_id != 0) {
            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
            }
        }

        return skt;
    }

    /**
     * @brief Removes a vmux socket only when pointer identity matches the caller.
     */
    vmux_net::vmux_skt_ptr vmux_net::release_connection(uint32_t connection_id, vmux_skt* refer_pointer) noexcept {
        vmux_skt_ptr skt;
        if (connection_id != 0) {
            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
                if (skt.get() == refer_pointer) {
                    skts_.erase(tail);
                    affinity_links_.erase(connection_id); // drop sticky binding (balance mode)
                    flows_.erase(connection_id);          // drop per-flow receive context (flow v2)
                    tx_flow_seq_.erase(connection_id);    // drop per-flow send DSN counter (flow v2)
                }
            }
        }

        return skt;
    }

    /**
     * @brief Queues or directly dispatches a prepared packet frame for transmit.
     */
    bool vmux_net::post_internal(const std::shared_ptr<Byte>& packet, int packet_length, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULLPTR == packet || packet_length < sizeof(vmux_hdr)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
            return false;
        }
        
        if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostInternalNotEstablished);
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)packet.get();
        bool prioritize_ctrl = false;
        if (ordering_mode_ == ordering_flow_v2) {
            // flow v2: per-flow data frames carry a per-connection DSN; control
            // frames carry seq=0 (the receiver ignores their DSN). This keeps the
            // wire header unchanged while letting the receiver order each
            // connection independently.
            Byte cmd = h->cmd;
            if (is_per_flow_data(cmd)) {
                uint32_t cid = ntohl(h->connection_id);
                // Per-connection DSN starts at 1; 0 is reserved as the control-frame
                // placeholder so a data DSN is never confused with a control frame.
                uint32_t& dsn = tx_flow_seq_[cid];
                if (dsn == 0) {
                    dsn = 1;
                }
                h->seq = htonl(dsn++);
            }
            else {
                h->seq = htonl(0);
                // Control frames (syn/syn_ok/acceleration/keep_alived/mux_mode_set)
                // are not DSN-gated at the receiver, so under flow v2 they take the
                // high-priority queue and are never starved by a data backlog.
                prioritize_ctrl = is_session_control(cmd) || is_connection_control(cmd);
            }
        }
        else {
            h->seq = htonl(status_.tx_seq_++);
        }

        if (prioritize_ctrl) {
            // Control frames bypass acceleration and jump the data backlog. The
            // optional completion is fired immediately (the frame is queued for a
            // priority drain that runs at the top of process_tx_all_packets).
            tx_ctrl_queue_.emplace_back(tx_packet{ packet, packet_length, posted_ac });
            return process_tx_all_packets();
        }

        // flow turbo: a new connection's first packet (cmd_syn) is sent over the
        // most-recently-active link to cut first-byte latency. This is a one-shot
        // hint only — the connection is NOT bound; all subsequent frames go through
        // the normal competition drain. Recency is an approximate signal (not RTT);
        // fail-open to competition when no turbo link is available or the link has
        // no send credit.
        if (turbo_ && h->cmd == cmd_syn) {
            vmux_linklayer_ptr turbo_link = select_turbo_linklayer();
            if (NULLPTR != turbo_link) {
                vmux_linklayer_list::iterator lt = tx_links_.begin();
                vmux_linklayer_list::iterator le = tx_links_.end();
                while (lt != le && *lt != turbo_link) {
                    ++lt;
                }

                if (lt != le) {
                    tx_links_.erase(lt);
                    ppp::telemetry::Count("mux.turbo.syn", 1);
                    return underlyin_sent(turbo_link, packet, packet_length, posted_ac);
                }
            }
            // fall through to the normal path when no free turbo link is available.
        }

        if (acceleration && base_.acceleration_) {
            vmux_linklayer_list::iterator linklayer_tail = tx_links_.begin();
            vmux_linklayer_list::iterator linklayer_endl = tx_links_.end();

            if (linklayer_tail != linklayer_endl) {
                // D11 backpressure: normally the acceleration fast-path fires the
                // completion immediately so the skt read-pump reads the next chunk
                // without waiting for the send to finish. That decouples reading
                // from draining and lets tx_queue_ grow unbounded when the carrier
                // stalls. Once the data queue reaches the high-water mark, fall back
                // to attaching the completion to the frame so it fires only when the
                // frame is actually sent — this re-couples the read-pump to drain
                // progress and throttles ingestion until the backlog clears.
                bool throttle = tx_queue_.size() >= tx_queue_high_water_;
                if (throttle) {
                    tx_queue_.emplace_back(tx_packet{ packet, packet_length, posted_ac });
                }
                else {
                    tx_queue_.emplace_back(tx_packet{ packet, packet_length });
                    if (NULLPTR != posted_ac) {
                        vmux_post_exec(context_, strand_,
                            [posted_ac]() noexcept {
                                posted_ac(true);
                            });
                    }
                }

                return process_tx_all_packets();
            }
        }

        tx_queue_.emplace_back(tx_packet{ packet, packet_length, posted_ac });
        return process_tx_all_packets();
    }

    /** @brief True when an underlying link-layer endpoint is usable. */
    bool vmux_net::is_linklayer_active(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR == linklayer) {
            return false;
        }

        // A link being retired (turbo dynamic pool shrink) takes no new frames.
        if (linklayer->retiring_) {
            return false;
        }

        const VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
        return NULLPTR != connection && connection->IsLinked();
    }

    /** @brief Picks or refreshes the primary link-layer endpoint for flow mode. */
    vmux_net::vmux_linklayer_ptr vmux_net::select_primary_linklayer() noexcept {
        if (is_linklayer_active(primary_linklayer_)) {
            return primary_linklayer_;
        }

        primary_linklayer_.reset();
        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (is_linklayer_active(linklayer)) {
                primary_linklayer_ = linklayer;
                ppp::telemetry::Log(Level::kDebug, "mux", "primary link selected");
                return primary_linklayer_;
            }
        }

        return NULLPTR;
    }

    /** @brief Drains queued packets across currently available transmit linklayers. */
    bool vmux_net::process_tx_compat_packets() noexcept {
        vmux_linklayer_list::iterator linklayer_tail = tx_links_.begin();
        vmux_linklayer_list::iterator linklayer_endl = tx_links_.end();

        while (linklayer_tail != linklayer_endl) {

            tx_packet_ssqueue::iterator packet_tail = tx_queue_.begin();
            tx_packet_ssqueue::iterator packet_endl = tx_queue_.end();

            if (packet_tail == packet_endl) {
                break;
            }

            vmux_linklayer_ptr linklayer = *linklayer_tail;
            linklayer_tail = tx_links_.erase(linklayer_tail);

            tx_packet nexting_packet = *packet_tail;
            tx_queue_.erase(packet_tail);

            bool forwarding = underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.ac);
            if (!forwarding) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }
        }

        return true;
    }

    /** @brief Drains queued packets for flow mode.
     *  @details flow is the latency-oriented "new direction": pure competition on
     *           the send side (any free link sends the next queued frame — no
     *           per-connection binding, which would risk load imbalance and the
     *           single-TCP degeneration the competition model is designed to avoid),
     *           with global ordering on receive (no per-flow reordering wait). The
     *           optional turbo path (best-link-first first packet + prewarmed carrier
     *           links) layers on top via --mux-mode-turbo without changing this
     *           competition core. */
    bool vmux_net::process_tx_flow_packets() noexcept {
        return process_tx_compat_packets();
    }

    /** @brief Reads the connection_id field stored in a queued vmux frame buffer. */
    uint32_t vmux_net::peek_connection_id(const std::shared_ptr<Byte>& packet, int packet_length) noexcept {
        if (NULLPTR == packet || packet_length < (int)sizeof(vmux_hdr)) {
            return 0;
        }

        const vmux_hdr* h = (const vmux_hdr*)packet.get();
        return ntohl(h->connection_id);
    }

    /**
     * @brief Picks a least-loaded active link-layer for a new connection.
     * @details "Load" is approximated by the number of connections currently
     *          bound to each link in the affinity map; ties keep the first seen.
     */
    vmux_net::vmux_linklayer_ptr vmux_net::select_balanced_linklayer() noexcept {
        vmux_linklayer_ptr best;
        size_t best_load = 0;

        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (!is_linklayer_active(linklayer)) {
                continue;
            }

            size_t load = 0;
            for (const std::pair<const uint32_t, vmux_linklayer_ptr>& kv : affinity_links_) {
                if (kv.second == linklayer) {
                    load++;
                }
            }

            if (NULLPTR == best || load < best_load) {
                best = linklayer;
                best_load = load;
            }
        }

        return best;
    }

    /**
     * @brief Returns the sticky link-layer bound to a connection.
     * @details Binds the connection to a balanced link on first use, and
     *          re-binds (migrates) when the previously bound link went away.
     *          connection_id 0 (session-global control frames) is not pinned.
     */
    vmux_net::vmux_linklayer_ptr vmux_net::select_affinity_linklayer(uint32_t connection_id) noexcept {
        if (connection_id != 0) {
            auto tail = affinity_links_.find(connection_id);
            if (tail != affinity_links_.end()) {
                if (is_linklayer_active(tail->second)) {
                    return tail->second;
                }

                affinity_links_.erase(tail); // bound link is gone; migrate below.
            }
        }

        vmux_linklayer_ptr linklayer = select_balanced_linklayer();
        if (NULLPTR != linklayer && connection_id != 0) {
            affinity_links_[connection_id] = linklayer;
        }

        return linklayer;
    }

    /** @brief Picks the next active link-layer round-robin for stripe mode. */
    vmux_net::vmux_linklayer_ptr vmux_net::select_striped_linklayer() noexcept {
        size_t count = rx_links_.size();
        if (count == 0) {
            return NULLPTR;
        }

        for (size_t i = 0; i < count; i++) {
            const vmux_linklayer_ptr& linklayer = rx_links_[stripe_cursor_ % count];
            stripe_cursor_++;
            if (is_linklayer_active(linklayer)) {
                return linklayer;
            }
        }

        return NULLPTR;
    }

    /** @brief Picks the most-recently-active link for a turbo first packet. */
    vmux_net::vmux_linklayer_ptr vmux_net::select_turbo_linklayer() noexcept {
        // Approximate "best link" = the active link that most recently carried
        // inbound traffic (largest last_active_). This is a recency heuristic, not
        // an RTT measurement: it reuses the per-link activity we already stamp in
        // linklayer_update(), adds no control frames, and is only a hint for the
        // first packet (the connection is never bound here). Fail-open: if none
        // qualifies, the caller falls back to the normal competition drain.
        vmux_linklayer_ptr best;
        uint64_t best_tick = 0;
        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (!is_linklayer_active(linklayer)) {
                continue;
            }

            if (NULLPTR == best || linklayer->last_active_ >= best_tick) {
                best = linklayer;
                best_tick = linklayer->last_active_;
            }
        }

        return best;
    }

    bool vmux_net::linklayer_id_in_use(uint16_t id, const vmux_linklayer_ptr& except) noexcept {
        if (id == 0) {
            return true;
        }

        for (const vmux_linklayer_ptr& linklayer : rx_links_) {
            if (NULLPTR != linklayer && linklayer != except && linklayer->id_ == id) {
                return true;
            }
        }

        return false;
    }

    uint16_t vmux_net::allocate_linklayer_id(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR == linklayer || status_.pool_hard_max == 0) {
            return 0;
        }

        if (linklayer->id_ != 0 && linklayer->id_ <= status_.pool_hard_max && !linklayer_id_in_use(linklayer->id_, linklayer)) {
            return linklayer->id_;
        }

        for (uint32_t id = 1; id <= status_.pool_hard_max; id++) {
            uint16_t candidate = (uint16_t)id;
            if (!linklayer_id_in_use(candidate, linklayer)) {
                linklayer->id_ = candidate;
                return candidate;
            }
        }

        return 0;
    }

    /**
     * @brief Send-side scheduling for balance mode.
     * @details balance uses the same competition policy as compat (any link with
     *          send credit sends the next queued frame; no per-connection binding).
     *          Per-connection link binding was removed deliberately: pinning a
     *          connection to a link makes load unpredictable and, in the worst case
     *          (several heavy flows landing on one link), degenerates to a single
     *          TCP — defeating multi-link VMUX. Instead balance keeps competition on
     *          send and adds per-flow DSN reordering on receive (negotiated flow v2),
     *          so a slow/blocked connection only head-of-line blocks itself, not the
     *          others, while every link stays fully and adaptively utilized.
     */
    bool vmux_net::process_tx_balance_packets() noexcept {
        return process_tx_compat_packets();
    }

    /** @brief Drains queued packets striped round-robin across links (stripe). */
    bool vmux_net::process_tx_stripe_packets() noexcept {
        for (;;) {
            tx_packet_ssqueue::iterator packet_tail = tx_queue_.begin();
            if (packet_tail == tx_queue_.end()) {
                return true;
            }

            if (tx_links_.empty()) {
                return true;
            }

            // Prefer the round-robin target when it currently has send credit;
            // otherwise use any free link so a busy target does not stall output.
            vmux_linklayer_ptr preferred = select_striped_linklayer();
            vmux_linklayer_list::iterator link_tail = tx_links_.end();
            if (NULLPTR != preferred) {
                for (auto it = tx_links_.begin(); it != tx_links_.end(); ++it) {
                    if (*it == preferred) {
                        link_tail = it;
                        break;
                    }
                }
            }

            if (link_tail == tx_links_.end()) {
                link_tail = tx_links_.begin();
            }

            vmux_linklayer_ptr linklayer = *link_tail;
            tx_links_.erase(link_tail);

            tx_packet nexting_packet = *packet_tail;
            tx_queue_.erase(packet_tail);

            if (!underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.ac)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }
        }
    }

    /** @brief Drains the high-priority control-frame queue (flow v2). */
    bool vmux_net::process_tx_ctrl_packets() noexcept {
        // Control frames are link-agnostic under flow v2 (seq=0, delivered inline by
        // the receiver), so send each on any link that currently has credit. This
        // runs before the data drain so SYN / heartbeats are never starved.
        while (!tx_ctrl_queue_.empty()) {
            if (tx_links_.empty()) {
                return true; // no credit right now; a completion will re-drive us.
            }

            vmux_linklayer_list::iterator link_tail = tx_links_.begin();
            vmux_linklayer_ptr linklayer = *link_tail;
            tx_links_.erase(link_tail);

            tx_packet_ssqueue::iterator packet_tail = tx_ctrl_queue_.begin();
            tx_packet nexting_packet = *packet_tail;
            tx_ctrl_queue_.erase(packet_tail);

            if (!underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.ac)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }
        }

        return true;
    }

    /** @brief Drains queued packets according to selected scheduler mode. */
    bool vmux_net::process_tx_all_packets() noexcept {
        // Always flush the high-priority control queue first (flow v2 only; empty
        // under compat). Keeps new-connection setup and heartbeats alive even when
        // the data queue is backlogged.
        if (!tx_ctrl_queue_.empty()) {
            if (!process_tx_ctrl_packets()) {
                return false;
            }
        }

        switch (mode_) {
        case mux_mode_flow:
            return process_tx_flow_packets();
        case mux_mode_balance:
            return process_tx_balance_packets();
        case mux_mode_stripe:
            return process_tx_stripe_packets();
        default:
            return process_tx_compat_packets();
        }
    }
    /**
     * @brief Builds a vmux frame from command/payload and schedules transmit.
     */
    bool vmux_net::post_internal(Byte cmd, const void* buffer, int buffer_size, uint32_t connection_id, bool acceleration, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULLPTR != buffer && buffer_size < 0) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostInternalNegativeBufferSize);
            return false;
        }

        if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostFrameNotEstablished);
            return false;
        }

        // Ensure packet length does not exceed negotiated max buffer size.
        if (buffer_size > max_buffers_size) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketTooLarge);
            return false;
        }

        int packet_length = sizeof(vmux_hdr) + buffer_size;
        std::shared_ptr<Byte> packet_managed = make_byte_array(packet_length);

        if (NULLPTR == packet_managed) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetPostFrameAllocFailed);
            return false;
        }

        Byte* packet_memory = packet_managed.get();
        if (NULLPTR != buffer && buffer_size > 0) {
            // memcpy with validated length to avoid overflow.
            memcpy(packet_memory + sizeof(vmux_hdr), buffer, buffer_size);
        }

        vmux_hdr* h = (vmux_hdr*)packet_memory;
        h->cmd = cmd;
        h->connection_id = htonl(connection_id);
        
        return post_internal(packet_managed, packet_length, acceleration, posted_ac);
    }

    /**
     * @brief Adds a new transport linklayer and optionally starts full forwarding.
     */
    bool vmux_net::add_linklayer(const VirtualEthernetTcpipConnectionPtr& connection, vmux_linklayer_ptr& linklayer, const vmux_native_add_linklayer_after_success_before_callback& cb) noexcept {
        if (NULLPTR == connection) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetAddLinklayerNullConnection);
            return false;
        }

        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        if (!connection->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        if (rx_links_.size() >= status_.pool_hard_max) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
            return false;
        }

        linklayer = ppp::make_shared_object<vmux_linklayer>();
        if (NULLPTR == linklayer) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetAddLinklayerAllocFailed);
            return false;
        }

        std::shared_ptr<Byte> buffer = make_byte_array(max_buffers_size);
        if (NULLPTR == buffer) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetAddLinklayerBufferAllocFailed);
            return false;
        }

        linklayer->connection = connection;
        tx_links_.emplace_back(linklayer);
        rx_links_.emplace_back(linklayer);
        refresh_runtime_active_links();

        ppp::telemetry::Log(Level::kInfo, "mux", "link open");
        ppp::telemetry::Count("mux.link.open", 1);
        ppp::telemetry::Log(Level::kDebug, "mux", "link count=%d", static_cast<int>(rx_links_.size()));

        // Runtime addition: the session is already established (turbo dynamic pool
        // grow on either end). Attach exactly this one link and spawn exactly ONE
        // forwarding coroutine for it — never iterate rx_links_ (which would
        // re-spawn forwarding on existing links = double-forwarding). The optional
        // cb (server-side DoMuxON ack) still runs.
        if (base_.established_) {
            // Keep the pending link in rx_links_ so it counts toward the hard
            // ceiling, but withhold send credit until its handshake completes.
            for (vmux_linklayer_list::iterator it = tx_links_.begin(); it != tx_links_.end();) {
                if (*it == linklayer) {
                    it = tx_links_.erase(it);
                }
                else {
                    ++it;
                }
            }

            if (NULLPTR != cb && !cb()) {
                remove_linklayer(linklayer);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            uint16_t connection_id = 0;
            if (base_.server_or_client_) {
                connection_id = allocate_linklayer_id(linklayer);
                if (connection_id == 0) {
                    remove_linklayer(linklayer);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                    return false;
                }
            }

            std::shared_ptr<vmux_net> self = shared_from_this();
            vmux_linklayer_ptr added = linklayer;

            ContextPtr connection_context = connection->GetContext();
            StrandPtr connection_strand = connection->GetStrand();

            auto process =
                [self, this, added, connection_id, connection_context, connection_strand](ppp::coroutines::YieldContext& y) noexcept {
                    bool ok = handshake(added, connection_id, y);
                    if (ok) {
                        ok = vmux_post_exec(context_, strand_,
                            [self, this, added]() noexcept {
                                if (base_.disposed_.load(std::memory_order_acquire) || added->retiring_) {
                                    return false;
                                }

                                tx_links_.emplace_back(added);
                                linklayer_update(added);
                                if (!process_tx_all_packets()) {
                                    close_exec();
                                    return false;
                                }

                                return true;
                            });
                    }

                    if (ok) {
                        (void)forwarding(added, y);
                    }

                    // Runtime grow links are best-effort; their setup/read failure
                    // must not tear down the established base pool.
                    vmux_post_exec(context_, strand_,
                        [self, this, added]() noexcept {
                            remove_linklayer(added);
                            if (NULLPTR != added->connection) {
                                added->connection->Dispose();
                            }

                            if (auto server = std::move(added->server); NULLPTR != server) {
                                server->Dispose();
                            }
                            return true;
                        });
                };
            if (!ppp::coroutines::YieldContext::Spawn(BufferAllocator.get(), *connection_context, connection_strand.get(), process)) {
                remove_linklayer(linklayer);
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                return false;
            }

            ppp::telemetry::Count("mux.link.open.runtime", 1);
            return true;
        }

        bool unlimited = rx_links_.size() < status_.max_connections;
        if (unlimited) {
            if (NULLPTR != cb && !cb()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            return true;
        }
        elif(NULLPTR != cb && !cb()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
            return false;
        }

        uint64_t now = now_tick();
        active(now);

        /**
         * @brief Complex startup block:
         * once enough linklayers are attached, spawn one forwarding coroutine per
         * linklayer and execute handshake + forwarding lifecycle on each.
         */
        std::shared_ptr<vmux_net> self = shared_from_this();
        for (vmux_linklayer_ptr& linklayer : rx_links_) {

            uint16_t connection_id = 0;
            if (base_.server_or_client_) {
                connection_id = allocate_linklayer_id(linklayer);
                if (connection_id == 0) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionQuotaExceeded);
                    return false;
                }
            }

            auto& connection = linklayer->connection;
            ContextPtr connection_context = connection->GetContext();
            StrandPtr connection_strand = connection->GetStrand();

            auto process =
                [self, this, linklayer, connection_id, connection_context, connection_strand](ppp::coroutines::YieldContext& y) noexcept {
                    if (handshake(linklayer, connection_id, y)) {
                        forwarding(linklayer, y);
                    }

                    close_exec();
                };

            if (!ppp::coroutines::YieldContext::Spawn(BufferAllocator.get(), *connection_context, connection_strand.get(), process)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeCoroutineSpawnFailed);
                return false;
            }

            linklayer_update(linklayer);
        }

        return true;
    }

    /**
     * @brief Begins retiring the least-recently-active carrier link at runtime (C-B4).
     */
    bool vmux_net::retire_linklayer_runtime() noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            return false;
        }

        // Never shrink below the base (--tun-mux): the base pool must always stand.
        // Count links that are not already retiring.
        size_t live = 0;
        for (const vmux_linklayer_ptr& l : rx_links_) {
            if (NULLPTR != l && !l->retiring_) {
                live++;
            }
        }

        if (live <= status_.max_connections) {
            return false;
        }

        // Pick the least-recently-active non-retiring link (the weakest contributor
        // to the competition pool by our recency proxy).
        vmux_linklayer_ptr victim;
        uint64_t oldest = 0;
        for (const vmux_linklayer_ptr& l : rx_links_) {
            if (NULLPTR == l || l->retiring_) {
                continue;
            }

            if (NULLPTR == victim || l->last_active_ <= oldest) {
                victim = l;
                oldest = l->last_active_;
            }
        }

        if (NULLPTR == victim) {
            return false;
        }

        victim->retiring_ = true;
        refresh_runtime_active_links();

        // Stop sending new frames on the victim: remove it from the free-link list.
        // (If it is currently busy it is not in tx_links_; its completion sees
        // retiring_ and will not re-credit it.)
        for (vmux_linklayer_list::iterator it = tx_links_.begin(); it != tx_links_.end(); ++it) {
            if (*it == victim) {
                tx_links_.erase(it);
                break;
            }
        }

        ppp::telemetry::Count("mux.link.retire.begin", 1);
        ppp::telemetry::Log(Level::kInfo, "mux", "link retiring (runtime shrink), inflight=%d", (int)victim->inflight_);

        // If it already has no in-flight writes, reap immediately.
        reap_retired_linklayers();
        return true;
    }

    /**
     * @brief Disposes carrier links that finished retiring (inflight_ == 0).
     */
    void vmux_net::reap_retired_linklayers() noexcept {
        for (vmux_linklayer_vector::iterator it = rx_links_.begin(); it != rx_links_.end();) {
            vmux_linklayer_ptr linklayer = *it;
            if (NULLPTR != linklayer && linklayer->retiring_ && linklayer->inflight_ <= 0) {
                it = rx_links_.erase(it);

                // Ensure it is not left in the free-link list, then dispose its transport.
                for (vmux_linklayer_list::iterator t = tx_links_.begin(); t != tx_links_.end();) {
                    if (*t == linklayer) {
                        t = tx_links_.erase(t);
                    }
                    else {
                        ++t;
                    }
                }

                if (NULLPTR != linklayer->connection) {
                    linklayer->connection->Dispose();
                }

                if (auto server = std::move(linklayer->server); NULLPTR != server) {
                    server->Dispose();
                }

                ppp::telemetry::Count("mux.link.retire.done", 1);
                ppp::telemetry::Log(Level::kInfo, "mux", "link retired (runtime shrink), links=%d", (int)rx_links_.size());
                refresh_runtime_active_links();
            }
            else {
                ++it;
            }
        }
    }

    /**
     * @brief Turbo pool controller step (C-B5): derive a quality target and move
     *        the live pool one step toward it, rate-limited by a cooldown.
     */
    void vmux_net::turbo_controller_tick(uint64_t now) noexcept {
        if (!turbo_ || base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            return;
        }

        uint16_t base = status_.max_connections;
        uint16_t hard_max = status_.pool_hard_max;
        if (hard_max <= base) {
            return; // no headroom (turbo factor 1 or misconfigured): nothing to do.
        }

        // Cooldown / hysteresis: at most one grow or shrink step per cooldown window.
        if (turbo_last_adjust_ != 0 && (now - turbo_last_adjust_) < (uint64_t)PPP_MUX_TURBO_CONTROL_COOLDOWN) {
            return;
        }

        // Quality proxy (worse quality => larger pool, per design): use the data
        // backlog relative to the high-water mark. Empty queue => quality good =>
        // factor 1 (target = base). At/above high-water => quality bad => factor
        // up to PPP_MUX_TURBO_FACTOR_MAX (target = base * max). This reuses an
        // existing signal (tx_queue_ depth) with no new measurement.
        size_t depth = tx_queue_.size();
        size_t hw = (tx_queue_high_water_ > 0) ? tx_queue_high_water_ : (size_t)PPP_MUX_TX_QUEUE_HIGH_WATER;

        int factor = 1;
        if (depth >= hw) {
            factor = PPP_MUX_TURBO_FACTOR_MAX;
        }
        else if (depth > 0) {
            // Linear interpolation of the factor in (1 .. FACTOR_MAX) by backlog ratio.
            int span = PPP_MUX_TURBO_FACTOR_MAX - 1;
            factor = 1 + (int)((depth * (size_t)span) / hw);
            if (factor < 1) {
                factor = 1;
            }
            else if (factor > PPP_MUX_TURBO_FACTOR_MAX) {
                factor = PPP_MUX_TURBO_FACTOR_MAX;
            }
        }

        uint32_t target = (uint32_t)base * (uint32_t)factor;
        if (target < base) {
            target = base;
        }
        else if (target > hard_max) {
            target = hard_max;
        }

        // Count live (non-retiring) links and any pending grow already requested.
        size_t live = 0;
        for (const vmux_linklayer_ptr& l : rx_links_) {
            if (NULLPTR != l && !l->retiring_) {
                live++;
            }
        }

        size_t effective = live + (size_t)(turbo_pending_grow_ > 0 ? turbo_pending_grow_ : 0);

        if (effective < (size_t)target) {
            // Grow one step: ask the exchanger to add a link (it owns connect()).
            turbo_pending_grow_++;
            turbo_last_adjust_ = now;
            status_.pool_current = (uint16_t)std::min<uint32_t>(effective + 1, hard_max);
            ppp::telemetry::Gauge("mux.turbo.pool.target", (int64_t)target);
            ppp::telemetry::Count("mux.turbo.pool.grow", 1);
        }
        elif((size_t)target < live) {
            // Shrink one step: retire the weakest link locally.
            if (retire_linklayer_runtime()) {
                turbo_last_adjust_ = now;
                status_.pool_current = (uint16_t)(live - 1);
                ppp::telemetry::Gauge("mux.turbo.pool.target", (int64_t)target);
                ppp::telemetry::Count("mux.turbo.pool.shrink", 1);
            }
        }
    }

    /**
     * @brief Performs server/client handshake for one attached linklayer.
     */
    bool vmux_net::handshake(const vmux_linklayer_ptr& linklayer, uint16_t connection_id, ppp::coroutines::YieldContext& y) noexcept {
        ppp::telemetry::SpanScope span("mux.link.setup");
        auto setup_started_at = std::chrono::steady_clock::now();

        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULLPTR == linklayer_transmission) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        /** @brief Packed handshake acknowledgement payload carrying receive id. */
#pragma pack(push, 1)
        typedef struct 
#if defined(__GNUC__) || defined(__clang__)
            __attribute__((packed)) 
#endif
        {
            uint16_t receive_id;
        } vmux_linlayer_add_ack_packet;
#pragma pack(pop)

        if (base_.server_or_client_) {
            if (connection_id == 0 || connection_id > status_.pool_hard_max) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            vmux_linlayer_add_ack_packet packet;
            packet.receive_id = htons(connection_id);

            if (!linklayer_transmission->Write(y, &packet, sizeof(vmux_linlayer_add_ack_packet))) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }
        }
        else {
            int buffer_size = 0;
            std::shared_ptr<Byte> packet_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULLPTR == packet_memory || buffer_size < sizeof(vmux_linlayer_add_ack_packet)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                return false;
            }

            vmux_linlayer_add_ack_packet* packet = (vmux_linlayer_add_ack_packet*)packet_memory.get();
            uint32_t receive_id = ntohs(packet->receive_id);

            // receive_id is assigned by the server and may exceed the base pool
            // when turbo grows carrier links at runtime.
            if (receive_id == 0 || receive_id > status_.pool_hard_max) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (linklayer_id_in_use((uint16_t)receive_id, linklayer)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolMuxFailed);
                return false;
            }

            linklayer->id_ = (uint16_t)receive_id;
        }

        {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            linklayer->handshake_complete_ = true;
            if (!base_.established_ && status_.opened_connections < status_.max_connections) {
                status_.opened_connections++;
            }
            refresh_runtime_active_links();
        }

        linklayer_established();
        auto setup_elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - setup_started_at).count();
        ppp::telemetry::Histogram("mux.link.setup.us", setup_elapsed);
        return true;
    }

    /** @brief Updates mux established state once enough linklayers are opened. */
    void vmux_net::linklayer_established() noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (!base_.established_) {
            base_.established_ = 
                status_.opened_connections >= status_.max_connections;

            ppp::telemetry::Log(Level::kDebug, "mux", "linklayer handshake complete, links=%d", static_cast<int>(status_.opened_connections));

            uint64_t now = now_tick();
            status_.last_heartbeat_ = now;

            active(now);
            switch_to_next_heartbeat_timeout();
        }
    }

    /**
     * @brief Runs continuous read/dispatch forwarding on one linklayer.
     */
    bool vmux_net::forwarding(const vmux_linklayer_ptr& linklayer, ppp::coroutines::YieldContext& y) noexcept {
        if (base_.disposed_.load(std::memory_order_acquire)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULLPTR == linklayer_transmission) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
            return false;
        }

        int buffer_size = 0;
        boost::system::error_code ec;

        bool any = false;
        std::shared_ptr<vmux_net> self = shared_from_this();

        linklayer_update(linklayer);
        for (;;) {
            if (base_.disposed_.load(std::memory_order_acquire)) {
                break;
            }

            if (!linklayer_socket->IsLinked()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionTransportMissing);
                break;
            }

            std::shared_ptr<Byte> buffer_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULLPTR == buffer_memory || buffer_size < sizeof(vmux_hdr)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolFrameInvalid);
                break;
            }

            vmux_hdr* h = (vmux_hdr*)buffer_memory.get();
            Byte cmd = h->cmd;
            if (cmd <= cmd_none || cmd >= cmd_max) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolPacketActionInvalid);
                break;
            }

            bool posted = vmux_post_exec(context_, strand_,
                [self, this, linklayer, buffer_memory, h, buffer_size]() noexcept {
                    uint64_t now = now_tick();
                    bool delivered = (ordering_mode_ == ordering_flow_v2)
                        ? packet_input_flow(linklayer, h, buffer_size, now)
                        : packet_input_unorder(linklayer, h, buffer_size, now);
                    if (delivered) {
                        return true;
                    }
                    else {
                        close_exec();
                        return false;
                    }
                });

            if (!posted) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            }

            any |= posted;
        }
        
        return any;
    }

    /** @brief Refreshes activity on the underlying linklayer connection. */
    void vmux_net::linklayer_update(const vmux_linklayer_ptr& linklayer) noexcept {
        if (NULLPTR != linklayer) {
            // Stamp the most-recent-inbound tick used by turbo's approximate
            // best-link selection (recency, not RTT). Strand-affine: called from
            // the vmux strand on every inbound frame.
            linklayer->last_active_ = now_tick();
        }

        VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
        if (connection->IsLinked()) {
            connection->Update();
        }
    }

    /** @brief Validates preconditions for initiating a logical vmux connect. */
    bool vmux_net::connect_require(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string&                               host,
        int                                                  port) noexcept {

        if (base_.disposed_.load(std::memory_order_acquire) || !base_.established_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectRequireNotEstablished);
            return false;
        }

        if (host.empty() || port <= 0 || port > UINT16_MAX) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectRequireHostOrPortInvalid);
            return false;
        }

        if (NULLPTR == sk) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectRequireNullSocket);
            return false;
        }

        return true;
    }

    /**
     * @brief Coroutine-friendly connect helper that waits for async completion.
     */
    bool vmux_net::connect_yield(
        ppp::coroutines::YieldContext&                       y,
        const ContextPtr&                                    context,
        const StrandPtr&                                     strand,
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string&                               host,
        int                                                  port,
        const std::shared_ptr<vmux_skt_ptr>&                 return_connection) noexcept {

        if (!y || !return_connection) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectYieldInvalidArguments);
            return false;
        }

        if (NULLPTR == context) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
            return false;
        }

        if (!connect_require(sk, host, port)) {
            return false;
        }

        std::shared_ptr<vmux_net::atomic_int> status = ppp::make_shared_object<vmux_net::atomic_int>(-1);
        if (NULLPTR == status) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectYieldStatusAllocFailed);
            return false;
        }

        // Guard Suspend() behind the post result: if the executor is unavailable the
        // lambda (and every ppp::coroutines::asio::R() inside it) will never run, so
        // calling Suspend() would park the coroutine with no future Resume() �?a
        // permanent coroutine leak.
        bool posted = vmux_post_exec(context_, strand_,
            [this, sk, host, port, status, context, strand, return_connection, &y]() noexcept {
                bool ok = connect(context, strand, sk, host, port,
                    [status, return_connection, &y](vmux_skt* sender, bool success) noexcept {

                        ppp::coroutines::asio::R(y, *status, success, 
                            [return_connection, sender]() noexcept {
                                *return_connection = sender->shared_from_this();
                            });
                    });

                if (!ok) {
                    ppp::coroutines::asio::R(y, *status, false);
                }
            });

        if (!posted) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTaskPostFailed);
            return false;
        }

        y.Suspend();
        return status->load() > 0;
    }

    /**
     * @brief Starts an asynchronous logical vmux connection creation workflow.
     */
    bool vmux_net::connect(const ContextPtr& context, const StrandPtr& strand, const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept {
        if (NULLPTR == context || !connect_require(sk, host, port)) {
            if (NULLPTR == context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
            }
            return false;
        }

        vmux_skt_ptr skt;
        std::shared_ptr<vmux_net> self = shared_from_this();

        for (;;) {
            uint32_t connection_id = generate_id();
            if (connection_id == 0) {
                continue;
            }

            vmux_skt_map::iterator skt_tail = skts_.find(connection_id);
            vmux_skt_map::iterator skt_endl = skts_.end();
            if (skt_tail != skt_endl) {
                continue;
            }

            skt = ppp::make_shared_object<vmux_skt>(self, connection_id);
            if (NULLPTR == skt) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VmuxNetConnectSocketAllocFailed);
                return false;
            }

            skt->tx_socket_ = sk;
            skts_[connection_id] = skt;
            break;
        }

        if (skt->connect(context, strand, host, port, ac)) {
            return true;
        }
        else {
            skt->clear_event();
            skt->close();
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketConnectFailed);
            return false;
        }
    }
}
