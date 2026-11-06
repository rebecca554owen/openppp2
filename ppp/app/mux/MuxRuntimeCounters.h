#pragma once

#include <atomic>
#include <cstdint>

namespace ppp::app::mux {

/**
 * @brief Process-wide mux counters, mirrored from the telemetry counter names.
 *
 * @details The telemetry counters (ppp::telemetry::Count) are only exported when
 * the telemetry backend is enabled, and they never reach the runtime stats
 * NDJSON that the operator already collects with --stats-json. That gap made
 * one production failure mode invisible: a flow whose FIRST data frame never
 * reached the peer looked exactly like a flow that was silently dropped, and
 * the two need different fixes.
 *
 * These counters are always compiled and always updated (relaxed atomics, one
 * add per event), so a default deployment can tell the two cases apart from
 * the stats file alone. The JSON key of every counter is the telemetry name
 * it mirrors, so the stats NDJSON and the telemetry export speak the same
 * vocabulary and need no translation table.
 */
struct MuxRuntimeCounters final {
    std::uint64_t tx_frames = 0;                    ///< mux.link.send
    std::uint64_t rx_frames = 0;                    ///< mux.link.recv
    std::uint64_t rx_flow_unknown_cid = 0;          ///< mux.rx.flow.unknown_cid
    std::uint64_t rx_flow_refused = 0;              ///< mux.rx.flow.refused
    std::uint64_t rx_flow_reack = 0;                ///< mux.rx.flow.reack
    std::uint64_t rx_closed_flow_drop = 0;          ///< mux.rx.closed_flow.drop
    std::uint64_t rx_closed_flow_reack = 0;         ///< mux.rx.closed_flow.reack
    std::uint64_t rx_flow_reset = 0;                ///< mux.rx.flow.reset
    std::uint64_t rx_gap_timeout = 0;               ///< mux.rx.compat.gap_timeout
    std::uint64_t rx_flow_max_open = 0;             ///< mux.rx.flow.max_open
    std::uint64_t tx_flow_after_fin = 0;            ///< mux.tx.flow.after_fin
    std::uint64_t tx_rtx_pto = 0;                   ///< mux.rtx.pto
    std::uint64_t tx_rtx_exhausted = 0;             ///< mux.rtx.exhausted
    std::uint64_t tx_rtx_exhausted_connection = 0;  ///< mux.rtx.exhausted.connection
    std::uint64_t rx_flow_refuse_post_failed = 0;   ///< mux.rx.flow.refuse_post_failed
    std::uint64_t rx_syn_ok_refused = 0;            ///< mux.rx.syn_ok.refused
    std::uint64_t rx_syn_ok_refused_no_socket = 0;  ///< mux.rx.syn_ok.refused.no_socket
    std::uint64_t tx_flow_overflow = 0;              ///< mux.tx.flow.overflow
    std::uint64_t tx_ctrl_cap = 0;                   ///< mux.tx.ctrl.cap
    std::uint64_t tx_ctrl_cap_rejected = 0;          ///< mux.tx.ctrl.cap.reject
    std::uint64_t tx_ack_suppressed = 0;               ///< mux.ack.suppressed
};

/**
 * @brief Process-wide holder for the mux counters.
 *
 * @details The counters are updated on the mux hot path, so every update is a
 * relaxed atomic add and the snapshot is a lock-free read of the same
 * atomics. Nothing here allocates or locks.
 */
class MuxRuntimeCounterRegistry final {
public:
    static void AddTxFrames(std::uint64_t n = 1) noexcept {
        tx_frames_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxFrames(std::uint64_t n = 1) noexcept {
        rx_frames_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxFlowUnknownCid(std::uint64_t n = 1) noexcept {
        rx_flow_unknown_cid_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxFlowRefused(std::uint64_t n = 1) noexcept {
        rx_flow_refused_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxFlowReack(std::uint64_t n = 1) noexcept {
        rx_flow_reack_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxClosedFlowDrop(std::uint64_t n = 1) noexcept {
        rx_closed_flow_drop_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxClosedFlowReack(std::uint64_t n = 1) noexcept {
        rx_closed_flow_reack_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxFlowReset(std::uint64_t n = 1) noexcept {
        rx_flow_reset_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxGapTimeout(std::uint64_t n = 1) noexcept {
        rx_gap_timeout_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxFlowMaxOpen(std::uint64_t n = 1) noexcept {
        rx_flow_max_open_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxFlowAfterFin(std::uint64_t n = 1) noexcept {
        tx_flow_after_fin_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxRtxPto(std::uint64_t n = 1) noexcept {
        tx_rtx_pto_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxRtxExhausted(std::uint64_t n = 1) noexcept {
        tx_rtx_exhausted_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxRtxExhaustedConnection(std::uint64_t n = 1) noexcept {
        tx_rtx_exhausted_connection_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxFlowRefusePostFailed(std::uint64_t n = 1) noexcept {
        rx_flow_refuse_post_failed_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxSynOkRefused(std::uint64_t n = 1) noexcept {
        rx_syn_ok_refused_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddRxSynOkRefusedNoSocket(std::uint64_t n = 1) noexcept {
        rx_syn_ok_refused_no_socket_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxFlowOverflow(std::uint64_t n = 1) noexcept {
        tx_flow_overflow_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxCtrlCap(std::uint64_t n = 1) noexcept {
        tx_ctrl_cap_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxCtrlCapRejected(std::uint64_t n = 1) noexcept {
        tx_ctrl_cap_rejected_.fetch_add(n, std::memory_order_relaxed);
    }

    static void AddTxAckSuppressed(std::uint64_t n = 1) noexcept {
        tx_ack_suppressed_.fetch_add(n, std::memory_order_relaxed);
    }

    /** @brief Reads every counter without locking. */
    static MuxRuntimeCounters GetSnapshot() noexcept {
        MuxRuntimeCounters snap;
        snap.tx_frames = tx_frames_.load(std::memory_order_relaxed);
        snap.rx_frames = rx_frames_.load(std::memory_order_relaxed);
        snap.rx_flow_unknown_cid = rx_flow_unknown_cid_.load(std::memory_order_relaxed);
        snap.rx_flow_refused = rx_flow_refused_.load(std::memory_order_relaxed);
        snap.rx_flow_reack = rx_flow_reack_.load(std::memory_order_relaxed);
        snap.rx_closed_flow_drop = rx_closed_flow_drop_.load(std::memory_order_relaxed);
        snap.rx_closed_flow_reack = rx_closed_flow_reack_.load(std::memory_order_relaxed);
        snap.rx_flow_reset = rx_flow_reset_.load(std::memory_order_relaxed);
        snap.rx_gap_timeout = rx_gap_timeout_.load(std::memory_order_relaxed);
        snap.rx_flow_max_open = rx_flow_max_open_.load(std::memory_order_relaxed);
        snap.tx_flow_after_fin = tx_flow_after_fin_.load(std::memory_order_relaxed);
        snap.tx_rtx_pto = tx_rtx_pto_.load(std::memory_order_relaxed);
        snap.tx_rtx_exhausted = tx_rtx_exhausted_.load(std::memory_order_relaxed);
        snap.tx_rtx_exhausted_connection = tx_rtx_exhausted_connection_.load(std::memory_order_relaxed);
        snap.rx_flow_refuse_post_failed = rx_flow_refuse_post_failed_.load(std::memory_order_relaxed);
        snap.rx_syn_ok_refused = rx_syn_ok_refused_.load(std::memory_order_relaxed);
        snap.rx_syn_ok_refused_no_socket = rx_syn_ok_refused_no_socket_.load(std::memory_order_relaxed);
        snap.tx_flow_overflow = tx_flow_overflow_.load(std::memory_order_relaxed);
        snap.tx_ctrl_cap = tx_ctrl_cap_.load(std::memory_order_relaxed);
        snap.tx_ctrl_cap_rejected = tx_ctrl_cap_rejected_.load(std::memory_order_relaxed);
        snap.tx_ack_suppressed = tx_ack_suppressed_.load(std::memory_order_relaxed);
        return snap;
    }

    /** @brief Resets every counter to zero (test isolation). */
    static void Reset() noexcept {
        tx_frames_.store(0, std::memory_order_relaxed);
        rx_frames_.store(0, std::memory_order_relaxed);
        rx_flow_unknown_cid_.store(0, std::memory_order_relaxed);
        rx_flow_refused_.store(0, std::memory_order_relaxed);
        rx_flow_reack_.store(0, std::memory_order_relaxed);
        rx_closed_flow_drop_.store(0, std::memory_order_relaxed);
        rx_closed_flow_reack_.store(0, std::memory_order_relaxed);
        rx_flow_reset_.store(0, std::memory_order_relaxed);
        rx_gap_timeout_.store(0, std::memory_order_relaxed);
        rx_flow_max_open_.store(0, std::memory_order_relaxed);
        tx_flow_after_fin_.store(0, std::memory_order_relaxed);
        tx_rtx_pto_.store(0, std::memory_order_relaxed);
        tx_rtx_exhausted_.store(0, std::memory_order_relaxed);
        tx_rtx_exhausted_connection_.store(0, std::memory_order_relaxed);
        rx_flow_refuse_post_failed_.store(0, std::memory_order_relaxed);
        rx_syn_ok_refused_.store(0, std::memory_order_relaxed);
        rx_syn_ok_refused_no_socket_.store(0, std::memory_order_relaxed);
        tx_flow_overflow_.store(0, std::memory_order_relaxed);
        tx_ctrl_cap_.store(0, std::memory_order_relaxed);
        tx_ctrl_cap_rejected_.store(0, std::memory_order_relaxed);
        tx_ack_suppressed_.store(0, std::memory_order_relaxed);
    }

private:
    inline static std::atomic<std::uint64_t> tx_frames_{ 0 };
    inline static std::atomic<std::uint64_t> rx_frames_{ 0 };
    inline static std::atomic<std::uint64_t> rx_flow_unknown_cid_{ 0 };
    inline static std::atomic<std::uint64_t> rx_flow_refused_{ 0 };
    inline static std::atomic<std::uint64_t> rx_flow_reack_{ 0 };
    inline static std::atomic<std::uint64_t> rx_closed_flow_drop_{ 0 };
    inline static std::atomic<std::uint64_t> rx_closed_flow_reack_{ 0 };
    inline static std::atomic<std::uint64_t> rx_flow_reset_{ 0 };
    inline static std::atomic<std::uint64_t> rx_gap_timeout_{ 0 };
    inline static std::atomic<std::uint64_t> rx_flow_max_open_{ 0 };
    inline static std::atomic<std::uint64_t> tx_flow_after_fin_{ 0 };
    inline static std::atomic<std::uint64_t> tx_rtx_pto_{ 0 };
    inline static std::atomic<std::uint64_t> tx_rtx_exhausted_{ 0 };
    inline static std::atomic<std::uint64_t> tx_rtx_exhausted_connection_{ 0 };
    inline static std::atomic<std::uint64_t> rx_flow_refuse_post_failed_{ 0 };
    inline static std::atomic<std::uint64_t> rx_syn_ok_refused_{ 0 };
    inline static std::atomic<std::uint64_t> rx_syn_ok_refused_no_socket_{ 0 };
    inline static std::atomic<std::uint64_t> tx_flow_overflow_{ 0 };
    inline static std::atomic<std::uint64_t> tx_ctrl_cap_{ 0 };
    inline static std::atomic<std::uint64_t> tx_ctrl_cap_rejected_{ 0 };
    inline static std::atomic<std::uint64_t> tx_ack_suppressed_{ 0 };
};

}  // namespace ppp::app::mux
