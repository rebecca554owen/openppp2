#pragma once

/**
 * @file MuxRetransmitBuffer.h
 * @brief Sender-side retransmission buffer for the vmux reliability
 *        sub-protocol (QUIC-style ACK + fast retransmit + PTO).
 * @license GPL-3.0
 *
 * Retains a shared_ptr copy of every reliably-sent frame until the peer's ACK
 * covers it, so a lost frame can be re-sent on another live carrier link with
 * its ORIGINAL sequence number (the receiver deduplicates). Keyed by
 * (connection_id, sequence); under ordering_compat the caller uses
 * connection_id 0 because the sequence space is already session-global.
 *
 * Bounded: a session-wide byte cap (Track fails when exceeded; the caller
 * degrades to fail_flow / session rebuild) and per-frame attempt accounting
 * (the caller tears down when attempts are exhausted).
 *
 * Not thread-safe: strand-affine by design, like the rest of vmux state.
 */

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <unordered_map>
#include <vector>

#include <ppp/app/mux/MuxAckTracker.h>
#include <ppp/diagnostics/Telemetry.h>

namespace ppp::app::mux {

/** One retained outbound frame awaiting peer acknowledgment. */
struct MuxRtxEntry final {
    std::shared_ptr<std::uint8_t> buffer;         ///< Full vmux frame (header + payload).
    int                           length = 0;     ///< Frame length in bytes.
    std::uint64_t                 first_sent_tick = 0; ///< Tick of the first transmission.
    std::uint64_t                 last_sent_tick = 0;  ///< Tick of the most recent (re)transmission.
    std::uint32_t                 attempts = 0;   ///< Retransmissions already performed.
    std::list<std::uint64_t>::iterator order;     ///< Position in the insertion-ordered list (stable iterator).
};

class MuxRetransmitBuffer final {
public:
    /** Pack (connection_id, sequence) into one ordering key. */
    static constexpr std::uint64_t Key(std::uint32_t connection_id, std::uint32_t sequence) noexcept {
        return (static_cast<std::uint64_t>(connection_id) << 32) | sequence;
    }

    static constexpr std::uint32_t KeyCid(std::uint64_t key) noexcept {
        return static_cast<std::uint32_t>(key >> 32);
    }

    /**
     * Retain one freshly-sent frame.
     * @return false when the byte cap would be exceeded (caller degrades).
     */
    bool Track(
        std::uint32_t connection_id,
        std::uint32_t sequence,
        const std::shared_ptr<std::uint8_t>& buffer,
        int length,
        std::uint64_t now,
        std::size_t byte_cap) {
        const std::uint64_t key = Key(connection_id, sequence);
        if (entries_.find(key) != entries_.end()) {
            return true; // Already tracked (defensive; sends are unique per key).
        }
        if (byte_cap > 0 && bytes_ + static_cast<std::size_t>(length) > byte_cap) {
            return false;
        }

        order_.emplace_back(key);
        MuxRtxEntry entry;
        entry.buffer = buffer;
        entry.length = length;
        entry.first_sent_tick = now;
        entry.last_sent_tick = now;
        entry.order = (--order_.end());
        entries_.emplace(key, std::move(entry));
        bytes_ += static_cast<std::size_t>(length);
        bytes_by_cid_[connection_id] += static_cast<std::size_t>(length);
        return true;
    }

    /**
     * Retained bytes of one sequence space.
     *
     * This is the sender's view of "sent but not yet acknowledged" for that
     * space. The peer can only reorder a bounded amount, so the sender must
     * stop feeding a space once this exceeds the peer's reorder budget —
     * otherwise the peer overruns its reorder buffer and resets the flow.
     */
    std::size_t BytesForCid(std::uint32_t connection_id) const noexcept {
        const auto it = bytes_by_cid_.find(connection_id);
        return it == bytes_by_cid_.end() ? 0 : it->second;
    }

    /**
     * Release every entry of @p connection_id covered by the ACK.
     *
     * @p largest is the peer's DELIVERY frontier: the peer acknowledges a
     * frame only once it was delivered in order, so "up to largest" means
     * fully consumed. Everything at or below it is therefore released
     * regardless of the SACK ranges, and the retained set is exactly "sent
     * but not yet delivered" -- which is also the peer's reorder budget.
     *
     * @return RTT sample in ms from the first newly-acked entry that was never
     *         retransmitted (Karn's rule); 0 when no usable sample exists.
     */
    std::uint64_t Ack(
        std::uint32_t connection_id,
        std::uint32_t largest,
        const std::vector<MuxAckRange>& ranges,
        std::uint64_t now) {
        std::uint64_t rtt_sample = 0;

        // Collect the keys first: the release loop below erases from the map.
        std::vector<std::uint64_t> acked;
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (KeyCid(it->first) != connection_id) {
                continue;
            }
            const std::uint32_t seq = static_cast<std::uint32_t>(it->first & 0xFFFFFFFFu);
            const std::int32_t behind = static_cast<std::int32_t>(largest - seq);
            if (behind >= 0) {
                acked.push_back(it->first);
                continue;
            }
            for (const MuxAckRange& range : ranges) {
                // Wrap-safe membership: signed 32-bit distance from range start
                // to seq must be non-negative and within the range length. Plain
                // unsigned comparisons break when either endpoint wrapped past
                // 2^32 (ftt random baselines land near the top of the space),
                // which stranded rtx entries until attempts were exhausted.
                const std::int32_t offset = static_cast<std::int32_t>(seq - range.start);
                const std::uint32_t span = range.end - range.start;
                if (offset >= 0 && static_cast<std::uint32_t>(offset) <= span) {
                    acked.push_back(it->first);
                    break;
                }
            }
        }

        for (std::uint64_t key : acked) {
            auto it = entries_.find(key);
            if (it == entries_.end()) {
                continue;
            }
            if (rtt_sample == 0 && it->second.attempts == 0 && now >= it->second.first_sent_tick) {
                rtt_sample = now - it->second.first_sent_tick;
            }
            bytes_ -= static_cast<std::size_t>(it->second.length);
            release_cid_bytes(connection_id, static_cast<std::size_t>(it->second.length));
            order_.erase(it->second.order);
            entries_.erase(it);
        }

        // NO fast retransmit here, on purpose.
        //
        // The acknowledgement's `largest` is the peer's DELIVERY frontier: a
        // frame is acknowledged only once it was delivered in order. The
        // sender therefore cannot tell "this frame was lost" from "this
        // frame is still in flight": everything above the frontier is
        // undelivered, and most of it is simply reordered across carriers.
        // Retransmitting the lowest unacknowledged entry on every advancing
        // acknowledgement therefore retransmits frames that are on their way
        // — one spurious copy per delivered frame, which halves the usable
        // bandwidth of a saturated link and burns the retransmit budget of
        // frames that were never lost.
        //
        // Loss is detected by the probe timeout instead (see CollectExpired):
        // the probe timeout is the only signal that survives a delivery-
        // frontier acknowledgement, and it is the one QUIC uses for the same
        // reason.

        return rtt_sample;
    }

    /**
     * Collect keys whose last (re)transmission is older than the backoff window
     * for that entry, oldest first, bounded by @p max_count.
     *
     * The walk follows the insertion-ordered list, NOT the hash map: the map
     * has no defined iteration order, so a "bounded by max_count" cut over it
     * picks an arbitrary subset. That subset can exclude the lowest
     * unacknowledged sequence — the exact frame the peer is waiting for — so
     * the hole starves while newer frames keep being retransmitted, and the
     * hole eventually exhausts its attempt budget and tears the session down.
     *
     * The window grows exponentially with the attempt count. A fixed window
     * spends the whole attempt budget inside one or two round trips: on a
     * saturated link the peer's acknowledgement is queued behind bulk data
     * and arrives seconds later, so the budget expires long before the answer
     * can arrive, and a frame that was in fact delivered is declared
     * unrecoverable. Backing off spreads the attempts over a window that
     * matches a real congestion delay, and the cap keeps a single entry from
     * waiting forever.
     */
    void CollectExpired(std::uint64_t now, std::uint64_t pto, std::size_t max_count,
        std::vector<std::uint64_t>& expired, std::uint32_t exhausted_after = 0,
        std::uint64_t exhausted_backoff_ms = 0) const {
        for (const std::uint64_t key : order_) {
            if (expired.size() >= max_count) {
                break;
            }
            const auto it = entries_.find(key);
            if (it == entries_.end()) {
                continue;
            }
            const MuxRtxEntry& entry = it->second;
            if (now < entry.last_sent_tick) {
                continue;
            }
            std::uint64_t window = BackoffWindow(pto, entry.attempts);
            // A frame that already spent its attempt budget is not dead yet: it
            // is kept alive until the fail deadline, but it is re-sent on a
            // relaxed cadence so the peer keeps seeing the hole (and the
            // carrier keeps getting a chance to drain) without the
            // retransmissions themselves crowding out the bulk traffic.
            if (exhausted_after > 0 && entry.attempts >= exhausted_after &&
                exhausted_backoff_ms > window) {
                window = exhausted_backoff_ms;
            }
            if ((now - entry.last_sent_tick) >= window) {
                expired.push_back(key);
            }
        }
    }

    /**
     * Collect keys whose retransmit attempt budget is spent AND that have
     * been unacknowledged for at least @p min_age_ms.
     *
     * The age floor is what keeps a congested-but-alive carrier from being
     * declared dead: the attempt budget is derived from the probe timeout,
     * which on a fast path is a few hundred milliseconds, while the
     * transport underneath may need tens of seconds of RTO backoff to
     * deliver the frame. Failing the flow on the attempt count alone kills
     * connections that the carrier was about to deliver.
     *
     * @param now          Current tick in milliseconds.
     * @param max_attempts Attempt budget a frame must have spent.
     * @param min_age_ms   Minimum unacknowledged age in milliseconds.
     * @param exhausted    Output vector; cleared by the caller beforehand.
     */
    void CollectExhausted(std::uint64_t now, std::uint32_t max_attempts, std::uint64_t min_age_ms,
        std::vector<std::uint64_t>& exhausted) const {
        if (max_attempts == 0) {
            return;
        }
        for (const std::uint64_t key : order_) {
            const auto it = entries_.find(key);
            if (it == entries_.end()) {
                continue;
            }
            const MuxRtxEntry& entry = it->second;
            if (entry.attempts < max_attempts) {
                continue;
            }
            if (now < entry.first_sent_tick) {
                continue;
            }
            if ((now - entry.first_sent_tick) < min_age_ms) {
                continue;
            }
            exhausted.push_back(key);
        }
    }

    /**
     * Backoff window for an entry that has already been retransmitted
     * @p attempts times: the base PTO doubled once per attempt, capped at
     * @c kMaxBackoffShift doublings.
     */
    static constexpr std::uint64_t BackoffWindow(std::uint64_t pto, std::uint32_t attempts) noexcept {
        constexpr std::uint32_t kMaxBackoffShift = 3; // at most 8x the base PTO
        std::uint32_t shift = attempts;
        if (shift > kMaxBackoffShift) {
            shift = kMaxBackoffShift;
        }
        return pto << shift;
    }

    /**
     * Total time a sender needs to exhaust its budget: the sum of the backoff
     * windows of all @p max_attempts attempts.
     *
     * A receiver must not declare a hole permanent before this window has
     * passed. The sender keeps retrying with an exponential backoff, so a
     * receiver that gives up earlier tears the direction down while the
     * sender is still legitimately trying — which nullifies the whole
     * reliability layer and turns a recoverable loss into a dead session.
     */
    static constexpr std::uint64_t TotalBackoffWindow(std::uint64_t pto, std::uint32_t max_attempts) noexcept {
        std::uint64_t total = 0;
        for (std::uint32_t i = 0; i < max_attempts; ++i) {
            total += BackoffWindow(pto, i);
        }
        return total;
    }

    MuxRtxEntry* Find(std::uint64_t key) noexcept {
        auto it = entries_.find(key);
        return it == entries_.end() ? nullptr : &it->second;
    }

    /** Account one retransmission of @p key. */
    void MarkRetransmitted(std::uint64_t key, std::uint64_t now) noexcept {
        MuxRtxEntry* entry = Find(key);
        if (nullptr != entry) {
            entry->attempts++;
            entry->last_sent_tick = now;
        }
    }

    /** Drop every entry of one connection space (flow reset / flow release). */
    void EraseCid(std::uint32_t connection_id) {
        for (auto it = entries_.begin(); it != entries_.end();) {
            if (KeyCid(it->first) == connection_id) {
                bytes_ -= static_cast<std::size_t>(it->second.length);
                release_cid_bytes(connection_id, static_cast<std::size_t>(it->second.length));
                order_.erase(it->second.order);
                it = entries_.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    /**
     * Drop one entry.
     *
     * Used when a frame's retransmit budget is exhausted: the frame can no
     * longer be recovered, so retaining it only keeps the byte budget (and
     * the session's send window) occupied by a frame that will never be
     * acknowledged.
     * @return true when an entry was removed.
     */
    bool Erase(std::uint64_t key) {
        auto it = entries_.find(key);
        if (it == entries_.end()) {
            return false;
        }
        bytes_ -= static_cast<std::size_t>(it->second.length);
        release_cid_bytes(KeyCid(key), static_cast<std::size_t>(it->second.length));
        order_.erase(it->second.order);
        entries_.erase(it);
        return true;
    }

    void Clear() noexcept {
        entries_.clear();
        order_.clear();
        bytes_by_cid_.clear();
        bytes_ = 0;
    }

    std::size_t size() const noexcept { return entries_.size(); }
    std::size_t bytes() const noexcept { return bytes_; }

private:
    // std::list iterators are stable across insert/erase, so each entry can
    // store its position for O(1) removal from the insertion-ordered list.
    std::list<std::uint64_t>                                       order_;
    std::unordered_map<std::uint64_t, MuxRtxEntry>                 entries_;
    std::unordered_map<std::uint32_t, std::size_t>                 bytes_by_cid_;
    std::size_t                                                    bytes_ = 0;

    /** Subtract released bytes from one space's running total. */
    void release_cid_bytes(std::uint32_t connection_id, std::size_t length) noexcept {
        const auto it = bytes_by_cid_.find(connection_id);
        if (it == bytes_by_cid_.end()) {
            return;
        }
        if (length >= it->second) {
            bytes_by_cid_.erase(it);
        }
        else {
            it->second -= length;
        }
    }
};

} // namespace ppp::app::mux
