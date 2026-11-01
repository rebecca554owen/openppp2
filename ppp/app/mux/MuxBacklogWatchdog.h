#pragma once

/**
 * @file MuxBacklogWatchdog.h
 * @brief D11 transmit-backlog stall watchdog: decides when a saturated
 *        send queue means "wedged" and the session must be rebuilt.
 * @license GPL-3.0
 *
 * A FULL transmit queue is not a STUCK transmit queue.
 *
 * On a slow but healthy path the carriers keep draining and the queue
 * depth keeps falling, so the queue legitimately stays at the high-water
 * mark for a long time. The previous rule -- "the depth stayed at/over
 * the high-water mark for N ms, therefore the session is wedged" -- read
 * a congested path as a dead one: it tore down every carrier of the
 * session at once, threw away the congestion window the carriers had
 * built up, and the rebuilt session started from slow-start again on the
 * very same slow path. Measured on a congested public path this fired
 * about every twelve minutes and killed all eleven carriers each time.
 *
 * This watchdog therefore requires BOTH of:
 *   1. the queue depth has not fallen since the baseline, and
 *   2. no data-plane progress (a completed carrier write) happened within
 *      the stall window.
 * A queue that is still draining is slow, not wedged, and is left alone.
 *
 * Not thread-safe: the owner (vmux_net) is strand-affine.
 */

#include <cstddef>
#include <cstdint>

namespace ppp::app::mux {

class MuxBacklogWatchdog final {
public:
    /**
     * @brief Feed one observation of the transmit queue.
     *
     * @param depth            Current aggregate data-frame queue depth.
     * @param high_water       Depth at or above which the queue counts as backlogged.
     * @param now              Monotonic tick in milliseconds.
     * @param stall_ms         Stall window in milliseconds.
     * @param last_drain_tick  Tick of the last completed carrier write (0 = never).
     *
     * @return true when the send side is wedged and the session must be rebuilt.
     */
    bool Observe(
        std::size_t depth,
        std::size_t high_water,
        std::uint64_t now,
        std::uint64_t stall_ms,
        std::uint64_t last_drain_tick) noexcept {
        if (high_water == 0 || depth < high_water) {
            Reset();
            return false;
        }

        if (since_ == 0) {
            // First observation above the high-water mark: arm the window and
            // remember the depth the window starts from.
            since_ = now;
            armed_depth_ = depth;
            return false;
        }

        // The queue shrank since the baseline: the send side is draining, so
        // the path is slow but alive. Re-baseline and restart the window --
        // a falling depth is the difference between "slow" and "wedged".
        if (depth < armed_depth_) {
            armed_depth_ = depth;
            since_ = now;
            return false;
        }

        // The depth did not shrink. A wedged send side also shows no
        // data-plane progress at all: nothing was handed to a carrier.
        const bool progressed = (last_drain_tick != 0) && (now > last_drain_tick) &&
            ((now - last_drain_tick) < stall_ms);
        if (progressed) {
            return false;
        }

        if ((now - since_) >= stall_ms) {
            Reset();
            return true;
        }
        return false;
    }

    /** @brief Forget the armed window (session rebuilt, or the queue drained). */
    void Reset() noexcept {
        armed_depth_ = 0;
        since_ = 0;
    }

    /** @brief Tick at which the current stall window opened (0 = not armed). */
    std::uint64_t baseline_tick() const noexcept {
        return since_;
    }

    /** @brief Queue depth captured when the current stall window opened. */
    std::size_t baseline_depth() const noexcept {
        return armed_depth_;
    }

private:
    std::size_t   armed_depth_ = 0;
    std::uint64_t since_ = 0;
};

} // namespace ppp::app::mux
