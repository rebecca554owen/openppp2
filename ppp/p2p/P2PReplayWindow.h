#pragma once

/**
 * @file P2PReplayWindow.h
 * @brief Bitmap-based sliding window for P2P packet replay protection.
 *
 * Fixed-size 136 bytes per channel (1024-bit window). O(1) accept and
 * duplicate check. No heap allocation. Fits in 2 cache lines.
 *
 * Bitmap convention: bit 0 = base (newest accepted), bit N = base - N.
 * When base advances, existing bits shift toward higher indices (older
 * sequences move to higher bit positions), and low bits are cleared.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <cstring>

namespace ppp {
    namespace p2p {

        /**
         * @brief Compact bitmap replay window for sequence number validation.
         *
         * Tracks the highest accepted sequence number (`base_`) and a 1024-bit
         * bitmap covering sequences [base_ - 1023, base_]. Each bit represents
         * whether a particular sequence number has been seen.
         *
         * Bit layout:
         *   bit 0 of bitmap_[0] = base_ (the newest accepted sequence)
         *   bit 1 of bitmap_[0] = base_ - 1
         *   ...
         *   bit k of bitmap_[j] = base_ - (j*8 + k)
         *
         * Thread safety: caller must ensure single-writer discipline. The struct
         * is intentionally lock-free for the hot path (check + set) and can be
         * protected by the channel's strand/mutex externally.
         */
        struct P2PReplayWindow {
            uint64_t    base_ = 0;                              ///< Highest accepted sequence.
            uint8_t     bitmap_[REPLAY_BITMAP_SIZE] = {};       ///< 1024-bit window bitmap.

            /**
             * @brief Resets the replay window to initial state.
             */
            void Reset() noexcept {
                base_ = 0;
                std::memset(bitmap_, 0, sizeof(bitmap_));
            }

            /**
             * @brief Tests whether a sequence number has already been accepted.
             *
             * @param seq Sequence number to test.
             * @return true if the packet is a duplicate (should be dropped).
             */
            bool IsDuplicate(uint32_t seq) const noexcept {
                if (base_ == 0) {
                    return false;  // Window empty — nothing is duplicate.
                }
                if (seq > base_) {
                    return false;  // Ahead of window — not duplicate.
                }
                uint64_t delta = base_ - seq;
                if (delta >= REPLAY_WINDOW_SIZE) {
                    return true;   // Too old — always reject.
                }
                uint64_t byte_idx = delta / 8;
                uint64_t bit_idx  = delta % 8;
                return (bitmap_[byte_idx] & (1u << bit_idx)) != 0;
            }

            /**
             * @brief Accepts a sequence number into the window.
             *
             * If seq > base_, the window is shifted forward and the new bit is set.
             * If seq is within the window, its bit is set.
             * If seq is too old, nothing changes.
             *
             * @param seq Sequence number to accept.
             * @return true if the packet was accepted (not duplicate, within window).
             */
            bool Accept(uint32_t seq) noexcept {
                if (base_ == 0) {
                    // First packet ever — initialize.
                    base_ = seq;
                    bitmap_[0] = 1u;  // Set bit 0 (the base itself).
                    return true;
                }

                if (seq > base_) {
                    // Advance window: existing bits move toward higher delta indices.
                    uint64_t shift = seq - base_;
                    if (shift >= REPLAY_WINDOW_SIZE) {
                        // Big jump — clear entire window.
                        std::memset(bitmap_, 0, sizeof(bitmap_));
                    } else {
                        ShiftBitmapLeft(static_cast<int>(shift));
                    }
                    base_ = seq;
                    bitmap_[0] |= 1u;  // Set bit 0 for the new base.
                    return true;
                }

                uint64_t delta = base_ - seq;
                if (delta >= REPLAY_WINDOW_SIZE) {
                    return false;  // Too old — silently drop.
                }

                uint64_t byte_idx = delta / 8;
                uint64_t bit_idx  = delta % 8;
                uint8_t  mask     = static_cast<uint8_t>(1u << bit_idx);

                if (bitmap_[byte_idx] & mask) {
                    return false;  // Already seen.
                }

                bitmap_[byte_idx] |= mask;
                return true;
            }

        private:
            /**
             * @brief Shifts the bitmap left by `n` bits.
             *
             * "Left" here means toward higher delta indices: bit positions
             * that represented delta=0..n-1 are now vacated (cleared), and
             * existing bits move to represent larger deltas.
             *
             * Implementation: shift bytes toward higher indices, then shift
             * remaining bits.
             */
            void ShiftBitmapLeft(int n) noexcept {
                if (n <= 0) {
                    return;
                }
                if (n >= REPLAY_WINDOW_SIZE) {
                    std::memset(bitmap_, 0, sizeof(bitmap_));
                    return;
                }

                int whole_bytes = n / 8;
                int extra_bits  = n % 8;

                // Shift by whole bytes toward higher indices.
                if (whole_bytes > 0) {
                    for (int i = REPLAY_BITMAP_SIZE - 1; i >= whole_bytes; --i) {
                        bitmap_[i] = bitmap_[i - whole_bytes];
                    }
                    for (int i = 0; i < whole_bytes && i < REPLAY_BITMAP_SIZE; ++i) {
                        bitmap_[i] = 0;
                    }
                }

                // Shift by remaining bits within bytes.
                // Each byte's bits shift right (LSB = delta 0 within that byte group),
                // with carry from the lower-index byte flowing into the MSBs.
                if (extra_bits > 0) {
                    uint8_t carry = 0;
                    for (int i = 0; i < REPLAY_BITMAP_SIZE; ++i) {
                        uint8_t new_carry = static_cast<uint8_t>(
                            bitmap_[i] >> (8 - extra_bits));
                        bitmap_[i] = static_cast<uint8_t>(
                            (bitmap_[i] << extra_bits) | carry);
                        carry = new_carry;
                    }
                    // Final carry is discarded (represents sequences beyond the window).
                }
            }
        };

        static_assert(sizeof(P2PReplayWindow) <= 140,
                      "P2PReplayWindow must fit in minimal memory (136 bytes expected)");

    }
}
