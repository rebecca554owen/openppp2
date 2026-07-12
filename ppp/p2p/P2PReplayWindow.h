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
#include <limits>

namespace ppp {
    namespace p2p {

        /**
         * @brief Compact bitmap replay window for sequence number validation.
         *
         * Tracks the highest accepted sequence number (`base_`) and a 1024-bit
         * bitmap covering sequences [base_ - 1023, base_]. Each bit represents
         * whether a particular sequence number has been seen.
         *
         * `UINT64_MAX` is reserved as the empty-window sentinel. Packet sequence
         * values are uint32_t, so sequence zero remains a valid first packet and
         * cannot be confused with an uninitialized window.
         *
         * Thread safety: caller must ensure single-writer discipline. The struct
         * is intentionally lock-free for the hot path (check + set) and can be
         * protected by the channel's strand/mutex externally.
         */
        struct P2PReplayWindow {
            static constexpr uint64_t EmptyBase = std::numeric_limits<uint64_t>::max();

            uint64_t    base_ = EmptyBase;                      ///< Highest accepted sequence, or EmptyBase.
            uint8_t     bitmap_[REPLAY_BITMAP_SIZE] = {};       ///< 1024-bit window bitmap.

            /** @brief Resets the replay window to initial state. */
            void Reset() noexcept {
                base_ = EmptyBase;
                std::memset(bitmap_, 0, sizeof(bitmap_));
            }

            /** @brief Tests whether a sequence number has already been accepted. */
            bool IsDuplicate(uint32_t seq) const noexcept {
                if (base_ == EmptyBase) {
                    return false;
                }
                if (seq > base_) {
                    return false;
                }
                uint64_t delta = base_ - seq;
                if (delta >= REPLAY_WINDOW_SIZE) {
                    return true;
                }
                uint64_t byte_idx = delta / 8;
                uint64_t bit_idx  = delta % 8;
                return (bitmap_[byte_idx] & (1u << bit_idx)) != 0;
            }

            /** @brief Accepts a sequence number into the window. */
            bool Accept(uint32_t seq) noexcept {
                if (base_ == EmptyBase) {
                    base_ = seq;
                    bitmap_[0] = 1u;
                    return true;
                }

                if (seq > base_) {
                    uint64_t shift = seq - base_;
                    if (shift >= REPLAY_WINDOW_SIZE) {
                        std::memset(bitmap_, 0, sizeof(bitmap_));
                    } else {
                        ShiftBitmapLeft(static_cast<int>(shift));
                    }
                    base_ = seq;
                    bitmap_[0] |= 1u;
                    return true;
                }

                uint64_t delta = base_ - seq;
                if (delta >= REPLAY_WINDOW_SIZE) {
                    return false;
                }

                uint64_t byte_idx = delta / 8;
                uint64_t bit_idx  = delta % 8;
                uint8_t  mask     = static_cast<uint8_t>(1u << bit_idx);

                if (bitmap_[byte_idx] & mask) {
                    return false;
                }

                bitmap_[byte_idx] |= mask;
                return true;
            }

        private:
            /** @brief Shifts the bitmap toward higher delta indices. */
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

                if (whole_bytes > 0) {
                    for (int i = REPLAY_BITMAP_SIZE - 1; i >= whole_bytes; --i) {
                        bitmap_[i] = bitmap_[i - whole_bytes];
                    }
                    for (int i = 0; i < whole_bytes && i < REPLAY_BITMAP_SIZE; ++i) {
                        bitmap_[i] = 0;
                    }
                }

                if (extra_bits > 0) {
                    uint8_t carry = 0;
                    for (int i = 0; i < REPLAY_BITMAP_SIZE; ++i) {
                        uint8_t new_carry = static_cast<uint8_t>(
                            bitmap_[i] >> (8 - extra_bits));
                        bitmap_[i] = static_cast<uint8_t>(
                            (bitmap_[i] << extra_bits) | carry);
                        carry = new_carry;
                    }
                }
            }
        };

        static_assert(sizeof(P2PReplayWindow) <= 140,
                      "P2PReplayWindow must fit in minimal memory (136 bytes expected)");

    }
}
