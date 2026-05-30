#pragma once

/**
 * @file P2PBufferPool.h
 * @brief Pre-allocated buffer pool for zero-allocation P2P fast path.
 *
 * Uses boost::lockfree::queue for lock-free pop/push. Each buffer is
 * P2P_BUFFER_SIZE bytes. Allocated once at channel creation; borrowed/
 * returned on the hot path.
 *
 * On pool exhaustion, Acquire() returns a null Buffer (no fallback heap
 * allocation). Callers must check the Buffer and drop the packet if null.
 * This preserves the zero-allocation invariant on the hot path.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <boost/lockfree/queue.hpp>
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <memory>
#include <cstring>

namespace ppp {
    namespace p2p {

        /**
         * @brief Pre-allocated packet buffer pool.
         *
         * One pool per P2P channel. Allocates `count` contiguous buffers of
         * P2P_BUFFER_SIZE bytes at construction time.  No heap allocation on
         * the hot path — Acquire() returns null when exhausted.
         */
        class P2PBufferPool final {
        public:
            /**
             * @brief A borrowed buffer from the pool.
             *
             * Holds a raw pointer and a back-reference to the pool.
             * Automatically returns the buffer to the pool on destruction.
             */
            class Buffer final {
            public:
                Buffer() noexcept : data_(nullptr), pool_(nullptr) {}
                Buffer(uint8_t* data, P2PBufferPool* pool) noexcept : data_(data), pool_(pool) {}

                Buffer(const Buffer&) = delete;
                Buffer& operator=(const Buffer&) = delete;

                Buffer(Buffer&& other) noexcept : data_(other.data_), pool_(other.pool_) {
                    other.data_ = nullptr;
                    other.pool_ = nullptr;
                }

                Buffer& operator=(Buffer&& other) noexcept {
                    if (this != &other) {
                        ReturnToPool();
                        data_ = other.data_;
                        pool_ = other.pool_;
                        other.data_ = nullptr;
                        other.pool_ = nullptr;
                    }
                    return *this;
                }

                ~Buffer() noexcept {
                    ReturnToPool();
                }

                /** @brief Returns the raw buffer pointer. */
                uint8_t* Data() noexcept { return data_; }
                /** @brief Returns the raw buffer pointer (const). */
                const uint8_t* Data() const noexcept { return data_; }
                /** @brief Returns buffer capacity. */
                int Capacity() const noexcept { return P2P_BUFFER_SIZE; }
                /** @brief Returns true if this buffer holds valid memory. */
                explicit operator bool() const noexcept { return data_ != nullptr; }

            private:
                void ReturnToPool() noexcept {
                    if (data_ && pool_) {
                        pool_->Release(data_);
                        data_ = nullptr;
                        pool_ = nullptr;
                    }
                }

                uint8_t*        data_;
                P2PBufferPool*  pool_;
            };

            /**
             * @brief Constructs the pool with the given number of pre-allocated buffers.
             *
             * @param count Number of buffers to pre-allocate. Clamped to [1, 1024].
             */
            explicit P2PBufferPool(int count = DEFAULT_BUFFER_POOL_COUNT) noexcept
                : total_(std::clamp(count, 1, 1024))
                , available_(total_)
                , free_list_(static_cast<unsigned int>(total_)) {
                storage_.reset(static_cast<uint8_t*>(
                    std::malloc(static_cast<size_t>(total_) * P2P_BUFFER_SIZE)));
                if (!storage_) {
                    total_ = 0;
                    return;
                }
                std::memset(storage_.get(), 0, static_cast<size_t>(total_) * P2P_BUFFER_SIZE);

                for (int i = 0; i < total_; ++i) {
                    free_list_.push(storage_.get() + (static_cast<size_t>(i) * P2P_BUFFER_SIZE));
                }
            }

            /** @brief Non-copyable, non-movable. */
            P2PBufferPool(const P2PBufferPool&) = delete;
            P2PBufferPool& operator=(const P2PBufferPool&) = delete;

            ~P2PBufferPool() noexcept = default;

            /**
             * @brief Borrows a buffer from the pool.
             *
             * @return A Buffer RAII wrapper. If the pool is exhausted, returns
             *         a null Buffer (operator bool() == false). No heap fallback.
             */
            Buffer Acquire() noexcept {
                uint8_t* ptr = nullptr;
                if (free_list_.pop(ptr)) {
                    available_.fetch_sub(1, std::memory_order_relaxed);
                    return Buffer(ptr, this);
                }
                // Pool exhausted — return null buffer (fail closed, no malloc).
                return Buffer();
            }

            /**
             * @brief Returns the number of buffers currently in the free list.
             */
            int Available() const noexcept {
                return available_.load(std::memory_order_relaxed);
            }

            /**
             * @brief Returns the total number of pre-allocated buffers.
             */
            int Total() const noexcept { return total_; }

        private:
            /**
             * @brief Returns a buffer to the pool.
             * @param ptr Buffer pointer to return.
             */
            void Release(uint8_t* ptr) noexcept {
                if (!ptr || !storage_) {
                    return;
                }
                // Verify this is a pool-owned buffer before returning.
                uint8_t* base = storage_.get();
                uint8_t* end  = base + static_cast<size_t>(total_) * P2P_BUFFER_SIZE;
                if (ptr >= base && ptr < end) {
                    free_list_.push(ptr);
                    available_.fetch_add(1, std::memory_order_relaxed);
                }
                // If not pool-owned (should not happen), silently ignore.
            }

            int                                         total_;         ///< Number of pre-allocated buffers.
            std::atomic<int>                            available_;     ///< Current number of buffers in free list.
            std::unique_ptr<uint8_t, decltype(&std::free)> storage_{nullptr, std::free}; ///< Contiguous buffer storage.
            boost::lockfree::queue<uint8_t*>            free_list_;     ///< Lock-free free list.
        };

    }
}
