#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferblockAllocator.h>

/**
 * @file BufferswapAllocator.h
 * @brief Declares a multi-block allocator that can swap allocations across blocks.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Coordinates multiple BufferblockAllocator instances as one allocator.
         */
        class BufferswapAllocator final : public std::enable_shared_from_this<BufferswapAllocator>
        {
            /** @brief Shared pointer alias for a memory block allocator. */
            typedef std::shared_ptr<BufferblockAllocator>               BufferblockAllocatorPtr;
            /** @brief Container alias for managed block allocators. */
            typedef ppp::list<BufferblockAllocatorPtr>                  BufferblockAllocatorList;
            /** @brief Mutex type used to guard allocator collections. */
            typedef std::mutex                                          SynchronizedObject;
            /** @brief RAII lock helper for synchronization. */
            typedef std::lock_guard<SynchronizedObject>                 SynchronizedObjectScope;

        public:
            /**
             * @brief Maximum size of a single memory block.
             * @details Capped to keep per-block allocations under practical 32-bit limits.
             */
            static constexpr uint64_t                                   MAX_MEMORY_BLOCK_SIZE = 1073741824; /* 4294967280 */

        public:
            /** @brief Creates a swap allocator rooted at path with target capacity. */
            BufferswapAllocator(const ppp::string& path, uint64_t memory_size) noexcept;
            /** @brief Releases all managed blocks and backing storage. */
            virtual ~BufferswapAllocator() noexcept;

        public:
            /** @brief Allocates memory from any available managed block. */
            void*                                                       Alloc(uint32_t allocated_size) noexcept;
            /** @brief Frees memory by locating its owner block. */
            bool                                                        Free(const void* allocated_memory) noexcept;
            /** @brief Checks whether at least one backing block is available. */
            bool                                                        IsVaild() noexcept;
            /** @brief Returns the block containing the provided pointer. */
            std::shared_ptr<BufferblockAllocator>                       IsInBlock(const void* allocated_memory) noexcept;
            /** @brief Returns the page size used by managed blocks. */
            uint32_t                                                    GetPageSize() noexcept;
            /** @brief Returns total configured memory across all blocks. */
            uint64_t                                                    GetMemorySize() noexcept;
            /** @brief Returns total free memory across all blocks. */
            uint64_t                                                    GetAvailableSize() noexcept;

        public:
            template <typename T>
            /**
             * @brief Allocates an array from swap blocks with heap fallback.
             * @param length Number of elements to allocate.
             * @return Shared pointer to the allocated array.
             */
            std::shared_ptr<T>                                          MakeArray(int length) noexcept {
                static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

                if (length < 1) {
                    return NULLPTR;
                }

                if (static_cast<size_t>(length) > (std::numeric_limits<uint32_t>::max)() / sizeof(T)) {
                    return NULLPTR;
                }

                uint32_t allocated_size = (uint32_t)((size_t)length * sizeof(T));
                T* memory = (T*)Alloc(allocated_size);

                if (NULLPTR == memory) {
                    return make_shared_alloc<T>(length);
                }

                auto self = shared_from_this();
                return std::shared_ptr<T>(memory,
                    [self, this](void* allocated_memory) noexcept {
                        Free(allocated_memory);
                    });
            }

            template <typename T, typename... A>
            /**
             * @brief Constructs an object in swap-managed memory with heap fallback.
             * @param args Constructor arguments forwarded to T.
             * @return Shared pointer to the constructed object.
             */
            std::shared_ptr<T>                                          MakeObject(A&&... args) noexcept {
                static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

                void* memory = Alloc(sizeof(T));
                if (NULLPTR == memory) {
                    return make_shared_object<T>(std::forward<A&&>(args)...);
                }
                
                auto self = shared_from_this();
                memset(memory, 0, sizeof(T));

                return std::shared_ptr<T>(new (memory) T(std::forward<A&&>(args)...),
                    [self, this](T* p) noexcept {
                        p->~T();
                        Free(p);
                    });
            }

            /**
             * @brief Allocates a byte buffer through allocator when available.
             * @param allocator Optional allocator instance to use.
             * @param datalen Requested byte length.
             * @return Shared pointer to the allocated byte array.
             */
            static std::shared_ptr<Byte>                                MakeByteArray(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, int datalen) noexcept {
                if (NULLPTR != allocator) {
                    return allocator->MakeArray<Byte>(datalen);
                }
                else {
                    return make_shared_alloc<Byte>(datalen);
                }
            }

        private:
            SynchronizedObject                                          syncobj_;
            BufferblockAllocatorList                                    blocks_;
            int                                                         block_count_     = 0;
            uint64_t                                                    memory_size_     = 0;
        };
    }
}
