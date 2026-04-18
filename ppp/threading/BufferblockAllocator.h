#pragma once

#include <ppp/stdafx.h>

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

/**
 * @file BufferblockAllocator.h
 * @brief Declares a single memory-block allocator backed by virtual memory.
 */

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Allocates and manages fixed backing storage for small allocations.
         */
        class BufferblockAllocator final : public std::enable_shared_from_this<BufferblockAllocator>
        {
            /** @brief Mutex type used to guard allocator state. */
            typedef std::mutex                                      SynchronizedObject;
            /** @brief RAII lock helper for allocator synchronization. */
            typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;

        public:
            /** @brief Creates an allocator with default sizing parameters. */
            BufferblockAllocator(const ppp::string& path) noexcept;
            /** @brief Creates an allocator with an explicit memory capacity. */
            BufferblockAllocator(const ppp::string& path, uint32_t memory_size) noexcept;
            /** @brief Creates an allocator with explicit capacity and page size. */
            BufferblockAllocator(const ppp::string& path, uint32_t memory_size, uint32_t page_size) noexcept;
            /** @brief Releases all mapped resources owned by this allocator. */
            ~BufferblockAllocator() noexcept;

        public:
            /** @brief Returns the storage path used by this block allocator. */
            ppp::string                                             GetPath() noexcept;
            /** @brief Checks whether the allocator is initialized and usable. */
            bool                                                    IsVaild() noexcept;
            /** @brief Tests whether a pointer belongs to this memory block. */
            bool                                                    IsInBlock(const void* allocated_memory) noexcept;
            /** @brief Returns the allocation page size in bytes. */
            uint32_t                                                GetPageSize() noexcept;
            /** @brief Returns the total managed memory size in bytes. */
            uint32_t                                                GetMemorySize() noexcept;
            /** @brief Returns currently available memory in bytes. */
            uint32_t                                                GetAvailableSize() noexcept;
            /** @brief Allocates a memory region from this block. */
            void*                                                   Alloc(uint32_t allocated_size) noexcept;
            /** @brief Frees a pointer previously returned by Alloc(). */
            bool                                                    Free(const void* allocated_memory) noexcept;
            /** @brief Disposes backing resources and invalidates this allocator. */
            void                                                    Dispose() noexcept;

        public:
            template <typename T>
            /**
             * @brief Allocates a contiguous array and wraps it in a shared pointer.
             * @param length Number of elements to allocate.
             * @return Shared pointer to the first element, or null on failure.
             */
            std::shared_ptr<T>                                      MakeArray(int length) noexcept {
                static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

                if (length < 1) {
                    return NULLPTR;
                }

                T* p = (T*)Alloc(length * sizeof(T));
                return std::shared_ptr<T>(p,
                    [self = shared_from_this(), this](void* allocated_memory) noexcept {
                        Free(allocated_memory);
                    });
            }
        
            template <typename T, typename... A>     
            /**
             * @brief Constructs an object in allocator-managed memory.
             * @param args Constructor arguments forwarded to T.
             * @return Shared pointer to the created object, or null on failure.
             */
            std::shared_ptr<T>                                      MakeObject(A&&... args) noexcept {
                static_assert(sizeof(T) > 0, "can't make pointer to incomplete type");

                void* memory = Alloc(sizeof(T));
                if (NULLPTR == memory) {
                    return NULLPTR;
                }
                
                memset(memory, 0, sizeof(T));
                return std::shared_ptr<T>(new (memory) T(std::forward<A&&>(args)...),
                    [self = shared_from_this(), this](T* p) noexcept {
                        p->~T();
                        Free(p);
                    });
            }

        private:
            SynchronizedObject                                      syncobj_;
            ppp::string                                             path_;
            uint32_t                                                page_size_    = 0;
            void*                                                   buddy_        = NULLPTR;
            void*                                                   memory_start_ = NULLPTR;
            void*                                                   memory_maxof_ = NULLPTR;
#if !defined(_WIN32)
            std::shared_ptr<boost::interprocess::file_mapping>      bip_mapping_file_;
            std::shared_ptr<boost::interprocess::mapped_region>     bip_mapped_region_;
#endif
        };
    }
}
