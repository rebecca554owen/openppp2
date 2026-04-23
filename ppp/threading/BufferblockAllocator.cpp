#include <ppp/stdafx.h>
#include <ppp/io/File.h>
#include <ppp/threading/BufferblockAllocator.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file BufferblockAllocator.cpp
 * @brief Implements a file/virtual-memory backed buddy allocator.
 */

#include <boost/interprocess/file_mapping.hpp>
#include <boost/interprocess/mapped_region.hpp>

#include <common/memory/buddy_allocator.h>

namespace ppp
{
    namespace threading
    {
        /**
         * @brief Constructs allocator with default memory size.
         * @param path Mapping file path used on non-Windows platforms.
         */
        BufferblockAllocator::BufferblockAllocator(const ppp::string& path) noexcept
            : BufferblockAllocator(path, 0)
        {

        }

        /**
         * @brief Constructs allocator with caller-specified memory size.
         * @param path Mapping file path used on non-Windows platforms.
         * @param memory_size Requested arena size in bytes.
         */
        BufferblockAllocator::BufferblockAllocator(const ppp::string& path, uint32_t memory_size) noexcept
            : BufferblockAllocator(path, memory_size, PPP_MEMORY_ALIGNMENT_SIZE)
        {

        }

        /**
         * @brief Constructs allocator and initializes backing arena.
         * @param path Mapping file path used on non-Windows platforms.
         * @param memory_size Requested arena size in bytes.
         * @param page_size Alignment/page granularity.
         */
        BufferblockAllocator::BufferblockAllocator(const ppp::string& path, uint32_t memory_size, uint32_t page_size) noexcept
            : path_(path)
            , page_size_(0)
            , buddy_(NULLPTR)
            , memory_start_(NULLPTR)
            , memory_maxof_(NULLPTR)
        {
            /**
             * @brief Normalize page size.
             *
             * The page size cannot be smaller than allocator alignment; when a
             * smaller value is provided, the system page size is used instead.
             */
            if (page_size < PPP_MEMORY_ALIGNMENT_SIZE)
            {
                page_size = GetMemoryPageSize();
            }

            /**
             * @brief Normalize arena size.
             *
             * Ensure at least 16 MB and align the arena size by page size so
             * backend mapping and buddy metadata operate on aligned storage.
             */
            memory_size = std::max<uint32_t>(1 << 24, memory_size);
            memory_size = (uint32_t)Malign<int64_t>(memory_size, (page_size_ = page_size)); // For byte size alignment by page size, the memory size of the request file map must be a power of two.

            /**
             * @brief Create backing memory region.
             *
             * Windows uses VirtualAlloc directly. POSIX platforms create/map a
             * file and then obtain the mapped address as buddy arena.
             */
            void* buddy_arena = NULLPTR;
            if (memory_size > 0)
            {
#if defined(_WIN32)
                /**
                 * @brief Allocate process virtual memory directly on Windows.
                 */
                memory_start_ = (char*)VirtualAlloc(NULLPTR, memory_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (NULLPTR != memory_start_)
                {
                    buddy_arena = memory_start_;
                    memory_maxof_ = (char*)buddy_arena + memory_size;
                }
#else
                /**
                 * @brief Allocate mapped arena on POSIX platforms.
                 *
                 * Use a temporary file mapping to avoid excessive platform
                 * branching between Linux and macOS allocation APIs.
                 */
                if (path.size() > 0)
                {
                    std::shared_ptr<boost::interprocess::file_mapping> bip_mapping_file;
                    std::shared_ptr<boost::interprocess::mapped_region> bip_mapped_region;
                    try
                    {
                        do
                        {
                            /**
                             * @brief Remove stale mapping file before recreation.
                             */
                            ppp::io::File::Delete(path.data());

                            /**
                             * @brief Create file with requested mapped size.
                             */
                            ppp::io::File::Create(path.data(), memory_size);

                            /**
                             * @brief Create mapping objects and map into process space.
                             */
                            boost::interprocess::file_mapping mapping_file(path.data(), boost::interprocess::read_write);
                            boost::interprocess::mapped_region mapped_region(mapping_file, boost::interprocess::read_write);

                            /**
                             * @brief Transfer mapping objects to managed shared pointers.
                             */
                            bip_mapping_file = make_shared_object<boost::interprocess::file_mapping>();
                            bip_mapped_region = make_shared_object<boost::interprocess::mapped_region>();
                            if (NULLPTR != bip_mapping_file && NULLPTR != bip_mapped_region)
                            {
                                bip_mapping_file->swap(mapping_file);
                                bip_mapped_region->swap(mapped_region);
                            }
                        } while (false);
                    }
                    catch (const boost::interprocess::interprocess_exception&)
                    {
                        ppp::io::File::Delete(path.data());
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryMapFailed);
                    }

                    /**
                     * @brief Persist mapping handles when setup succeeded.
                     */
                    if (NULLPTR != bip_mapping_file && NULLPTR != bip_mapped_region)
                    {
                        bip_mapping_file_ = bip_mapping_file;
                        bip_mapped_region_ = bip_mapped_region;
                        buddy_arena = bip_mapped_region->get_address();
                    }
                }
#endif
            }

            if (NULLPTR != buddy_arena)
            {
                /* You need space for arena and builtin metadata */
                /**
                 * @brief Initialize embedded buddy allocator in mapped arena.
                 */
                struct buddy* buddy = buddy_embed((unsigned char*)buddy_arena, memory_size);
                if (NULLPTR != buddy)
                {
                    buddy_ = buddy; /* buddy_init(buddy_metadata, buddy_arena, arena_size); */
                }

                /* Sets the header and tail Pointers that the file maps to memory. */
                memory_start_ = (char*)buddy_arena;
                memory_maxof_ = (char*)buddy_arena + memory_size;
            }

#if !defined(_WIN32)
            /* After mapping a file into virtual memory, attempting to immediately delete the file created by the mapping. */
            /**
             * @brief Remove temporary backing file after mapping.
             */
            ppp::io::File::Delete(path.data());
#endif
        }

        /**
         * @brief Disposes allocator resources.
         */
        BufferblockAllocator::~BufferblockAllocator() noexcept
        {
            Dispose();
        }

        /**
         * @brief Releases mapped memory resources and resets allocator state.
         */
        void BufferblockAllocator::Dispose() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
#if defined(_WIN32)
            if (VirtualFree(memory_start_, 0, MEM_RELEASE))
            {
                memory_start_ = NULLPTR;
                memory_maxof_ = NULLPTR;
            }
#else
            bip_mapped_region_ = NULLPTR;
            bip_mapping_file_ = NULLPTR;
#endif
            buddy_ = NULLPTR;
            memory_start_ = NULLPTR;
            memory_maxof_ = NULLPTR;

#if !defined(_WIN32)
            ppp::io::File::Delete(path_.data());
#endif
        }

        /**
         * @brief Checks whether buddy allocator state is initialized.
         * @return true if allocator is valid.
         */
        bool BufferblockAllocator::IsVaild() noexcept
        {
            return NULLPTR != buddy_;
        }

        /**
         * @brief Tests whether a pointer belongs to managed arena range.
         * @param allocated_memory Pointer to test.
         * @return true if pointer is within allocator memory interval.
         */
        bool BufferblockAllocator::IsInBlock(const void* allocated_memory) noexcept
        {
            if (NULLPTR == buddy_ || NULLPTR == allocated_memory)
            {
                return false;
            }

            if (allocated_memory >= memory_start_ && allocated_memory < memory_maxof_)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /**
         * @brief Returns mapping path associated with allocator.
         */
        ppp::string BufferblockAllocator::GetPath() noexcept
        {
            return path_;
        }

        /**
         * @brief Returns page/alignment size used by allocator.
         */
        uint32_t BufferblockAllocator::GetPageSize() noexcept
        {
            return page_size_;
        }

        /**
         * @brief Returns total arena size in bytes.
         */
        uint32_t BufferblockAllocator::GetMemorySize() noexcept
        {
            return (uint32_t)((char*)memory_maxof_ - (char*)memory_start_);
        }

        /**
         * @brief Queries currently available free memory in buddy arena.
         * @return Free size in bytes.
         */
        uint32_t BufferblockAllocator::GetAvailableSize() noexcept
        {
            SynchronizedObjectScope scope(syncobj_);
            struct buddy* buddy = reinterpret_cast<struct buddy*>(buddy_);
            if (NULLPTR == buddy)
            {
                return 0;
            }

            return buddy_arena_free_size(buddy);
        }

        /**
         * @brief Frees a previously allocated block.
         * @param allocated_memory Pointer returned by Alloc.
         * @return true if block belongs to this arena and is released.
         */
        bool BufferblockAllocator::Free(const void* allocated_memory) noexcept
        {
            if (NULLPTR == allocated_memory)
            {
                return false;
            }

            if (allocated_memory < memory_start_ || allocated_memory >= memory_maxof_)
            {
                return false;
            }

            SynchronizedObjectScope scope(syncobj_);
            struct buddy* buddy = reinterpret_cast<struct buddy*>(buddy_);
            if (NULLPTR == buddy)
            {
                return false;
            }

            /* Free using the buddy allocator */
            buddy_free(buddy, constantof(allocated_memory));
            return true;
        }

        /**
         * @brief Allocates an aligned block from buddy arena.
         * @param allocated_size Requested byte size.
         * @return Allocated pointer, or null on failure.
         */
        void* BufferblockAllocator::Alloc(uint32_t allocated_size) noexcept
        {
            if (allocated_size == 0)
            {
                return NULLPTR;
            }

            SynchronizedObjectScope scope(syncobj_);
            struct buddy* buddy = reinterpret_cast<struct buddy*>(buddy_);
            if (NULLPTR == buddy)
            {
                return NULLPTR;
            }
            else
            {
                allocated_size = Malign(allocated_size, page_size_);
            }

            /* Allocate using the buddy allocator */
            void* data = buddy_malloc(buddy, allocated_size);
            return data;
        }
    }
}
