#pragma once

/**
 * @file Stream.h
 * @brief Declares the abstract byte stream interface used by PPP components.
 */

#include <ppp/stdafx.h>
#include <ppp/io/SeekOrigin.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace io {
        /**
         * @brief Defines the common read/write/seek contract for stream implementations.
         */
        class Stream {
        public:
            /**
             * @brief Optional allocator used by concrete stream implementations.
             *
             * When non-null, internal buffer allocations are routed through this
             * object (backed by jemalloc) instead of the global heap.  Set by the
             * caller before the first read/write to keep allocations consistent
             * with the surrounding pipeline.
             */
            std::shared_ptr<ppp::threading::BufferswapAllocator>    BufferAllocator;

        public:
            /**
             * @brief Releases stream resources.
             */
            virtual ~Stream() noexcept = default;

        public:
            /** @brief Returns whether random seek operations are supported. */
            virtual bool                                            CanSeek() = 0;
            /** @brief Returns whether read operations are supported. */
            virtual bool                                            CanRead() = 0;
            /** @brief Returns whether write operations are supported. */
            virtual bool                                            CanWrite() = 0;

        public:
            /** @brief Gets the current stream position in bytes. */
            virtual int                                             GetPosition() = 0;
            /** @brief Gets the total stream length in bytes. */
            virtual int                                             GetLength() = 0;
            /** @brief Moves the current position by offset and origin. */
            virtual bool                                            Seek(int offset, SeekOrigin loc) = 0;
            /** @brief Sets the current position in bytes. */
            virtual bool                                            SetPosition(int position)  = 0;
            /** @brief Resizes the stream to the specified length. */
            virtual bool                                            SetLength(int value) = 0;

        public:
            /** @brief Writes a single byte into the stream. */
            virtual bool                                            WriteByte(Byte value) = 0;
            /** @brief Writes a range of bytes from the provided buffer. */
            virtual bool                                            Write(const void* buffer, int offset, int count) = 0;

        public:
            /** @brief Reads one byte and returns it as an integer value. */
            virtual int                                             ReadByte() = 0;
            /** @brief Reads bytes into the provided buffer range. */
            virtual int                                             Read(const void* buffer, int offset, int count) = 0;

        public:
            /** @brief Closes the stream and frees all associated resources. */
            virtual void                                            Dispose() = 0;
        };
    }
}
