#pragma once 

/**
 * @file MemoryStream.h
 * @brief Defines an in-memory implementation of `ppp::io::Stream`.
 */

#include <string.h>
#include <limits.h>
#include <ppp/stdafx.h>
#include <ppp/io/Stream.h>

#ifndef __INT_MAX__
#define __INT_MAX__ 2147483647
#endif

namespace ppp {
    namespace io {
        /**
         * @brief Stream implementation backed by a contiguous byte buffer.
         */
        class MemoryStream : public Stream {
        public:
            /**
             * @brief Initializes an empty expandable memory stream.
             */
            MemoryStream() noexcept
                : MemoryStream(0) {

            }
            /**
             * @brief Initializes an expandable memory stream with initial capacity.
             * @param capacity Initial buffer capacity in bytes.
             */
            MemoryStream(int capacity) noexcept
                : _expandable(true)
                , _disposed(false)
                , _position(0)
                , _length(0)
                , _capacity(0) {
                if (capacity > 0) {
                    this->SetCapacity(capacity);
                }
            }
            /**
             * @brief Wraps an external buffer as a non-expandable stream.
             * @param buffer Shared byte buffer.
             * @param count Valid byte count in the wrapped buffer.
             */
            MemoryStream(const std::shared_ptr<Byte>& buffer, int count) noexcept
                : _expandable(false)
                , _disposed(false)
                , _position(0)
                , _length(count)
                , _capacity(count)
                , _buffer(buffer) {
                
            }

        public:
            /** @brief Indicates that seeking is supported. */
            virtual bool                        CanSeek() noexcept override { return true; }
            /** @brief Indicates that reading is supported. */
            virtual bool                        CanRead() noexcept override { return true; }
            /** @brief Indicates that writing is supported. */
            virtual bool                        CanWrite() noexcept override { return true; }

        public:
            /** @brief Gets the current read/write position. */
            virtual int                         GetPosition() noexcept override { return this->_position; }
            /** @brief Gets the current logical stream length. */
            virtual int                         GetLength() noexcept override { return this->_length; }
            /** @brief Gets remaining free capacity (`capacity - length`). */
            virtual int                         GetCapacity() noexcept { return this->_capacity - this->_length; }

        public:         
            /**
             * @brief Moves the current position relative to an origin.
             * @param offset Signed offset in bytes.
             * @param loc Origin for the seek operation.
             * @return `true` when resulting position is valid.
             */
            virtual bool                        Seek(int offset, SeekOrigin loc) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                /** Validate bounds after translating offset with selected origin. */
                switch (loc) {
                case SeekOrigin::Begin: {
                    int now = offset;
                    if (now < 0 || now > this->_length) {
                        return false;
                    }

                    this->_position = offset;
                    break;
                }
                case SeekOrigin::Current: {
                    int now = this->_position + offset;
                    if (now < 0 || now > this->_length) {
                        return false;
                    }
                    
                    this->_position = now;
                    break;
                }
                case SeekOrigin::End: {
                    int now = this->_length + offset;
                    if (now < 0 || now > this->_length) {
                        return false;
                    }

                    this->_position = now;
                    break;
                }
                default:
                    return false;
                }
                return true;
            }
            /** @brief Sets the absolute current position from stream begin. */
            virtual bool                        SetPosition(int position) noexcept override { return this->Seek(position, SeekOrigin::Begin); }
            /**
             * @brief Adjusts logical stream length and expands capacity when needed.
             * @param value New length in bytes.
             * @return `true` on success.
             */
            virtual bool                        SetLength(int value) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                if (value < 0) {
                    return false;
                }

                if (!this->EnsureCapacity(value)) {
                    return false;
                }

                this->_length = value;
                if (this->_position > value) {
                    this->_position = value;
                }
                
                return true;
            }
            /**
             * @brief Changes internal buffer capacity.
             * @param value New capacity in bytes.
             * @return `true` if capacity is accepted and applied.
             */
            virtual bool                        SetCapacity(int value) noexcept {
                if (this->_disposed) {
                    return false;
                }

                if (value < this->_length) {
                    return false;
                }

                if (!this->_expandable && value != this->_capacity) {
                    return false;
                }

                if (!this->_expandable || value == this->_capacity) {
                    return true;
                }

                if (value > 0) {
                    std::shared_ptr<Byte> array = this->NewBuffer(value);
                    if (this->_length > 0) {
                        memcpy(array.get(), this->_buffer.get(), this->_length);
                    }

                    this->_buffer = array;
                }
                else {
                    this->_buffer = NULLPTR;
                }

                this->_capacity = value;
                return true;
            }
            /** @brief Releases buffer resources and marks stream as disposed. */
            virtual void                        Dispose() noexcept override {
                if (!this->_disposed) {
                    this->_expandable = false;
                    this->_position = 0;
                    this->_length = 0;
                    this->_capacity = 0;
                    this->_buffer = NULLPTR;
                    this->_disposed = true;
                }
            }     

        public:
            /**
             * @brief Writes one byte at the current position.
             * @param value Byte value to write.
             * @return `true` on success.
             */
            virtual bool                        WriteByte(Byte value) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                int num = this->_position + 1;
                if (num > this->_length) {
                    if (!this->EnsureCapacity(num)) {
                        return false;
                    }

                    this->_length = num;
                }

                this->_buffer.get()[this->_position++] = value;
                return true;
            }
            /**
             * @brief Writes a block of bytes into the stream.
             * @param buffer Source memory address.
             * @param offset Source offset in bytes.
             * @param count Number of bytes to write.
             * @return `true` on success.
             */
            virtual bool                        Write(const void* buffer, int offset, int count) noexcept override {
                if (this->_disposed) {
                    return false;
                }

                if (NULLPTR == buffer) {
                    if (offset == 0 && count == 0) {
                        return true;
                    }
                    
                    return false;
                }

                if (offset < 0) {
                    return false;
                }

                if (count < 0) {
                    return false;
                }

                if (count == 0) {
                    return true;
                }

                int num = this->_position + count;
                if (num > this->_length) {
                    if (!this->EnsureCapacity(num)) {
                        return false;
                    }
                    
                    this->_length = num;
                }

                memcpy(this->_buffer.get() + this->_position, (char*)buffer + offset, count);
                this->_position = num;
                
                return true;
            }                                

        public:
            /**
             * @brief Reads one byte from the current position.
             * @return Byte value in range [0,255], or `-1` on end/disposed.
             */
            virtual int                         ReadByte() noexcept override {
                if (this->_disposed) {
                    return -1;
                }

                if (this->_position >= this->_length) {
                    return -1;
                }

                return this->_buffer.get()[this->_position++];
            }
            /**
             * @brief Reads a block of bytes from the stream.
             * @param buffer Destination memory address.
             * @param offset Destination offset in bytes.
             * @param count Number of bytes requested.
             * @return Number of bytes actually read, or `-1` on invalid/disposed state.
             */
            virtual int                         Read(const void* buffer, int offset, int count) noexcept override {
                if (this->_disposed) {
                    return -1;
                }

                if (NULLPTR == buffer) {
                    if (offset == 0 && count == 0) {
                        return 0;
                    }
                    return -1;
                }

                if (offset < 0) {
                    return -1;
                }

                if (count < 0) {
                    return -1;
                }
                elif(count == 0) {
                    return 0;
                }

                int num = this->_length - this->_position;
                if (num > count) {
                    num = count;
                }

                if (num < 1) {
                    return 0;
                }

                memcpy((char*)buffer + offset, this->_buffer.get() + this->_position, num);
                this->_position += num;

                return num;
            }

        public:
            /** @brief Returns the underlying internal buffer without copying. */
            std::shared_ptr<Byte>               GetBuffer() const noexcept { return this->_buffer; }
            /**
             * @brief Creates a copy of current stream content.
             * @param length Receives copied byte count.
             * @return New shared byte array, or `NULLPTR` when empty/failed.
             */
            std::shared_ptr<Byte>               ToArray(int& length) noexcept {
                length = this->_length;
                if (length < 1) {
                    return NULLPTR;
                }

                std::shared_ptr<Byte> dest = this->NewBuffer(length);
                if (NULLPTR == dest) {
                    length = 0;
                    return NULLPTR;
                }

                std::shared_ptr<Byte> src = this->_buffer;
                if (NULLPTR == src) {
                    length = 0;
                    return NULLPTR;
                }

                memcpy(dest.get(), src.get(), length);
                return dest;
            }
        
        private:        
            /**
             * @brief Allocates a new byte buffer using configured allocator.
             * @param length Requested buffer length in bytes.
             * @return Allocated shared byte array, or `NULLPTR`.
             */
            std::shared_ptr<Byte>               NewBuffer(int length) noexcept {
                if (length < 1) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = this->BufferAllocator;
                return ppp::threading::BufferswapAllocator::MakeByteArray(allocator, length);
            }
            /**
             * @brief Ensures internal capacity is at least `value`.
             * @param value Minimum required capacity in bytes.
             * @return `true` when capacity requirement is satisfied.
             */
            bool                                EnsureCapacity(int value) noexcept {
                if (value < 0) {
                    return false;
                }

                int& capacity = this->_capacity;
                if (value > capacity) {
                    /** Grow geometrically with a small minimum while honoring int limits. */
                    int num = value;
                    if (num < 256) {
                        num = 256;
                    }
                    
                    int64_t ndw = (int64_t)capacity << 1;
                    if (num < ndw) {
                        num = ndw;
                    }
                    
                    if (ndw > 2147483591u) {
                        if (value > 2147483591) {
                            return false;
                        }

                        num = 2147483591;
                    }
                    
                    return this->SetCapacity(num);
                }

                return true;
            }

        private:
            bool                                _expandable : 1; ///< true when the buffer can grow automatically on write.
            bool                                _disposed   : 7; ///< true when Dispose() has been called; all operations become no-ops.
            int                                 _position   = 0; ///< Current read/write cursor position in bytes.
            int                                 _length     = 0; ///< Logical content length in bytes.
            int                                 _capacity   = 0; ///< Allocated buffer capacity in bytes.
            std::shared_ptr<Byte>               _buffer;         ///< Underlying heap buffer shared between stream and callers via GetBuffer().
        };
    }
}
