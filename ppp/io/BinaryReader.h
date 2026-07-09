#pragma once

/**
 * @file BinaryReader.h
 * @brief Defines a lightweight binary reader over `ppp::io::Stream`.
 */

#include <ppp/stdafx.h>
#include <ppp/io/Stream.h>

namespace ppp {
    namespace io {
        /**
         * @brief Reads primitive values and value arrays from a stream.
         */
        class BinaryReader final {
        public:
            /**
             * @brief Initializes a reader bound to an existing stream.
             * @param stream Stream instance used for subsequent reads.
             */
            BinaryReader(Stream& stream) noexcept
                : _stream(stream) {

            }

        public:
            /**
             * @brief Reads raw bytes into a caller-provided buffer.
             * @param buffer Destination memory address.
             * @param offset Destination offset in bytes.
             * @param length Number of bytes to read.
             * @return Number of bytes actually read.
             */
            int                                             Read(const void* buffer, int offset, int length) noexcept {
                return _stream.Read(buffer, offset, length);
            }

            template <typename TValueType>           
            /**
             * @brief Reads a fixed number of values of `TValueType`.
             * @param counts Number of values to read.
             * @return Shared array on success; `NULLPTR` on failure or short read.
             */
            std::shared_ptr<TValueType>                     ReadValues(int counts) noexcept {
                if (counts < 1) {
                    return NULLPTR;
                }

                std::shared_ptr<TValueType> buf;
                /** Use stream allocator when available to keep allocation policy consistent. */
                std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = _stream.BufferAllocator;
                if (NULLPTR != allocator) {
                    buf = allocator->MakeArray<TValueType>(counts);
                }
                else {
                    buf = make_shared_alloc<TValueType>(counts);
                }

                if (NULLPTR == buf) {
                    return NULLPTR;
                }

                /** Guard against integer overflow when converting element count to byte size. */
                if (static_cast<size_t>(counts) > (std::numeric_limits<int>::max)() / sizeof(TValueType)) {
                    return NULLPTR;
                }

                int size = static_cast<int>((static_cast<size_t>(counts) * sizeof(TValueType)));
                int len = _stream.Read(buf.get(), 0, size);
                return len > 0 && len == size ? buf : NULLPTR;
            }

            /**
             * @brief Reads a fixed-size byte array.
             * @param counts Number of bytes to read.
             * @return Shared byte array on success; otherwise `NULLPTR`.
             */
            std::shared_ptr<Byte>                           ReadBytes(int counts) noexcept {
                return ReadValues<Byte>(counts);
            }

            template <typename TValueType>           
            /**
             * @brief Attempts to read one value of `TValueType`.
             * @param out Output value when read succeeds.
             * @return `true` if exactly `sizeof(TValueType)` bytes are read.
             */
            bool                                            TryReadValue(TValueType& out) noexcept {
                TValueType* p = (TValueType*)&reinterpret_cast<const char&>(out);
                if (NULLPTR == p) {
                    return false;
                }

                int len = _stream.Read(p, 0, sizeof(TValueType));
                return (size_t)len == sizeof(TValueType);
            }

            template <typename TValueType>                   
            /**
             * @brief Reads one value of `TValueType` or throws on failure.
             * @return Parsed value of `TValueType`.
             * @throws std::runtime_error Thrown when the stream cannot provide enough bytes.
             */
            TValueType                                      ReadValue() {
                TValueType out;
                if (!TryReadValue(out)) {
                    throw std::runtime_error("Unable to read from stream to TValueType size values.");
                }

                return out;
            }

            /**
             * @brief Returns the underlying stream reference.
             * @return Bound stream instance.
             */
            Stream&                                         GetStream() noexcept { return _stream; }

        public:
            /** @brief Reads a signed 16-bit integer. */
            Int16                                           ReadInt16() noexcept { return ReadValue<Int16>(); }
            /** @brief Reads a signed 32-bit integer. */
            Int32                                           ReadInt32() noexcept { return ReadValue<Int32>(); }
            /** @brief Reads a signed 64-bit integer. */
            Int64                                           ReadInt64() noexcept { return ReadValue<Int64>(); }
            /** @brief Reads an unsigned 16-bit integer. */
            UInt16                                          ReadUInt16() noexcept { return ReadValue<UInt16>(); }
            /** @brief Reads an unsigned 32-bit integer. */
            UInt32                                          ReadUInt32() noexcept { return ReadValue<UInt32>(); }
            /** @brief Reads an unsigned 64-bit integer. */
            UInt64                                          ReadUInt64() noexcept { return ReadValue<UInt64>(); }
            /** @brief Reads a signed byte. */
            SByte                                           ReadSByte() noexcept { return ReadValue<SByte>(); }
            /** @brief Reads a byte. */
            Byte                                            ReadByte() noexcept { return ReadValue<Byte>(); }
            /** @brief Reads a single-precision floating-point value. */
            Single                                          ReadSingle() noexcept { return ReadValue<Single>(); }
            /** @brief Reads a double-precision floating-point value. */
            Double                                          ReadDouble() noexcept { return ReadValue<Double>(); }
            /** @brief Reads a Boolean value. */
            bool                                            ReadBoolean() noexcept { return ReadValue<bool>(); }
            /** @brief Reads a character value. */
            Char                                            ReadChar() noexcept { return ReadValue<Char>(); }

        public:     
            /** @brief Attempts to read a signed 16-bit integer. */
            bool                                            TryReadInt16(Int16& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a signed 32-bit integer. */
            bool                                            TryReadInt32(Int32& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a signed 64-bit integer. */
            bool                                            TryReadInt64(Int64& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read an unsigned 16-bit integer. */
            bool                                            TryReadUInt16(UInt16& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read an unsigned 32-bit integer. */
            bool                                            TryReadUInt32(UInt32& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read an unsigned 64-bit integer. */
            bool                                            TryReadUInt64(UInt64& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a signed byte. */
            bool                                            TryReadSByte(SByte& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a byte. */
            bool                                            TryReadByte(Byte& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a single-precision floating-point value. */
            bool                                            TryReadSingle(Single& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a double-precision floating-point value. */
            bool                                            TryReadDouble(bool& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a Boolean value. */
            bool                                            TryReadBoolean(bool& out) noexcept { return TryReadValue(out); }
            /** @brief Attempts to read a character value. */
            bool                                            TryReadChar(Char& out) noexcept { return TryReadValue(out); }

        private:            
            Stream&                                         _stream;
        };
    }
}
