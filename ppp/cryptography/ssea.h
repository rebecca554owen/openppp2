#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file ssea.h
 * @brief Declares lightweight data obfuscation and Base94 conversion helpers.
 *
 * @details
 * The `ssea` class provides a set of stateless, allocation-aware helpers used by
 * the PPP obfuscation pipeline:
 *
 *  - **Shuffle / Unshuffle** — deterministic in-place byte permutation driven by a
 *    32-bit key; the permutation is its own inverse via `unshuffle_data`.
 *  - **Delta encode / decode** — differential byte coding that reduces entropy prior
 *    to further compression or transmission.
 *  - **Base94** — a printable-ASCII encoding scheme that maps arbitrary binary data
 *    to 94-character printable ASCII, including integer ↔ string conversion for
 *    compact numeric identifiers.
 *  - **PRNG** — a lightweight LCG-based pseudo-random generator used internally to
 *    derive permutation indices and XOR masks.
 *  - **Masked XOR** — fixed and PRNG-driven in-place XOR transforms over raw memory
 *    ranges for lightweight obfuscation.
 *
 * @note  None of the methods in this class provide cryptographic security.  They are
 *        obfuscation aids only; do not rely on them for confidentiality.
 * @note  All methods are `static` and `noexcept`; the class cannot be instantiated.
 */

namespace ppp
{
    namespace cryptography
    {
        /**
         * @brief Utility collection for data shuffling, delta coding, Base94 conversion,
         *        pseudo-random generation, and in-place masked XOR transforms.
         */
        class ssea
        {
        public:
            /**
             * @brief Deterministically permutes a byte buffer in place.
             * @param encoded_data Mutable buffer whose bytes will be shuffled.
             * @param data_size    Number of bytes in `encoded_data`.
             * @param key          32-bit seed that controls the permutation order.
             * @note  Calling with the same `key` and `data_size` on already-shuffled
             *        data does NOT restore the original order; use `unshuffle_data` for that.
             */
            static void                     shuffle_data(char* encoded_data, int data_size, uint32_t key) noexcept;

            /**
             * @brief Reverses @ref shuffle_data for the same key and size.
             * @param encoded_data Mutable buffer produced by `shuffle_data`.
             * @param data_size    Number of bytes in `encoded_data`.
             * @param key          32-bit seed that was used during the original shuffle.
             */
            static void                     unshuffle_data(char* encoded_data, int data_size, uint32_t key) noexcept;

            /**
             * @brief Delta-encodes a byte sequence into an output buffer.
             * @param allocator  Shared allocator used to allocate `output`; may be null for
             *                   default heap allocation.
             * @param data       Pointer to source bytes.
             * @param data_size  Number of source bytes.
             * @param kf         Key factor used to seed the delta transformation.
             * @param output     Receives the allocated encoded buffer on success.
             * @return Number of bytes written to `output`, or a negative value on failure.
             */
            static int                      delta_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, int kf, std::shared_ptr<Byte>& output) noexcept;

            /**
             * @brief Restores bytes previously encoded by @ref delta_encode.
             * @param allocator  Shared allocator used to allocate `output`; may be null for
             *                   default heap allocation.
             * @param data       Pointer to delta-encoded source bytes.
             * @param data_size  Number of source bytes.
             * @param kf         Key factor that was supplied to `delta_encode`.
             * @param output     Receives the allocated decoded buffer on success.
             * @return Number of bytes written to `output`, or a negative value on failure.
             */
            static int                      delta_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, int kf, std::shared_ptr<Byte>& output) noexcept;

            /**
             * @brief Encodes binary data using the project Base94 variant.
             * @param allocator  Shared allocator for output buffer; may be null.
             * @param data       Pointer to input binary bytes.
             * @param datalen    Number of input bytes.
             * @param kf         Key factor applied during encoding.
             * @param outlen     Receives the number of encoded output bytes on success.
             * @return Shared buffer containing Base94-encoded data, or null on failure.
             * @note  Output consists of printable ASCII characters in the 94-character set.
             */
            static std::shared_ptr<Byte>    base94_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept;

            /**
             * @brief Decodes bytes produced by @ref base94_encode.
             * @param allocator  Shared allocator for output buffer; may be null.
             * @param data       Pointer to Base94-encoded bytes.
             * @param datalen    Number of encoded input bytes.
             * @param kf         Key factor that was supplied to `base94_encode`.
             * @param outlen     Receives the number of decoded output bytes on success.
             * @return Shared buffer containing the recovered binary data, or null on failure.
             */
            static std::shared_ptr<Byte>    base94_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept;

            /**
             * @brief Encodes an unsigned integer into a Base94 string.
             * @param v Unsigned 64-bit value to encode.
             * @return Base94 string representation of `v`.
             */
            static ppp::string              base94_decimal(uint64_t v) noexcept;

            /**
             * @brief Decodes a Base94 string into an unsigned integer.
             * @param v Base94 string produced by `base94_decimal(uint64_t)`.
             * @return Decoded unsigned 64-bit value; 0 when the string is empty or invalid.
             */
            static uint64_t                 base94_decimal(const ppp::string& v) noexcept;

            /**
             * @brief Decodes Base94 raw bytes into an unsigned integer.
             * @param data    Pointer to Base94-encoded byte data.
             * @param datalen Number of bytes to decode.
             * @return Decoded unsigned 64-bit value; 0 on failure or empty input.
             */
            static uint64_t                 base94_decimal(const void* data, int datalen) noexcept;

        public:
            /**
             * @brief Generates a pseudo-random integer from a copy of the seed.
             * @param seed Seed value; the original is not modified.
             * @return Next pseudo-random integer derived from `seed`.
             */
            static int                      random_next(unsigned int seed) noexcept { return random_next(&seed); }

            /**
             * @brief Generates a pseudo-random integer and advances the seed in place.
             * @param seed Pointer to the current seed; updated to the next state on return.
             * @return Next pseudo-random integer.
             */
            static int                      random_next(unsigned int* seed) noexcept;

            /**
             * @brief Generates a pseudo-random integer in [min, max].
             * @param seed Pointer to the current seed; updated to the next state on return.
             * @param min  Inclusive lower bound.
             * @param max  Inclusive upper bound.
             * @return Pseudo-random integer in [min, max].
             */
            static int                      random_next(unsigned int* seed, int min, int max) noexcept;

        public:
            /**
             * @brief Convenience wrapper that maps a key through @ref random_next.
             * @param kf  32-bit key factor reinterpreted as the PRNG seed.
             * @param min Inclusive lower bound for the output range.
             * @param max Inclusive upper bound for the output range.
             * @return Pseudo-random integer in [min, max].
             */
            static int                      lcgmod(int32_t kf, int min, int max) noexcept { return random_next((unsigned int*)&kf, min, max); }

        public:
            /**
             * @brief Applies a fixed XOR mask derived from `kf` to every byte in [min, max).
             * @param min Pointer to the start of the memory range (inclusive).
             * @param max Pointer to the end of the memory range (exclusive).
             * @param kf  Key factor whose bytes are XOR-ed repeatedly over the range.
             * @return true on success; false when the range is invalid.
             */
            static bool                     masked_xor(const void* min, const void* max, int32_t kf) noexcept;

            /**
             * @brief Applies an evolving XOR mask driven by @ref random_next over [min, max).
             * @param min Pointer to the start of the memory range (inclusive).
             * @param max Pointer to the end of the memory range (exclusive).
             * @param kf  Initial key factor used to seed the PRNG; advanced per byte.
             * @return true on success; false when the range is invalid.
             */
            static bool                     masked_xor_random_next(const void* min, const void* max, int32_t kf) noexcept;
        };
    }
}
