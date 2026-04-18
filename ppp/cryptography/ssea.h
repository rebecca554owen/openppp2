#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

/**
 * @file ssea.h
 * @brief Declares lightweight data obfuscation and Base94 conversion helpers.
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
            /** @brief Deterministically permutes a byte buffer in place. */
            static void                     shuffle_data(char* encoded_data, int data_size, uint32_t key) noexcept;
            /** @brief Reverses @ref shuffle_data for the same key and size. */
            static void                     unshuffle_data(char* encoded_data, int data_size, uint32_t key) noexcept;
            /** @brief Delta-encodes a byte sequence into an output buffer. */
            static int                      delta_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, int kf, std::shared_ptr<Byte>& output) noexcept;
            /** @brief Restores bytes previously encoded by @ref delta_encode. */
            static int                      delta_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int data_size, int kf, std::shared_ptr<Byte>& output) noexcept;
            /** @brief Encodes binary data using the project Base94 variant. */
            static std::shared_ptr<Byte>    base94_encode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept;
            /** @brief Decodes bytes produced by @ref base94_encode. */
            static std::shared_ptr<Byte>    base94_decode(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const void* data, int datalen, int kf, int& outlen) noexcept;
            /** @brief Encodes an unsigned integer into a Base94 string. */
            static ppp::string              base94_decimal(uint64_t v) noexcept;
            /** @brief Decodes a Base94 string into an unsigned integer. */
            static uint64_t                 base94_decimal(const ppp::string& v) noexcept;
            /** @brief Decodes Base94 raw bytes into an unsigned integer. */
            static uint64_t                 base94_decimal(const void* data, int datalen) noexcept;

        public:
            /** @brief Generates a pseudo-random integer from a copy of the seed. */
            static int                      random_next(unsigned int seed) noexcept { return random_next(&seed); }
            /** @brief Generates a pseudo-random integer and advances the seed. */
            static int                      random_next(unsigned int* seed) noexcept;
            /** @brief Generates a pseudo-random integer in [min, max]. */
            static int                      random_next(unsigned int* seed, int min, int max) noexcept;

        public:
            /** @brief Convenience wrapper that maps a key through @ref random_next. */
            static int                      lcgmod(int32_t kf, int min, int max) noexcept { return random_next((unsigned int*)&kf, min, max); }

        public:
            /** @brief Applies a fixed XOR mask to a memory range. */
            static bool                     masked_xor(const void* min, const void* max, int32_t kf) noexcept;
            /** @brief Applies an evolving XOR mask driven by @ref random_next. */
            static bool                     masked_xor_random_next(const void* min, const void* max, int32_t kf) noexcept;
        };
    }
}
