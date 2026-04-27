#pragma once

/**
 * @file hash_bytes.h
 * @brief Hash primitives used by internal hashing helpers.
 */

#include <ppp/stdafx.h>

namespace ppp
{
    namespace hash
    {
        /**
         * @brief Computes a Murmur-style hash for a byte sequence.
         * @param ptr Pointer to input bytes.
         * @param len Number of bytes in the input.
         * @param seed Initial hash seed.
         * @return Hash value for the provided bytes.
         */
        size_t _Hash_bytes(const void* ptr, size_t len, size_t seed) noexcept;

        /**
         * @brief Computes an FNV-1a hash for a byte sequence.
         * @param ptr Pointer to input bytes.
         * @param len Number of bytes in the input.
         * @param hash Initial hash value.
         * @return Hash value for the provided bytes.
         */
        size_t _Fnv_hash_bytes(const void* ptr, size_t len, size_t hash) noexcept;
    }
}
