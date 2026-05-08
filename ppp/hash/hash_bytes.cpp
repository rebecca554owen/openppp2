// Definition of _Hash_bytes. -*- C++ -*-
/**
 * @file hash_bytes.cpp
 * @brief Implements Murmur-style and FNV-1a byte hashing primitives.
 */
// Copyright (C) 2010-2014 Free Software Foundation, Inc.
//
// This file is part of the GNU ISO C++ Library.  This library is free
// software; you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the
// Free Software Foundation; either version 3, or (at your option)
// any later version.
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// Under Section 7 of GPL version 3, you are granted additional
// permissions described in the GCC Runtime Library Exception, version
// 3.1, as published by the Free Software Foundation.
// You should have received a copy of the GNU General Public License and
// a copy of the GCC Runtime Library Exception along with this program;
// see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
// <http://www.gnu.org/licenses/>.
// This file defines Hash_bytes, a primitive used for defining hash
// functions. Based on public domain MurmurHashUnaligned2, by Austin
// Appleby.  http://murmurhash.googlepages.com/
// This file also defines _Fnv_hash_bytes, another primitive with
// exactly the same interface but using a different hash algorithm,
// Fowler / Noll / Vo (FNV) Hash (type FNV-1a). The Murmur hash
// function apears to be better in both speed and hash quality, and
// FNV is provided primarily for backward compatibility.

#include <cstdio>
#include <cstdint>
#include <cstring>

#if defined(_WIN32)
#include <intrin.h>
#endif

namespace ppp
{
    /**
     * @brief Loads one machine word from a potentially unaligned address.
     * @param p Pointer to byte buffer.
     * @return Word-sized value copied from memory.
     */
    inline std::size_t unaligned_load(const char* p)
    {
        std::size_t result;
#if defined(__GNUC__) || defined(__clang__)
        __builtin_memcpy(&result, p, sizeof(result));
#else
        std::memcpy(&result, p, sizeof(result));
#endif
        return result;
    }

#if defined(_M_X64) || defined(__x86_64__) || defined(__aarch64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
    /**
     * @brief Loads 1..7 bytes into a word on 64-bit targets.
     * @param p Pointer to tail bytes.
     * @param n Byte count in range [1, 7].
     * @return Packed value built from the input bytes.
     */
    inline std::size_t load_bytes(const char* p, int n)
    {
        std::size_t result = 0;
        --n;
        do
            result = (result << 8) + static_cast<unsigned char>(p[n]);
        while (--n >= 0);
        return result;
    }

    /**
     * @brief Applies a Murmur-style shift/xor mixing step (64-bit variant).
     * @param v Input value.
     * @return Mixed value.
     */
    inline std::size_t shift_mix(std::size_t v)
    {
        return v ^ (v >> 47);
    }
#else
    /**
     * @brief Loads 1..3 bytes into a word on 32-bit targets.
     * @param p Pointer to tail bytes.
     * @param n Byte count in range [1, 3].
     * @return Packed value built from the input bytes.
     */
    inline std::size_t load_bytes(const char* p, int n)
    {
        std::size_t result = 0;
        --n;
        do
            result = (result << 8) + static_cast<unsigned char>(p[n]);
        while (--n >= 0);
        return result;
    }

    /**
     * @brief Applies a Murmur-style shift/xor mixing step (32-bit variant).
     * @param v Input value.
     * @return Mixed value.
     */
    inline std::size_t shift_mix(std::size_t v)
    {
        return v ^ (v >> 16);
    }
#endif
}

namespace ppp
{
    namespace hash
    {
#if defined(_M_X64) || defined(__x86_64__) || defined(__aarch64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
        /**
         * @brief Computes Murmur-style hash on 64-bit platforms.
         * @param ptr Pointer to input bytes.
         * @param len Input length in bytes.
         * @param seed Initial seed value.
         * @return Computed hash value.
         */
        size_t _Hash_bytes(const void* ptr, size_t len, size_t seed) noexcept
        {
            static const size_t mul = (((size_t)0xc6a4a793UL) << 32UL)
                + (size_t)0x5bd1e995UL;
            const char* const buf = static_cast<const char*>(ptr);
            /**
             * @brief Aligns processing length so the main loop handles whole machine words.
             */
            const size_t len_aligned = len & ~0x7ULL;
            const char* const end = buf + len_aligned;
            size_t hash = seed ^ (len * mul);
            for (const char* p = buf; p != end; p += 8)
            {
                const size_t data = shift_mix(unaligned_load(p) * mul) * mul;
                hash ^= data;
                hash *= mul;
            }
            if ((len & 0x7) != 0)
            {
                const size_t data = load_bytes(end, len & 0x7);
                hash ^= data;
                hash *= mul;
            }
            hash = shift_mix(hash) * mul;
            hash = shift_mix(hash);
            return hash;
        }

        /**
         * @brief Computes FNV-1a hash on 64-bit platforms.
         * @param ptr Pointer to input bytes.
         * @param len Input length in bytes.
         * @param hash Initial hash value.
         * @return Computed hash value.
         */
        size_t _Fnv_hash_bytes(const void* ptr, size_t len, size_t hash) noexcept
        {
            const char* cptr = static_cast<const char*>(ptr);
            for (; len; --len)
            {
                hash ^= static_cast<size_t>(*cptr++);
                hash *= static_cast<size_t>(1099511628211ULL);
            }
            return hash;
        }

#else
        /**
         * @brief Computes Murmur-style hash on 32-bit platforms.
         * @param ptr Pointer to input bytes.
         * @param len Input length in bytes.
         * @param seed Initial seed value.
         * @return Computed hash value.
         */
        size_t _Hash_bytes(const void* ptr, size_t len, size_t seed) noexcept
        {
            const size_t m = 0x5bd1e995;
            size_t hash = seed ^ len;
            const char* buf = static_cast<const char*>(ptr);
            /**
             * @brief Mixes 4-byte chunks into the running hash state.
             */
            while (len >= 4)
            {
                size_t k = unaligned_load(buf);
                k *= m;
                k ^= k >> 24;
                k *= m;
                hash *= m;
                hash ^= k;
                buf += 4;
                len -= 4;
            }
            /**
             * @brief Handles the trailing 1..3 bytes.
             */
            switch (len)
            {
            case 3:
                hash ^= static_cast<unsigned char>(buf[2]) << 16;
                // fall through
            case 2:
                hash ^= static_cast<unsigned char>(buf[1]) << 8;
                // fall through
            case 1:
                hash ^= static_cast<unsigned char>(buf[0]);
                hash *= m;
            };
            /**
             * @brief Performs Murmur finalization mixing.
             */
            hash ^= hash >> 13;
            hash *= m;
            hash ^= hash >> 15;
            return hash;
        }

        /**
         * @brief Computes FNV-1a hash on 32-bit platforms.
         * @param ptr Pointer to input bytes.
         * @param len Input length in bytes.
         * @param hash Initial hash value.
         * @return Computed hash value.
         */
        size_t _Fnv_hash_bytes(const void* ptr, size_t len, size_t hash) noexcept
        {
            const char* cptr = static_cast<const char*>(ptr);
            for (; len; --len)
            {
                hash ^= static_cast<size_t>(*cptr++);
                hash *= static_cast<size_t>(16777619UL);
            }
            return hash;
        }
#endif

    }
}
