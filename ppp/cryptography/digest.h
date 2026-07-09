#pragma once

/**
 * @file digest.h
 * @brief Declares digest utility APIs for MD5 and SHA-family hashing.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace cryptography {
        /**
         * @brief Enumerates supported digest algorithms.
         */
        enum DigestAlgorithmic {
            DigestAlgorithmic_md5,
            DigestAlgorithmic_sha1,
            DigestAlgorithmic_sha224,
            DigestAlgorithmic_sha256,
            DigestAlgorithmic_sha384,
            DigestAlgorithmic_sha512,
        };

        /**
         * @brief Computes a digest string using hexadecimal output by default.
         * @param data Input bytes.
         * @param size Input size in bytes.
         * @param agorithm Target digest algorithm.
         * @param toupper True for uppercase hexadecimal output.
         * @return Digest string; empty when computation fails.
         */
        ppp::string     hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool toupper) noexcept;
        /**
         * @brief Computes a digest string in hexadecimal or raw binary form.
         * @param data Input bytes.
         * @param size Input size in bytes.
         * @param agorithm Target digest algorithm.
         * @param hex_or_binarys True for hexadecimal, false for raw binary bytes.
         * @param toupper True for uppercase hexadecimal output when enabled.
         * @return Digest string; empty when computation fails.
         */
        ppp::string     hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept;
        /**
         * @brief Computes a digest and writes it to an output string.
         * @param data Input bytes.
         * @param size Input size in bytes.
         * @param digest Receives digest output in hexadecimal or binary form.
         * @param agorithm Target digest algorithm.
         * @param hex_or_binarys True for hexadecimal, false for raw binary bytes.
         * @param toupper True for uppercase hexadecimal output when enabled.
         * @return True on success; otherwise false.
         */
        bool            hash_hmac(const void* data, int size, ppp::string& digest, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept;
    }
}
