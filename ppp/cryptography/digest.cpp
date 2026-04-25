#include <stdio.h>
#include <string.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file digest.cpp
 * @brief Implements MD5 and SHA digest conversion helpers.
 */

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include "EVP.h"
#include "digest.h"

namespace ppp {
    namespace cryptography {
        /**
         * @brief Function pointer type for SHA-family one-shot digest routines.
         */
        typedef unsigned char* (*SHA_PROC)(const unsigned char*, size_t, unsigned char*);

        /**
         * @brief Lookup table mapping SHA enum values to OpenSSL SHA routines.
         */
        static SHA_PROC sha_proc_table[] = {
            SHA1,
            SHA224,
            SHA256,
            SHA384,
            SHA512,
        };

        /**
         * @brief Digest-length lookup table corresponding to `sha_proc_table`.
         */
        static size_t sha_len_table[] = {
            SHA_DIGEST_LENGTH,
            SHA224_DIGEST_LENGTH,
            SHA256_DIGEST_LENGTH,
            SHA384_DIGEST_LENGTH,
            SHA512_DIGEST_LENGTH,
        };

        /**
         * @brief Convenience overload that returns hexadecimal digest output.
         * @param data Input bytes.
         * @param size Input size in bytes.
         * @param agorithm Target digest algorithm.
         * @param toupper True for uppercase hexadecimal output.
         * @return Digest string; empty when computation fails.
         */
        ppp::string hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool toupper) noexcept {
            return hash_hmac(data, size, agorithm, true, toupper);
        }

        /**
         * @brief Convenience overload that returns digest output as a string.
         * @param data Input bytes.
         * @param size Input size in bytes.
         * @param agorithm Target digest algorithm.
         * @param hex_or_binarys True for hexadecimal, false for raw binary bytes.
         * @param toupper True for uppercase hexadecimal output when enabled.
         * @return Digest string; empty when computation fails.
         */
        ppp::string hash_hmac(const void* data, int size, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept {
            ppp::string digest;
            hash_hmac(data, size, digest, agorithm, hex_or_binarys, toupper);
            return digest;
        }

        /**
         * @brief Computes digest output for MD5 or SHA-family algorithms.
         * @param data Input bytes. Null input is treated as an empty buffer.
         * @param size Input size in bytes.
         * @param digest Receives digest output in requested format.
         * @param agorithm Target digest algorithm.
         * @param hex_or_binarys True for hexadecimal, false for raw binary bytes.
         * @param toupper True for uppercase hexadecimal output when enabled.
         * @return True on success; otherwise false.
         */
        bool hash_hmac(const void* data, int size, ppp::string& digest, DigestAlgorithmic agorithm, bool hex_or_binarys, bool toupper) noexcept {
            if (NULLPTR == data || size < 1) {
                data = "";
                size = 0;
            }

            if (agorithm == DigestAlgorithmic_md5) {
                if (hex_or_binarys) {
                    digest = ComputeMD5(ppp::string((char*)data, size), toupper);
                }
                else {
                    Byte md5[16];
                    int md5len;
                    if (!ComputeMD5(ppp::string((char*)data, size), md5, md5len)) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
                        return false;
                    }
                    else {
                        digest = ppp::string((char*)md5, md5len);
                    }
                }
                return true;
            }

            if (agorithm < DigestAlgorithmic_sha1 || agorithm > DigestAlgorithmic_sha512) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidArgument);
                return false;
            }

            int sha_agorithm = ((int)agorithm) - 1;
            unsigned char digest_sz[SHA512_DIGEST_LENGTH];

            size_t digest_sz_len = sha_len_table[sha_agorithm];

            SHA_PROC sha_proc = sha_proc_table[sha_agorithm];
            sha_proc((unsigned char*)data, size, digest_sz);

            if (!hex_or_binarys) {
                digest = ppp::string((char*)digest_sz, digest_sz_len);
            }
            else {
                /**
                 * @brief Converts binary digest bytes into two-character hex pairs.
                 */
                char hex_sz[SHA512_DIGEST_LENGTH * 2];
                const char* hex_fmt = toupper ? "%02X" : "%02x";
                for (size_t i = 0; i < digest_sz_len; i++) {
                    int ch = digest_sz[i];
                    sprintf(hex_sz + (i * 2), hex_fmt, ch);
                }

                digest = ppp::string(hex_sz, digest_sz_len * 2);
            }
            return true;
        }
    }
}
