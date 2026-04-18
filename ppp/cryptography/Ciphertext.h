#pragma once

/**
 * @file Ciphertext.h
 * @brief Declares a unified encryption/decryption facade for supported cipher implementations.
 */

#include <ppp/cryptography/EVP.h>
#include <ppp/cryptography/rc4.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace cryptography {
        /**
         * @brief Dispatches encrypt/decrypt operations to an EVP or RC4 backend.
         */
        class Ciphertext : public std::enable_shared_from_this<Ciphertext> {
        public:
            /**
             * @brief Constructs a ciphertext wrapper for the specified algorithm and password.
             * @param method Cipher method name.
             * @param password Password used to derive internal key material.
             */
            Ciphertext(const ppp::string& method, const ppp::string& password) noexcept;
            virtual ~Ciphertext() noexcept = default;

        public:
            /**
             * @brief Encrypts input bytes using the active backend.
             * @param allocator Byte buffer allocator used for output allocation.
             * @param data Input plaintext bytes.
             * @param datalen Number of input bytes.
             * @param outlen Receives output byte length, or a negative value on failure.
             * @return Shared output buffer on success, or null on failure.
             */
            virtual std::shared_ptr<Byte>                       Encrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;
            /**
             * @brief Decrypts input bytes using the active backend.
             * @param allocator Byte buffer allocator used for output allocation.
             * @param data Input ciphertext bytes.
             * @param datalen Number of input bytes.
             * @param outlen Receives output byte length, or a negative value on failure.
             * @return Shared output buffer on success, or null on failure.
             */
            virtual std::shared_ptr<Byte>                       Decrypt(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, Byte* data, int datalen, int& outlen) noexcept;

        public:
            /**
             * @brief Returns a shared reference to this instance.
             * @return Shared pointer bound to this object.
             */
            std::shared_ptr<Ciphertext>                         GetReference() noexcept { return this->shared_from_this(); }
            /**
             * @brief Checks whether a cipher method is supported by any backend.
             * @param method Cipher method name.
             * @return True if supported; otherwise false.
             */
            static bool                                         Support(const ppp::string& method) noexcept;

        private:
            std::shared_ptr<RC4>                                rc4_;
            std::shared_ptr<EVP>                                evp_;
        };
    }
}
