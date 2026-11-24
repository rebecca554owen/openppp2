// explicit_aead_cipher_test.cpp -- an explicit AEAD cipher has to be
// recognisable, so the configuration can be reported.
//
// Background:
//   The legacy data path is equal-length: EVP::Encrypt stops at
//   EVP_CipherUpdate and never calls EVP_CipherFinal, so the AEAD tag is
//   never produced and the frame carries the ciphertext only. The cipher
//   therefore provides encryption without authentication, while keeping the
//   failure mode of an AEAD cipher. EVP::resetCipher rewinds the context to
//   the same derived IV before every packet, so a GCM nonce repeats per
//   packet under the same key, which leaks the GHASH subkey and permits
//   forgery.
//
//   A deployment that names such a cipher therefore has to be told, and the
//   decision starts with recognising the name. That is what this test pins.

#include <ppp/cryptography/EVP.h>

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main() {
    try {
        // 1) The AEAD families have to be recognised.
        Require(ppp::cryptography::EVP::IsAeadCipher("aes-256-gcm"), "aes-256-gcm is an AEAD cipher");
        Require(ppp::cryptography::EVP::IsAeadCipher("aes-128-gcm"), "aes-128-gcm is an AEAD cipher");
        Require(ppp::cryptography::EVP::IsAeadCipher("aes-256-ccm"), "aes-256-ccm is an AEAD cipher");
        Require(ppp::cryptography::EVP::IsAeadCipher("chacha20-poly1305"),
                "chacha20-poly1305 is an AEAD cipher");
        Require(ppp::cryptography::EVP::IsAeadCipher("ChaCha20-Poly1305"),
                "the name is matched case-insensitively");
        Require(ppp::cryptography::EVP::IsAeadCipher("AES-256-GCM"),
                "the name is matched case-insensitively");

        // 2) The ciphers of the legacy data path are not AEAD.
        Require(!ppp::cryptography::EVP::IsAeadCipher("aes-256-cfb"), "aes-256-cfb is not an AEAD cipher");
        Require(!ppp::cryptography::EVP::IsAeadCipher("aes-128-cfb"), "aes-128-cfb is not an AEAD cipher");
        Require(!ppp::cryptography::EVP::IsAeadCipher("simd-aes-256-cfb"), "simd-aes-256-cfb is not an AEAD cipher");
        Require(!ppp::cryptography::EVP::IsAeadCipher("rc4"), "rc4 is not an AEAD cipher");
        Require(!ppp::cryptography::EVP::IsAeadCipher("des-cbc"), "des-cbc is not an AEAD cipher");
        Require(!ppp::cryptography::EVP::IsAeadCipher(""), "an empty name is not an AEAD cipher");

        std::cout << "explicit_aead_cipher_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "explicit_aead_cipher_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
