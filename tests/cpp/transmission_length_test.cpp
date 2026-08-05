#define BOOST_TEST_MODULE transmission_length_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/cryptography/EVP.h>

#include <memory>
#include <string>

namespace pppc = ppp::cryptography;

namespace {

/** @brief Builds an EVP instance for the given cipher method name. */
std::shared_ptr<pppc::EVP> MakeEVP(const std::string& method) {
    return std::make_shared<pppc::EVP>(
        ppp::string(method.data(), method.size()), "test-password");
}

} // namespace

BOOST_AUTO_TEST_SUITE(evp_gcm_mode_detection)

BOOST_AUTO_TEST_CASE(gcm_cipher_is_detected_as_aead_mode) {
    // aes-256-gcm must resolve to the real OpenSSL AEAD path (never promoted
    // to the unauthenticated SIMD variant) and be reported as GCM mode.
    auto evp = MakeEVP("aes-256-gcm");
    BOOST_REQUIRE(evp != nullptr);
    BOOST_CHECK(evp->IsGcmMode());
}

BOOST_AUTO_TEST_CASE(cfb_cipher_is_not_gcm_mode) {
    auto evp = MakeEVP("aes-256-cfb");
    BOOST_REQUIRE(evp != nullptr);
    BOOST_CHECK(!evp->IsGcmMode());
}

BOOST_AUTO_TEST_CASE(simd_cfb_cipher_is_not_gcm_mode) {
    auto evp = MakeEVP("simd-aes-256-cfb");
    BOOST_REQUIRE(evp != nullptr);
    BOOST_CHECK(!evp->IsGcmMode());
}

BOOST_AUTO_TEST_SUITE_END()
