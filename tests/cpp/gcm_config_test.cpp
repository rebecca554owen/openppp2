// gcm_config_test.cpp
//
// Regression coverage for KNOWN_ISSUES defect 1 (GCM configuration-name
// promotion trap):
//
//   1. A plain GCM (AEAD) algorithm name such as "aes-256-gcm" must never be
//      transparently promoted to "simd-aes-256-gcm" by the simd-auto logic:
//      the SIMD GCM variant is unauthenticated (CTR without tag), while the
//      plain GCM name selects the real OpenSSL AEAD path with authentication
//      tags.
//
//   2. An AppConfiguration JSON that explicitly names "aes-256-gcm" in
//      key.protocol / key.transport must load successfully (never rejected or
//      silently replaced by the default) and preserve the GCM names, which
//      also exercises the explicit-GCM telemetry warning emitted during load.
//
// CMake registration: reuse the exact source list of
// transport_auth_configuration_test in tests/cpp/CMakeLists.txt (it links
// AppConfiguration.cpp, EVP.cpp, Ciphertext.cpp and the AES-NI/OpenSSL/Boost
// dependency chain); this test adds no new link requirements on top of it.

#define BOOST_TEST_MODULE gcm_config_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/cryptography/EVP.h>

#include <json/json.h>

#include <string>

using ppp::configurations::AppConfiguration;
using ppp::cryptography::EVP;

BOOST_AUTO_TEST_CASE(gcm_method_name_is_not_promoted_to_simd) {
    EVP::SetSimdAuto(true);

    /* With simd-auto enabled, a plain GCM name must stay on the real OpenSSL
     * AEAD path.  If the promotion logic regresses and rewrites "aes-256-gcm"
     * into "simd-aes-256-gcm", the unauthenticated SIMD GCM variant is
     * attached and IsHardwareAccelerated() reports true on AES-NI capable
     * machines (Linux CI), failing this test. */
    EVP gcm_evp("aes-256-gcm", "0123456789abcdef0123456789abcdef");
    BOOST_TEST(!gcm_evp.IsHardwareAccelerated());
}

BOOST_AUTO_TEST_CASE(explicit_gcm_config_is_accepted_and_preserved) {
    AppConfiguration defaults;
    Json::Value json = defaults.ToJson();
    json["key"]["protocol"] = "aes-256-gcm";
    json["key"]["transport"] = "aes-256-gcm";

    AppConfiguration loaded;
    BOOST_REQUIRE(loaded.Load(json));

    /* The GCM names must survive loading unchanged: they are supported cipher
     * names (never rejected or replaced by the default), and the load path
     * emits the explicit-GCM telemetry warning for them. */
    BOOST_TEST(loaded.key.protocol == "aes-256-gcm");
    BOOST_TEST(loaded.key.transport == "aes-256-gcm");
}

BOOST_AUTO_TEST_CASE(legacy_cfb_names_remain_accepted) {
    AppConfiguration defaults;
    Json::Value json = defaults.ToJson();
    json["key"]["protocol"] = "aes-256-cfb";
    json["key"]["transport"] = "aes-256-cfb";

    AppConfiguration loaded;
    BOOST_REQUIRE(loaded.Load(json));
    BOOST_TEST(loaded.key.protocol == "aes-256-cfb");
    BOOST_TEST(loaded.key.transport == "aes-256-cfb");
}
