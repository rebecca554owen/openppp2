#define BOOST_TEST_MODULE record_protector_install_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/cryptography/AuthenticatedRecordProtector.h>
#include <ppp/cryptography/RecordKeyDerivation.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using ppp::cryptography::AuthenticatedRecordProtector;
using ppp::cryptography::DeriveRecordKeyMaterial;
using ppp::cryptography::RecordDirection;
using ppp::cryptography::RecordKeyContext;
using ppp::cryptography::RecordKeyMaterial;

std::array<std::uint8_t, 32> FixedIkm(std::uint8_t start) noexcept {
    std::array<std::uint8_t, 32> ikm{};
    for (std::size_t i = 0; i < ikm.size(); ++i) {
        ikm[i] = static_cast<std::uint8_t>(start + i);
    }
    return ikm;
}

RecordKeyMaterial Derive(const std::array<std::uint8_t, 32>& ikm,
    std::uint8_t carrier_kind = 0) {
    RecordKeyContext context;
    context.exporter_secret = ikm.data();
    context.exporter_secret_len = ikm.size();
    context.carrier_kind = carrier_kind;
    RecordKeyMaterial material;
    BOOST_REQUIRE(DeriveRecordKeyMaterial(context, material));
    return material;
}

std::vector<std::uint8_t> Plaintext(std::size_t size, std::uint8_t start = 0x11) {
    std::vector<std::uint8_t> data(size);
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<std::uint8_t>(start + i);
    }
    return data;
}

template <std::size_t N>
bool BytesEqual(const std::array<std::uint8_t, N>& lhs,
    const std::array<std::uint8_t, N>& rhs) noexcept {
    return std::memcmp(lhs.data(), rhs.data(), N) == 0;
}

constexpr std::size_t RecordOverhead =
    AuthenticatedRecordProtector::RecordHeaderLength +
    AuthenticatedRecordProtector::TagLength;

} // namespace

BOOST_AUTO_TEST_CASE(seal_open_roundtrip_restores_plaintext) {
    const RecordKeyMaterial material = Derive(FixedIkm(0x01));
    AuthenticatedRecordProtector protector(
        material.client_to_server_key,
        material.client_to_server_nonce_prefix,
        RecordDirection::ClientToServer,
        0);

    const std::vector<std::uint8_t> plaintext = Plaintext(100);
    std::vector<std::uint8_t> sealed(plaintext.size() + RecordOverhead);
    std::size_t sealed_len = 0;
    BOOST_REQUIRE(protector.Seal(plaintext.data(), plaintext.size(),
        sealed.data(), sealed_len));
    BOOST_TEST(sealed_len == plaintext.size() + RecordOverhead);

    std::vector<std::uint8_t> opened(sealed.size());
    std::size_t opened_len = 0;
    BOOST_REQUIRE(protector.Open(sealed.data(), sealed_len,
        opened.data(), opened_len));
    BOOST_TEST(opened_len == plaintext.size());
    BOOST_TEST(std::memcmp(opened.data(), plaintext.data(),
        plaintext.size()) == 0);

    // A second record (sequence 1) must roundtrip as well, validating the
    // big-endian sequence serialization used in header and nonce.
    BOOST_REQUIRE(protector.Seal(plaintext.data(), plaintext.size(),
        sealed.data(), sealed_len));
    opened_len = 0;
    BOOST_REQUIRE(protector.Open(sealed.data(), sealed_len,
        opened.data(), opened_len));
    BOOST_TEST(opened_len == plaintext.size());
    BOOST_TEST(std::memcmp(opened.data(), plaintext.data(),
        plaintext.size()) == 0);
}

BOOST_AUTO_TEST_CASE(tampered_or_truncated_records_are_rejected) {
    const RecordKeyMaterial material = Derive(FixedIkm(0x21));
    AuthenticatedRecordProtector protector(
        material.client_to_server_key,
        material.client_to_server_nonce_prefix,
        RecordDirection::ClientToServer,
        0);

    const std::vector<std::uint8_t> plaintext = Plaintext(64, 0x22);
    std::vector<std::uint8_t> sealed(plaintext.size() + RecordOverhead);
    std::size_t sealed_len = 0;
    BOOST_REQUIRE(protector.Seal(plaintext.data(), plaintext.size(),
        sealed.data(), sealed_len));

    std::vector<std::uint8_t> opened(sealed.size());
    std::size_t opened_len = 0;
    BOOST_REQUIRE(protector.Open(sealed.data(), sealed_len,
        opened.data(), opened_len));

    // Replaying the same record must be rejected: the receive sequence
    // advanced past the header sequence on the successful open.
    opened_len = 0;
    BOOST_TEST(!protector.Open(sealed.data(), sealed_len,
        opened.data(), opened_len));

    // A fresh record; flip one ciphertext byte: tag verification must fail.
    BOOST_REQUIRE(protector.Seal(plaintext.data(), plaintext.size(),
        sealed.data(), sealed_len));
    std::vector<std::uint8_t> tampered = sealed;
    tampered[AuthenticatedRecordProtector::RecordHeaderLength + 7] ^= 0x40;
    opened_len = 0;
    BOOST_TEST(!protector.Open(tampered.data(), sealed_len,
        opened.data(), opened_len));
    BOOST_TEST(opened_len == 0);

    // Flip one header byte (length field): rejected by length decoding.
    tampered = sealed;
    tampered[0] ^= 0x01;
    opened_len = 0;
    BOOST_TEST(!protector.Open(tampered.data(), sealed_len,
        opened.data(), opened_len));

    // Truncated record: rejected by the length check.
    opened_len = 0;
    BOOST_TEST(!protector.Open(sealed.data(), sealed_len - 1,
        opened.data(), opened_len));
}

BOOST_AUTO_TEST_CASE(hkdf_derivation_is_deterministic_and_directional) {
    const std::array<std::uint8_t, 32> ikm = FixedIkm(0x31);
    const RecordKeyMaterial first = Derive(ikm);
    const RecordKeyMaterial second = Derive(ikm);

    // Same inputs produce identical material (HKDF determinism).
    BOOST_TEST(BytesEqual(first.client_to_server_key, second.client_to_server_key));
    BOOST_TEST(BytesEqual(first.client_to_server_nonce_prefix,
        second.client_to_server_nonce_prefix));
    BOOST_TEST(BytesEqual(first.server_to_client_key, second.server_to_client_key));
    BOOST_TEST(BytesEqual(first.server_to_client_nonce_prefix,
        second.server_to_client_nonce_prefix));

    // Each direction derives distinct key material.
    BOOST_TEST(!BytesEqual(first.client_to_server_key, first.server_to_client_key));
    BOOST_TEST(!BytesEqual(first.client_to_server_nonce_prefix,
        first.server_to_client_nonce_prefix));

    // Changing the IKM changes every derived value.
    const RecordKeyMaterial changed = Derive(FixedIkm(0x32));
    BOOST_TEST(!BytesEqual(first.client_to_server_key, changed.client_to_server_key));
    BOOST_TEST(!BytesEqual(first.server_to_client_key, changed.server_to_client_key));
}
