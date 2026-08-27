#define BOOST_TEST_MODULE noise_psk_exporter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/cryptography/RecordKeyDerivation.h>
#include <ppp/cryptography/noise/NoisePsk.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace noise = ppp::cryptography::noise;

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> Filled(std::uint8_t start) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) {
        value[i] = static_cast<std::uint8_t>(start + i);
    }
    return value;
}

noise::Secret32 Secret(std::uint8_t start) {
    return noise::Secret32(Filled<32>(start));
}

std::vector<std::uint8_t> BindingContext(noise::BindingPurpose purpose,
    std::uint8_t start = 0x70) {
    const std::size_t size = purpose == noise::BindingPurpose::P2PWrapV1
        ? 113u
        : 16u;
    std::vector<std::uint8_t> context(size);
    for (std::size_t i = 0; i < size; ++i) {
        context[i] = static_cast<std::uint8_t>(start + i);
    }
    return context;
}

bool Derive(noise::NoisePskHandshakeResult& result,
    noise::BindingPurpose purpose, noise::Secret32& output,
    std::uint8_t context_start = 0x70) {
    const auto context = BindingContext(purpose, context_start);
    return result.DeriveBinding(purpose, context.data(), context.size(), output);
}

std::vector<std::uint8_t> Prologue(
    std::uint8_t session_start = 0x10,
    const std::string& key_id = "primary-2026") {
    std::vector<std::uint8_t> output;
    const auto session_id = Filled<noise::NoiseSessionIdSize>(session_start);
    BOOST_REQUIRE(noise::BuildCanonicalPrologue(noise::Carrier::Tcp, session_id,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(), output));
    return output;
}

std::string Hex(const std::uint8_t* data, std::size_t size) {
    std::ostringstream stream;
    stream << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i) {
        stream << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return stream.str();
}

template <std::size_t N>
std::string Hex(const std::array<std::uint8_t, N>& value) {
    return Hex(value.data(), value.size());
}

struct Results {
    noise::NoisePskHandshakeResult client;
    noise::NoisePskHandshakeResult server;
};

Results Complete(const std::vector<std::uint8_t>& prologue = Prologue(),
    const std::string& key_id = "primary-2026") {
    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    noise::NoisePskHandshake server(
        noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x20)));
    BOOST_REQUIRE(server.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x40)));
    std::vector<std::uint8_t> message1;
    std::vector<std::uint8_t> message2;
    BOOST_REQUIRE(client.WriteMessage1(message1));
    BOOST_REQUIRE(server.ReadMessage1(message1.data(), message1.size()));
    BOOST_REQUIRE(server.WriteMessage2(message2));
    BOOST_REQUIRE(client.ReadMessage2(message2.data(), message2.size()));
    Results results;
    const std::uint8_t* key_id_bytes =
        reinterpret_cast<const std::uint8_t*>(key_id.data());
    BOOST_REQUIRE(client.TakeResult(results.client, key_id_bytes, key_id.size()));
    BOOST_REQUIRE(server.TakeResult(results.server, key_id_bytes, key_id.size()));
    return results;
}

}

BOOST_AUTO_TEST_CASE(split3_exporter_hash_proof_and_bindings_match_fixed_vectors) {
    auto results = Complete();
    noise::Bytes32 hash{};
    noise::ClientSuccessProof proof{};
    noise::Secret32 retained;
    noise::Secret32 candidate;
    noise::Secret32 p2p;
    BOOST_REQUIRE(results.client.GetHandshakeHash(hash));
    BOOST_REQUIRE(results.client.GenerateClientSuccessConfirmationProof(proof));
    BOOST_REQUIRE(Derive(results.client,
        noise::BindingPurpose::SessionResumeRetainedRootV1, retained));
    BOOST_REQUIRE(Derive(results.client,
        noise::BindingPurpose::SessionResumeCandidateV1, candidate));
    BOOST_REQUIRE(Derive(results.client, noise::BindingPurpose::P2PWrapV1, p2p));
    noise::Secret32 exporter;
    BOOST_REQUIRE(results.client.TakeExporterSecret(exporter));

    const std::string expected_hash =
        "c6c5d79071525f846bc773eb9a4192badb53b5fc53333effc85beed0cb1a7a5b";
    const std::string expected_proof =
        "8ca41e4fba30aacc35d363d255fa614836c8fbf5173e52b61903fa2ad89c241b";
    const std::string expected_retained =
        "054c33c788255b069e99b8564710b3b2a2fe46fcc09aa8dcecb801a0a76b13b4";
    const std::string expected_candidate =
        "fe365e653bf917ac4a40309fb99de9fed82119c7811e0eb986aafeaefb313c69";
    const std::string expected_p2p =
        "5628a916c9294f550a6ee7869795a9b7cc0d3370f6b2075583f9612d8c48cf1d";
    const std::string expected_exporter =
        "85af00ab9b2f805c1857fa2505c4247ca46e8ae6025638389df3cf7b074a4f07";
    BOOST_TEST(Hex(hash) == expected_hash);
    BOOST_TEST(Hex(proof) == expected_proof);
    BOOST_TEST(Hex(retained.data(), retained.size()) == expected_retained);
    BOOST_TEST(Hex(candidate.data(), candidate.size()) == expected_candidate);
    BOOST_TEST(Hex(p2p.data(), p2p.size()) == expected_p2p);
    BOOST_TEST(Hex(exporter.data(), exporter.size()) == expected_exporter);
}

BOOST_AUTO_TEST_CASE(client_and_server_agree_on_proof_exporter_and_each_binding) {
    auto results = Complete();
    noise::ClientSuccessProof client_proof{};
    noise::ClientSuccessProof server_proof{};
    BOOST_REQUIRE(results.client.GenerateClientSuccessConfirmationProof(client_proof));
    BOOST_REQUIRE(results.server.GenerateClientSuccessConfirmationProof(server_proof));
    BOOST_TEST(client_proof == server_proof);
    BOOST_TEST(results.server.VerifyClientSuccessConfirmationProof(client_proof));

    const std::array<noise::BindingPurpose, 3> purposes = {{
        noise::BindingPurpose::SessionResumeRetainedRootV1,
        noise::BindingPurpose::SessionResumeCandidateV1,
        noise::BindingPurpose::P2PWrapV1,
    }};
    for (const auto purpose : purposes) {
        noise::Secret32 client_binding;
        noise::Secret32 server_binding;
        BOOST_REQUIRE(Derive(results.client, purpose, client_binding));
        BOOST_REQUIRE(Derive(results.server, purpose, server_binding));
        BOOST_TEST(Hex(client_binding.data(), client_binding.size()) ==
            Hex(server_binding.data(), server_binding.size()));
    }

    noise::Secret32 client_exporter;
    noise::Secret32 server_exporter;
    BOOST_REQUIRE(results.client.TakeExporterSecret(client_exporter));
    BOOST_REQUIRE(results.server.TakeExporterSecret(server_exporter));
    BOOST_TEST(Hex(client_exporter.data(), client_exporter.size()) ==
        Hex(server_exporter.data(), server_exporter.size()));
}

BOOST_AUTO_TEST_CASE(proof_verification_is_transcript_bound_and_rejects_tamper) {
    auto baseline = Complete();
    noise::ClientSuccessProof proof{};
    BOOST_REQUIRE(baseline.client.GenerateClientSuccessConfirmationProof(proof));
    BOOST_TEST(baseline.server.VerifyClientSuccessConfirmationProof(proof));

    auto tampered = proof;
    tampered[0] ^= 1;
    BOOST_TEST(!baseline.server.VerifyClientSuccessConfirmationProof(tampered));
    tampered = proof;
    tampered.back() ^= 1;
    BOOST_TEST(!baseline.server.VerifyClientSuccessConfirmationProof(tampered));

    auto changed_session = Complete(Prologue(0x11));
    BOOST_TEST(!changed_session.server.VerifyClientSuccessConfirmationProof(proof));
    auto changed_key_id = Complete(Prologue(0x10, "secondary-2026"), "secondary-2026");
    BOOST_TEST(!changed_key_id.server.VerifyClientSuccessConfirmationProof(proof));
}

BOOST_AUTO_TEST_CASE(context_and_typed_purposes_are_strictly_bound) {
    auto results = Complete();
    noise::Secret32 retained;
    noise::Secret32 changed_retained;
    noise::Secret32 candidate;
    noise::Secret32 p2p;
    BOOST_REQUIRE(Derive(results.client,
        noise::BindingPurpose::SessionResumeRetainedRootV1, retained));
    BOOST_REQUIRE(Derive(results.client,
        noise::BindingPurpose::SessionResumeRetainedRootV1, changed_retained, 0x71));
    BOOST_REQUIRE(Derive(results.client,
        noise::BindingPurpose::SessionResumeCandidateV1, candidate));
    BOOST_REQUIRE(Derive(results.client, noise::BindingPurpose::P2PWrapV1, p2p));
    BOOST_TEST(Hex(retained.data(), retained.size()) !=
        Hex(changed_retained.data(), changed_retained.size()));
    BOOST_TEST(Hex(retained.data(), retained.size()) != Hex(candidate.data(), candidate.size()));
    BOOST_TEST(Hex(retained.data(), retained.size()) != Hex(p2p.data(), p2p.size()));
    BOOST_TEST(Hex(candidate.data(), candidate.size()) != Hex(p2p.data(), p2p.size()));

    const auto resume_context = BindingContext(
        noise::BindingPurpose::SessionResumeRetainedRootV1);
    const auto p2p_context = BindingContext(noise::BindingPurpose::P2PWrapV1);
    for (const std::size_t invalid_size : {0u, 15u, 17u}) {
        noise::Secret32 invalid;
        BOOST_TEST(!results.client.DeriveBinding(
            noise::BindingPurpose::SessionResumeRetainedRootV1,
            resume_context.data(), invalid_size, invalid));
        BOOST_TEST(!invalid.IsSet());
    }
    for (const std::size_t invalid_size : {112u, 114u}) {
        noise::Secret32 invalid;
        BOOST_TEST(!results.client.DeriveBinding(noise::BindingPurpose::P2PWrapV1,
            p2p_context.data(), invalid_size, invalid));
        BOOST_TEST(!invalid.IsSet());
    }
    noise::Secret32 null_context;
    BOOST_TEST(!results.client.DeriveBinding(
        noise::BindingPurpose::SessionResumeRetainedRootV1,
        nullptr, resume_context.size(), null_context));

    noise::Secret32 unknown;
    BOOST_TEST(!results.client.DeriveBinding(
        static_cast<noise::BindingPurpose>(0), resume_context.data(),
        resume_context.size(), unknown));
    BOOST_TEST(!unknown.IsSet());
    BOOST_TEST(!results.client.DeriveBinding(
        static_cast<noise::BindingPurpose>(255), resume_context.data(),
        resume_context.size(), unknown));
    BOOST_TEST(!unknown.IsSet());
}

BOOST_AUTO_TEST_CASE(binding_changes_with_transcript_inputs_even_when_deterministic_keys_repeat) {
    auto baseline = Complete();
    auto changed_session = Complete(Prologue(0x11));
    auto changed_key_id = Complete(Prologue(0x10, "secondary-2026"), "secondary-2026");
    noise::Secret32 baseline_binding;
    noise::Secret32 session_binding;
    noise::Secret32 key_id_binding;
    BOOST_REQUIRE(Derive(baseline.client, noise::BindingPurpose::P2PWrapV1,
        baseline_binding));
    BOOST_REQUIRE(Derive(changed_session.client, noise::BindingPurpose::P2PWrapV1,
        session_binding));
    BOOST_REQUIRE(Derive(changed_key_id.client, noise::BindingPurpose::P2PWrapV1,
        key_id_binding));
    BOOST_TEST(Hex(baseline_binding.data(), baseline_binding.size()) !=
        Hex(session_binding.data(), session_binding.size()));
    BOOST_TEST(Hex(baseline_binding.data(), baseline_binding.size()) !=
        Hex(key_id_binding.data(), key_id_binding.size()));
}

BOOST_AUTO_TEST_CASE(exporter_is_single_owner_and_clear_disables_all_secret_operations) {
    auto results = Complete();
    noise::Secret32 occupied(Filled<32>(0xa0));
    BOOST_TEST(!Derive(results.client, noise::BindingPurpose::P2PWrapV1, occupied));
    BOOST_TEST(!results.client.TakeExporterSecret(occupied));

    noise::Secret32 exporter;
    BOOST_REQUIRE(results.client.TakeExporterSecret(exporter));
    BOOST_TEST(exporter.IsSet());
    BOOST_TEST(results.client.IsValid());
    noise::Bytes32 public_hash{};
    BOOST_TEST(results.client.GetHandshakeHash(public_hash));
    noise::ClientSuccessProof proof{};
    BOOST_TEST(!results.client.GenerateClientSuccessConfirmationProof(proof));
    BOOST_TEST(!results.client.VerifyClientSuccessConfirmationProof(proof));
    noise::Secret32 binding;
    BOOST_TEST(!Derive(results.client, noise::BindingPurpose::P2PWrapV1, binding));
    BOOST_TEST(!results.client.TakeExporterSecret(binding));

    exporter.Clear();
    BOOST_TEST(!exporter.IsSet());
    results.server.Clear();
    BOOST_TEST(!results.server.IsValid());
    BOOST_TEST(!results.server.GenerateClientSuccessConfirmationProof(proof));
}

BOOST_AUTO_TEST_CASE(record_protector_context_is_explicit_variable_length_and_key_id_bound) {
    auto results = Complete();

    // The negotiated canonical key id must be stored on the result and
    // retrievable by both peers.
    for (const auto* result : { &results.client, &results.server }) {
        const std::uint8_t* key_id = nullptr;
        std::size_t key_id_length = 0;
        BOOST_REQUIRE(result->GetTransportAuthKeyId(key_id, key_id_length));
        BOOST_TEST(key_id_length == std::strlen("primary-2026"));
        BOOST_TEST(std::memcmp(key_id, "primary-2026", key_id_length) == 0);
    }

    // Build the canonical RecordProtector context from explicit fields.
    const auto ivv = Filled<noise::NoiseSessionIdSize>(0x60);
    const std::string key_id = "primary-2026";
    std::vector<std::uint8_t> context;
    BOOST_REQUIRE(noise::BuildRecordProtectorBindingContext(
        ivv.data(), ivv.size(), 0,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(),
        context));
    BOOST_TEST(context.size() ==
        noise::RecordProtectorBindingContextFixedLength + key_id.size());
    BOOST_TEST(context[0] == noise::RecordProtectorBindingContextVersion);
    BOOST_TEST(context[17] == 0);                       // carrier kind
    BOOST_TEST(context[18] == key_id.size());           // key id length
    BOOST_TEST(std::memcmp(context.data() + 19, key_id.data(), key_id.size()) == 0);

    // Both peers derive the identical record root (peer-symmetric context).
    noise::Secret32 client_binding;
    noise::Secret32 server_binding;
    BOOST_REQUIRE(results.client.DeriveBinding(noise::BindingPurpose::RecordProtector,
        context.data(), context.size(), client_binding));
    BOOST_REQUIRE(results.server.DeriveBinding(noise::BindingPurpose::RecordProtector,
        context.data(), context.size(), server_binding));
    BOOST_TEST(Hex(client_binding.data(), client_binding.size()) ==
        Hex(server_binding.data(), server_binding.size()));

    // A different canonical key id changes the derived root.
    const std::string other_key_id = "secondary-2026";
    std::vector<std::uint8_t> other_context;
    BOOST_REQUIRE(noise::BuildRecordProtectorBindingContext(
        ivv.data(), ivv.size(), 0,
        reinterpret_cast<const std::uint8_t*>(other_key_id.data()),
        other_key_id.size(), other_context));
    noise::Secret32 other_binding;
    BOOST_REQUIRE(results.client.DeriveBinding(noise::BindingPurpose::RecordProtector,
        other_context.data(), other_context.size(), other_binding));
    BOOST_TEST(Hex(client_binding.data(), client_binding.size()) !=
        Hex(other_binding.data(), other_binding.size()));

    // A different carrier kind changes the derived root.
    std::vector<std::uint8_t> ws_context;
    BOOST_REQUIRE(noise::BuildRecordProtectorBindingContext(
        ivv.data(), ivv.size(), 1,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(),
        ws_context));
    noise::Secret32 ws_binding;
    BOOST_REQUIRE(results.client.DeriveBinding(noise::BindingPurpose::RecordProtector,
        ws_context.data(), ws_context.size(), ws_binding));
    BOOST_TEST(Hex(client_binding.data(), client_binding.size()) !=
        Hex(ws_binding.data(), ws_binding.size()));

    // End-to-end key separation: the record root is the sole HKDF input, so
    // the binding-context separation proven above on the root propagates to
    // the per-direction record keys (different binding context -> different
    // record root -> different record keys).  The HKDF API itself never sees
    // the key id, ivv or carrier.
    ppp::cryptography::RecordKeyMaterial primary_keys;
    ppp::cryptography::RecordKeyMaterial other_keys;
    ppp::cryptography::RecordKeyMaterial ws_keys;
    BOOST_REQUIRE(ppp::cryptography::DeriveRecordKeyMaterial(
        client_binding.data(), client_binding.size(), primary_keys));
    BOOST_REQUIRE(ppp::cryptography::DeriveRecordKeyMaterial(
        other_binding.data(), other_binding.size(), other_keys));
    BOOST_REQUIRE(ppp::cryptography::DeriveRecordKeyMaterial(
        ws_binding.data(), ws_binding.size(), ws_keys));
    BOOST_TEST(std::memcmp(primary_keys.client_to_server_key.data(),
        other_keys.client_to_server_key.data(),
        primary_keys.client_to_server_key.size()) != 0);
    BOOST_TEST(std::memcmp(primary_keys.server_to_client_key.data(),
        other_keys.server_to_client_key.data(),
        primary_keys.server_to_client_key.size()) != 0);
    BOOST_TEST(std::memcmp(primary_keys.client_to_server_key.data(),
        ws_keys.client_to_server_key.data(),
        primary_keys.client_to_server_key.size()) != 0);
    // Direction separation at the HKDF layer itself.
    BOOST_TEST(std::memcmp(primary_keys.client_to_server_key.data(),
        primary_keys.server_to_client_key.data(),
        primary_keys.client_to_server_key.size()) != 0);

    // Peers that shared the same binding context share the same record keys.
    ppp::cryptography::RecordKeyMaterial server_keys;
    BOOST_REQUIRE(ppp::cryptography::DeriveRecordKeyMaterial(
        server_binding.data(), server_binding.size(), server_keys));
    BOOST_TEST(std::memcmp(primary_keys.client_to_server_key.data(),
        server_keys.client_to_server_key.data(),
        primary_keys.client_to_server_key.size()) == 0);
    BOOST_TEST(std::memcmp(primary_keys.server_to_client_key.data(),
        server_keys.server_to_client_key.data(),
        primary_keys.server_to_client_key.size()) == 0);
}

BOOST_AUTO_TEST_CASE(record_protector_context_strictly_rejects_malformed_layout) {
    auto results = Complete();
    const auto ivv = Filled<noise::NoiseSessionIdSize>(0x60);
    const std::string key_id = "primary-2026";
    std::vector<std::uint8_t> context;
    BOOST_REQUIRE(noise::BuildRecordProtectorBindingContext(
        ivv.data(), ivv.size(), 0,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(),
        context));

    auto derive_expect_fail = [&](const std::uint8_t* data, std::size_t size) {
        noise::Secret32 invalid;
        BOOST_TEST(!results.client.DeriveBinding(
            noise::BindingPurpose::RecordProtector, data, size, invalid));
        BOOST_TEST(!invalid.IsSet());
    };

    // Null context and truncated prefix.
    derive_expect_fail(nullptr, context.size());
    derive_expect_fail(context.data(), noise::RecordProtectorBindingContextFixedLength - 1);

    // Wrong version byte.
    std::vector<std::uint8_t> bad_version = context;
    bad_version[0] = 0;
    derive_expect_fail(bad_version.data(), bad_version.size());
    bad_version[0] = 2;
    derive_expect_fail(bad_version.data(), bad_version.size());

    // Illegal carrier kind (role-like byte must not be smuggled in).
    std::vector<std::uint8_t> bad_carrier = context;
    bad_carrier[17] = 2;
    derive_expect_fail(bad_carrier.data(), bad_carrier.size());

    // Zero key id length.
    std::vector<std::uint8_t> zero_length = context;
    zero_length[18] = 0;
    derive_expect_fail(zero_length.data(), zero_length.size());

    // Total length not matching the declared key id length.
    derive_expect_fail(context.data(), context.size() - 1);
    derive_expect_fail(context.data(), context.size() + 1);

    // Non-canonical key id bytes (uppercase inside the key id field).
    std::vector<std::uint8_t> bad_key_id = context;
    bad_key_id[19] = 'P';
    derive_expect_fail(bad_key_id.data(), bad_key_id.size());

    // Oversized key id (64 bytes) is rejected by the builder.
    std::array<std::uint8_t, noise::RecordProtectorBindingMaximumKeyIdLength + 1> oversized{};
    for (std::size_t i = 0; i < oversized.size(); ++i) {
        oversized[i] = static_cast<std::uint8_t>('a' + (i % 26));
    }
    std::vector<std::uint8_t> rejected;
    BOOST_TEST(!noise::BuildRecordProtectorBindingContext(ivv.data(), ivv.size(), 0,
        oversized.data(), oversized.size(), rejected));
    BOOST_TEST(rejected.empty());

    // Null / wrong-size ivv is rejected by the builder.
    BOOST_TEST(!noise::BuildRecordProtectorBindingContext(nullptr, 0, 0,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(), rejected));
    BOOST_TEST(!noise::BuildRecordProtectorBindingContext(ivv.data(), 15, 0,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(), rejected));
    BOOST_TEST(rejected.empty());
}

BOOST_AUTO_TEST_CASE(take_result_roundtrips_and_rejects_illegal_key_ids) {
    const auto prologue = Prologue();
    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    noise::NoisePskHandshake server(
        noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x20)));
    BOOST_REQUIRE(server.SetDeterministicEphemeralPrivateKeyForTesting(Secret(0x40)));
    std::vector<std::uint8_t> message1;
    std::vector<std::uint8_t> message2;
    BOOST_REQUIRE(client.WriteMessage1(message1));
    BOOST_REQUIRE(server.ReadMessage1(message1.data(), message1.size()));
    BOOST_REQUIRE(server.WriteMessage2(message2));
    BOOST_REQUIRE(client.ReadMessage2(message2.data(), message2.size()));

    // Illegal key ids (empty-with-nonzero-length, non-canonical, oversized)
    // are rejected before storage and the handshake is not consumed.
    const std::uint8_t one_byte = 'a';
    noise::NoisePskHandshakeResult illegal;
    BOOST_TEST(!client.TakeResult(illegal, nullptr, 1));
    BOOST_TEST(!client.TakeResult(illegal, &one_byte, 0));
    const char* uppercase = "Primary2026";
    BOOST_TEST(!client.TakeResult(illegal,
        reinterpret_cast<const std::uint8_t*>(uppercase), std::strlen(uppercase)));
    std::array<std::uint8_t, noise::RecordProtectorBindingMaximumKeyIdLength + 1> oversized{};
    for (std::size_t i = 0; i < oversized.size(); ++i) {
        oversized[i] = static_cast<std::uint8_t>('a' + (i % 26));
    }
    BOOST_TEST(!client.TakeResult(illegal, oversized.data(), oversized.size()));

    // Without a key id, the result stays valid but carries none.
    noise::NoisePskHandshakeResult no_key_id;
    BOOST_REQUIRE(client.TakeResult(no_key_id));
    const std::uint8_t* key_id = nullptr;
    std::size_t key_id_length = 1;
    BOOST_TEST(!no_key_id.GetTransportAuthKeyId(key_id, key_id_length));
    BOOST_TEST(key_id == nullptr);
    BOOST_TEST(key_id_length == 0);

    // The canonical key id is stored, retrieved, then cleansed by Clear().
    const std::string canonical = "primary-2026";
    noise::NoisePskHandshakeResult stored;
    BOOST_REQUIRE(server.TakeResult(stored,
        reinterpret_cast<const std::uint8_t*>(canonical.data()), canonical.size()));
    BOOST_REQUIRE(stored.GetTransportAuthKeyId(key_id, key_id_length));
    BOOST_TEST(key_id_length == canonical.size());
    BOOST_TEST(std::memcmp(key_id, canonical.data(), canonical.size()) == 0);
    stored.Clear();
    BOOST_TEST(!stored.IsValid());
    BOOST_TEST(!stored.GetTransportAuthKeyId(key_id, key_id_length));
    BOOST_TEST(key_id == nullptr);
    BOOST_TEST(key_id_length == 0);
}
