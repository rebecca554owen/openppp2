#define BOOST_TEST_MODULE record_protector_install_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/cryptography/AuthenticatedRecordProtector.h>
#include <ppp/cryptography/RecordKeyDerivation.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace {

using ppp::cryptography::AuthenticatedRecordProtector;
using ppp::cryptography::DeriveRecordKeyMaterial;
using ppp::cryptography::RecordDirection;
using ppp::cryptography::RecordKeyMaterial;

std::array<std::uint8_t, 32> FixedIkm(std::uint8_t start) noexcept {
    std::array<std::uint8_t, 32> ikm{};
    for (std::size_t i = 0; i < ikm.size(); ++i) {
        ikm[i] = static_cast<std::uint8_t>(start + i);
    }
    return ikm;
}

RecordKeyMaterial Derive(const std::array<std::uint8_t, 32>& ikm) {
    RecordKeyMaterial material;
    BOOST_REQUIRE(DeriveRecordKeyMaterial(ikm.data(), ikm.size(), material));
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
        0,
        "aes-256-gcm");

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
        0,
        "aes-256-gcm");

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
    const std::array<std::uint8_t, 32> root = FixedIkm(0x31);
    const RecordKeyMaterial first = Derive(root);
    const RecordKeyMaterial second = Derive(root);

    // Same record root produces identical material (HKDF determinism).
    BOOST_TEST(BytesEqual(first.client_to_server_key, second.client_to_server_key));
    BOOST_TEST(BytesEqual(first.client_to_server_nonce_prefix,
        second.client_to_server_nonce_prefix));
    BOOST_TEST(BytesEqual(first.server_to_client_key, second.server_to_client_key));
    BOOST_TEST(BytesEqual(first.server_to_client_nonce_prefix,
        second.server_to_client_nonce_prefix));

    // Each direction derives distinct key material (label separation).
    BOOST_TEST(!BytesEqual(first.client_to_server_key, first.server_to_client_key));
    BOOST_TEST(!BytesEqual(first.client_to_server_nonce_prefix,
        first.server_to_client_nonce_prefix));

    // A different record root changes every derived value.  The root is the
    // Noise exporter output, so in production a different root can only come
    // from a different binding context (different ivv, carrier or key id).
    const RecordKeyMaterial changed = Derive(FixedIkm(0x32));
    BOOST_TEST(!BytesEqual(first.client_to_server_key, changed.client_to_server_key));
    BOOST_TEST(!BytesEqual(first.server_to_client_key, changed.server_to_client_key));
    BOOST_TEST(!BytesEqual(first.client_to_server_nonce_prefix,
        changed.client_to_server_nonce_prefix));
    BOOST_TEST(!BytesEqual(first.server_to_client_nonce_prefix,
        changed.server_to_client_nonce_prefix));

    // Peers that negotiated the identical binding context share the identical
    // record root and must therefore derive identical material (the binding
    // context is peer-symmetric -- no role byte).
    const RecordKeyMaterial peer_a = Derive(FixedIkm(0x41));
    const RecordKeyMaterial peer_b = Derive(FixedIkm(0x41));
    BOOST_TEST(BytesEqual(peer_a.client_to_server_key, peer_b.client_to_server_key));
    BOOST_TEST(BytesEqual(peer_a.server_to_client_key, peer_b.server_to_client_key));
    BOOST_TEST(BytesEqual(peer_a.client_to_server_nonce_prefix,
        peer_b.client_to_server_nonce_prefix));
    BOOST_TEST(BytesEqual(peer_a.server_to_client_nonce_prefix,
        peer_b.server_to_client_nonce_prefix));
}

BOOST_AUTO_TEST_CASE(record_root_is_the_sole_hkdf_input_and_bad_roots_are_rejected) {
    const std::array<std::uint8_t, 32> root = FixedIkm(0x51);

    // The HKDF layer never re-encodes session, carrier or key id: identical
    // roots derive identical material, and only a different root (produced by
    // a different RecordProtector binding context upstream) separates keys.
    const RecordKeyMaterial a = Derive(root);
    const RecordKeyMaterial b = Derive(root);
    BOOST_TEST(BytesEqual(a.client_to_server_key, b.client_to_server_key));
    BOOST_TEST(BytesEqual(a.server_to_client_key, b.server_to_client_key));

    const RecordKeyMaterial different = Derive(FixedIkm(0x52));
    BOOST_TEST(!BytesEqual(a.client_to_server_key, different.client_to_server_key));
    BOOST_TEST(!BytesEqual(a.server_to_client_key, different.server_to_client_key));
    BOOST_TEST(!BytesEqual(a.client_to_server_nonce_prefix,
        different.client_to_server_nonce_prefix));
    BOOST_TEST(!BytesEqual(a.server_to_client_nonce_prefix,
        different.server_to_client_nonce_prefix));

    // A null or empty record root must be rejected.
    RecordKeyMaterial material;
    BOOST_TEST(!DeriveRecordKeyMaterial(nullptr, 32, material));
    BOOST_TEST(!DeriveRecordKeyMaterial(root.data(), 0, material));
}

namespace {

// Start gate so all worker threads are parked before the race is released.
struct StartGate {
    std::atomic<std::size_t> started{0};
    std::atomic<bool> go{false};

    void ArriveAndWait() noexcept {
        started.fetch_add(1, std::memory_order_release);
        while (!go.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
    }

    void WaitForAll(std::size_t count) noexcept {
        while (started.load(std::memory_order_acquire) < count) {
            std::this_thread::yield();
        }
        go.store(true, std::memory_order_release);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(concurrent_seal_never_reuses_a_sequence) {
    const RecordKeyMaterial material = Derive(FixedIkm(0x61));
    AuthenticatedRecordProtector protector(
        material.client_to_server_key,
        material.client_to_server_nonce_prefix,
        RecordDirection::ClientToServer,
        0,
        "aes-256-gcm");

    // 8 threads seal 512 records each through the same protector.  The
    // atomic CAS must hand each thread a unique sequence: no two records may
    // share a GCM nonce even though Seal() is entered concurrently.
    constexpr std::size_t kThreads = 8;
    constexpr std::size_t kPerThread = 512;
    const std::size_t total = kThreads * kPerThread;

    const std::vector<std::uint8_t> plaintext = Plaintext(48, 0x62);
    StartGate gate;
    std::atomic<std::size_t> failures{0};
    std::vector<std::vector<std::uint64_t>> per_thread(kThreads);

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (std::size_t t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            gate.ArriveAndWait();
            std::vector<std::uint8_t> sealed(plaintext.size() + RecordOverhead);
            std::vector<std::uint64_t>& sequences = per_thread[t];
            sequences.reserve(kPerThread);
            for (std::size_t i = 0; i < kPerThread; ++i) {
                std::size_t sealed_len = 0;
                if (!protector.Seal(plaintext.data(), plaintext.size(),
                        sealed.data(), sealed_len)) {
                    failures.fetch_add(1, std::memory_order_relaxed);
                    continue;
                }
                // Header is 4-byte length || 8-byte big-endian sequence.
                std::uint64_t sequence = 0;
                for (int b = 0; b < 8; ++b) {
                    sequence = (sequence << 8) | sealed[4 + b];
                }
                sequences.push_back(sequence);
            }
        });
    }
    gate.WaitForAll(kThreads);
    for (std::thread& thread : threads) {
        thread.join();
    }

    BOOST_REQUIRE(failures.load() == 0);
    std::set<std::uint64_t> unique;
    for (const auto& sequences : per_thread) {
        unique.insert(sequences.begin(), sequences.end());
    }
    // Total count matches, no duplicate, no gap: exactly [0, total).
    BOOST_TEST(unique.size() == total);
    BOOST_TEST(*unique.begin() == 0);
    BOOST_TEST(*unique.rbegin() == total - 1);
    BOOST_TEST(protector.SendSequence() == total);
}

BOOST_AUTO_TEST_CASE(concurrent_open_accepts_duplicate_sequence_exactly_once) {
    const RecordKeyMaterial material = Derive(FixedIkm(0x71));
    AuthenticatedRecordProtector protector(
        material.client_to_server_key,
        material.client_to_server_nonce_prefix,
        RecordDirection::ClientToServer,
        0,
        "aes-256-gcm");

    // Seal three records; record 0 is the one every thread races to open.
    constexpr std::size_t kRecords = 3;
    const std::vector<std::uint8_t> plaintext = Plaintext(32, 0x72);
    std::vector<std::vector<std::uint8_t>> sealed(kRecords);
    for (std::size_t i = 0; i < kRecords; ++i) {
        sealed[i].resize(plaintext.size() + RecordOverhead);
        std::size_t sealed_len = 0;
        BOOST_REQUIRE(protector.Seal(plaintext.data(), plaintext.size(),
            sealed[i].data(), sealed_len));
        sealed[i].resize(sealed_len);
    }

    constexpr std::size_t kThreads = 8;
    StartGate gate;
    std::atomic<std::size_t> successes{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (std::size_t t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            gate.ArriveAndWait();
            std::vector<std::uint8_t> opened(sealed[0].size());
            std::size_t opened_len = 0;
            if (protector.Open(sealed[0].data(), sealed[0].size(),
                    opened.data(), opened_len)) {
                successes.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    gate.WaitForAll(kThreads);
    for (std::thread& thread : threads) {
        thread.join();
    }

    // A concurrent duplicate delivery has a definite outcome: exactly one
    // thread advances the receive counter, every other thread is rejected.
    BOOST_TEST(successes.load() == 1);
    BOOST_TEST(protector.ReceiveSequence() == 1);

    // Strict sequencing afterwards: a jump to record 2 is rejected, record 1
    // (the next sequence) opens, replaying record 0 stays rejected, and then
    // record 2 opens in order.
    std::vector<std::uint8_t> opened(sealed[2].size());
    std::size_t opened_len = 0;
    BOOST_TEST(!protector.Open(sealed[2].data(), sealed[2].size(),
        opened.data(), opened_len));

    opened.resize(sealed[1].size());
    opened_len = 0;
    BOOST_REQUIRE(protector.Open(sealed[1].data(), sealed[1].size(),
        opened.data(), opened_len));
    BOOST_TEST(opened_len == plaintext.size());
    BOOST_TEST(std::memcmp(opened.data(), plaintext.data(),
        plaintext.size()) == 0);

    opened.resize(sealed[0].size());
    opened_len = 0;
    BOOST_TEST(!protector.Open(sealed[0].data(), sealed[0].size(),
        opened.data(), opened_len));

    opened.resize(sealed[2].size());
    opened_len = 0;
    BOOST_REQUIRE(protector.Open(sealed[2].data(), sealed[2].size(),
        opened.data(), opened_len));
    BOOST_TEST(opened_len == plaintext.size());
}

BOOST_AUTO_TEST_CASE(concurrent_failed_auth_never_advances_receive_sequence) {
    const RecordKeyMaterial material = Derive(FixedIkm(0x81));
    AuthenticatedRecordProtector protector(
        material.client_to_server_key,
        material.client_to_server_nonce_prefix,
        RecordDirection::ClientToServer,
        0,
        "aes-256-gcm");

    const std::vector<std::uint8_t> plaintext = Plaintext(40, 0x82);
    std::vector<std::uint8_t> sealed(plaintext.size() + RecordOverhead);
    std::size_t sealed_len = 0;
    BOOST_REQUIRE(protector.Seal(plaintext.data(), plaintext.size(),
        sealed.data(), sealed_len));

    // Corrupt one ciphertext byte: tag verification must fail for every
    // concurrent opener, and the receive counter must not move.
    std::vector<std::uint8_t> tampered = sealed;
    tampered[AuthenticatedRecordProtector::RecordHeaderLength + 3] ^= 0x01;

    constexpr std::size_t kThreads = 8;
    StartGate gate;
    std::atomic<std::size_t> successes{0};

    std::vector<std::thread> threads;
    threads.reserve(kThreads);
    for (std::size_t t = 0; t < kThreads; ++t) {
        threads.emplace_back([&] {
            gate.ArriveAndWait();
            std::vector<std::uint8_t> opened(tampered.size());
            std::size_t opened_len = 0;
            if (protector.Open(tampered.data(), tampered.size(),
                    opened.data(), opened_len)) {
                successes.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    gate.WaitForAll(kThreads);
    for (std::thread& thread : threads) {
        thread.join();
    }

    BOOST_TEST(successes.load() == 0);
    BOOST_TEST(protector.ReceiveSequence() == 0);

    // The stream is not poisoned: the genuine record still opens afterwards.
    std::vector<std::uint8_t> opened(sealed.size());
    std::size_t opened_len = 0;
    BOOST_REQUIRE(protector.Open(sealed.data(), sealed.size(),
        opened.data(), opened_len));
    BOOST_TEST(opened_len == plaintext.size());
}
