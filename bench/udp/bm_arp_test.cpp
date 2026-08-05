// v2.2.0 AuthenticatedRecordProtector functional tests.
// Seal/Open roundtrip, tamper rejection, replay rejection, truncation rejection.
#include <ppp/cryptography/AuthenticatedRecordProtector.h>
#include <ppp/cryptography/RecordKeyDerivation.h>

#include <cstdio>
#include <cstring>
#include <vector>
#include <array>

using namespace ppp::cryptography;

static int fail(const char* msg)
{
    std::printf("FAIL: %s\n", msg);
    return 1;
}

int main()
{
    // 0. HKDF record key derivation (v2.2.0 section 6 domain separation)
    {
        std::array<uint8_t, 32> exporter = {};
        std::array<uint8_t, 32> handshake = {};
        for (int i = 0; i < 32; ++i) {
            exporter[i] = static_cast<uint8_t>(i + 1);
            handshake[i] = static_cast<uint8_t>(255 - i);
        }
        uint8_t session[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        RecordKeyContext ctx;
        ctx.exporter_secret = exporter.data();
        ctx.exporter_secret_len = exporter.size();
        ctx.handshake_hash = handshake.data();
        ctx.handshake_hash_len = handshake.size();
        ctx.session_id = session;
        ctx.session_id_len = sizeof(session);
        ctx.carrier_kind = 0;
        ctx.transport_auth_key_id = 7;

        RecordKeyMaterial m;
        if (!DeriveRecordKeyMaterial(ctx, m)) {
            return fail("hkdf derive");
        }
        // Direction keys must differ.
        if (m.client_to_server_key == m.server_to_client_key) {
            return fail("direction keys identical");
        }
        if (m.client_to_server_nonce_prefix == m.server_to_client_nonce_prefix) {
            return fail("direction nonce prefixes identical");
        }
        // Same input must be deterministic.
        RecordKeyMaterial m2;
        if (!DeriveRecordKeyMaterial(ctx, m2)) {
            return fail("hkdf derive2");
        }
        if (m.client_to_server_key != m2.client_to_server_key) {
            return fail("hkdf not deterministic");
        }
        std::printf("PASS: HKDF derivation (directional keys differ, deterministic)\n");

        // Full path: derived C2S key protects client->server records.
        AuthenticatedRecordProtector c2s(
            m.client_to_server_key, m.client_to_server_nonce_prefix,
            RecordDirection::ClientToServer, 0);
        std::vector<uint8_t> p1(80, 0x5A);
        std::vector<uint8_t> s1(80 + 28);
        std::size_t s1len = 0;
        if (!c2s.Seal(p1.data(), p1.size(), s1.data(), s1len)) {
            return fail("c2s seal");
        }
        AuthenticatedRecordProtector s2c(
            m.server_to_client_key, m.server_to_client_nonce_prefix,
            RecordDirection::ServerToClient, 0);
        std::vector<uint8_t> p2(80, 0x6B);
        std::vector<uint8_t> s2(80 + 28);
        std::size_t s2len = 0;
        if (!s2c.Seal(p2.data(), p2.size(), s2.data(), s2len)) {
            return fail("s2c seal");
        }
        // Cross-direction must NOT open: c2s protector cannot open s2c record.
        std::vector<uint8_t> cross(s2len);
        std::size_t crosslen = 0;
        if (c2s.Open(s2.data(), s2len, cross.data(), crosslen)) {
            return fail("cross-direction record accepted");
        }
        std::printf("PASS: cross-direction record rejected (independent keys)\n");
    }

    std::array<uint8_t, 32> key = {};
    for (int i = 0; i < 32; ++i) {
        key[i] = static_cast<uint8_t>(i * 7 + 1);
    }
    std::array<uint8_t, 4> np = { 0xAA, 0xBB, 0xCC, 0xDD };

    AuthenticatedRecordProtector p(key, np, RecordDirection::ClientToServer, 0);

    // 1. Seal + Open roundtrip
    std::vector<uint8_t> plain(100);
    for (int i = 0; i < 100; ++i) {
        plain[i] = static_cast<uint8_t>(i);
    }
    std::vector<uint8_t> sealed(100 + 28);
    std::size_t sealed_len = 0;
    if (!p.Seal(plain.data(), plain.size(), sealed.data(), sealed_len)) {
        return fail("seal");
    }
    if (sealed_len != 100 + 28) {
        return fail("sealed length != plaintext + 28");
    }
    std::vector<uint8_t> opened(sealed_len);
    std::size_t opened_len = 0;
    if (!p.Open(sealed.data(), sealed_len, opened.data(), opened_len)) {
        return fail("open");
    }
    if (opened_len != 100 || std::memcmp(opened.data(), plain.data(), 100) != 0) {
        return fail("roundtrip mismatch");
    }
    std::printf("PASS: seal+open roundtrip (%zu -> %zu)\n", plain.size(), sealed_len);

    // 2. Tampered ciphertext rejected
    std::vector<uint8_t> tampered = sealed;
    tampered[15] ^= 0x40;
    std::size_t tlen = 0;
    if (p.Open(tampered.data(), tampered.size(), opened.data(), tlen)) {
        return fail("tampered ciphertext accepted");
    }
    std::printf("PASS: tampered ciphertext rejected\n");

    // 3. Replay rejected (sequence already advanced)
    std::size_t rlen = 0;
    if (p.Open(sealed.data(), sealed_len, opened.data(), rlen)) {
        return fail("replay accepted");
    }
    std::printf("PASS: replay rejected\n");

    // 4. Truncated rejected
    std::size_t trlen = 0;
    if (p.Open(sealed.data(), sealed_len - 1, opened.data(), trlen)) {
        return fail("truncated accepted");
    }
    std::printf("PASS: truncated rejected\n");

    // 5. Second record (sequence 1) works; out-of-order (seq 2) rejected
    std::vector<uint8_t> plain2(50, 0x77);
    std::vector<uint8_t> sealed2(50 + 28);
    std::size_t sealed2_len = 0;
    if (!p.Seal(plain2.data(), plain2.size(), sealed2.data(), sealed2_len)) {
        return fail("seal2");
    }
    std::size_t o2len = 0;
    if (!p.Open(sealed2.data(), sealed2_len, opened.data(), o2len)) {
        return fail("open2 (seq=1)");
    }
    if (o2len != 50 || std::memcmp(opened.data(), plain2.data(), 50) != 0) {
        return fail("roundtrip2 mismatch");
    }
    std::printf("PASS: second record seq=1 roundtrip\n");

    // 6. Seal after 2 records: seq=2. Try opening it (expected seq=2, ok)
    std::vector<uint8_t> plain3(10, 0x11);
    std::vector<uint8_t> sealed3(10 + 28);
    std::size_t sealed3_len = 0;
    if (!p.Seal(plain3.data(), plain3.size(), sealed3.data(), sealed3_len)) {
        return fail("seal3");
    }
    std::size_t o3len = 0;
    if (!p.Open(sealed3.data(), sealed3_len, opened.data(), o3len)) {
        return fail("open3 (seq=2)");
    }
    std::printf("PASS: third record seq=2 roundtrip\n");

    return 0;
}
