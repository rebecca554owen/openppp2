// BM1a —— 底层密码器微基准 / H4 验证台。
// 对比真实 OpenSSL EVP 路径 (aes-*-cfb) 与 AES-NI 路径 (simd-aes-*-cfb)。
#include <benchmark/benchmark.h>

#include <ppp/cryptography/Ciphertext.h>
#include <ppp/cryptography/EVP.h>

#include <memory>
#include <vector>
#include <cstring>
#include <wmmintrin.h>

using ppp::Byte;
using ppp::cryptography::Ciphertext;
using ppp::cryptography::EVP;

namespace aesni {
    void aes256_cfb_key_expansion(const uint8_t* key, __m128i* round_key) noexcept;
    void aes256_cfb_decrypt(uint8_t* plaintext, const uint8_t* ciphertext, size_t len,
        const uint8_t* iv, const __m128i* round_key) noexcept;
}

static inline __m128i aes256_encrypt_block_reference(__m128i block, const __m128i* round_key) {
    block = _mm_xor_si128(block, round_key[0]);
    for (int i = 1; i < 14; ++i) block = _mm_aesenc_si128(block, round_key[i]);
    return _mm_aesenclast_si128(block, round_key[14]);
}

// Kept in the benchmark as the pre-optimization one-block-at-a-time oracle.
static void aes256_cfb_decrypt_scalar_reference(uint8_t* plaintext,
    const uint8_t* ciphertext, size_t len, const uint8_t* iv,
    const __m128i* round_key) {
    __m128i feedback = _mm_loadu_si128(reinterpret_cast<const __m128i*>(iv));
    const size_t blocks = len / 16;
    const size_t remaining = len % 16;
    for (size_t i = 0; i < blocks; ++i) {
        const __m128i cipher_block = _mm_loadu_si128(
            reinterpret_cast<const __m128i*>(ciphertext + i * 16));
        const __m128i plain_block = _mm_xor_si128(
            cipher_block, aes256_encrypt_block_reference(feedback, round_key));
        _mm_storeu_si128(reinterpret_cast<__m128i*>(plaintext + i * 16), plain_block);
        feedback = cipher_block;
    }
    if (remaining != 0) {
        const __m128i keystream = aes256_encrypt_block_reference(feedback, round_key);
        for (size_t i = 0; i < remaining; ++i) {
            plaintext[blocks * 16 + i] = ciphertext[blocks * 16 + i] ^
                reinterpret_cast<const uint8_t*>(&keystream)[i];
        }
    }
}

static std::vector<Byte> make_payload(int n) {
    std::vector<Byte> v((size_t)n);
    for (int i = 0; i < n; ++i) {
        v[(size_t)i] = (Byte)((i * 131 + 7) & 0xFF);
    }
    return v;
}

static std::shared_ptr<Ciphertext> make_benchmark_cipher(const char* method) {
    // method 本身决定后端。普通 aes-* 必须保持 OpenSSL，显式 simd-aes-* 走 AES-NI。
    EVP::SetSimdAuto(false);
    auto cipher = std::make_shared<Ciphertext>(ppp::string(method), ppp::string("bench-pw"));
    EVP::SetSimdAuto(true);
    return cipher;
}

static bool roundtrip_ok(const char* method) {
    auto c = make_benchmark_cipher(method);
    std::vector<Byte> data = make_payload(256);

    int enclen = 0;
    std::shared_ptr<Byte> enc = c->Encrypt(nullptr, data.data(), (int)data.size(), enclen);
    if (!enc || enclen <= 0) {
        return false;
    }

    int declen = 0;
    std::shared_ptr<Byte> dec = c->Decrypt(nullptr, enc.get(), enclen, declen);
    if (!dec || declen != (int)data.size()) {
        return false;
    }
    return std::memcmp(dec.get(), data.data(), data.size()) == 0;
}

// v2.2.0: GCM must reject tampered ciphertext/tag (authentication check).
static bool tamper_rejected(const char* method) {
    auto c = make_benchmark_cipher(method);
    std::vector<Byte> data = make_payload(256);

    int enclen = 0;
    std::shared_ptr<Byte> enc = c->Encrypt(nullptr, data.data(), (int)data.size(), enclen);
    if (!enc || enclen <= 16) {
        return false;
    }

    // Flip one bit in the final tag byte.
    std::vector<Byte> tampered(enc.get(), enc.get() + enclen);
    tampered[tampered.size() - 1] ^= 0x01;

    int declen = 0;
    std::shared_ptr<Byte> dec = c->Decrypt(nullptr, tampered.data(), (int)tampered.size(), declen);
    return dec == nullptr;   // must be rejected
}

static void BM_TamperRejected(benchmark::State& state, const char* method) {
    if (!Ciphertext::Support(ppp::string(method))) {
        state.SkipWithError("cipher method not supported");
        return;
    }
    if (!tamper_rejected(method)) {
        state.SkipWithError("tampered record was NOT rejected - authentication broken");
        return;
    }
    for (auto _ : state) {
        benchmark::DoNotOptimize(tamper_rejected(method));
    }
}

#define REGISTER_TAMPER(name, method) \
    BENCHMARK_CAPTURE(BM_TamperRejected, name, method)->Repetitions(3)

REGISTER_TAMPER(aes256gcm_tamper, "aes-256-gcm");
REGISTER_TAMPER(aes128gcm_tamper, "aes-128-gcm");

#undef REGISTER_TAMPER

static void BM_Encrypt(benchmark::State& state, const char* method) {
    if (!Ciphertext::Support(ppp::string(method))) {
        state.SkipWithError("cipher method not supported (simd-* needs __SIMD__ + AES-NI)");
        return;
    }
    if (!roundtrip_ok(method)) {
        state.SkipWithError("self-check roundtrip failed");
        return;
    }

    auto c = make_benchmark_cipher(method);
    const int datalen = (int)state.range(0);
    std::vector<Byte> data = make_payload(datalen);

    for (auto _ : state) {
        int outlen = 0;
        std::shared_ptr<Byte> out = c->Encrypt(nullptr, data.data(), datalen, outlen);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed((int64_t)state.iterations() * datalen);
    state.counters["payload_B"] = datalen;
    state.counters["allocations"] = 1;
}

static void BM_Decrypt(benchmark::State& state, const char* method) {
    if (!Ciphertext::Support(ppp::string(method))) {
        state.SkipWithError("cipher method not supported (simd-* needs __SIMD__ + AES-NI)");
        return;
    }
    if (!roundtrip_ok(method) || (std::strcmp(method, "simd-aes-256-cfb") == 0 &&
        (!simd_decrypt_matches_openssl() || !simd_decrypt_matches_scalar()))) {
        state.SkipWithError("decrypt compatibility self-check failed");
        return;
    }

    auto c = make_benchmark_cipher(method);
    auto reference = make_benchmark_cipher("aes-256-cfb");
    const int datalen = (int)state.range(0);
    std::vector<Byte> plain = make_payload(datalen);
    int cipher_len = 0;
    std::shared_ptr<Byte> encrypted = reference->Encrypt(nullptr, plain.data(), datalen, cipher_len);
    if (!encrypted || cipher_len != datalen) {
        state.SkipWithError("could not prepare AES-256-CFB ciphertext");
        return;
    }

    for (auto _ : state) {
        int outlen = 0;
        std::shared_ptr<Byte> out = c->Decrypt(nullptr, encrypted.get(), cipher_len, outlen);
        benchmark::DoNotOptimize(out.get());
        benchmark::DoNotOptimize(outlen);
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());
    state.SetBytesProcessed((int64_t)state.iterations() * datalen);
    state.counters["payload_B"] = datalen;
    state.counters["allocations"] = 1;
}

// 保留每次 repetition 原始样本，供 compare.py 做 bootstrap CI。
#define REGISTER(name, method)                                            \
    BENCHMARK_CAPTURE(BM_Encrypt, name, method)                           \
        ->Arg(64)->Arg(512)->Arg(1400)                                    \
        ->Repetitions(15)->UseRealTime()

REGISTER(aes128cfb_openssl, "aes-128-cfb");
REGISTER(aes128cfb_simd,    "simd-aes-128-cfb");
REGISTER(aes256cfb_openssl, "aes-256-cfb");
REGISTER(aes256cfb_simd,    "simd-aes-256-cfb");

// v2.2.0 EVP GCM vs SIMD pseudo-GCM baseline
REGISTER(aes256gcm_openssl, "aes-256-gcm");
REGISTER(aes128gcm_openssl,  "aes-128-gcm");
REGISTER(simd_gcm256,        "simd-aes-256-gcm");
REGISTER(simd_gcm128,        "simd-aes-128-gcm");

#undef REGISTER
#undef REGISTER_DECRYPT

BENCHMARK_MAIN();
