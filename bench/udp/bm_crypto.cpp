// BM1a —— 底层密码器微基准 / H4 验证台。
// 同一个 Ciphertext 门面，对比 OpenSSL EVP 路径 (aes-*-cfb) 与 AES-NI 路径 (simd-aes-*-cfb)：
// 前者每包取锁 + 重置 CTX，后者无锁。差值即"切 simd-aes-* 能省多少每包成本"。
// 每包成本 = ns/op(benchmark) + pps(items/s) + cycles/packet(外部 perf stat 采)。
#include <benchmark/benchmark.h>

#include <ppp/cryptography/Ciphertext.h>

#include <memory>
#include <vector>
#include <cstring>

using ppp::Byte;
using ppp::cryptography::Ciphertext;

// 确定性负载（避免 Math.random 依赖，按下标生成）。
static std::vector<Byte> make_payload(int n) {
    std::vector<Byte> v((size_t)n);
    for (int i = 0; i < n; ++i) {
        v[(size_t)i] = (Byte)((i * 131 + 7) & 0xFF);
    }
    return v;
}

// self-check：加密后能解密还原（CFB 为流密码，密文长 == 明文长）。
static bool roundtrip_ok(const char* method) {
    auto c = std::make_shared<Ciphertext>(ppp::string(method), ppp::string("bench-pw"));
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

static void BM_Encrypt(benchmark::State& state, const char* method) {
    if (!Ciphertext::Support(ppp::string(method))) {
        state.SkipWithError("cipher method not supported (simd-* needs __SIMD__ + AES-NI)");
        return;
    }
    if (!roundtrip_ok(method)) {
        state.SkipWithError("self-check roundtrip failed");
        return;
    }

    auto c = std::make_shared<Ciphertext>(ppp::string(method), ppp::string("bench-pw"));
    const int datalen = (int)state.range(0);
    std::vector<Byte> data = make_payload(datalen);

    for (auto _ : state) {
        int outlen = 0;
        std::shared_ptr<Byte> out = c->Encrypt(nullptr, data.data(), datalen, outlen);
        benchmark::DoNotOptimize(out.get());
        benchmark::ClobberMemory();
    }
    state.SetItemsProcessed(state.iterations());                       // → items_per_second = pps
    state.SetBytesProcessed((int64_t)state.iterations() * datalen);    // → bytes_per_second
    state.counters["payload_B"] = datalen;
}

// 三档包长；15 次重复取聚合。aes-128/256 各自 OpenSSL vs SIMD 四路对照。
#define REGISTER(name, method)                                            \
    BENCHMARK_CAPTURE(BM_Encrypt, name, method)                           \
        ->Arg(64)->Arg(512)->Arg(1400)                                    \
        ->Repetitions(15)->DisplayAggregatesOnly(true)->UseRealTime()

REGISTER(aes128cfb_openssl, "aes-128-cfb");
REGISTER(aes128cfb_simd,    "simd-aes-128-cfb");
REGISTER(aes256cfb_openssl, "aes-256-cfb");
REGISTER(aes256cfb_simd,    "simd-aes-256-cfb");

#undef REGISTER

BENCHMARK_MAIN();
