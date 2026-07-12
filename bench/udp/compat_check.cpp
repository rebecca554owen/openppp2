// Phase 1 探索验证 —— aes-*-cfb(OpenSSL EVP) 与 simd-aes-*(AES-NI) 的密文互操作性。
// 决定 H4 落地方案：若互操作兼容，可让代码在支持 AES-NI 时对 aes-*-cfb 透明走无锁路径
// （所有现有部署自动加速、两端可混用）；若不兼容，只能两端一起改配置。
// 不改生产代码，仅测现有两条加密路径的行为。
#include <ppp/cryptography/Ciphertext.h>

#include <cstdio>
#include <cstring>
#include <vector>
#include <memory>

using ppp::Byte;
using ppp::cryptography::Ciphertext;

static std::vector<Byte> payload(int n) {
    std::vector<Byte> v((size_t)n);
    for (int i = 0; i < n; ++i) v[(size_t)i] = (Byte)((i * 131 + 7) & 0xFF);
    return v;
}

// 返回: cross_decrypt_ok（enc_method 加密能被 dec_method 解密还原）
static bool cross(const char* enc_method, const char* dec_method, const char* pw, int n, bool* byte_identical) {
    auto enc = std::make_shared<Ciphertext>(ppp::string(enc_method), ppp::string(pw));
    auto dec = std::make_shared<Ciphertext>(ppp::string(dec_method), ppp::string(pw));
    std::vector<Byte> data = payload(n);

    int clen = 0;
    auto ct = enc->Encrypt(nullptr, data.data(), n, clen);
    if (!ct || clen <= 0) { printf("  [%s->%s] encrypt failed\n", enc_method, dec_method); return false; }

    int plen = 0;
    auto pt = dec->Decrypt(nullptr, ct.get(), clen, plen);
    bool ok = pt && plen == n && std::memcmp(pt.get(), data.data(), (size_t)n) == 0;

    if (byte_identical) {
        int clen2 = 0;
        auto ct2 = dec->Encrypt(nullptr, data.data(), n, clen2);
        *byte_identical = ct2 && clen2 == clen && std::memcmp(ct.get(), ct2.get(), (size_t)clen) == 0;
    }
    return ok;
}

int main() {
    const char* pw = "interop-test-password";
    int fails = 0;
    struct { const char* a; const char* b; } pairs[] = {
        {"aes-128-cfb", "simd-aes-128-cfb"},
        {"aes-256-cfb", "simd-aes-256-cfb"},
    };
    for (auto& p : pairs) {
        bool ident_ab = false, ident_ba = false;
        bool ab = cross(p.a, p.b, pw, 512, &ident_ab);   // openssl 加密 -> aesni 解密
        bool ba = cross(p.b, p.a, pw, 512, &ident_ba);   // aesni 加密 -> openssl 解密
        printf("%-16s <-> %-20s : openssl->aesni=%s  aesni->openssl=%s  ciphertext-identical=%s\n",
               p.a, p.b, ab ? "OK" : "FAIL", ba ? "OK" : "FAIL", (ident_ab ? "YES" : "NO"));
        if (!ab || !ba) ++fails;
    }
    printf("\nRESULT: %s\n", fails == 0 ? "INTEROPERABLE (透明加速可行)" : "NOT interoperable (须两端一起切配置)");
    return fails == 0 ? 0 : 1;
}
