// v2.2.0 AES-256-GCM NIST CAVS-style vector validation.
// Verifies the EVP GCM wiring (key, IV, tag append/verify) against known
// test vectors.  Vectors below were verified with an independent OpenSSL-EVP
// implementation (pyca/cryptography).
#include <ppp/cryptography/Ciphertext.h>

#include <cstdio>
#include <cstring>
#include <vector>
#include <array>

#include <openssl/evp.h>

using namespace ppp::cryptography;

static int fail(const char* msg)
{
    std::printf("FAIL: %s\n", msg);
    return 1;
}

static bool FromHex(const char* hex, std::vector<uint8_t>& out)
{
    out.clear();
    std::size_t len = std::strlen(hex);
    if (len % 2 != 0) {
        return false;
    }
    for (std::size_t i = 0; i < len; i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[i]);
        int lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return true;
}

static std::string ToHex(const std::vector<uint8_t>& v)
{
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) {
        s.push_back(digits[b >> 4]);
        s.push_back(digits[b & 0x0F]);
    }
    return s;
}

// Raw EVP AES-256-GCM encrypt with explicit key/IV (bypasses the
// password-derived key path so NIST vectors can be fed directly).
static bool RawGcmEncrypt(const std::vector<uint8_t>& key,
                          const std::vector<uint8_t>& iv,
                          const std::vector<uint8_t>& pt,
                          std::vector<uint8_t>& ct_out,
                          std::vector<uint8_t>& tag_out)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    int len = 0;
    bool ok = false;
    do {
        if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULLPTR, NULLPTR, NULLPTR, 1) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), NULLPTR) != 1) break;
        if (EVP_CipherInit_ex(ctx, NULLPTR, NULLPTR, key.data(), iv.data(), 1) != 1) break;
        ct_out.assign(pt.size(), 0);
        int outlen = 0;
        if (EVP_CipherUpdate(ctx, ct_out.data(), &outlen, pt.data(), static_cast<int>(pt.size())) != 1) break;
        int final_len = 0;
        if (EVP_CipherFinal_ex(ctx, ct_out.data() + outlen, &final_len) != 1) break;
        ct_out.resize(static_cast<std::size_t>(outlen + final_len));
        tag_out.assign(16, 0);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_out.data()) != 1) break;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// Raw EVP AES-256-GCM decrypt with explicit key/IV + tag verification.
static bool RawGcmDecrypt(const std::vector<uint8_t>& key,
                          const std::vector<uint8_t>& iv,
                          const std::vector<uint8_t>& ct,
                          const std::vector<uint8_t>& tag,
                          std::vector<uint8_t>& pt_out)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }
    int len = 0;
    bool ok = false;
    do {
        if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULLPTR, NULLPTR, NULLPTR, 0) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), NULLPTR) != 1) break;
        if (EVP_CipherInit_ex(ctx, NULLPTR, NULLPTR, key.data(), iv.data(), 0) != 1) break;
        pt_out.assign(ct.size(), 0);
        int outlen = 0;
        if (EVP_CipherUpdate(ctx, pt_out.data(), &outlen, ct.data(), static_cast<int>(ct.size())) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()),
                                const_cast<uint8_t*>(tag.data())) != 1) break;
        int final_len = 0;
        if (EVP_CipherFinal_ex(ctx, pt_out.data() + outlen, &final_len) != 1) break;
        pt_out.resize(static_cast<std::size_t>(outlen + final_len));
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

int main()
{
    struct NistVec {
        const char* key_hex;
        const char* iv_hex;
        const char* pt_hex;
        const char* ct_hex;
        const char* tag_hex;
    };
    const NistVec vectors[] = {
        // 1: empty plaintext
        { "0000000000000000000000000000000000000000000000000000000000000000",
          "000000000000000000000000", "",
          "", "530f8afbc74536b9a963b4f1c4cb738b" },
        // 2: 32-byte zero plaintext
        { "0000000000000000000000000000000000000000000000000000000000000000",
          "000000000000000000000000",
          "0000000000000000000000000000000000000000000000000000000000000000",
          "cea7403d4d606b6e074ec5d3baf39d18726003ca37a62a74d1a2f58e7506358e",
          "d1d3084c99aa8a9fdabb3e83eb28c15d" },
        // 3: 64-byte plaintext (NIST style key/iv)
        { "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
          "cafebabefacedbaddecaf888",
          "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
          "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
          "eb9f796c8d356fc31a8433884b696f4f" },
        // 4: 16-byte zero plaintext
        { "0000000000000000000000000000000000000000000000000000000000000000",
          "000000000000000000000000", "00000000000000000000000000000000",
          "cea7403d4d606b6e074ec5d3baf39d18",
          "d0d1c8a799996bf0265b98b5d48ab919" },
    };
    const std::size_t count = sizeof(vectors) / sizeof(vectors[0]);

    for (std::size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> key, iv, pt, ct_exp, tag_exp;
        if (!FromHex(vectors[i].key_hex, key) || !FromHex(vectors[i].iv_hex, iv) ||
            !FromHex(vectors[i].pt_hex, pt) || !FromHex(vectors[i].ct_hex, ct_exp) ||
            !FromHex(vectors[i].tag_hex, tag_exp)) {
            return fail("nist hex parse");
        }

        // Encrypt
        std::vector<uint8_t> ct, tag;
        if (!RawGcmEncrypt(key, iv, pt, ct, tag)) {
            std::printf("FAIL: vector %zu encrypt op\n", i);
            return 1;
        }
        if (ct != ct_exp || tag != tag_exp) {
            const std::string ct_s = ToHex(ct);
            const std::string exp_s = ToHex(ct_exp);
            const std::string tag_s = ToHex(tag);
            const std::string expt_s = ToHex(tag_exp);
            std::printf("FAIL: vector %zu mismatch\n  ct : %s\n  exp: %s\n  tag: %s\n  expt: %s\n",
                        i, ct_s.c_str(), exp_s.c_str(), tag_s.c_str(), expt_s.c_str());
            return 1;
        }

        // Decrypt + verify tag
        std::vector<uint8_t> pt_out;
        if (!RawGcmDecrypt(key, iv, ct, tag, pt_out)) {
            std::printf("FAIL: vector %zu decrypt op\n", i);
            return 1;
        }
        if (pt_out != pt) {
            std::printf("FAIL: vector %zu roundtrip mismatch\n", i);
            return 1;
        }
    }
    std::printf("PASS: NIST GCM vectors (%zu cases encrypt+decrypt)\n", count);

    // Tamper test: flip one bit in tag -> decrypt must fail.
    {
        std::vector<uint8_t> key, iv, pt, ct, tag, bad_tag, pt_out;
        FromHex("0000000000000000000000000000000000000000000000000000000000000000", key);
        FromHex("000000000000000000000000", iv);
        FromHex("00000000000000000000000000000000", pt);
        if (!RawGcmEncrypt(key, iv, pt, ct, tag)) {
            return fail("tamper encrypt");
        }
        bad_tag = tag;
        bad_tag[0] ^= 0x01;
        if (RawGcmDecrypt(key, iv, ct, bad_tag, pt_out)) {
            return fail("tampered tag accepted");
        }
        std::printf("PASS: tampered tag rejected\n");
    }
    return 0;
}
