#include <ppp/net/native/checksum.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>

#include <common/dnslib/message.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

namespace ppp {
    namespace diagnostics {
        ErrorCode SetLastErrorCode(ErrorCode code) noexcept {
            return code;
        }
    }

    namespace telemetry {
        void Log(Level, const char*, const char*, ...) noexcept {
        }
    }
}

namespace {
    struct TestFailure final {
        explicit TestFailure(const char* message_) : message(message_) {}
        const char* message;
    };

    void Require(bool condition, const char* message) {
        if (!condition) {
            throw TestFailure(message);
        }
    }

    std::vector<uint8_t> EncodeMessage(::dns::Message& message) {
        std::vector<uint8_t> packet(512);
        size_t encoded_size = 0;
        Require(::dns::BufferResult::NoError == message.encode(packet.data(), packet.size(), encoded_size),
            "message encode failed");
        packet.resize(encoded_size);
        return packet;
    }

    ::dns::ResourceRecord MakeARecord(const std::string& name, uint32_t ttl, const std::string& ip) {
        auto rdata = std::make_shared<::dns::RDataA>();
        rdata->setAddress(ip);

        ::dns::ResourceRecord rr;
        rr.mName = name;
        rr.mType = ::dns::RecordType::kA;
        rr.mClass = ::dns::RecordClass::kIN;
        rr.mTtl = ttl;
        rr.setRData(rdata);
        return rr;
    }

    ::dns::ResourceRecord MakeCnameRecord(const std::string& name, uint32_t ttl, const std::string& target) {
        auto rdata = std::make_shared<::dns::RDataCNAME>();
        rdata->mName = target;

        ::dns::ResourceRecord rr;
        rr.mName = name;
        rr.mType = ::dns::RecordType::kCNAME;
        rr.mClass = ::dns::RecordClass::kIN;
        rr.mTtl = ttl;
        rr.setRData(rdata);
        return rr;
    }

    ::dns::Message MakeBaseResponse(uint16_t id = 0x1234) {
        ::dns::Message message;
        message.mId = id;
        message.mQr = 1;
        message.mRD = 1;
        message.mRA = 1;
        message.mRCode = static_cast<uint16_t>(::dns::ResponseCode::kNOERROR);
        message.questions.emplace_back("example.com", ::dns::RecordType::kA, ::dns::RecordClass::kIN);
        return message;
    }

    void TestExtractsMinimumPositiveTtlAcrossCnameChain() {
        ::dns::Message message = MakeBaseResponse();
        message.answers.emplace_back(MakeCnameRecord("example.com", 50, "alias.example.com"));
        message.answers.emplace_back(MakeARecord("alias.example.com", 120, "203.0.113.7"));

        std::vector<uint8_t> packet = EncodeMessage(message);
        uint32_t ttl = 0;
        Require(ppp::net::native::dns::ExtractPositiveResponseMinTtl(packet.data(), static_cast<int>(packet.size()), ttl),
            "positive CNAME+A response should be cacheable");
        Require(ttl == 50, "minimum positive TTL should include CNAME TTL");
    }

    void TestRewriteResponseIdAndTtl() {
        ::dns::Message message = MakeBaseResponse(0x1111);
        message.answers.emplace_back(MakeCnameRecord("example.com", 50, "alias.example.com"));
        message.answers.emplace_back(MakeARecord("alias.example.com", 120, "203.0.113.7"));

        std::vector<uint8_t> packet = EncodeMessage(message);
        std::shared_ptr<ppp::Byte> rewritten;
        int rewritten_length = 0;
        Require(ppp::net::native::dns::RewriteResponseIdAndTtl(
            packet.data(), static_cast<int>(packet.size()), 0xabcd, 17, rewritten, rewritten_length),
            "response rewrite should succeed");
        Require(rewritten != nullptr, "rewritten response buffer should be allocated");
        Require(rewritten_length > 0, "rewritten response should have bytes");

        ::dns::Message decoded;
        Require(::dns::BufferResult::NoError == decoded.decode(rewritten.get(), static_cast<size_t>(rewritten_length)),
            "rewritten response should decode");
        Require(decoded.mId == 0xabcd, "rewritten response should use caller transaction id");
        Require(decoded.answers.size() == 2, "rewritten response should preserve answers");
        Require(decoded.answers[0].mTtl == 17, "CNAME TTL should be rewritten to remaining TTL");
        Require(decoded.answers[1].mTtl == 17, "A TTL should be rewritten to remaining TTL");
    }

    void TestRejectsZeroTtlAddressAnswer() {
        ::dns::Message message = MakeBaseResponse();
        message.answers.emplace_back(MakeARecord("example.com", 0, "203.0.113.7"));

        std::vector<uint8_t> packet = EncodeMessage(message);
        uint32_t ttl = 99;
        Require(!ppp::net::native::dns::ExtractPositiveResponseMinTtl(packet.data(), static_cast<int>(packet.size()), ttl),
            "zero-TTL A answer should not be cacheable");
        Require(ttl == 0, "failed extraction should clear TTL");
    }

    void TestRejectsCnameWithoutTerminalAddress() {
        ::dns::Message message = MakeBaseResponse();
        message.answers.emplace_back(MakeCnameRecord("example.com", 30, "alias.example.com"));

        std::vector<uint8_t> packet = EncodeMessage(message);
        uint32_t ttl = 0;
        Require(!ppp::net::native::dns::ExtractPositiveResponseMinTtl(packet.data(), static_cast<int>(packet.size()), ttl),
            "CNAME-only response should not be cacheable");
    }
}

int main() {
    struct TestCase {
        const char* name;
        void (*run)();
    };

    const TestCase tests[] = {
        {"extracts minimum positive TTL across CNAME chain", TestExtractsMinimumPositiveTtlAcrossCnameChain},
        {"rewrites response id and remaining TTL", TestRewriteResponseIdAndTtl},
        {"rejects zero-TTL address answer", TestRejectsZeroTtlAddressAnswer},
        {"rejects CNAME without terminal address", TestRejectsCnameWithoutTerminalAddress},
    };

    int failures = 0;
    for (const TestCase& test : tests) {
        try {
            test.run();
            std::printf("[PASS] %s\n", test.name);
        }
        catch (const TestFailure& failure) {
            ++failures;
            std::printf("[FAIL] %s: %s\n", test.name, failure.message);
        }
        catch (const std::exception& ex) {
            ++failures;
            std::printf("[FAIL] %s: unexpected exception: %s\n", test.name, ex.what());
        }
        catch (...) {
            ++failures;
            std::printf("[FAIL] %s: unknown exception\n", test.name);
        }
    }

    if (failures != 0) {
        std::printf("%d DNS cache TTL unit test(s) failed\n", failures);
        return 1;
    }

    std::printf("All DNS cache TTL unit tests passed\n");
    return 0;
}
