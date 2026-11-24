// explicit_aead_advisory_contract_test.cpp -- an explicit AEAD cipher on the
// legacy data path has to be reported at startup.
//
// Background:
//   The legacy data path is equal-length and never emits the AEAD tag, and
//   EVP::resetCipher rewinds to the same derived IV before every packet. A
//   deployment that names such a cipher therefore runs an unauthenticated
//   cipher with the failure mode of an AEAD one, and the operator has to be
//   told which configuration field is affected.
//
//   The advisory was lost together with the abandoned AEAD record layer, so
//   this file pins that the warning is back and that it is wired to both
//   cipher fields. The predicate itself is pinned by
//   tests/cpp/explicit_aead_cipher_test.cpp.

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string ReadSource(const std::string& relative_path) {
    const std::string path = std::string(OPENPPP2_SOURCE_ROOT) + "/" + relative_path;
    std::ifstream file(path);
    Require(file.good(), "cannot open source file for contract check");
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// The body of a function: from the first '{' after the signature, balanced.
std::string FunctionBody(const std::string& text, const std::string& signature) {
    const size_t start = text.find(signature);
    if (start == std::string::npos) {
        return std::string();
    }
    const size_t open = text.find('{', start);
    if (open == std::string::npos) {
        return std::string();
    }
    int depth = 0;
    for (size_t i = open; i < text.size(); ++i) {
        if (text[i] == '{') {
            ++depth;
        }
        else if (text[i] == '}') {
            --depth;
            if (depth == 0) {
                return text.substr(open, i - open + 1);
            }
        }
    }
    return std::string();
}

} // namespace

int main() {
    try {
        const std::string config = ReadSource("ppp/configurations/AppConfiguration.cpp");

        // 1) The advisory must exist and must be reachable from the
        //    configuration loader.
        const std::string body = FunctionBody(config, "WarnExplicitAeadOnLegacyPath(");
        Require(!body.empty(), "the explicit-AEAD advisory must exist");

        Require(config.find("WarnExplicitAeadOnLegacyPath(\"protocol\", config.key.protocol)") != std::string::npos,
                "the advisory must cover key.protocol");
        Require(config.find("WarnExplicitAeadOnLegacyPath(\"transport\", config.key.transport)") != std::string::npos,
                "the advisory must cover key.transport");

        // 2) It must go through the warn channel, which reaches the console
        //    even when telemetry is off -- that is the whole point of the
        //    channel.
        Require(body.find("telemetry::Warn") != std::string::npos,
                "the advisory must use the warn channel");

        // 3) The message has to name the two facts that make the
        //    configuration unsafe, and the change that fixes it.
        Require(body.find("the tag is never produced") != std::string::npos,
                "the message must say that the tag is never produced");
        Require(body.find("authentication at all") != std::string::npos,
                "the message must say that the frame carries no authentication");
        Require(body.find("same derived IV") != std::string::npos,
                "the message must say that the nonce repeats per packet");
        Require(body.find("buys nothing here") != std::string::npos,
                "the message must say that the AEAD name buys nothing here");
        Require(body.find("not make that promise") != std::string::npos,
                "the message must name a cipher that does not promise a unique nonce");
        Require(body.find("transport-auth") != std::string::npos,
                "the message must say that transport-auth does not change this path");

        // 4) A name that selects the unauthenticated SIMD variant on purpose
        //    must not be reported.
        Require(body.find("simd-") != std::string::npos,
                "a simd- name must not be reported");

        std::cout << "explicit_aead_advisory_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "explicit_aead_advisory_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
