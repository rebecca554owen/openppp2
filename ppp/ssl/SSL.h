#pragma once

#include <ppp/stdafx.h>

namespace ppp {
    namespace ssl {
        // SSL/TLS protocol versions
        // Note: SSLv2 and SSLv3 are deprecated due to POODLE attack (CVE-2014-3566) and other vulnerabilities.
        // Minimum recommended version is TLS 1.2.
        class SSL final {
        public:
            typedef enum {
                tlsv13,     // TLS 1.3 (recommended)
                tlsv12,     // TLS 1.2 (minimum secure version)
                tlsv11,     // TLS 1.1 (deprecated, legacy support only)
                tls,        // TLS (auto-select best available)
                sslv23,     // SSLv2/v3 fallback (deprecated)
                sslv3,      // SSLv3 - DEPRECATED (POODLE attack) - disabled
                sslv2,      // SSLv2 - DEPRECATED (multiple vulnerabilities) - disabled
                ssl,        // Alias for sslv23 (deprecated)
            } SSL_METHOD;
            static boost::asio::ssl::context::method                        SSL_C_METHOD(int method) noexcept;
            static boost::asio::ssl::context::method                        SSL_S_METHOD(int method) noexcept;

        public:
            static bool                                                     VerifySslCertificate(
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file) noexcept;
            static const char*                                              GetSslCiphersuites() noexcept;

        public:
            static std::shared_ptr<boost::asio::ssl::context>               CreateServerSslContext(
                int                                                         method,
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file,
                const std::string&                                          certificate_key_password,
                const std::string&                                          ciphersuites) noexcept;
            static std::shared_ptr<boost::asio::ssl::context>               CreateClientSslContext(
                int                                                         method,
                bool                                                        verify_peer,
                const std::string&                                          ciphersuites) noexcept;
        };
    }
}