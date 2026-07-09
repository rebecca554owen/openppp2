#pragma once

/**
 * @file SSL.h
 * @brief Declares SSL/TLS context helpers for PPP networking.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace ssl {
        /**
         * @brief Provides static helpers for SSL/TLS method and context setup.
         */
        class SSL final {
        public:
            /**
             * @brief Supported SSL/TLS method selectors.
             */
            typedef enum {
                tlsv13,
                tlsv12,
                tlsv11,
                tls,
                sslv23,
                sslv3,
                sslv2,
                ssl,
            } SSL_METHOD;
            /**
             * @brief Maps a method selector to a client-side Asio SSL method.
             * @param method A value from @ref SSL_METHOD.
             * @return Asio SSL context method for client usage.
             */
            static boost::asio::ssl::context::method                        SSL_C_METHOD(int method) noexcept;
            /**
             * @brief Maps a method selector to a server-side Asio SSL method.
             * @param method A value from @ref SSL_METHOD.
             * @return Asio SSL context method for server usage.
             */
            static boost::asio::ssl::context::method                        SSL_S_METHOD(int method) noexcept;

        public:
            /**
             * @brief Validates that certificate files are readable and loadable.
             * @param certificate_file Path to certificate PEM file.
             * @param certificate_key_file Path to private key PEM file.
             * @param certificate_chain_file Path to certificate chain file.
             * @return `true` when the certificate set can be loaded.
             */
            static bool                                                     VerifySslCertificate(
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file) noexcept;
            /**
             * @brief Returns default TLS 1.3 cipher suite preference order.
             * @return Cipher suite string accepted by OpenSSL.
             */
            static const char*                                              GetSslCiphersuites() noexcept;

        public:
            /**
             * @brief Creates and configures a server SSL context.
             * @param method SSL/TLS method selector.
             * @param certificate_file Path to certificate PEM file.
             * @param certificate_key_file Path to private key PEM file.
             * @param certificate_chain_file Path to certificate chain file.
             * @param certificate_key_password Password for encrypted private key.
             * @param ciphersuites TLS 1.3 cipher suite override.
             * @return Shared server SSL context or `NULLPTR` on allocation failure.
             */
            static std::shared_ptr<boost::asio::ssl::context>               CreateServerSslContext(
                int                                                         method,
                const std::string&                                          certificate_file,
                const std::string&                                          certificate_key_file,
                const std::string&                                          certificate_chain_file,
                const std::string&                                          certificate_key_password,
                const std::string&                                          ciphersuites) noexcept;
            /**
             * @brief Creates and configures a client SSL context.
             * @param method SSL/TLS method selector.
             * @param verify_peer Whether peer certificate verification is enabled.
             * @param ciphersuites TLS 1.3 cipher suite override.
             * @return Shared client SSL context or `NULLPTR` on allocation failure.
             */
            static std::shared_ptr<boost::asio::ssl::context>               CreateClientSslContext(
                int                                                         method,
                bool                                                        verify_peer,
                const std::string&                                          ciphersuites) noexcept;
        };
    }
}
