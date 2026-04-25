#include <ppp/ssl/root_certificates.hpp>
#include <ppp/ssl/SSL.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/io/File.h>
#include <common/chnroutes2/chnroutes2.h>

/**
 * @file SSL.cpp
 * @brief Implements SSL/TLS helper routines used by PPP.
 */

namespace ppp {
    namespace ssl {
        /**
         * @brief Resolves a server-side SSL method from a generic selector.
         * @param method A value from @ref SSL::SSL_METHOD.
         * @return The corresponding Boost.Asio server method.
         */
        boost::asio::ssl::context::method SSL::SSL_S_METHOD(int method) noexcept {
            switch (method) {
            case SSL_METHOD::tlsv13:
                return boost::asio::ssl::context::tlsv13_server;
            case SSL_METHOD::tlsv12:
                return boost::asio::ssl::context::tlsv12_server;
            case SSL_METHOD::tlsv11:
                return boost::asio::ssl::context::tlsv11_server;
            case SSL_METHOD::tls:
                return boost::asio::ssl::context::tls_server;
            case SSL_METHOD::sslv23:
                return boost::asio::ssl::context::sslv23_server;
            case SSL_METHOD::sslv3:
                return boost::asio::ssl::context::sslv3_server;
            case SSL_METHOD::sslv2:
                return boost::asio::ssl::context::sslv2_server;
            default:
                return boost::asio::ssl::context::tlsv12_server;
            };
        }

        /**
         * @brief Resolves a client-side SSL method from a generic selector.
         * @param method A value from @ref SSL::SSL_METHOD.
         * @return The corresponding Boost.Asio client method.
         */
        boost::asio::ssl::context::method SSL::SSL_C_METHOD(int method) noexcept {
            switch (method) {
            case SSL_METHOD::tlsv13:
                return boost::asio::ssl::context::tlsv13_client;
            case SSL_METHOD::tlsv12:
                return boost::asio::ssl::context::tlsv12_client;
            case SSL_METHOD::tlsv11:
                return boost::asio::ssl::context::tlsv11_client;
            case SSL_METHOD::tls:
                return boost::asio::ssl::context::tls_client;
            case SSL_METHOD::sslv23:
                return boost::asio::ssl::context::sslv23_client;
            case SSL_METHOD::sslv3:
                return boost::asio::ssl::context::sslv3_client;
            case SSL_METHOD::sslv2:
                return boost::asio::ssl::context::sslv2_client;
            default:
                return boost::asio::ssl::context::tlsv12_client;
            };
        }

        /**
         * @brief Verifies that certificate artifacts are accessible and loadable.
         * @param certificate_file Path to the end-entity certificate file.
         * @param certificate_key_file Path to the certificate private key file.
         * @param certificate_chain_file Path to the certificate chain file.
         * @return `true` if all files are valid and can be loaded into a context.
         */
        bool SSL::VerifySslCertificate(
            const std::string&                          certificate_file,
            const std::string&                          certificate_key_file,
            const std::string&                          certificate_chain_file) noexcept {

            typedef ppp::io::File                       File;
            typedef ppp::io::FileAccess                 FileAccess;

            if (certificate_file.empty() ||
                certificate_key_file.empty() ||
                certificate_chain_file.empty()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SslVerifyCertificateInvalidArguments);
                return false;
            }

            if (!File::CanAccess(certificate_file.data(), FileAccess::Read) ||
                !File::CanAccess(certificate_key_file.data(), FileAccess::Read) ||
                !File::CanAccess(certificate_chain_file.data(), FileAccess::Read)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                return false;
            }

            std::shared_ptr<boost::asio::ssl::context> ssl_context = make_shared_object<boost::asio::ssl::context>(
                ppp::ssl::SSL::SSL_S_METHOD(ppp::ssl::SSL::SSL_METHOD::ssl));
            if (!ssl_context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                return false;
            }

            boost::system::error_code ec;
            /*ssl_context_->set_options(boost::asio::ssl::context::default_workarounds |
                boost::asio::ssl::context::no_sslv2 |
                boost::asio::ssl::context::no_sslv3 |
                boost::asio::ssl::context::single_dh_use);*/
            /** @brief Load the chain, leaf certificate, and private key in sequence. */
            ssl_context->use_certificate_chain_file(certificate_chain_file, ec);
            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                return false;
            }

            ssl_context->use_certificate_file(certificate_file, boost::asio::ssl::context::file_format::pem, ec);
            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionHandshakeFailed);
                return false;
            }

            ssl_context->use_private_key_file(certificate_key_file, boost::asio::ssl::context::file_format::pem, ec);
            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::CryptoAlgorithmUnsupported);
                return false;
            }
            return true;
        }

        /**
         * @brief Builds a configured SSL context for server endpoints.
         * @param method SSL/TLS method selector.
         * @param certificate_file PEM certificate path.
         * @param certificate_key_file PEM private key path.
         * @param certificate_chain_file PEM chain path.
         * @param certificate_key_password Password for encrypted private keys.
         * @param ciphersuites Optional TLS 1.3 cipher suite list.
         * @return Shared server context instance.
         */
        std::shared_ptr<boost::asio::ssl::context> SSL::CreateServerSslContext(
            int                                         method,
            const std::string&                          certificate_file,
            const std::string&                          certificate_key_file,
            const std::string&                          certificate_chain_file,
            const std::string&                          certificate_key_password,
            const std::string&                          ciphersuites) noexcept {

            std::shared_ptr<boost::asio::ssl::context> ssl_context = make_shared_object<boost::asio::ssl::context>(
                ppp::ssl::SSL::SSL_S_METHOD(method));
            if (!ssl_context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                return NULLPTR;
            }

            boost::system::error_code ec;
            /*ssl_context_->set_options(boost::asio::ssl::context::default_workarounds |
                boost::asio::ssl::context::no_sslv2 |
                boost::asio::ssl::context::no_sslv3 |
                boost::asio::ssl::context::single_dh_use);*/
            ssl_context->use_certificate_chain_file(certificate_chain_file, ec);
            ssl_context->use_certificate_file(certificate_file, boost::asio::ssl::context::file_format::pem, ec);
            ssl_context->use_private_key_file(certificate_key_file, boost::asio::ssl::context::file_format::pem, ec);

            /**
             * @brief Register password callback used when reading encrypted PEM keys.
             */
            std::string certificate_key_password_ = certificate_key_password;
            ssl_context->set_password_callback([certificate_key_password_](
                std::size_t max_length,
                boost::asio::ssl::context_base::password_purpose purpose) noexcept -> std::string {
                    return certificate_key_password_;
                }, ec);

            /** @brief Populate trust store from system default locations. */
            ssl_context->set_default_verify_paths();

            SSL_CTX_set_cipher_list(ssl_context->native_handle(), "DEFAULT");
            if (ciphersuites.size()) {
                /** @brief Apply caller-provided TLS 1.3 ciphersuite preferences. */
                SSL_CTX_set_ciphersuites(ssl_context->native_handle(), ciphersuites.data());
            }
            SSL_CTX_set_ecdh_auto(ssl_context->native_handle(), 1);
            return ssl_context;
        }

        /**
         * @brief Builds a configured SSL context for client endpoints.
         * @param method SSL/TLS method selector.
         * @param verify_peer Enables peer certificate verification when true.
         * @param ciphersuites Optional TLS 1.3 cipher suite list.
         * @return Shared client context instance.
         */
        std::shared_ptr<boost::asio::ssl::context> SSL::CreateClientSslContext(
            int                                         method, 
            bool                                        verify_peer, 
            const std::string&                          ciphersuites) noexcept {

            std::shared_ptr<boost::asio::ssl::context> ssl_context = make_shared_object<boost::asio::ssl::context>(
                ppp::ssl::SSL::SSL_C_METHOD(ppp::ssl::SSL::SSL_METHOD::tlsv13));
            if (!ssl_context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                return NULLPTR;
            }

            /**
             * @brief Try loading the configured CA bundle file first.
             */
            boost::system::error_code ec = boost::asio::error::invalid_argument;
            if (ppp::string cacert = chnroutes2_cacertpath_default(); !cacert.empty()) {
                if (ppp::io::File::Exists(cacert.data())) {
                    ssl_context->load_verify_file(cacert.data(), ec);
                }
            }

            /**
             * @brief Fall back to built-in root certificates if file-based loading fails.
             */
            if (ec) {
                load_root_certificates(*ssl_context);
            }

            /** @brief Populate trust store from system default locations. */
            ssl_context->set_default_verify_paths();
            ssl_context->set_verify_mode(verify_peer ? boost::asio::ssl::verify_peer : boost::asio::ssl::verify_none);

            SSL_CTX_set_cipher_list(ssl_context->native_handle(), "DEFAULT");
            if (ciphersuites.size()) {
                /** @brief Apply caller-provided TLS 1.3 ciphersuite preferences. */
                SSL_CTX_set_ciphersuites(ssl_context->native_handle(), ciphersuites.data());
            }

            SSL_CTX_set_ecdh_auto(ssl_context->native_handle(), 1);
            return ssl_context;
        }

        /**
         * @brief Returns preferred TLS 1.3 cipher suites for the current platform.
         * @return OpenSSL ciphersuite string ordered by preference.
         */
        const char* SSL::GetSslCiphersuites() noexcept {
#if !(defined(__aarch64__) || defined(_M_ARM64))
            if (strstr(GetPlatformCode(), "ARM")) {
                return "TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384";
            }
#endif
            return "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
        }
    }
}
