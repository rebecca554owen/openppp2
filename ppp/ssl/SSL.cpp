#include <ppp/ssl/root_certificates.hpp>
#include <ppp/ssl/SSL.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/io/File.h>
#include <common/chnroutes2/chnroutes2.h>
#include <mutex>
#include <openssl/ssl.h>
#include <openssl/x509.h>

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

            /**
             * @brief Populate trust store from system default locations.
             *
             * @details On Android, set_default_verify_paths() is skipped because
             *          Android does not expose system CAs via standard OpenSSL paths.
             *          For server contexts this is less critical — the server loads
             *          its own certificate chain and private key explicitly.
             */
#if !defined(__ANDROID__)

            ssl_context->set_default_verify_paths();
#endif

            /**
             * @brief Avoid the "DEFAULT" cipher alias on BoringSSL. OpenSSL builds
             *        get an explicit high-strength cipher filter below.
             */
            if (ciphersuites.size()) {
                /** @brief Apply caller-provided TLS 1.3 ciphersuite preferences. */
                SSL_CTX_set_ciphersuites(ssl_context->native_handle(), ciphersuites.data());
            }
#if !defined(OPENSSL_IS_BORINGSSL)
            SSL_CTX_set_cipher_list(ssl_context->native_handle(), "HIGH:!aNULL:!eNULL:!MD5:!RC4:!DES");
#endif
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

            /**
             * @brief Warm up OpenSSL/BoringSSL global SSL_CTX state once.
             *
             * @details boost::asio::ssl::context's constructor invokes
             *          SSL_CTX_new, which lazily initialises BoringSSL's
             *          global tables. Only that first global initialisation is
             *          serialised; per-context allocation and CA loading below
             *          can run concurrently.
             */
            static std::once_flag s_ssl_ctx_init_once;
            std::call_once(s_ssl_ctx_init_once, []() noexcept {
                SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
                if (ctx != NULLPTR) {
                    SSL_CTX_free(ctx);
                }
            });

            std::shared_ptr<boost::asio::ssl::context> ssl_context =
                make_shared_object<boost::asio::ssl::context>(
                    ppp::ssl::SSL::SSL_C_METHOD(method));
            if (!ssl_context) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeInitializationFailed);
                return NULLPTR;
            }

            /**
             * @brief Try loading the configured CA bundle file first.
             *
             * @details On all platforms, chnroutes2_cacertpath_default() returns
             *          "./cacert.pem" (or ".\cacert.pem" on Windows). If the file
             *          exists and is readable, it is loaded as the primary CA source.
             */
            boost::system::error_code ec = boost::asio::error::invalid_argument;
            if (ppp::string cacert = chnroutes2_cacertpath_default(); !cacert.empty()) {
                if (ppp::io::File::Exists(cacert.data())) {
                    ssl_context->load_verify_file(cacert.data(), ec);
                }
            }

            /**
             * @brief Fall back to built-in root certificates if file-based loading fails.
             *
             * @details Uses the non-throwing overload (safe inside noexcept context).
             *          On Android, this is typically the primary CA source because
             *          set_default_verify_paths() is skipped (Android does not expose
             *          the system CA store through standard OpenSSL filesystem paths).
             *          The hardcoded set in root_certificates.hpp contains Mozilla root
             *          CAs which provide adequate trust coverage for common servers.
             */
            if (ec) {
                load_root_certificates(*ssl_context, ec);
            }

            /**
             * @brief Populate trust store from system default locations.
             *
             * @details On Android (BoringSSL), set_default_verify_paths() is a
             *          no-op because Android does not expose the system CA store
             *          through the standard filesystem paths that OpenSSL queries.
             *          The trust source chain on Android is therefore:
             *            1. cacert.pem file (if present and loadable)
             *            2. Built-in root certificates from root_certificates.hpp
             *          Both paths ensure verify_peer has CA data. If no CA source
             *          succeeded, verify_peer will fail-closed during handshake
             *          (correct secure behavior — not a silent downgrade).
             */
#if !defined(__ANDROID__)

            ssl_context->set_default_verify_paths();
#endif

            /**
             * @brief Set verify mode. On Android with verify_peer, trust anchors
             *        come from cacert.pem or the bundled root_certificates.hpp.
             *
             * @details If all CA loading paths failed (ec still set) and the caller
             *          requested verify_peer, the trust store will be empty and every
             *          handshake will fail — this is intentional fail-closed behavior,
             *          not a silent security downgrade. We record a diagnostic here so
             *          operators can trace the root cause of subsequent handshake errors.
             */
#if defined(__ANDROID__)
            if (verify_peer && ec) {
                /**
                 * @brief Diagnostic: verify_peer was requested but no CA source was
                 *        successfully loaded (cacert.pem missing/unreadable AND the
                 *        built-in root certificate set failed to parse). The trust
                 *        store is empty; all TLS handshakes will reject peer certs.
                 *        Operators should ensure a valid cacert.pem is deployed at
                 *        the path returned by chnroutes2_cacertpath_default().
                 */
                ppp::diagnostics::SetLastErrorCode(
                    ppp::diagnostics::ErrorCode::SslHandshakeFailed);
            }
#endif
            ssl_context->set_verify_mode(verify_peer ? boost::asio::ssl::verify_peer : boost::asio::ssl::verify_none);

            /**
             * @brief Avoid the "DEFAULT" cipher alias on BoringSSL. OpenSSL builds
             *        get an explicit high-strength cipher filter below.
             */
            if (ciphersuites.size()) {
                /** @brief Apply caller-provided TLS 1.3 ciphersuite preferences. */
                SSL_CTX_set_ciphersuites(ssl_context->native_handle(), ciphersuites.data());
            }
#if !defined(OPENSSL_IS_BORINGSSL)
            SSL_CTX_set_cipher_list(ssl_context->native_handle(), "HIGH:!aNULL:!eNULL:!MD5:!RC4:!DES");
#endif

            SSL_CTX_set_ecdh_auto(ssl_context->native_handle(), 1);

            /**
             * @brief Pre-sort the X509_STORE's internal objects stack.
             *
             * @details After CA loading (load_verify_file / load_root_certificates),
             *          the X509_STORE's objects stack is populated but NOT
             *          sorted. The first lookup during TLS handshake calls
             *          OPENSSL_sk_find, which lazily sorts the stack via
             *          qsort. When two handshakes on two separate SSL_CTXs
             *          run concurrently on scheduler threads, each triggers
             *          its own lazy sort — but both touch shared BoringSSL
             *          globals (OBJ ASN.1 tables, error-string init) that
             *          the qsort callback path dereferences. The race has
             *          been observed on Android as SIGSEGV inside
             *          OPENSSL_sk_find / local_qsort with fault addr 0x0.
             *
             *          Force-sorting here keeps each context's store in its
             *          sorted, immutable-from-here state before the caller sees
             *          the SSL_CTX, so subsequent concurrent handshakes take the
             *          fast bsearch path without ever calling qsort.
             */
            if (X509_STORE* store = SSL_CTX_get_cert_store(ssl_context->native_handle())) {
                if (STACK_OF(X509_OBJECT)* objs = X509_STORE_get0_objects(store)) {
                    sk_X509_OBJECT_sort(objs);
                }
            }
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
