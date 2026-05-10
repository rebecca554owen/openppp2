#pragma once

#include <ppp/stdafx.h>
#include <ppp/ssl/SSL.h>
#include <ppp/IDisposable.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file SslSocket.h
 * @brief Declares a reusable TLS socket bootstrap template.
 */

namespace ppp {
    namespace net {
        namespace asio {
            namespace templates {
                /**
                 * @brief SSL socket bootstrap helper for client/server TLS handshakes.
                 * @tparam T SSL stream holder type managed by the caller.
                 */
                template <class T>
                class SslSocket : public IDisposable {
                public:
                    /** @brief Coroutine yield context alias used during async handshake. */
                    typedef ppp::coroutines::YieldContext               YieldContext;

                public:
                    /**
                     * @brief Initializes SSL socket bootstrap settings and references.
                     * @param tcp_socket Underlying TCP socket shared pointer reference.
                     * @param ssl_context SSL context shared pointer reference.
                     * @param ssl_socket SSL socket object reference to populate.
                     * @param verify_peer Whether peer certificate verification is enabled.
                     * @param host Optional SNI host name.
                     * @param certificate_file Server certificate file path.
                     * @param certificate_key_file Server private key file path.
                     * @param certificate_chain_file Certificate chain file path.
                     * @param certificate_key_password Password for encrypted private key.
                     * @param ciphersuites TLS cipher suites configuration string.
                     */
                    SslSocket(
                        std::shared_ptr<boost::asio::ip::tcp::socket>&  tcp_socket,
                        std::shared_ptr<boost::asio::ssl::context>&     ssl_context,
                        T&                                              ssl_socket,
                        bool                                            verify_peer,
                        const ppp::string&                              host,
                        const std::string&                              certificate_file,
                        const std::string&                              certificate_key_file,
                        const std::string&                              certificate_chain_file,
                        const std::string&                              certificate_key_password,
                        const std::string&                              ciphersuites) noexcept 
                        : tcp_socket_(tcp_socket)
                        , ssl_context_(ssl_context)
                        , ssl_socket_(ssl_socket)
                        , verify_peer_(verify_peer)
                        , host_(host) 
                        , certificate_file_(certificate_file)
                        , certificate_key_file_(certificate_key_file)
                        , certificate_chain_file_(certificate_chain_file)
                        , certificate_key_password_(certificate_key_password)
                        , ciphersuites_(ciphersuites) {
                        
                    }
                    virtual ~SslSocket()                                              noexcept = default;

                public:
                    /**
                     * @brief Creates SSL context/stream and performs handshake.
                     * @param handshaked_client true for client mode, false for server mode.
                     * @param y Coroutine context used by handshake implementation.
                     * @return true when SSL socket creation and handshake succeed.
                     */
                    bool                                                Run(bool handshaked_client, YieldContext& y) noexcept {
                        typedef typename stl::remove_pointer<T>::type SslSocket; /* decltype(*ssl_socket_); */

                        if (ssl_context_) {
                            return false;
                        }

                        std::shared_ptr<boost::asio::ip::tcp::socket>& tcpSocket = tcp_socket_;
                        if (!tcpSocket) {
                            return false;
                        }

                        if (!tcpSocket->is_open()) {
                            return false;
                        }

                        if (handshaked_client) {
                            ssl_context_ = ppp::ssl::SSL::CreateClientSslContext(ppp::ssl::SSL::SSL_METHOD::tlsv13, verify_peer_, ciphersuites_);
                        }
                        elif(certificate_file_.empty() || certificate_key_file_.empty() || certificate_chain_file_.empty()) {
                            return false;
                        }
                        else {
                            ssl_context_ = ppp::ssl::SSL::CreateServerSslContext(ppp::ssl::SSL::SSL_METHOD::tlsv13, certificate_file_, certificate_key_file_, certificate_chain_file_, certificate_key_password_, ciphersuites_);
                        }

                        boost::system::error_code ec;
                        if (!ssl_context_) {
                            return false;
                        }

                        ssl_socket_ = make_shared_object<SslSocket>(std::move(*tcpSocket), *ssl_context_);
                        if (!ssl_socket_) {
                            return false;
                        }

                        /** @brief Sets SNI hostname to satisfy virtual-host TLS endpoints. */
                        if (host_.size() > 0) {
                            if (!SSL_set_tlsext_host_name(GetSslHandle(), host_.data())) {
                                return false; /* throw boost::system::system_error{ { static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category() } }; */
                            }
                        }

                        /**
                         * @brief When peer verification is enabled, set OpenSSL hostname
                         *        verification so the certificate chain is checked against
                         *        the expected hostname (SAN / CN).
                         *
                         * SSL_set1_host() (OpenSSL ≥ 1.0.2 / BoringSSL) causes the
                         * built-in verify callback to reject certificates whose
                         * SubjectAltName or Subject CN does not match `host_`.
                         *
                         * An empty host with verify_peer enabled is a misconfiguration
                         * and must not silently skip hostname verification.
                         */
                        if (verify_peer_) {
                            if (host_.empty()) {
                                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SslWebSocketRunInvalidHostOrPath);
                                return false;
                            }

                            if (!SSL_set1_host(GetSslHandle(), host_.data())) {
                                return false;
                            }
                        }

                        return PerformSslHandshake(handshaked_client, y);
                    }

                protected:
                    /** @brief Returns mutable SSL socket reference. */
                    T&                                                  GetSslSocket() noexcept { return ssl_socket_; }
                    /** @brief Returns native OpenSSL handle for SNI and low-level configuration. */
                    virtual SSL*                                        GetSslHandle() noexcept = 0;
                    /** @brief Performs mode-specific handshake implementation. */
                    virtual bool                                        PerformSslHandshake(bool handshaked_client, YieldContext& y) noexcept = 0;

                public:
                    /** @brief Underlying TCP socket reference. */
                    std::shared_ptr<boost::asio::ip::tcp::socket>&      tcp_socket_;
                    /** @brief SSL context reference used to initialize SSL stream. */
                    std::shared_ptr<boost::asio::ssl::context>&         ssl_context_;
                    /** @brief SSL stream/socket reference managed externally. */
                    T&                                                  ssl_socket_;
                    /** @brief Indicates whether peer certificate verification is enabled. */
                    bool                                                verify_peer_ = false;
                    /** @brief Optional SNI host used by client handshake. */
                    ppp::string                                         host_;
                    /** @brief Certificate file path for server mode. */
                    std::string                                         certificate_file_;
                    /** @brief Private key file path for server mode. */
                    std::string                                         certificate_key_file_;
                    /** @brief Certificate chain file path for server mode. */
                    std::string                                         certificate_chain_file_;
                    /** @brief Password used for encrypted private key files. */
                    std::string                                         certificate_key_password_;
                    /** @brief Cipher suite configuration string. */
                    std::string                                         ciphersuites_;
                };
            }
        }
    }
}
