#include <ppp/transmissions/IWebsocketTransmission.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file IWebsocketTransmission.cpp
 * @brief Implements websocket handshake and HTTP header decoration helpers.
 */

namespace ppp {
    namespace transmissions {
        /**
         * @brief Applies all configured HTTP headers to a websocket request/response.
         * @tparam R Beast HTTP message type supporting set(name, value).
         * @param headers Source header map.
         * @param r Target request/response object.
         * @return true if at least one header set is attempted.
         */
        template <typename R>
        static inline bool DecoratorWebsocketAllHeaders(ppp::map<ppp::string, ppp::string>& headers, R& r) noexcept {
            if (headers.empty()) {
                return false;
            }

            for (auto&& [k, v] : headers) {
                boost::beast::string_view vsv(v.data(), v.size());
                boost::beast::string_view ksv(k.data(), k.size());
                r.set(ksv, vsv);
            }

            return true;
        }

        /**
         * @brief Decorates websocket handshake response for web clients.
         * @param configuration Runtime app configuration.
         * @param res Websocket HTTP response object.
         * @return true if response headers are decorated.
         */
        static inline bool DecoratorWebsocketResponseToWebclient(const ITransmission::AppConfigurationPtr& configuration, boost::beast::websocket::response_type& res) noexcept {
            if (NULLPTR == configuration) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
                return false;
            }

            int status_code = res.result_int();
            bool ok = DecoratorWebsocketAllHeaders(configuration->websocket.http.response, res);
            if (status_code == 404) {
                std::string& response_body = res.body();
                response_body = configuration->websocket.http.error;
            }

            return ok;
        }

        IWebsocketTransmission::IWebsocketTransmission(
            const ContextPtr&                                       context,
            const StrandPtr&                                        strand,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
            const AppConfigurationPtr&                              configuration) noexcept
            : WebSocket(context, strand, socket, configuration) {

        }

        /**
         * @brief Performs websocket handshake using override or configuration endpoint.
         */
        bool IWebsocketTransmission::HandshakeWebsocket(
            const AppConfigurationPtr&                              configuration,
            const std::shared_ptr<ppp::net::asio::websocket>&       socket,
            HandshakeType                                           handshake_type,
            YieldContext&                                           y) noexcept {

            if (NULLPTR == configuration || NULLPTR == socket) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebsocketTransmissionHandshakeInvalidArguments);
                return false;
            }

            /**
             * @brief Uses instance overrides when both Host and Path are available.
             */
            ppp::string host = std::move(this->Host);
            ppp::string path = std::move(this->Path);

            if (host.size() > 0 && path.size() > 0) {
                bool ok = socket->Run(handshake_type, host, path, y);
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                }

                return ok;
            }
            else {
                auto& cfg = configuration->websocket;
                bool ok = socket->Run(handshake_type, cfg.host, cfg.path, y);
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                }

                return ok;
            }
        }

        /**
         * @brief Applies configured custom headers to websocket requests.
         */
        bool IWebsocketTransmission::Decorator(boost::beast::websocket::request_type& req) noexcept {
            auto configuration = GetConfiguration();
            if (NULLPTR == configuration) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
                return false;
            }

            return DecoratorWebsocketAllHeaders(configuration->websocket.http.request, req);
        }
        
        /**
         * @brief Applies configured custom headers/content to websocket responses.
         */
        bool IWebsocketTransmission::Decorator(boost::beast::websocket::response_type& res) noexcept {
            return DecoratorWebsocketResponseToWebclient(GetConfiguration(), res);
        }

        ISslWebsocketTransmission::ISslWebsocketTransmission(
            const ContextPtr&                                       context,
            const StrandPtr&                                        strand,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&    socket,
            const AppConfigurationPtr&                              configuration) noexcept
            : WebSocket(context, strand, socket, configuration) {

        }

        /**
         * @brief Performs TLS websocket handshake using override or configuration endpoint.
         */
        bool ISslWebsocketTransmission::HandshakeWebsocket(
            const AppConfigurationPtr&                              configuration,
            const std::shared_ptr<ppp::net::asio::sslwebsocket>&    socket,
            HandshakeType                                           handshake_type,
            YieldContext&                                           y) noexcept {

            if (NULLPTR == configuration || NULLPTR == socket) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebsocketTransmissionHandshakeInvalidArguments);
                return false;
            }

            /**
             * @brief Uses instance overrides when both Host and Path are available.
             */
            ppp::string host = std::move(this->Host);
            ppp::string path = std::move(this->Path);

            if (host.size() > 0 && path.size() > 0) {
                auto& cfg = configuration->websocket;
                bool ok = socket->Run(handshake_type,
                    host,
                    path,
                    cfg.ssl.verify_peer,
                    cfg.ssl.certificate_file,
                    cfg.ssl.certificate_key_file,
                    cfg.ssl.certificate_chain_file,
                    cfg.ssl.certificate_key_password,
                    cfg.ssl.ciphersuites,
                    y);
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                }

                return ok;
            }
            else {
                auto& cfg = configuration->websocket;
                bool ok = socket->Run(handshake_type,
                    cfg.host,
                    cfg.path,
                    cfg.ssl.verify_peer,
                    cfg.ssl.certificate_file,
                    cfg.ssl.certificate_key_file,
                    cfg.ssl.certificate_chain_file,
                    cfg.ssl.certificate_key_password,
                    cfg.ssl.ciphersuites,
                    y);
                if (!ok) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WebSocketHandshakeFailed);
                }

                return ok;
            }
        }

        /**
         * @brief Applies configured custom headers to TLS websocket requests.
         */
        bool ISslWebsocketTransmission::Decorator(boost::beast::websocket::request_type& req) noexcept {
            auto configuration = GetConfiguration();
            if (NULLPTR == configuration) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppContextUnavailable);
                return false;
            }

            return DecoratorWebsocketAllHeaders(configuration->websocket.http.request, req);
        }

        /**
         * @brief Applies configured custom headers/content to TLS websocket responses.
         */
        bool ISslWebsocketTransmission::Decorator(boost::beast::websocket::response_type& res) noexcept {
            return DecoratorWebsocketResponseToWebclient(GetConfiguration(), res);
        }
    }
}
