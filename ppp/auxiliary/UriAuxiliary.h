#pragma once

#include <ppp/coroutines/YieldContext.h>

/**
 * @file UriAuxiliary.h
 * @brief URI encoding, decoding, and endpoint parsing helpers.
 */

namespace ppp {
    namespace auxiliary {
        /**
         * @brief Provides utility functions for URI processing.
         */
        class UriAuxiliary final {
        public:
            typedef ppp::coroutines::YieldContext       YieldContext;

        public:
            /**
             * @brief Percent-encodes a URI component.
             * @param input Source text to encode.
             * @return Encoded text.
             */
            static ppp::string                          Encode(const ppp::string& input) noexcept;
            /**
             * @brief Decodes a percent-encoded URI component.
             * @param input Encoded text.
             * @return Decoded text.
             */
            static ppp::string                          Decode(const ppp::string& input) noexcept;

        public:
            /**
             * @brief Protocol kinds recognized by URI parsing.
             */
            typedef enum {
                ProtocolType_Socks                      = -1,
                ProtocolType_PPP                        = 0,
                ProtocolType_Http,
                ProtocolType_HttpSSL,
                ProtocolType_WebSocket,
                ProtocolType_WebSocketSSL,
            }                                           ProtocolType;
            /**
             * @brief Parses a URI and resolves endpoint information.
             * @param url URI string to parse.
             * @param hostname Parsed host name.
             * @param address Parsed host address.
             * @param path Parsed URI path.
             * @param port Parsed port.
             * @param protocol Parsed protocol type.
             * @param y Coroutine yield context used for async resolution.
             * @return Empty string on success, otherwise an error message.
             */
            static ppp::string                          Parse(
                const ppp::string&                      url,
                ppp::string&                            hostname,
                ppp::string&                            address,
                ppp::string&                            path,
                int&                                    port,
                ProtocolType&                           protocol,
                YieldContext&                           y) noexcept;
            /**
             * @brief Parses a URI and optionally returns absolute URI text.
             * @param url URI string to parse.
             * @param hostname Parsed host name.
             * @param address Parsed host address.
             * @param path Parsed URI path.
             * @param port Parsed port.
             * @param protocol Parsed protocol type.
             * @param abs Optional output for absolute URI representation.
             * @param y Coroutine yield context used for async resolution.
             * @return Empty string on success, otherwise an error message.
             */
            static ppp::string                          Parse(
                const ppp::string&                      url,
                ppp::string&                            hostname,
                ppp::string&                            address,
                ppp::string&                            path,
                int&                                    port,
                ProtocolType&                           protocol,
                ppp::string*                            abs,
                YieldContext&                           y) noexcept;
            /**
             * @brief Parses a URI with explicit resolver behavior control.
             * @param url URI string to parse.
             * @param hostname Parsed host name.
             * @param address Parsed host address.
             * @param path Parsed URI path.
             * @param port Parsed port.
             * @param protocol Parsed protocol type.
             * @param abs Optional output for absolute URI representation.
             * @param y Coroutine yield context used for async resolution.
             * @param resolver True to perform host resolution.
             * @return Empty string on success, otherwise an error message.
             */
            static ppp::string                          Parse(
                const ppp::string&                      url,
                ppp::string&                            hostname,
                ppp::string&                            address,
                ppp::string&                            path,
                int&                                    port,
                ProtocolType&                           protocol,
                ppp::string*                            abs,
                YieldContext&                           y,
                bool                                    resolver) noexcept;
        };
    }
}
