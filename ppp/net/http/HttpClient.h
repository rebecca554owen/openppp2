#pragma once

#include <ppp/stdafx.h>

/**
 * @file HttpClient.h
 * @brief Declares a lightweight HTTP/HTTPS client wrapper for simple GET and POST requests.
 */

namespace ppp {
    namespace net {
        namespace http {
            /**
             * @brief Minimal HTTP client with optional CA certificate verification support.
             */
            class HttpClient final {
            public:
                /**
                 * @brief Creates a client bound to a base host.
                 * @param host Base host URL accepted by cpp-httplib client constructor.
                 * @param cacert_path Optional path to a CA bundle file.
                 */
                HttpClient(const ppp::string& host, const ppp::string& cacert_path) noexcept;

            public:
                /**
                 * @brief Sends a GET request.
                 * @param api Request path or API endpoint.
                 * @param status Output HTTP status code.
                 * @return Response body, or empty string on failure.
                 */
                std::string                             Get(const ppp::string& api, int& status) noexcept { 
                    return this->HttpGetOrPostImpl(false, api, NULLPTR, 0, status); 
                }
                /**
                 * @brief Sends a POST request with form-urlencoded content type.
                 * @param api Request path or API endpoint.
                 * @param data Request body pointer.
                 * @param size Request body size.
                 * @param status Output HTTP status code.
                 * @return Response body, or empty string on failure.
                 */
                std::string                             Post(const ppp::string& api, const char* data, size_t size, int& status) noexcept { 
                    return this->HttpGetOrPostImpl(true, api, data, size, status); 
                }
                /**
                 * @brief Validates and decomposes an HTTP/HTTPS URL.
                 * @param url URL string to validate.
                 * @param host Optional output host.
                 * @param port Optional output port.
                 * @param path Optional output request path.
                 * @param https Optional output flag indicating HTTPS.
                 * @return true if parsing succeeds and protocol is HTTP(S); otherwise false.
                 */
                static bool                             VerifyUri(const ppp::string& url, ppp::string* host, int* port, ppp::string* path, bool* https) noexcept;

            private:
                /**
                 * @brief Shared implementation for GET and POST.
                 * @param post true for POST, false for GET.
                 * @param api Request path or endpoint.
                 * @param data Request body pointer for POST.
                 * @param size Request body size.
                 * @param status Output HTTP status code.
                 * @return Response body, or empty string on failure.
                 */
                std::string                             HttpGetOrPostImpl(bool post, const ppp::string& api, const char* data, size_t size, int& status) noexcept;

            private:        
                /** @brief Base host URL for requests. */
                ppp::string                             _host;
                /** @brief CA certificate file path. */
                ppp::string                             _cacert_path;
                /** @brief Indicates whether the CA certificate file exists. */
                bool                                    _cacert_exist = false;
            };
        }
    }
}
