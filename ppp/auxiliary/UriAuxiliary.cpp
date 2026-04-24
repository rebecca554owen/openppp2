/**
 * @file UriAuxiliary.cpp
 * @brief URI parsing and percent-encoding helper implementations.
 */
#include <ppp/auxiliary/UriAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>

#include <iostream>
#include <string>
#include <cctype>
#include <sstream>

namespace ppp {
    namespace auxiliary {
#if defined(_WIN32)
#pragma optimize("", off)
#pragma optimize("gsyb2", on) /* /O1 = /Og /Os /Oy /Ob2 /GF /Gy */
#else
// TRANSMISSIONO1 compiler macros are defined to perform O1 optimizations, 
// Otherwise gcc compiler version If <= 7.5.X, 
// The O1 optimization will also be applied, 
// And the other cases will not be optimized, 
// Because this will cause the program to crash, 
// Which is a fatal BUG caused by the gcc compiler optimization. 
// Higher-version compilers should not optimize the code for gcc compiling this section.
#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC push_options
#if defined(TRANSMISSION_O1) || (__GNUC__ < 7) || (__GNUC__ == 7 && __GNUC_MINOR__ <= 5) /* __GNUC_PATCHLEVEL__ */
#pragma GCC optimize("O1")
#else
#pragma GCC optimize("O0")
#endif
#endif
#endif
        /**
         * @brief Resolve host and port through Boost.Asio DNS resolver.
         * @param host_string Host name to resolve.
         * @param port_number Target port.
         * @param y Coroutine yield context.
         * @return Resolved endpoint, or invalid endpoint on failure.
         */
        static ppp::net::IPEndPoint UriAuxiliary_ResolveEndPointWithBoost(const ppp::string& host_string, int port_number, ppp::coroutines::YieldContext& y) noexcept {
            boost::asio::ip::udp::endpoint result = ppp::coroutines::asio::GetAddressByHostName<boost::asio::ip::udp>(host_string.data(), port_number, y);
            return ppp::net::IPEndPoint::ToEndPoint(result);
        }

        /**
         * @brief Resolve an endpoint from host/address text with optional DNS lookup.
         * @param host_string Host part from URI.
         * @param address_string Explicit address override if present.
         * @param port_number Parsed destination port.
         * @param y Coroutine yield context.
         * @param resolver Whether DNS fallback resolution is allowed.
         * @return Parsed or resolved endpoint.
         */
        static ppp::net::IPEndPoint UriAuxiliary_ResolveEndPoint(const ppp::string& host_string, const ppp::string& address_string, int port_number, ppp::coroutines::YieldContext& y, bool resolver) noexcept {
            ppp::net::IPEndPoint remoteEP(ppp::net::IPEndPoint::NoneAddress, port_number);
            if (address_string.empty()) {
                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(host_string.data(), ec);
                if (ec && resolver) {
                    ppp::coroutines::YieldContext* co = y.GetPtr();
                    if (co) {
                        remoteEP = UriAuxiliary_ResolveEndPointWithBoost(host_string, port_number, y);
                    }
                    else {
                        remoteEP = ppp::net::Ipep::GetEndPoint(host_string, port_number, true);
                    }
                }
                else {
                    remoteEP = ppp::net::IPEndPoint::ToEndPoint(boost::asio::ip::udp::endpoint(address, port_number));
                }
            }
            else {
                remoteEP = ppp::net::Ipep::GetEndPoint(address_string, port_number, false);
            }

            return remoteEP;
        }
#if defined(_WIN32)
#pragma optimize("", on)
#else
#if defined(__clang__)
#pragma clang optimize on
#else
#pragma GCC pop_options
#endif
#endif

        /**
         * @brief Parse URI and return normalized text.
         */
        ppp::string UriAuxiliary::Parse(
            const ppp::string&                                              url,
            ppp::string&                                                    hostname,
            ppp::string&                                                    address,
            ppp::string&                                                    path,
            int&                                                            port,
            ProtocolType&                                                   protocol,
            YieldContext&                                                   y) noexcept {

            ppp::string* abs = NULLPTR;
            return UriAuxiliary::Parse(url, hostname, address, path, port, protocol, abs, y);
        }

        /**
         * @brief Parse URI and optionally output absolute normalized URI.
         */
        ppp::string UriAuxiliary::Parse(
            const ppp::string&                                              url,
            ppp::string&                                                    hostname,
            ppp::string&                                                    address,
            ppp::string&                                                    path,
            int&                                                            port,
            ProtocolType&                                                   protocol,
            ppp::string*                                                    abs,
            YieldContext&                                                   y) noexcept {

            return UriAuxiliary::Parse(url, hostname, address, path, port, protocol, abs, y, true);
        }

        /**
         * @brief Parse URI components and normalize host/address/port fields.
         * @param url Input URI string.
         * @param hostname Output host name part.
         * @param address Output resolved/parsed address string.
         * @param path Output path part.
         * @param port Output port number.
         * @param protocol Output protocol type.
         * @param abs Optional output for normalized absolute URI.
         * @param y Coroutine yield context.
         * @param resolver Whether DNS resolution should be attempted.
         * @return Normalized URI string, or empty string on parse failure.
         */
        ppp::string UriAuxiliary::Parse(
            const ppp::string&                                              url,
            ppp::string&                                                    hostname,
            ppp::string&                                                    address,
            ppp::string&                                                    path,
            int&                                                            port,
            ProtocolType&                                                   protocol,
            ppp::string*                                                    abs,
            YieldContext&                                                   y,
            bool                                                            resolver) noexcept {

            using ppp::net::IPEndPoint;
            using ppp::net::Ipep;

            port = IPEndPoint::MinPort;
            hostname.clear();
            path.clear();
            address.clear();
            protocol = ProtocolType_PPP;

            if (url.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::GenericInvalidArgument, ppp::string());
            }

            ppp::string url_string = ToLower(LTrim(RTrim(url)));
            if (url_string.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::GenericInvalidArgument, ppp::string());
            }

            std::size_t scheme_sep = url_string.find("://");
            if (scheme_sep == ppp::string::npos) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::GenericParseFailed, ppp::string());
            }

            /**
             * @brief Accept only known protocol schemes and map them to ProtocolType.
             */
            ppp::string proto_string = url_string.substr(0, scheme_sep);
            ppp::string rest = url_string.substr(scheme_sep + 3); 

            ProtocolType protocol_type = ProtocolType_PPP;
            if (proto_string == "tcp" || proto_string == BOOST_BEAST_VERSION_STRING) {
                protocol_type = ProtocolType_PPP;
            }
            elif (proto_string == "ws") {
                protocol_type = ProtocolType_WebSocket;
            }
            elif (proto_string == "wss") {
                protocol_type = ProtocolType_WebSocketSSL;
            }
            elif (proto_string == "http") {
                protocol_type = ProtocolType_Http;
            }
            elif (proto_string == "https") {
                protocol_type = ProtocolType_HttpSSL;
            }
            elif (proto_string == "socks") {
                protocol_type = ProtocolType_Socks;
            }
            else {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkProtocolUnsupported, ppp::string());
            }

            ppp::string host_string;
            ppp::string path_string;
            std::size_t path_pos = rest.find('/');
            if (path_pos != ppp::string::npos) {
                host_string = rest.substr(0, path_pos);
                path_string = rest.substr(path_pos);
            }
            else {
                host_string = rest;
                path_string = "/";
            }

            int port_number = 0;
            std::size_t port_sep = host_string.rfind(':');
            if (port_sep != ppp::string::npos) {
                std::size_t right_bracket = host_string.rfind(']');
                if (right_bracket == ppp::string::npos || port_sep > right_bracket) {
                    /**
                     * @brief Parse explicit port and enforce valid endpoint bounds.
                     */
                    ppp::string port_str = host_string.substr(port_sep + 1);
                    port_str = LTrim(RTrim(port_str));

                    if (!port_str.empty()) {
                        char* end = NULLPTR;
                        long val = strtol(port_str.c_str(), &end, 10);

                        if (end == port_str.c_str() || *end != '\0' || val <= IPEndPoint::MinPort || val > IPEndPoint::MaxPort) {
                            return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid, ppp::string());
                        }

                        port_number = static_cast<int>(val);
                        host_string = host_string.substr(0, port_sep); 
                    }
                }
            }

            ppp::string address_string;
            std::size_t left_bracket = host_string.find('[');
            if (left_bracket != ppp::string::npos) {
                /**
                 * @brief Extract bracketed address payload (typically IPv6 literal).
                 */
                std::size_t right_bracket = host_string.find(']', left_bracket);
                if (right_bracket == ppp::string::npos || left_bracket > right_bracket) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::GenericParseFailed, ppp::string());
                }

                address_string = host_string.substr(left_bracket + 1, right_bracket - left_bracket - 1);
                host_string = host_string.substr(0, left_bracket) + host_string.substr(right_bracket + 1);
                host_string = LTrim(RTrim(host_string));
            }

            /**
             * @brief Assign default ports only for HTTP/WebSocket protocol families.
             */
            host_string = LTrim(RTrim(host_string));
            if (port_number <= IPEndPoint::MinPort || port_number > IPEndPoint::MaxPort) {
                if (protocol_type == ProtocolType_Http || protocol_type == ProtocolType_WebSocket) {
                    port_number = PPP_HTTP_SYS_PORT;
                }
                elif (protocol_type == ProtocolType_HttpSSL || protocol_type == ProtocolType_WebSocketSSL) {
                    port_number = PPP_HTTPS_SYS_PORT;
                }
                else {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid, ppp::string());
                }
            }

            IPEndPoint remoteEP = UriAuxiliary_ResolveEndPoint(host_string, address_string, port_number, y, resolver);
            if (!IPEndPoint::IsInvalid(remoteEP)) {
                address_string = remoteEP.ToAddressString();
            }

            if (host_string.empty()) {
                host_string = address_string;
            }

            hostname = host_string;
            address = address_string;
            path = path_string;
            port = port_number;
            protocol = protocol_type;

            /**
             * @brief Build normalized URI using bracket notation for IPv6 addresses.
             */
            ppp::string normalized = proto_string + "://";
            bool is_ipv6 = (address_string.find(':') != ppp::string::npos);  
            if (is_ipv6 && !address_string.empty()) {
                normalized += "[" + address_string + "]";
            }
            elif (!hostname.empty()) {
                normalized += hostname;
            }
            else {
                normalized += address_string;
            }

            normalized += ":" + stl::to_string<ppp::string>(port) + path_string;
            if (NULLPTR != abs) {
                ppp::string abs_string = proto_string + "://";
                if (is_ipv6 && !address_string.empty()) {
                    abs_string += "[" + address_string + "]";
                }
                elif (!hostname.empty()) {
                    abs_string += hostname;
                }
                else {
                    abs_string += address_string;
                }

                abs_string += ":" + stl::to_string<ppp::string>(port) + path_string;
                *abs = abs_string;
            }

            return normalized;
        }

        /**
         * @brief Percent-encode URI component text.
         * @param input Raw component text.
         * @return Encoded text where reserved bytes are escaped.
         */
        ppp::string UriAuxiliary::Encode(const ppp::string& input) noexcept {
            ppp::string encoded;
            for (std::size_t i = 0, length = input.length(); i < length; i++) {
                if (std::isalnum((unsigned char)input[i]) || (input[i] == '-') || (input[i] == '_') || (input[i] == '.') || (input[i] == '~')) {
                    encoded += input[i];
                }
                elif(input[i] == ' ') {
                    encoded += "+";
                }
                else {
                    encoded += '%';
                    encoded += StringAuxiliary::ToHex((unsigned char)input[i] >> 4);
                    encoded += StringAuxiliary::ToHex((unsigned char)input[i] % 16);
                }
            }

            return encoded;
        }

        /**
         * @brief Decode percent-encoded URI component text.
         * @param input Encoded component text.
         * @return Decoded text.
         */
        ppp::string UriAuxiliary::Decode(const ppp::string& input) noexcept {
            ppp::string decoded;
            for (std::size_t i = 0, length = input.length(); i < length; i++) {
                if (input[i] == '+') {
                    decoded += ' ';
                }
                elif(input[i] == '%') {
                    if ((i + 2) < length) {
                        unsigned char high = StringAuxiliary::FromHex((unsigned char)input[++i]);
                        unsigned char low = StringAuxiliary::FromHex((unsigned char)input[++i]);
                        decoded += high << 4 | low;
                    }
                    else {
                        break;
                    }
                }
                else {
                    decoded += input[i];
                }
            }
            
            return decoded;
        }
    }
}
