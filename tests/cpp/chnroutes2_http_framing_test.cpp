// chnroutes2_http_framing_test.cpp -- the route-list fetch has to frame its
// body exactly.
//
// Background:
//   The route list decides which destinations the client sends directly and
//   which ones it sends through the tunnel, so a body that is not framed
//   exactly must never be taken for a complete one:
//
//   1) The client used to read the response until the peer closed the
//      connection and to strip the headers, without ever looking at the
//      status line or at the announced length. The body of an error
//      response (a 404 page, a captive portal) was therefore parsed as a
//      route list, and a connection that ended early produced a truncated
//      route list that was applied as if it were complete.
//   2) The response was also read into memory without a bound, so a peer
//      that never ends its response exhausted the memory of the client.
//
// These helpers decide how the body of a response is framed. The behavioural
// cases live with the client itself; this file pins the rules.

#include <common/chnroutes2/chnroutes2_http_framing.h>

#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

} // namespace

int main() {
    try {
        // 1) The status line decides whether the body is a route list.
        Require(chnroutes2::StatusCode("HTTP/1.1 200 OK\r\n\r\n") == 200,
                "a success status line must be recognised");
        Require(chnroutes2::StatusCode("HTTP/1.0 200 OK\r\n\r\n") == 200,
                "HTTP/1.0 must be recognised too");
        Require(chnroutes2::StatusCode("HTTP/1.1 404 Not Found\r\n\r\n") == 404,
                "an error status must be reported, not hidden");
        Require(chnroutes2::StatusCode("HTTP/1.1 503 Service Unavailable\r\n\r\n") == 503,
                "an error status must be reported, not hidden");
        Require(chnroutes2::StatusCode("garbage\r\n\r\n") == 0,
                "a malformed status line must not be read as a status code");
        Require(chnroutes2::StatusCode("") == 0,
                "an empty response must not be read as a status code");
        Require(chnroutes2::StatusCode("HTTP/1.1 20 OK\r\n\r\n") == 0,
                "a status code that is not three digits must be rejected");

        // 2) The announced length is the framing of the body.
        long long length = -1;
        Require(chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n", length),
                "a well formed length must be accepted");
        Require(length == 1234, "the announced length must be reported");

        length = -1;
        Require(chnroutes2::ContentLength("HTTP/1.1 200 OK\r\ncontent-length: 7\r\n\r\n", length),
                "the header name is case insensitive");
        Require(length == 7, "the announced length must be reported");

        length = -1;
        Require(chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length:   42  \r\n\r\n", length),
                "the value may be padded");
        Require(length == 42, "the announced length must be reported");

        length = -1;
        Require(chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n", length),
                "a response without a length is framed by the end of the connection");
        Require(length == -1, "a response without a length must report -1");

        // 3) A framing that cannot be trusted is refused.
        length = -1;
        Require(!chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n", length),
                "a length that is not a number must be refused");
        Require(!chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n", length),
                "a negative length must be refused");
        Require(!chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n\r\n", length),
                "a length with trailing garbage must be refused");
        Require(!chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", length),
                "two different lengths make the framing ambiguous");
        Require(!chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", length),
                "a chunked body must be refused instead of mis-framed");
        Require(!chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length: 999999999999\r\n\r\n", length),
                "a length beyond the bound must be refused");

        length = -1;
        Require(chnroutes2::ContentLength("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n", length),
                "the same length twice is harmless");
        Require(length == 5, "the announced length must be reported");

        // 4) The bounds themselves.
        Require(chnroutes2::kMaxHeaderBytes > 0, "the header bound must be positive");
        Require(chnroutes2::kMaxBodyBytes > 0, "the body bound must be positive");
        Require(chnroutes2::kMaxBodyBytes >= 1024 * 1024,
                "the body bound has to fit the route list it fetches");

        std::cout << "chnroutes2_http_framing_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "chnroutes2_http_framing_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
