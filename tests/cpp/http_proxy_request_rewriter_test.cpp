#define BOOST_TEST_MODULE http_proxy_request_rewriter_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/proxys/HttpProxyRequestRewriter.h>

#include <string>

namespace {

using ppp::app::client::proxys::HttpProxyRequestRewriter;

/**
 * @brief Runs the rewriter over a whole client->peer stream.
 * @param input Raw bytes a client would send on a reused proxy connection.
 * @return The bytes the proxy forwards upstream.
 */
std::string Rewrite(const std::string& input, int content_length = -1, int forwarded = 0,
                    bool chunked = false, bool upgrade = false) {
    HttpProxyRequestRewriter rewriter;
    rewriter.Seed(content_length, forwarded, chunked, upgrade);

    ppp::string out;
    rewriter.Consume(input.data(), static_cast<int>(input.size()), out);
    return std::string(out.data(), out.size());
}

} // namespace

/**
 * @brief The reported regression: a reused connection must still drop the
 *        absolute-form target (RFC 7230 5.3.2) before reaching the origin.
 */
BOOST_AUTO_TEST_CASE(absolute_form_is_converted_to_origin_form) {
    const std::string raw =
        "GET http://example.com/path?q=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    const std::string expected =
        "GET /path?q=1 HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    BOOST_TEST(Rewrite(raw) == expected);
}

/** @brief Every request of a keep-alive connection must be rewritten. */
BOOST_AUTO_TEST_CASE(every_pipelined_request_is_rewritten) {
    const std::string raw =
        "GET http://example.com/a HTTP/1.1\r\n\r\n"
        "GET http://example.com/b HTTP/1.1\r\n\r\n";

    const std::string expected =
        "GET /a HTTP/1.1\r\n\r\n"
        "GET /b HTTP/1.1\r\n\r\n";

    BOOST_TEST(Rewrite(raw) == expected);
}

/** @brief The rewrite must survive a request split across reads. */
BOOST_AUTO_TEST_CASE(split_reads_are_buffered) {
    HttpProxyRequestRewriter rewriter;
    rewriter.Seed(-1, 0, false, false);

    ppp::string out1;
    rewriter.Consume("GET http://example.com/", 23, out1);
    BOOST_TEST(out1.empty());

    ppp::string out2;
    rewriter.Consume("z HTTP/1.1\r\n\r\n", 14, out2);
    BOOST_TEST(std::string(out2.data(), out2.size()) == std::string("GET /z HTTP/1.1\r\n\r\n"));
}

/** @brief Hop-by-hop headers (RFC 7230 6.1) must be stripped, Host kept. */
BOOST_AUTO_TEST_CASE(hop_by_hop_headers_are_stripped) {
    const std::string raw =
        "GET http://example.com/ HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Connection: keep-alive\r\n"
        "TE: trailers\r\n"
        "\r\n";

    const std::string expected =
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    BOOST_TEST(Rewrite(raw) == expected);
}

/** @brief A Content-Length body must pass through verbatim, including a body
 *         that looks like an absolute-form request. */
BOOST_AUTO_TEST_CASE(content_length_body_is_passed_through) {
    const std::string body = "GET http://evil/ HTTP/1.1";
    const std::string raw =
        "POST http://example.com/upload HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" + body;

    const std::string expected =
        "POST /upload HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "\r\n" + body;

    BOOST_TEST(Rewrite(raw) == expected);
}

/** @brief Transfer-Encoding: chunked keeps its framing and the next request
 *         on the same connection is still rewritten. */
BOOST_AUTO_TEST_CASE(chunked_body_keeps_framing_and_next_request) {
    const std::string raw =
        "POST http://example.com/upload HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n"
        "GET http://example.com/next HTTP/1.1\r\n\r\n";

    const std::string expected =
        "POST /upload HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "5\r\nhello\r\n0\r\n\r\n"
        "GET /next HTTP/1.1\r\n\r\n";

    BOOST_TEST(Rewrite(raw) == expected);
}

/** @brief An Upgrade request switches the connection to verbatim passthrough
 *         so WebSocket et al. keep working. */
BOOST_AUTO_TEST_CASE(upgrade_switches_to_passthrough) {
    const std::string raw =
        "GET http://example.com/chat HTTP/1.1\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n"
        "\r\n"
        "GET http://example.com/still-raw HTTP/1.1\r\n\r\n";

    // Everything after the upgrade request head is relayed verbatim.
    const std::string out = Rewrite(raw);
    BOOST_TEST(out.find("GET /chat HTTP/1.1") != std::string::npos);
    BOOST_TEST(out.find("GET http://example.com/still-raw HTTP/1.1") != std::string::npos);
}

/** @brief Origin-form requests are forwarded unchanged. */
BOOST_AUTO_TEST_CASE(origin_form_is_unchanged) {
    const std::string raw =
        "GET /already-origin HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    BOOST_TEST(Rewrite(raw) == raw);
}

/**
 * @brief The reported SIGSEGV regression: a framing violation (repeated
 *        Content-Length, the RFC 9112 6.1 smuggling shape) makes Fail() flush
 *        line_ and the whole tail (p + i .. size) and switch to Passthrough.
 *        Consume must fall out of the loop immediately — the Passthrough
 *        branch at the top of the next iteration would otherwise append the
 *        same tail a second time, doubling the bytes on the wire.
 */
BOOST_AUTO_TEST_CASE(fail_path_emits_trailing_bytes_exactly_once) {
    const std::string head =
        "GET /a HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Length: 5\r\n"
        "Content-Length: 6\r\n";
    const std::string tail =
        "GET /b HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "\r\n";

    const std::string out = Rewrite(head + tail);

    // Everything through the violating header line is forwarded once, then the
    // remainder streams verbatim (Passthrough) — exactly once, never doubled.
    const std::string expected = head + tail;
    BOOST_TEST(out == expected);

    // Byte-count guard independent of the exact framing above: the first and
    // last occurrence of the tail request coincide iff it appears exactly once.
    BOOST_TEST(out.find("GET /b HTTP/1.1") != std::string::npos);
    BOOST_TEST(out.find("GET /b HTTP/1.1") == out.rfind("GET /b HTTP/1.1"));
}

/**
 * @brief Locks the kMaxLineBytes path: an over-long line without a terminating
 *        LF is cut off once and the remainder streams verbatim. This path
 *        returns directly from Consume (a different control flow than the
 *        EmitHeaderLine violations above) and must not double-emit either.
 */
BOOST_AUTO_TEST_CASE(overlong_line_is_flushed_once) {
    const std::string long_line(10000, 'X'); // > kMaxLineBytes (8192), no '\n'
    const std::string tail = "GET /b HTTP/1.1\r\n";

    const std::string out = Rewrite(long_line + tail);

    BOOST_TEST(out == long_line + tail);
}
