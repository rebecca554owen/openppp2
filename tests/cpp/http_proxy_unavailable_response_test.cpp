#define BOOST_TEST_MODULE http_proxy_unavailable_response_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/client/proxys/HttpProxyUnavailableResponse.h>

#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

namespace {

using ppp::app::client::proxys::HttpProxyUnavailableResponse;
using ppp::app::client::proxys::WriteAndCloseProxySocket;

static const char* kUnavailableResponse = HttpProxyUnavailableResponse();

/**
 * @brief Reads everything the peer can still receive, then closes it.
 * @param fd Client side of the socket pair.
 * @return The bytes received before the peer closed the socket.
 */
std::string Drain(int fd) {
    std::string received;
    char buffer[512];
    for (;;) {
        ssize_t n = ::recv(fd, buffer, sizeof(buffer), 0);
        if (n <= 0) {
            break;
        }
        received.append(buffer, (size_t)n);
    }
    return received;
}

} // namespace

/**
 * @brief A client that arrives before the session is established must receive
 *        the response, not a bare connection reset.
 */
BOOST_AUTO_TEST_CASE(response_is_delivered_before_the_socket_is_closed) {
    int fds[2] = { -1, -1 };
    BOOST_TEST(0 == ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    WriteAndCloseProxySocket(fds[0], kUnavailableResponse);

    std::string received = Drain(fds[1]);
    ::close(fds[1]);

    BOOST_TEST(received.find("HTTP/1.1 503 Service Unavailable") != std::string::npos);
    BOOST_TEST(received.find("Content-Length: 0") != std::string::npos);
    BOOST_TEST(received.find("\r\n\r\n") != std::string::npos);
}

/**
 * @brief The peer may already have sent its request bytes.  Closing a socket
 *        that still holds unread data makes the kernel emit RST, which would
 *        discard the response, so the response must survive that case.
 */
BOOST_AUTO_TEST_CASE(unread_request_bytes_do_not_discard_the_response) {
    int fds[2] = { -1, -1 };
    BOOST_TEST(0 == ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    const char* request = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
    BOOST_TEST((ssize_t)strlen(request) == ::send(fds[1], request, strlen(request), 0));

    WriteAndCloseProxySocket(fds[0], kUnavailableResponse);

    std::string received = Drain(fds[1]);
    ::close(fds[1]);

    BOOST_TEST(received.find("HTTP/1.1 503 Service Unavailable") != std::string::npos);
}

/**
 * @brief A protocol that cannot answer before it is greeted (SOCKS) keeps the
 *        previous behaviour: close the socket without sending anything.
 */
BOOST_AUTO_TEST_CASE(null_response_closes_without_sending) {
    int fds[2] = { -1, -1 };
    BOOST_TEST(0 == ::socketpair(AF_UNIX, SOCK_STREAM, 0, fds));

    WriteAndCloseProxySocket(fds[0], NULLPTR);

    std::string received = Drain(fds[1]);
    ::close(fds[1]);

    BOOST_TEST(received.empty());
}
