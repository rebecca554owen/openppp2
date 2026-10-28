#pragma once

/**
 * @file HttpProxyUnavailableResponse.h
 * @brief Answers a local proxy client that arrives before the tunnel is ready.
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 */

#include <ppp/stdafx.h>

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief The response a local HTTP proxy sends while the session is down.
                 *
                 * @details A client that connects while the mux session is being rebuilt
                 *          used to get a bare connection reset: the accept path closed
                 *          the socket without writing anything, so the peer saw the
                 *          connection die before it could be served.  An HTTP client
                 *          can retry a 503; it can only fail on a reset.
                 *
                 * @return The response line set, ready to be written to a socket.
                 */
                inline const char* HttpProxyUnavailableResponse() noexcept {
                    // Content-Length: 0 keeps the response bodyless, so a proxy-aware
                    // client can parse it and retry without waiting for a payload.
                    return "HTTP/1.1 503 Service Unavailable\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n"
                           "\r\n";
                }

                /**
                 * @brief Writes a plain-text response to a client socket and closes it.
                 *
                 * @details The peer may already have sent its request bytes.  Closing a
                 *          socket that still holds unread data makes the kernel emit
                 *          RST, and the RST would discard the response just written,
                 *          so the incoming bytes are drained first.
                 *
                 * @param sockfd Accepted socket descriptor to answer and close.
                 * @param response Response text to send, or nullptr to close silently.
                 * @note The socket is always closed, even if the response cannot be
                 *       written in full.
                 */
                inline void WriteAndCloseProxySocket(int sockfd, const char* response) noexcept {
                    if (NULLPTR != response && '\x00' != *response) {
                        size_t length = ::strlen(response);
                        size_t offset = 0;

                        while (offset < length) {
                            ssize_t written = ::send(sockfd, response + offset, length - offset, MSG_NOSIGNAL);
                            if (written > 0) {
                                offset += (size_t)written;
                                continue;
                            }
                            if (written < 0 && (EAGAIN == errno || EWOULDBLOCK == errno)) {
                                struct pollfd pfd = { sockfd, POLLOUT, 0 };
                                ::poll(&pfd, 1, 50);
                                continue;
                            }
                            break;
                        }

                        // Half close so the peer reads the response and then sees EOF.
                        ::shutdown(sockfd, SHUT_WR);

                        // Drain what the peer already sent, so that close() below does
                        // not turn the connection into an RST.
                        char scratch[1024];
                        for (int i = 0; i < 8; i++) {
                            struct pollfd pfd = { sockfd, POLLIN, 0 };
                            if (::poll(&pfd, 1, 10) <= 0) {
                                break;
                            }
                            ssize_t received = ::recv(sockfd, scratch, sizeof(scratch), MSG_DONTWAIT);
                            if (received <= 0) {
                                break;
                            }
                        }
                    }

                    if (-1 != sockfd) {
                        ::close(sockfd);
                    }
                }
            }
        }
    }
}
