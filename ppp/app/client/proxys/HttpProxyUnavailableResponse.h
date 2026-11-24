#pragma once

/**
 * @file HttpProxyUnavailableResponse.h
 * @brief Answers a local proxy client that arrives before the tunnel is ready.
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 */

#include <ppp/stdafx.h>

#include <errno.h>
#include <string.h>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {
                /**
                 * @brief The last error a socket call reported.
                 *
                 * @details Winsock reports through WSAGetLastError(), while the
                 *          POSIX sockets report through errno.  Reading the wrong
                 *          one leaves a would-block retry undetected, so the
                 *          write loop would give up instead of waiting.
                 */
                inline int ProxySocketLastError() noexcept {
#if defined(_WIN32)
                    return ::WSAGetLastError();
#else
                    return errno;
#endif
                }

                /**
                 * @brief Tells whether a socket error means "the socket is busy".
                 *
                 * @param error The value ProxySocketLastError() returned.
                 * @return true when the call may be retried after a short wait.
                 */
                inline bool ProxySocketWouldBlock(int error) noexcept {
#if defined(_WIN32)
                    return WSAEWOULDBLOCK == error || WSAEINPROGRESS == error;
#else
                    return EAGAIN == error || EWOULDBLOCK == error;
#endif
                }

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
                 * @brief Waits until a socket becomes readable or writable.
                 *
                 * @param sockfd Native socket descriptor.
                 * @param timeout_ms Upper bound on the wait.
                 * @param for_write true to wait for writability, false for readability.
                 * @return true when the socket became ready; false on timeout or error.
                 */
                inline bool WaitProxySocket(int sockfd, int timeout_ms, bool for_write) noexcept {
#if defined(_WIN32)
                    fd_set sockets;
                    FD_ZERO(&sockets);
                    FD_SET(static_cast<SOCKET>(sockfd), &sockets);
                    struct timeval tv;
                    tv.tv_sec = timeout_ms / 1000;
                    tv.tv_usec = (timeout_ms % 1000) * 1000;
                    // Winsock ignores the first argument; POSIX needs the highest
                    // descriptor plus one.
                    if (for_write) {
                        return ::select(0, NULLPTR, &sockets, NULLPTR, &tv) > 0;
                    }
                    return ::select(0, &sockets, NULLPTR, NULLPTR, &tv) > 0;
#else
                    fd_set sockets;
                    FD_ZERO(&sockets);
                    FD_SET(sockfd, &sockets);
                    struct timeval tv;
                    tv.tv_sec = timeout_ms / 1000;
                    tv.tv_usec = (timeout_ms % 1000) * 1000;
                    if (for_write) {
                        return ::select(sockfd + 1, NULLPTR, &sockets, NULLPTR, &tv) > 0;
                    }
                    return ::select(sockfd + 1, &sockets, NULLPTR, NULLPTR, &tv) > 0;
#endif
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

#if defined(MSG_NOSIGNAL)
                        // Linux needs the flag; macOS relies on SO_NOSIGPIPE, which
                        // the accept path already set on the socket.
                        static constexpr int kSendFlags = MSG_NOSIGNAL;
#else
                        static constexpr int kSendFlags = 0;
#endif
                        while (offset < length) {
#if defined(_WIN32)
                            // Winsock takes and returns an int length, while POSIX
                            // uses size_t and ssize_t.
                            const int written = ::send(static_cast<SOCKET>(sockfd),
                                response + offset,
                                static_cast<int>(length - offset),
                                kSendFlags);
#else
                            const ssize_t written = ::send(sockfd, response + offset, length - offset, kSendFlags);
#endif
                            if (written > 0) {
                                offset += (size_t)written;
                                continue;
                            }
                            if (written < 0 && ProxySocketWouldBlock(ProxySocketLastError())) {
                                if (!WaitProxySocket(sockfd, 50, true)) {
                                    break;
                                }
                                continue;
                            }
                            break;
                        }

                        // Half close so the peer reads the response and then sees EOF.
#if defined(_WIN32)
                        ::shutdown(static_cast<SOCKET>(sockfd), SD_SEND);
#else
                        ::shutdown(sockfd, SHUT_WR);
#endif

                        // Drain what the peer already sent, so that the close below
                        // does not turn the connection into an RST.
                        char scratch[1024];
                        for (int i = 0; i < 8; i++) {
                            if (!WaitProxySocket(sockfd, 10, false)) {
                                break;
                            }
#if defined(_WIN32)
                            const int received = ::recv(static_cast<SOCKET>(sockfd),
                                scratch,
                                static_cast<int>(sizeof(scratch)),
                                0);
#else
                            const ssize_t received = ::recv(sockfd, scratch, sizeof(scratch), 0);
#endif
                            if (received <= 0) {
                                break;
                            }
                        }
                    }

                    // Close the socket without pulling in Socket.cpp: this header is
                    // included by a standalone unit test that links no other source.
#if defined(_WIN32)
                    ::closesocket(static_cast<SOCKET>(sockfd));
#else
                    ::close(sockfd);
#endif
                }
            }
        }
    }
}
