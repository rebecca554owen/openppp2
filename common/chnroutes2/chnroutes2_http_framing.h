#pragma once

// Framing rules for one HTTP response of a route-list fetch.
//
// The route list decides which destinations the client sends directly and
// which ones it sends through the tunnel, so a body that is not framed
// exactly must never be taken for a complete one: a truncated route list
// silently changes the routing policy of the client, and a body that belongs
// to an error response is not a route list at all.
//
// These helpers decide how the body of a response is framed:
//   - a success status line, otherwise the body is not a route list;
//   - the announced Content-Length, which the body has to match exactly;
//   - a response that announces no length ends when the peer closes the
//     connection (the request asks for "Connection: close").
//
// The helpers are header-only and free of the project's stdafx, so they can
// be unit tested on their own.

#include <cstddef>
#include <string>

namespace chnroutes2 {

/** Upper bound for the response headers of a route-list fetch. */
inline constexpr std::size_t kMaxHeaderBytes = 64 * 1024;

/** Upper bound for the body of a route-list fetch (the APNIC file is about a megabyte). */
inline constexpr std::size_t kMaxBodyBytes = 32 * 1024 * 1024;

/**
 * @brief Compares a header name with a literal, ignoring the case.
 * @param left The header name.
 * @param right The literal to compare with (lower case).
 * @return True when both are the same name.
 */
inline bool EqualsIgnoreCase(const std::string& left, const char* right) noexcept {
    std::size_t i = 0;
    for (; i < left.size() && right[i] != '\x0'; ++i) {
        char a = left[i];
        char b = right[i];
        if (a >= 'A' && a <= 'Z') {
            a = static_cast<char>(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = static_cast<char>(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return i == left.size() && right[i] == '\x0';
}

/**
 * @brief Removes the spaces and tabs around a header value.
 * @param text The text to trim.
 * @return The trimmed text.
 */
inline std::string Trim(const std::string& text) noexcept {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t')) {
        ++begin;
    }
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t')) {
        --end;
    }
    return text.substr(begin, end - begin);
}

/**
 * @brief Returns the status code of an HTTP response header block.
 * @param headers The header block, status line first.
 * @return The status code, or 0 when the status line is missing or malformed.
 */
inline int StatusCode(const std::string& headers) noexcept {
    if (headers.size() < 12) {
        return 0;
    }
    if (!EqualsIgnoreCase(headers.substr(0, 5), "HTTP/")) {
        return 0;
    }

    const std::size_t line_end = headers.find("\r\n");
    const std::string status_line = headers.substr(0, line_end);
    const std::size_t first = status_line.find(' ');
    if (first == std::string::npos) {
        return 0;
    }

    const std::size_t second = status_line.find(' ', first + 1);
    const std::size_t code_end = (second == std::string::npos) ? status_line.size() : second;
    if (code_end - first - 1 != 3) {
        return 0;
    }

    int value = 0;
    for (std::size_t i = first + 1; i < code_end; ++i) {
        const char c = status_line[i];
        if (c < '0' || c > '9') {
            return 0;
        }
        value = value * 10 + (c - '0');
    }
    return value;
}

/**
 * @brief Reads the framing of an HTTP response header block.
 * @details A response that announces a length has to deliver exactly that
 *          many body bytes: the body is the route list, and a truncated one
 *          would be applied as if it were complete. A response that announces
 *          no length is read until the peer closes the connection.
 * @param headers The header block.
 * @param content_length Receives the announced body length, or -1 when the
 *        response announces none.
 * @return True when the body can be framed; false when the response cannot be
 *         used (a malformed or oversized length, conflicting lengths, or a
 *         chunked body this client does not decode).
 */
inline bool ContentLength(const std::string& headers, long long& content_length) noexcept {
    content_length = -1;

    std::size_t line_start = headers.find("\r\n");
    if (line_start == std::string::npos) {
        return false;
    }
    line_start += 2;

    bool seen = false;
    while (line_start < headers.size()) {
        std::size_t line_end = headers.find("\r\n", line_start);
        if (line_end == std::string::npos) {
            break;
        }
        const std::string line = headers.substr(line_start, line_end - line_start);
        line_start = line_end + 2;

        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        const std::string name = Trim(line.substr(0, colon));
        const std::string value = Trim(line.substr(colon + 1));

        if (EqualsIgnoreCase(name, "transfer-encoding")) {
            // A chunked body is not framed by a length and this client does
            // not decode it: the response is refused instead of mis-framed.
            return false;
        }

        if (EqualsIgnoreCase(name, "content-length")) {
            if (value.empty() || value.size() > 19) {
                return false;
            }
            long long parsed = 0;
            for (std::size_t i = 0; i < value.size(); ++i) {
                const char c = value[i];
                if (c < '0' || c > '9') {
                    return false;
                }
                parsed = parsed * 10 + (c - '0');
            }
            if (parsed > static_cast<long long>(kMaxBodyBytes)) {
                return false;
            }
            if (seen) {
                // The same length twice is harmless, two different lengths
                // make the framing ambiguous.
                if (content_length != parsed) {
                    return false;
                }
                continue;
            }
            content_length = parsed;
            seen = true;
        }
    }
    return true;
}

} // namespace chnroutes2
