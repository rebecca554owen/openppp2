#pragma once

/**
 * @file HttpProxyRequestRewriter.h
 * @brief Streaming HTTP/1.1 request-target normaliser for the forward proxy.
 * @author("OPENPPP2 Team")
 * @license("GPL-3.0")
 */

#include <ppp/stdafx.h>
#include <algorithm>

namespace ppp {
    namespace app {
        namespace client {
            namespace proxys {                
                /**
                 * @brief Streaming HTTP/1.1 request-target normaliser for the forward proxy.
                 *
                 * The bridge transports relay client->peer bytes verbatim and only the first
                 * request of a connection is parsed by Handshake(). A client reusing the
                 * connection (keep-alive) therefore forwards its absolute-form request target
                 * (RFC 7230 5.3.2 proxy form) straight to the origin, which treats it as an
                 * origin-form path and answers 404. This rewriter consumes the client->peer
                 * stream and, for every request, converts the target back to origin-form and
                 * drops hop-by-hop headers (RFC 7230 6.1).
                 *
                 * The response direction is never touched, so the origin's framing and the
                 * end-to-end keep-alive semantics are preserved. A request asking for a
                 * protocol upgrade switches the connection to verbatim passthrough so that
                 * WebSocket and friends keep working.
                 */
                class HttpProxyRequestRewriter final {
                public:
                    HttpProxyRequestRewriter() noexcept = default;
                    ~HttpProxyRequestRewriter() noexcept = default;
                
                public:
                    /**
                     * @brief Arms the state machine once the first request has been forwarded.
                     * @param content_length First request Content-Length, or <0 when absent.
                     * @param body_bytes_forwarded Body bytes already forwarded with it.
                     * @param chunked First request used Transfer-Encoding: chunked.
                     * @param upgrade First request asked for a protocol upgrade.
                     * @return None.
                     */
                    void Seed(int content_length, int body_bytes_forwarded, bool chunked, bool upgrade) noexcept {
                        line_.clear();
                        hop_by_hop_.clear();
                        content_length_ = -1;
                        chunk_left_ = false;
                        upgrade_ = false;
                
                        if (upgrade) {
                            state_ = State::Passthrough;
                        }
                        elif(chunked) {
                            state_ = State::ChunkSize;
                        }
                        elif(content_length > body_bytes_forwarded) {
                            remaining_ = content_length - body_bytes_forwarded;
                            state_ = State::Body;
                        }
                        else {
                            state_ = State::RequestLine;
                        }
                    }
                
                    /**
                     * @brief Rewrites bytes read from the client and appends the result.
                     * @param data Incoming bytes.
                     * @param size Byte count.
                     * @param out Receives the bytes to forward; stays empty while buffering.
                     * @return None.
                     */
                    void Consume(const void* data, int size, ppp::string& out) noexcept {
                        const char* p = static_cast<const char*>(data);
                        int i = 0;
                        while (i < size) {
                            if (state_ == State::Passthrough) {
                                out.append(p + i, static_cast<std::size_t>(size - i));
                                return;
                            }
                
                            if (state_ == State::Body || state_ == State::ChunkData) {
                                int n = static_cast<int>(std::min<long long>(remaining_, size - i));
                                out.append(p + i, static_cast<std::size_t>(n));
                                i += n;
                                remaining_ -= n;
                                if (remaining_ <= 0) {
                                    state_ = (state_ == State::Body) ? State::RequestLine : State::ChunkDataCrlf;
                                }
                                continue;
                            }
                
                            char ch = p[i++];
                            line_.push_back(ch);
                            if (ch != '\n') {
                                continue;
                            }
                
                            if (state_ == State::RequestLine) {
                                EmitRequestLine(out);
                            }
                            elif(state_ == State::Headers) {
                                EmitHeaderLine(out);
                            }
                            elif(state_ == State::ChunkSize) {
                                EmitChunkSizeLine(out);
                            }
                            elif(state_ == State::ChunkDataCrlf) {
                                out.append(line_);
                                state_ = State::ChunkSize;
                            }
                            elif(state_ == State::ChunkTrailer) {
                                // The terminating CRLF is part of the chunked framing.
                                out.append(line_);
                                if (line_.size() <= 2) {
                                    state_ = State::RequestLine;
                                }
                            }
                
                            line_.clear();
                        }
                    }
                
                private:
                    enum class State { RequestLine, Headers, Body, ChunkSize, ChunkData, ChunkDataCrlf, ChunkTrailer, Passthrough };
                
                    static char ToLowerAsciiChar(char c) noexcept {
                        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
                    }
                
                    static ppp::string ToLowerAscii(ppp::string s) noexcept {
                        for (std::size_t i = 0, l = s.size(); i < l; ++i) {
                            s[i] = ToLowerAsciiChar(s[i]);
                        }
                        return s;
                    }
                
                    static ppp::string Trim(const ppp::string& s) noexcept {
                        std::size_t b = 0;
                        std::size_t e = s.size();
                        while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) {
                            ++b;
                        }
                        while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) {
                            --e;
                        }
                        return s.substr(b, e - b);
                    }
                
                    static bool IsHttpScheme(const char* s, int n) noexcept {
                        static const char kHttp[]  = "http://";
                        static const char kHttps[] = "https://";
                        if (n >= 7) {
                            bool m = true;
                            for (int i = 0; i < 7; ++i) { if (ToLowerAsciiChar(s[i]) != kHttp[i]) { m = false; break; } }
                            if (m) { return true; }
                        }
                        if (n >= 8) {
                            bool m = true;
                            for (int i = 0; i < 8; ++i) { if (ToLowerAsciiChar(s[i]) != kHttps[i]) { m = false; break; } }
                            if (m) { return true; }
                        }
                        return false;
                    }
                
                    static bool IsFixedHopByHop(const ppp::string& name) noexcept {
                        static const char* const kFixed[] = {
                            "connection", "proxy-connection", "keep-alive", "proxy-authenticate",
                            "proxy-authorization", "te", "trailer", "upgrade",
                        };
                        for (std::size_t i = 0; i < arraysizeof(kFixed); ++i) {
                            if (name == kFixed[i]) {
                                return true;
                            }
                        }
                        return false;
                    }
                
                    /** @brief Converts the buffered request line to origin-form. */
                    void EmitRequestLine(ppp::string& out) noexcept {
                        content_length_ = -1;
                        chunk_left_ = false;
                        upgrade_ = false;
                        hop_by_hop_.clear();
                
                        std::size_t s1 = line_.find(' ');
                        std::size_t s2 = (s1 == ppp::string::npos) ? ppp::string::npos : line_.find(' ', s1 + 1);
                        if (s1 == ppp::string::npos || s2 == ppp::string::npos) {
                            out.append(line_);
                            state_ = State::Headers;
                            return;
                        }
                
                        const char* target = line_.data() + s1 + 1;
                        int target_len = static_cast<int>(s2 - s1 - 1);
                        if (IsHttpScheme(target, target_len)) {
                            int sep = (target_len >= 8 && target[7] == '/') ? 8 : 7;
                            int path = -1;
                            for (int i = sep; i < target_len; ++i) {
                                if (target[i] == '/') { path = i; break; }
                            }
                
                            ppp::string rebuilt;
                            rebuilt.append(line_.data(), s1 + 1);
                            if (path < 0) {
                                rebuilt.append(1, '/');
                            }
                            else {
                                rebuilt.append(target + path, static_cast<std::size_t>(target_len - path));
                            }
                            rebuilt.append(line_.data() + s2, line_.size() - s2);
                            out.append(rebuilt);
                        }
                        else {
                            out.append(line_);
                        }
                
                        state_ = State::Headers;
                    }
                
                    /** @brief Filters one header line and drives the body framing. */
                    void EmitHeaderLine(ppp::string& out) noexcept {
                        if (line_.size() <= 2) {
                            out.append(line_);
                            if (upgrade_) {
                                state_ = State::Passthrough;
                            }
                            elif(chunk_left_) {
                                state_ = State::ChunkSize;
                            }
                            elif(content_length_ > 0) {
                                remaining_ = content_length_;
                                state_ = State::Body;
                            }
                            else {
                                state_ = State::RequestLine;
                            }
                            return;
                        }
                
                        std::size_t colon = line_.find(':');
                        if (colon == ppp::string::npos) {
                            out.append(line_);
                            return;
                        }
                
                        ppp::string name = ToLowerAscii(Trim(line_.substr(0, colon)));
                        ppp::string value = Trim(line_.substr(colon + 1));
                
                        if (name == "content-length") {
                            content_length_ = atoi(value.data());
                        }
                        elif(name == "transfer-encoding") {
                            if (ToLowerAscii(value).find("chunked") != ppp::string::npos) {
                                chunk_left_ = true;
                            }
                            out.append(line_);
                            return;
                        }
                        elif(name == "connection" || name == "proxy-connection") {
                            ppp::string lower = ToLowerAscii(value);
                            std::size_t b = 0;
                            for (;;) {
                                std::size_t e = lower.find(',', b);
                                if (e == ppp::string::npos) { e = lower.size(); }
                                ppp::string token = Trim(lower.substr(b, e - b));
                                if (!token.empty()) {
                                    if (token == "upgrade") { upgrade_ = true; }
                                    hop_by_hop_.push_back(token);
                                }
                                if (e >= lower.size()) { break; }
                                b = e + 1;
                            }
                            return;
                        }
                
                        if (IsFixedHopByHop(name) || std::find(hop_by_hop_.begin(), hop_by_hop_.end(), name) != hop_by_hop_.end()) {
                            if (name == "upgrade") { upgrade_ = true; }
                            return;
                        }
                
                        out.append(line_);
                    }
                
                    /** @brief Tracks chunked transfer framing. */
                    void EmitChunkSizeLine(ppp::string& out) noexcept {
                        out.append(line_);
                
                        std::size_t semi = line_.find(';');
                        ppp::string hex = Trim(line_.substr(0, (semi == ppp::string::npos) ? line_.size() : semi));
                        long long size = 0;
                        for (std::size_t i = 0, l = hex.size(); i < l; ++i) {
                            char c = hex[i];
                            int d = -1;
                            if (c >= '0' && c <= '9') { d = c - '0'; }
                            elif(c >= 'a' && c <= 'f') { d = c - 'a' + 10; }
                            elif(c >= 'A' && c <= 'F') { d = c - 'A' + 10; }
                            if (d < 0) { break; }
                            size = (size << 4) | d;
                        }
                
                        if (size <= 0) {
                            state_ = State::ChunkTrailer;
                        }
                        else {
                            remaining_ = size;
                            state_ = State::ChunkData;
                        }
                    }
                
                private:
                    State                               state_ = State::RequestLine;
                    ppp::string                         line_;
                    long long                           remaining_ = 0;
                    int                                 content_length_ = -1;
                    bool                                chunk_left_ = false;
                    bool                                upgrade_ = false;
                    std::vector<ppp::string>            hop_by_hop_; ///< Tokens named by Connection plus the fixed hop-by-hop set.
                };
                
            }
        }
    }
}
