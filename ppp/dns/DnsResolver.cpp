#include <ppp/stdafx.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/ssl/SSL.h>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>

namespace ppp {
    namespace dns {

        static constexpr int PPP_DNS_RESOLVER_UDP_BUFFER_SIZE = 4096;
        static constexpr int PPP_DNS_RESOLVER_TCP_MAX_SIZE    = 65535;
        static constexpr int PPP_DNS_RESOLVER_TIMEOUT_MS      = 5000;

        typedef boost::asio::ip::udp udp;
        typedef boost::asio::ip::tcp tcp;

        static ppp::string NormalizeProviderName(const ppp::string& name) noexcept {
            return ToLower(ATrim(name));
        }

        static boost::asio::ip::address ParseAddressOnly(const ppp::string& address_text, boost::system::error_code& ec) noexcept {
            ppp::string text = ATrim(address_text);
            std::size_t colon = text.find(':');
            if (colon != ppp::string::npos && text.find(':', colon + 1) == ppp::string::npos) {
                text = text.substr(0, colon);
            }

            return StringToAddress(text, ec);
        }

        static int ParsePort(const ppp::string& address_text, int default_port) noexcept {
            ppp::string text = ATrim(address_text);
            std::size_t colon = text.find(':');
            if (colon == ppp::string::npos || text.find(':', colon + 1) != ppp::string::npos) {
                return default_port;
            }

            ppp::string port_text = ATrim(text.substr(colon + 1));
            if (port_text.empty()) {
                return default_port;
            }

            int port = atoi(port_text.data());
            return port > 0 && port <= UINT16_MAX ? port : default_port;
        }

        static ServerEntry MakeEntry(Protocol protocol, const char* address, const char* hostname = NULLPTR, const char* url = NULLPTR) noexcept {
            ServerEntry entry;
            entry.protocol = protocol;
            if (NULLPTR != address) {
                entry.address = address;
            }
            if (NULLPTR != hostname) {
                entry.hostname = hostname;
            }
            if (NULLPTR != url) {
                entry.url = url;
            }
            return entry;
        }

        static const ppp::unordered_map<ppp::string, ppp::vector<ServerEntry> >& Providers() noexcept {
            static const ppp::unordered_map<ppp::string, ppp::vector<ServerEntry> > providers = {
                { "doh.pub", {
                    MakeEntry(Protocol::DoH, "119.29.29.29:443", "doh.pub", "https://doh.pub/dns-query"),
                    MakeEntry(Protocol::DoT, "119.29.29.29:853", "dot.pub"),
                    MakeEntry(Protocol::TCP, "119.29.29.29:53"),
                    MakeEntry(Protocol::UDP, "119.29.29.29:53") } },
                { "alidns", {
                    MakeEntry(Protocol::DoH, "223.5.5.5:443", "dns.alidns.com", "https://dns.alidns.com/dns-query"),
                    MakeEntry(Protocol::DoT, "223.5.5.5:853", "dns.alidns.com"),
                    MakeEntry(Protocol::TCP, "223.5.5.5:53"),
                    MakeEntry(Protocol::UDP, "223.5.5.5:53") } },
                { "cloudflare", {
                    MakeEntry(Protocol::DoH, "1.1.1.1:443", "cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
                    MakeEntry(Protocol::DoT, "1.1.1.1:853", "cloudflare-dns.com"),
                    MakeEntry(Protocol::TCP, "1.1.1.1:53"),
                    MakeEntry(Protocol::UDP, "1.1.1.1:53") } },
                { "google", {
                    MakeEntry(Protocol::DoH, "8.8.8.8:443", "dns.google", "https://dns.google/dns-query"),
                    MakeEntry(Protocol::DoT, "8.8.8.8:853", "dns.google"),
                    MakeEntry(Protocol::TCP, "8.8.8.8:53"),
                    MakeEntry(Protocol::UDP, "8.8.8.8:53") } },
            };
            return providers;
        }

        struct CompletionState final {
            std::atomic<bool> completed{ false };
            DnsResolver::ResolveCallback callback;

            explicit CompletionState(const DnsResolver::ResolveCallback& cb) noexcept : callback(cb) {}

            void Complete(ppp::vector<Byte> response) noexcept {
                bool expected = false;
                if (!completed.compare_exchange_strong(expected, true)) {
                    return;
                }

                DnsResolver::ResolveCallback cb = std::move(callback);
                callback = NULLPTR;
                if (NULLPTR != cb) {
                    cb(std::move(response));
                }
            }
        };

        DnsResolver::DnsResolver(boost::asio::io_context& context) noexcept
            : context_(context) {
        }

        void DnsResolver::SetProtectSocketCallback(const ProtectSocketCallback& cb) noexcept {
            protect_socket_ = cb;
        }

        void DnsResolver::SetExitIP(const boost::asio::ip::address& ip) noexcept {
            exit_ip_ = ip;
        }

        void DnsResolver::SetEcsConfig(bool enabled, const ppp::string& override_ip) noexcept {
            ecs_enabled_ = enabled;
            ecs_override_ip_ = override_ip;
        }

        boost::asio::ip::address DnsResolver::GetEcsIp() const noexcept {
            // Priority 1: manual override_ip from configuration.
            if (!ecs_override_ip_.empty()) {
                boost::system::error_code ec;
                boost::asio::ip::address addr = StringToAddress(ecs_override_ip_.data(), ec);
                if (!ec && addr.is_v4() && !addr.is_unspecified()) {
                    return addr;
                }
            }

            // Priority 2: exit_ip from server (ClientExitIP / SetExitIP).
            if (exit_ip_.is_v4() && !exit_ip_.is_unspecified()) {
                return exit_ip_;
            }

            return boost::asio::ip::address();
        }

        void DnsResolver::SetDefaultProviders(const ppp::string& domestic, const ppp::string& foreign) noexcept {
            default_domestic_ = domestic;
            default_foreign_  = foreign;
        }

        void DnsResolver::ResolveAsyncWithFallback(
            const ppp::string& provider_name,
            const ppp::string& fallback1,
            const ppp::string& fallback2,
            const Byte* packet,
            int length,
            const ResolveCallback& callback) noexcept {

            if (NULLPTR == callback) {
                return;
            }

            if (NULLPTR == packet || length <= 0) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // Copy packet data once for the entire fallback chain.
            auto packet_copy = make_shared_object<ppp::vector<Byte> >();
            if (NULLPTR == packet_copy) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }
            try {
                packet_copy->assign(packet, packet + length);
            }
            catch (const std::exception&) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // Build ordered list of non-empty, registered provider names.
            ppp::vector<ppp::string> candidates;
            if (!provider_name.empty() && HasProvider(provider_name)) {
                candidates.emplace_back(provider_name);
            }
            if (!fallback1.empty() && HasProvider(fallback1)) {
                candidates.emplace_back(fallback1);
            }
            if (!fallback2.empty() && HasProvider(fallback2)) {
                candidates.emplace_back(fallback2);
            }

            if (candidates.empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // Build the fallback chain from last to first.
            //
            // Chain structure (bottom-up wrapping):
            //   layer[i] = try candidates[i], on success → callback, on fail → layer[i+1]
            //
            // We use shared_ptr<ResolveCallback> to keep each layer alive through
            // async hand-offs without dangling references.
            auto resolver_weak = weak_from_this();

            // Terminal: invoke the caller's callback.
            std::shared_ptr<ResolveCallback> chain = make_shared_object<ResolveCallback>(
                [callback](ppp::vector<Byte> response) noexcept {
                    callback(std::move(response));
                });
            if (NULLPTR == chain) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            for (int i = static_cast<int>(candidates.size()) - 1; i >= 0; --i) {
                ppp::string name = candidates[static_cast<std::size_t>(i)];
                std::shared_ptr<ResolveCallback> next = std::move(chain);
                chain = make_shared_object<ResolveCallback>();
                if (NULLPTR == chain) {
                    // Fallback: invoke callback with empty on allocation failure.
                    boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                    return;
                }

                *chain = [resolver_weak, name, packet_copy, next](ppp::vector<Byte> response) noexcept {
                    if (!response.empty()) {
                        (*next)(std::move(response));
                        return;
                    }

                    // Current provider failed; try via ResolveAsync which itself
                    // falls through all protocols (DoH→DoT→TCP→UDP) for this provider.
                    std::shared_ptr<DnsResolver> resolver = resolver_weak.lock();
                    if (NULLPTR == resolver) {
                        (*next)(ppp::vector<Byte>());
                        return;
                    }

                    resolver->ResolveAsync(name, false,
                        packet_copy->data(), static_cast<int>(packet_copy->size()),
                        [next](ppp::vector<Byte> inner_response) noexcept {
                            if (!inner_response.empty()) {
                                (*next)(std::move(inner_response));
                            }
                            else {
                                // All protocols for this provider failed.
                                (*next)(ppp::vector<Byte>());
                            }
                        });
                };
            }

            // Kick off: try the first candidate (chain[0]).
            (*chain)(ppp::vector<Byte>());
        }

        bool DnsResolver::HasProvider(const ppp::string& name) noexcept {
            return NULLPTR != GetProvider(name);
        }

        const ppp::vector<ServerEntry>* DnsResolver::GetProvider(const ppp::string& name) noexcept {
            ppp::string key = NormalizeProviderName(name);
            const auto& providers = Providers();
            auto tail = providers.find(key);
            return tail == providers.end() ? NULLPTR : &tail->second;
        }

        void DnsResolver::ResolveAsync(const ppp::string& provider_name, bool domestic, const Byte* packet, int length, const ResolveCallback& callback) noexcept {
            if (NULLPTR == callback) {
                return;
            }

            if (NULLPTR == packet || length <= 0 || length > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            const ppp::vector<ServerEntry>* provider = GetProvider(provider_name);
            if (NULLPTR == provider || provider->empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            std::shared_ptr<ppp::vector<Byte> > request = make_shared_object<ppp::vector<Byte> >();
            std::shared_ptr<ppp::vector<ServerEntry> > entries = make_shared_object<ppp::vector<ServerEntry> >();
            if (NULLPTR == request || NULLPTR == entries) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            try {
                request->assign(packet, packet + length);
                *entries = *provider;
            }
            catch (const std::exception&) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // EDNS Client Subnet (ECS) injection for domestic queries.
            // When ecs_enabled_ is true and the query is domestic, append an
            // OPT RR containing the ECS option so that authoritative servers
            // can return geo-optimised answers.
            if (ecs_enabled_ && domestic) {
                boost::asio::ip::address ecs_ip = GetEcsIp();
                if (ecs_ip.is_v4() && !ecs_ip.is_unspecified()) {
                    InjectEcsOptRr(*request, ecs_ip);
                    // InjectEcsOptRr is best-effort: failure simply means the
                    // query is sent without ECS.  The packet is never corrupted.
                }
            }

            TryProtocols(entries, 0, request, callback);
        }

        bool DnsResolver::ProtectSocket(int native_handle) noexcept {
            if (NULLPTR == protect_socket_) {
                return true;
            }

            try {
                return protect_socket_(native_handle);
            }
            catch (const std::exception&) {
                return false;
            }
        }

        void DnsResolver::TryProtocols(std::shared_ptr<ppp::vector<ServerEntry> > entries, std::size_t index, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            if (NULLPTR == entries || NULLPTR == packet || index >= entries->size()) {
                callback(ppp::vector<Byte>());
                return;
            }

            std::weak_ptr<DnsResolver> weak_self = weak_from_this();
            ResolveCallback next = [weak_self, entries, index, packet, callback](ppp::vector<Byte> response) noexcept {
                if (!response.empty()) {
                    callback(std::move(response));
                    return;
                }

                std::shared_ptr<DnsResolver> self = weak_self.lock();
                if (NULLPTR == self) {
                    callback(ppp::vector<Byte>());
                    return;
                }

                self->TryProtocols(entries, index + 1, packet, callback);
            };

            const ServerEntry& entry = (*entries)[index];
            switch (entry.protocol) {
            case Protocol::UDP:
                SendUdp(entry, packet, next);
                break;
            case Protocol::TCP:
                SendTcp(entry, packet, next);
                break;
            case Protocol::DoH:
                SendDoh(entry, packet, next);
                break;
            case Protocol::DoT:
                SendDot(entry, packet, next);
                break;
            default:
                next(ppp::vector<Byte>());
                break;
            }
        }

        void DnsResolver::SendDoh(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            /* Parse the DoH URL to extract host and path. */
            ppp::string url = ATrim(entry.url);
            if (url.empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            ppp::string host;
            ppp::string path;
            {
                /* Strip https:// prefix. */
                const char* https_prefix = "https://";
                std::size_t scheme_pos = url.find(https_prefix);
                if (scheme_pos == ppp::string::npos) {
                    boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                    return;
                }
                ppp::string remainder = url.substr(scheme_pos + strlen(https_prefix));

                /* Split host and path. */
                std::size_t slash_pos = remainder.find('/');
                if (slash_pos == ppp::string::npos) {
                    host = remainder;
                    path = "/";
                }
                else {
                    host = remainder.substr(0, slash_pos);
                    path = remainder.substr(slash_pos);
                }

                /* Strip port from host if present (e.g. "dns.example.com:443"). */
                std::size_t colon_pos = host.find(':');
                if (colon_pos != ppp::string::npos) {
                    host = host.substr(0, colon_pos);
                }

                if (host.empty()) {
                    boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                    return;
                }
            }

            boost::system::error_code ec;
            boost::asio::ip::address ip = ParseAddressOnly(entry.address, ec);
            if (ec || ip.is_unspecified()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            tcp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, 443)));
            std::shared_ptr<tcp::socket> socket = make_shared_object<tcp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            if (NULLPTR == socket || NULLPTR == timer || NULLPTR == state) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            socket->open(remote.protocol(), ec);
            if (ec) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            /* Create TLS 1.2+ client context with system/bundled CA verification enabled. */
            std::shared_ptr<boost::asio::ssl::context> ssl_ctx = ppp::ssl::SSL::CreateClientSslContext(
                ppp::ssl::SSL::SSL_METHOD::tlsv12, tls_verify_peer_, std::string());
            if (NULLPTR == ssl_ctx) {
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            std::shared_ptr<boost::asio::ssl::stream<tcp::socket> > stream =
                make_shared_object<boost::asio::ssl::stream<tcp::socket> >(std::move(*socket), *ssl_ctx);
            if (NULLPTR == stream) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            /* SNI: use the URL host (or entry.hostname fallback) for TLS Server Name Indication. */
            ppp::string sni_name = !entry.hostname.empty() ? entry.hostname : host;
            if (!sni_name.empty()) {
                SSL_set_tlsext_host_name(stream->native_handle(), sni_name.data());
                if (tls_verify_peer_) {
                    stream->set_verify_callback(boost::asio::ssl::host_name_verification(stl::transform<std::string>(sni_name)));
                }
            }

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TIMEOUT_MS));
            timer->async_wait([stream, state](const boost::system::error_code& ec_) noexcept {
                if (!ec_) {
                    boost::system::error_code ignored;
                    stream->lowest_layer().close(ignored);
                    state->Complete(ppp::vector<Byte>());
                }
            });

            stream->lowest_layer().async_connect(remote,
                [stream, timer, packet, state, host, path, sni_name](const boost::system::error_code& connect_ec) noexcept {
                    if (connect_ec) {
                        boost::system::error_code ignored;
                        stream->lowest_layer().close(ignored);
                        ppp::net::Socket::Cancel(*timer);
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    stream->async_handshake(boost::asio::ssl::stream_base::client,
                        [stream, timer, packet, state, host, path, sni_name](const boost::system::error_code& handshake_ec) noexcept {
                            if (handshake_ec) {
                                boost::system::error_code ignored;
                                stream->lowest_layer().close(ignored);
                                ppp::net::Socket::Cancel(*timer);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            /* Build HTTP/1.1 POST request with DNS wire-format body. */
                            typedef boost::beast::http::request<boost::beast::http::string_body> http_request_t;
                            std::shared_ptr<http_request_t> http_req = make_shared_object<http_request_t>();
                            std::shared_ptr<boost::beast::flat_buffer> read_buf = make_shared_object<boost::beast::flat_buffer>();
                            std::shared_ptr<boost::beast::http::response<boost::beast::http::string_body> > http_res =
                                make_shared_object<boost::beast::http::response<boost::beast::http::string_body> >();
                            if (NULLPTR == http_req || NULLPTR == read_buf || NULLPTR == http_res) {
                                boost::system::error_code ignored;
                                stream->lowest_layer().close(ignored);
                                ppp::net::Socket::Cancel(*timer);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            try {
                                http_req->method(boost::beast::http::verb::post);
                                http_req->target(path);
                                http_req->version(11);
                                http_req->set(boost::beast::http::field::host, host);
                                http_req->set(boost::beast::http::field::content_type, "application/dns-message");
                                http_req->set(boost::beast::http::field::accept, "application/dns-message");
                                http_req->body().assign(packet->begin(), packet->end());
                                http_req->prepare_payload();
                            }
                            catch (const std::exception&) {
                                boost::system::error_code ignored;
                                stream->lowest_layer().close(ignored);
                                ppp::net::Socket::Cancel(*timer);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            /* Send HTTP request. */
                            boost::beast::http::async_write(*stream, *http_req,
                                [stream, timer, http_req, read_buf, http_res, state](const boost::system::error_code& write_ec, std::size_t) noexcept {
                                    if (write_ec) {
                                        boost::system::error_code ignored;
                                        stream->lowest_layer().close(ignored);
                                        ppp::net::Socket::Cancel(*timer);
                                        state->Complete(ppp::vector<Byte>());
                                        return;
                                    }

                                    /* Read HTTP response. */
                                    boost::beast::http::async_read(*stream, *read_buf, *http_res,
                                        [stream, timer, http_res, state](const boost::system::error_code& read_ec, std::size_t) noexcept {
                                            boost::system::error_code ignored;
                                            stream->lowest_layer().close(ignored);
                                            ppp::net::Socket::Cancel(*timer);
                                            if (read_ec) {
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            if (http_res->result_int() != 200 || http_res->body().empty()) {
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            const std::string& body = http_res->body();
                                            try {
                                                ppp::vector<Byte> response(body.begin(), body.end());
                                                state->Complete(std::move(response));
                                            }
                                            catch (const std::exception&) {
                                                state->Complete(ppp::vector<Byte>());
                                            }
                                        });
                                });
                        });
                });
        }

        void DnsResolver::SendDot(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            boost::system::error_code ec;
            boost::asio::ip::address ip = ParseAddressOnly(entry.address, ec);
            if (ec || ip.is_unspecified()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            tcp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, 853)));
            std::shared_ptr<tcp::socket> socket = make_shared_object<tcp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            std::shared_ptr<ppp::vector<Byte> > request = make_shared_object<ppp::vector<Byte> >();
            std::shared_ptr<std::array<Byte, 2> > length_buffer = make_shared_object<std::array<Byte, 2> >();
            if (NULLPTR == socket || NULLPTR == timer || NULLPTR == state || NULLPTR == request || NULLPTR == length_buffer) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            /* Build DNS-over-TCP request: 2-byte big-endian length prefix + raw DNS query. */
            try {
                request->resize(packet->size() + 2);
                (*request)[0] = static_cast<Byte>((packet->size() >> 8) & 0xff);
                (*request)[1] = static_cast<Byte>(packet->size() & 0xff);
                memcpy(request->data() + 2, packet->data(), packet->size());
            }
            catch (const std::exception&) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            socket->open(remote.protocol(), ec);
            if (ec) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            /* Create a TLS 1.2+ client context with system/bundled CA verification enabled. */
            std::shared_ptr<boost::asio::ssl::context> ssl_ctx = ppp::ssl::SSL::CreateClientSslContext(
                ppp::ssl::SSL::SSL_METHOD::tlsv12, tls_verify_peer_, std::string());
            if (NULLPTR == ssl_ctx) {
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            std::shared_ptr<boost::asio::ssl::stream<tcp::socket> > stream =
                make_shared_object<boost::asio::ssl::stream<tcp::socket> >(std::move(*socket), *ssl_ctx);
            if (NULLPTR == stream) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            /* SNI: use entry.hostname for TLS Server Name Indication. */
            if (!entry.hostname.empty()) {
                SSL_set_tlsext_host_name(stream->native_handle(), entry.hostname.data());
                if (tls_verify_peer_) {
                    stream->set_verify_callback(boost::asio::ssl::host_name_verification(stl::transform<std::string>(entry.hostname)));
                }
            }

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TIMEOUT_MS));
            timer->async_wait([stream, state](const boost::system::error_code& ec_) noexcept {
                if (!ec_) {
                    boost::system::error_code ignored;
                    stream->lowest_layer().close(ignored);
                    state->Complete(ppp::vector<Byte>());
                }
            });

            stream->lowest_layer().async_connect(remote,
                [stream, timer, request, length_buffer, state, hostname = entry.hostname](const boost::system::error_code& connect_ec) noexcept {
                    if (connect_ec) {
                        boost::system::error_code ignored;
                        stream->lowest_layer().close(ignored);
                        ppp::net::Socket::Cancel(*timer);
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    /* Protect the connected socket before TLS handshake. */
                    stream->async_handshake(boost::asio::ssl::stream_base::client,
                        [stream, timer, request, length_buffer, state](const boost::system::error_code& handshake_ec) noexcept {
                            if (handshake_ec) {
                                boost::system::error_code ignored;
                                stream->lowest_layer().close(ignored);
                                ppp::net::Socket::Cancel(*timer);
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            /* Send: 2-byte length prefix + DNS query. */
                            boost::asio::async_write(*stream, boost::asio::buffer(request->data(), request->size()),
                                [stream, timer, length_buffer, state](const boost::system::error_code& write_ec, std::size_t) noexcept {
                                    if (write_ec) {
                                        boost::system::error_code ignored;
                                        stream->lowest_layer().close(ignored);
                                        ppp::net::Socket::Cancel(*timer);
                                        state->Complete(ppp::vector<Byte>());
                                        return;
                                    }

                                    /* Read: 2-byte response length prefix. */
                                    boost::asio::async_read(*stream, boost::asio::buffer(length_buffer->data(), length_buffer->size()),
                                        [stream, timer, length_buffer, state](const boost::system::error_code& read_len_ec, std::size_t) noexcept {
                                            if (read_len_ec) {
                                                boost::system::error_code ignored;
                                                stream->lowest_layer().close(ignored);
                                                ppp::net::Socket::Cancel(*timer);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            int response_size = (static_cast<int>((*length_buffer)[0]) << 8) | static_cast<int>((*length_buffer)[1]);
                                            if (response_size <= 0 || response_size > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                                                boost::system::error_code ignored;
                                                stream->lowest_layer().close(ignored);
                                                ppp::net::Socket::Cancel(*timer);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            std::shared_ptr<ppp::vector<Byte> > response = make_shared_object<ppp::vector<Byte> >(response_size);
                                            if (NULLPTR == response) {
                                                boost::system::error_code ignored;
                                                stream->lowest_layer().close(ignored);
                                                ppp::net::Socket::Cancel(*timer);
                                                state->Complete(ppp::vector<Byte>());
                                                return;
                                            }

                                            /* Read: response body. */
                                            boost::asio::async_read(*stream, boost::asio::buffer(response->data(), response->size()),
                                                [stream, timer, response, state](const boost::system::error_code& read_body_ec, std::size_t) noexcept {
                                                    boost::system::error_code ignored;
                                                    stream->lowest_layer().close(ignored);
                                                    ppp::net::Socket::Cancel(*timer);
                                                    if (read_body_ec) {
                                                        state->Complete(ppp::vector<Byte>());
                                                        return;
                                                    }

                                                    state->Complete(std::move(*response));
                                                });
                                        });
                                });
                        });
                });
        }

        void DnsResolver::SendUdp(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            boost::system::error_code ec;
            boost::asio::ip::address ip = ParseAddressOnly(entry.address, ec);
            if (ec || ip.is_unspecified()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            udp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, PPP_DNS_SYS_PORT)));
            std::shared_ptr<udp::socket> socket = make_shared_object<udp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<ppp::vector<Byte> > buffer = make_shared_object<ppp::vector<Byte> >(PPP_DNS_RESOLVER_UDP_BUFFER_SIZE);
            std::shared_ptr<udp::endpoint> source = make_shared_object<udp::endpoint>();
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            if (NULLPTR == socket || NULLPTR == timer || NULLPTR == buffer || NULLPTR == source || NULLPTR == state) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            socket->open(remote.protocol(), ec);
            if (ec) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TIMEOUT_MS));
            timer->async_wait([socket, state](const boost::system::error_code& ec_) noexcept {
                if (!ec_) {
                    ppp::net::Socket::Closesocket(socket);
                    state->Complete(ppp::vector<Byte>());
                }
            });

            socket->async_send_to(boost::asio::buffer(packet->data(), packet->size()), remote,
                [socket, timer, buffer, source, state](const boost::system::error_code& send_ec, std::size_t) noexcept {
                    if (send_ec) {
                        ppp::net::Socket::Closesocket(socket);
                        ppp::net::Socket::Cancel(*timer);
                        state->Complete(ppp::vector<Byte>());
                        return;
                    }

                    socket->async_receive_from(boost::asio::buffer(buffer->data(), buffer->size()), *source,
                        [socket, timer, buffer, state](const boost::system::error_code& recv_ec, std::size_t size) noexcept {
                            ppp::net::Socket::Cancel(*timer);
                            ppp::net::Socket::Closesocket(socket);
                            if (recv_ec || size < 1) {
                                state->Complete(ppp::vector<Byte>());
                                return;
                            }

                            try {
                                buffer->resize(size);
                                state->Complete(std::move(*buffer));
                            }
                            catch (const std::exception&) {
                                state->Complete(ppp::vector<Byte>());
                            }
                        });
                });
        }

        void DnsResolver::SendTcp(const ServerEntry& entry, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback) noexcept {
            boost::system::error_code ec;
            boost::asio::ip::address ip = ParseAddressOnly(entry.address, ec);
            if (ec || ip.is_unspecified()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            tcp::endpoint remote(ip, static_cast<unsigned short>(ParsePort(entry.address, PPP_DNS_SYS_PORT)));
            std::shared_ptr<tcp::socket> socket = make_shared_object<tcp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<CompletionState> state = make_shared_object<CompletionState>(callback);
            std::shared_ptr<ppp::vector<Byte> > request = make_shared_object<ppp::vector<Byte> >();
            std::shared_ptr<std::array<Byte, 2> > length_buffer = make_shared_object<std::array<Byte, 2> >();
            if (NULLPTR == socket || NULLPTR == timer || NULLPTR == state || NULLPTR == request || NULLPTR == length_buffer) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            try {
                request->resize(packet->size() + 2);
                (*request)[0] = static_cast<Byte>((packet->size() >> 8) & 0xff);
                (*request)[1] = static_cast<Byte>(packet->size() & 0xff);
                memcpy(request->data() + 2, packet->data(), packet->size());
            }
            catch (const std::exception&) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            socket->open(remote.protocol(), ec);
            if (ec) {
                state->Complete(ppp::vector<Byte>());
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), ip.is_v4());
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                ppp::net::Socket::Closesocket(socket);
                state->Complete(ppp::vector<Byte>());
                return;
            }

            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TIMEOUT_MS));
            timer->async_wait([socket, state](const boost::system::error_code& ec_) noexcept {
                if (!ec_) {
                    ppp::net::Socket::Closesocket(socket);
                    state->Complete(ppp::vector<Byte>());
                }
            });

            socket->async_connect(remote, [socket, timer, request, length_buffer, state](const boost::system::error_code& connect_ec) noexcept {
                if (connect_ec) {
                    ppp::net::Socket::Closesocket(socket);
                    ppp::net::Socket::Cancel(*timer);
                    state->Complete(ppp::vector<Byte>());
                    return;
                }

                boost::asio::async_write(*socket, boost::asio::buffer(request->data(), request->size()),
                    [socket, timer, length_buffer, state](const boost::system::error_code& write_ec, std::size_t) noexcept {
                        if (write_ec) {
                            ppp::net::Socket::Closesocket(socket);
                            ppp::net::Socket::Cancel(*timer);
                            state->Complete(ppp::vector<Byte>());
                            return;
                        }

                        boost::asio::async_read(*socket, boost::asio::buffer(length_buffer->data(), length_buffer->size()),
                            [socket, timer, length_buffer, state](const boost::system::error_code& read_len_ec, std::size_t) noexcept {
                                if (read_len_ec) {
                                    ppp::net::Socket::Closesocket(socket);
                                    ppp::net::Socket::Cancel(*timer);
                                    state->Complete(ppp::vector<Byte>());
                                    return;
                                }

                                int response_size = (static_cast<int>((*length_buffer)[0]) << 8) | static_cast<int>((*length_buffer)[1]);
                                if (response_size <= 0 || response_size > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                                    ppp::net::Socket::Closesocket(socket);
                                    ppp::net::Socket::Cancel(*timer);
                                    state->Complete(ppp::vector<Byte>());
                                    return;
                                }

                                std::shared_ptr<ppp::vector<Byte> > response = make_shared_object<ppp::vector<Byte> >(response_size);
                                if (NULLPTR == response) {
                                    ppp::net::Socket::Closesocket(socket);
                                    ppp::net::Socket::Cancel(*timer);
                                    state->Complete(ppp::vector<Byte>());
                                    return;
                                }

                                boost::asio::async_read(*socket, boost::asio::buffer(response->data(), response->size()),
                                    [socket, timer, response, state](const boost::system::error_code& read_body_ec, std::size_t) noexcept {
                                        ppp::net::Socket::Closesocket(socket);
                                        ppp::net::Socket::Cancel(*timer);
                                        if (read_body_ec) {
                                            state->Complete(ppp::vector<Byte>());
                                            return;
                                        }

                                        state->Complete(std::move(*response));
                                    });
                            });
                    });
            });
        }

        bool DnsResolver::InjectEcsOptRr(ppp::vector<Byte>& packet, const boost::asio::ip::address& ecs_ip) noexcept {
            // Minimal DNS header is 12 bytes.
            // ARCOUNT is at offset 10-11 (big-endian).
            static constexpr std::size_t kDnsHeaderSize = 12;
            // OPT RR fixed overhead: name(1) + type(2) + class(2) + ttl(4) + rdlength(2) = 11
            // ECS RDATA: option-code(2) + option-length(2) + family(2) + src-prefix(1) + scope-prefix(1) + addr(4) = 12
            // Total OPT RR size = 11 + 12 = 23 bytes
            static constexpr std::size_t kEcsOptRrSize = 23;

            if (packet.size() < kDnsHeaderSize) {
                return false;
            }

            // Read ARCOUNT (big-endian at offset 10).
            uint16_t arcount = (static_cast<uint16_t>(packet[10]) << 8) | static_cast<uint16_t>(packet[11]);

            // Conservative guard: if there are already additional records,
            // skip injection to avoid generating a double-OPT packet.
            // TODO: scan additional records for existing OPT RR (type 0x0029)
            //       and merge ECS into it when found.  For now, only inject
            //       when ARCOUNT == 0 (the common case for client queries).
            if (arcount > 0) {
                return false;
            }

            // Only support IPv4 for the first version.
            if (!ecs_ip.is_v4()) {
                return false;
            }

            // Ensure total size won't exceed the classic 512-byte UDP limit.
            // Larger packets are still valid for TCP/DoH/DoT, but many resolvers
            // enforce the limit on UDP.  We allow up to 512 to stay safe.
            if (packet.size() + kEcsOptRrSize > 512) {
                return false;
            }

            try {
                std::size_t old_size = packet.size();
                packet.resize(old_size + kEcsOptRrSize);
                Byte* p = packet.data() + old_size;

                // OPT RR header
                // Name: root (0x00)
                *p++ = 0x00;
                // Type: OPT (41 = 0x0029)
                *p++ = 0x00; *p++ = 0x29;
                // Class: UDP payload size (4096 = 0x1000)
                *p++ = 0x10; *p++ = 0x00;
                // TTL: extended-rcode(8) + version(8) + DO|Z(16) = all zero
                *p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;
                // RDLENGTH: 12 bytes of ECS RDATA
                *p++ = 0x00; *p++ = 0x0C;

                // ECS option RDATA (RFC 7871)
                // Option Code: ECS (8 = 0x0008)
                *p++ = 0x00; *p++ = 0x08;
                // Option Length: 8 bytes (family + prefix + scope + address)
                *p++ = 0x00; *p++ = 0x08;
                // Address Family: IPv4 (1 = 0x0001)
                *p++ = 0x00; *p++ = 0x01;
                // Source Prefix-Length: 24 (for /24 subnet)
                *p++ = 24;
                // Scope Prefix-Length: 0 (no scope)
                *p++ = 0;
                // Client IPv4 address (4 bytes, last byte zeroed for /24)
                boost::asio::ip::address_v4::bytes_type addr_bytes = ecs_ip.to_v4().to_bytes();
                *p++ = addr_bytes[0];
                *p++ = addr_bytes[1];
                *p++ = addr_bytes[2];
                *p++ = 0; // zero the last octet for /24 prefix

                // Increment ARCOUNT (big-endian at offset 10-11).
                arcount++;
                packet[10] = static_cast<Byte>((arcount >> 8) & 0xff);
                packet[11] = static_cast<Byte>(arcount & 0xff);

                return true;
            }
            catch (const std::exception&) {
                return false;
            }
        }

    } // namespace dns
} // namespace ppp
