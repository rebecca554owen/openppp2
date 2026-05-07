#include <ppp/stdafx.h>
#include <ppp/dns/DnsResolver.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/ssl/SSL.h>
#include <ppp/diagnostics/Telemetry.h>

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
        static constexpr int PPP_DNS_RESOLVER_STUN_TIMEOUT_MS = 3000;

        using ppp::telemetry::Level;

        typedef boost::asio::ip::udp udp;
        typedef boost::asio::ip::tcp tcp;

        /* ========================================================================
         * STUN protocol constants (RFC 5389)
         * ======================================================================== */

        static constexpr uint16_t   kStunMsgTypeBindingRequest  = 0x0001;
        static constexpr uint16_t   kStunMsgTypeBindingResponse = 0x0101;
        static constexpr uint32_t   kStunMagicCookie            = 0x2112A442;
        static constexpr uint16_t   kStunAttrXorMappedAddr      = 0x0020;

        /* Default STUN candidate list — well-known public STUN servers.
         * IPs are hardcoded where possible to avoid DNS bootstrap dependency.
         * Hostname entries are resolved at runtime via bootstrap. */
        static const ppp::vector<StunCandidate>& DefaultStunCandidates() noexcept {
            static const ppp::vector<StunCandidate> candidates = [] {
                ppp::vector<StunCandidate> v;
                auto add = [&v](const char* ip, int port) noexcept {
                    boost::system::error_code ec;
                    boost::asio::ip::address a = StringToAddress(ip, ec);
                    if (!ec && !a.is_unspecified()) {
                        v.push_back({ a, port });
                    }
                };
                /* Google STUN servers */
                add("74.125.24.127",   19302);   /* stun.l.google.com:19302 */
                add("74.125.25.127",   19302);   /* stun2.l.google.com:19302 */
                add("173.194.76.127",  19302);   /* stun3.l.google.com:19302 */
                add("74.125.200.127",  19302);   /* stun4.l.google.com:19302 */
                /* Cloudflare STUN */
                add("162.159.200.123", 3478);    /* stun.cloudflare.com */
                /* Twilio STUN */
                add("54.241.125.61",   3478);    /* global.stun.twilio.com */
                add("35.155.227.88",   3478);    /* us1.stun.twilio.com */
                add("34.205.20.150",   3478);    /* us2.stun.twilio.com */
                add("54.169.62.43",    3478);    /* sg1.stun.twilio.com */
                add("13.115.118.38",   3478);    /* jp1.stun.twilio.com */
                return v;
            }();
            return candidates;
        }

        /* ========================================================================
         * DNS OPT RR constants (RFC 6891 / RFC 7871)
         * ======================================================================== */

        static constexpr std::size_t kDnsHeaderSize   = 12;
        static constexpr uint16_t    kOptType         = 41;
        static constexpr uint16_t    kEcsOptionCode   = 8;
        static constexpr std::size_t kEcsNewOptionLen = 8;    /* family(2) + prefix(1) + scope(1) + addr(4) */
        static constexpr std::size_t kEcsNewRdataLen  = 4 + kEcsNewOptionLen; /* opt-code(2) + opt-len(2) + data */
        static constexpr std::size_t kOptRrOverhead   = 11;   /* name(1) + type(2) + class(2) + ttl(4) + rdlen(2) */

        /* ========================================================================
         * DNS wire-format parsing helpers
         * ======================================================================== */

        /**
         * @brief Skips a DNS name (sequence of labels or a compression pointer)
         *        starting at position @p pos in @p data.
         *
         * @return Number of bytes consumed from position @p pos, or 0 on error.
         */
        static std::size_t SkipDnsName(const Byte* data, std::size_t size, std::size_t pos) noexcept {
            if (pos >= size) {
                return 0;
            }

            std::size_t consumed = 0;
            for (;;) {
                if (pos + consumed >= size) {
                    return 0;
                }

                Byte label = data[pos + consumed];
                if (label == 0x00) {
                    /* Root label — single null byte. */
                    return consumed + 1;
                }
                if ((label & 0xC0) == 0xC0) {
                    /* Compression pointer — two bytes. */
                    if (pos + consumed + 2 > size) {
                        return 0;
                    }
                    return consumed + 2;
                }

                /* Regular label: length byte + characters. */
                std::size_t label_len = static_cast<std::size_t>(label);
                if (label_len > 63) {
                    return 0; /* Invalid label length. */
                }

                consumed += 1 + label_len;
            }
        }

        /**
         * @brief Skips @p count DNS query (question) entries starting at @p pos.
         *
         * Each question entry consists of: name + QTYPE(2) + QCLASS(2).
         *
         * @return New position after skipping, or 0 on parse error.
         */
        static std::size_t SkipDnsQuestionSection(const Byte* data, std::size_t size, std::size_t pos, uint16_t count) noexcept {
            for (uint16_t i = 0; i < count; ++i) {
                std::size_t name_len = SkipDnsName(data, size, pos);
                if (name_len == 0) {
                    return 0;
                }
                pos += name_len;

                /* QTYPE(2) + QCLASS(2) = 4 bytes */
                if (pos + 4 > size) {
                    return 0;
                }
                pos += 4;
            }
            return pos;
        }

        /**
         * @brief Skips @p count DNS resource records (answers, authority, or additional).
         *
         * Each RR consists of: name + type(2) + class(2) + ttl(4) + rdlength(2) + RDATA(rdlength).
         *
         * @return New position after skipping, or 0 on parse error.
         */
        static std::size_t SkipDnsRrSection(const Byte* data, std::size_t size, std::size_t pos, uint16_t count) noexcept {
            for (uint16_t i = 0; i < count; ++i) {
                std::size_t name_len = SkipDnsName(data, size, pos);
                if (name_len == 0) {
                    return 0;
                }
                pos += name_len;

                /* type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes */
                if (pos + 10 > size) {
                    return 0;
                }

                uint16_t rdlength = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                     static_cast<uint16_t>(data[pos + 9]);
                pos += 10 + rdlength;
            }
            return pos;
        }

        /* ========================================================================
         * Original helper functions (unchanged)
         * ======================================================================== */

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

        /**
         * @brief Returns true when @p address_text is an IP literal with optional port.
         */
        static bool IsAddressLiteral(const ppp::string& address_text) noexcept {
            boost::system::error_code ec;
            boost::asio::ip::address ip = ParseAddressOnly(address_text, ec);
            return !ec && !ip.is_unspecified();
        }

        /**
         * @brief Appends built-in provider entries when text is a provider short-name.
         */
        static bool AppendProviderEntries(ppp::vector<ServerEntry>& entries, const ppp::string& provider_name) noexcept {
            const ppp::vector<ServerEntry>* provider = DnsResolver::GetProvider(provider_name);
            if (NULLPTR == provider) {
                return false;
            }

            entries.insert(entries.end(), provider->begin(), provider->end());
            return true;
        }

        /**
         * @brief Expands structured entries that use provider shorthand addresses.
         *
         * Configuration accepts string shorthand for dns.servers.domestic/foreign.
         * The config parser stores such strings as DnsServerEntry.address.  Without
         * this expansion, ResolveAsyncWithEntries() treats "cloudflare" or
         * "doh.pub" as UDP address literals, exhausts immediately, and unmatched
         * domains can fail while system DNS has already been pointed at the tunnel.
         */
        static ppp::vector<ServerEntry> ExpandResolverEntries(const ppp::vector<ServerEntry>& explicit_entries) noexcept {
            ppp::vector<ServerEntry> expanded;
            expanded.reserve(explicit_entries.size());

            for (const ServerEntry& entry : explicit_entries) {
                ppp::string provider_name = ATrim(entry.address);
                if (!provider_name.empty() && entry.url.empty() && entry.hostname.empty() && entry.bootstrap_ips.empty() && !IsAddressLiteral(provider_name)) {
                    if (AppendProviderEntries(expanded, provider_name)) {
                        continue;
                    }
                }

                expanded.emplace_back(entry);
            }

            return expanded;
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

        /* ========================================================================
         * Provider table — all 12 documented providers.
         * ======================================================================== */

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
                { "baidu", {
                    MakeEntry(Protocol::DoH, "180.76.76.76:443", "doh.baidu.com", "https://doh.baidu.com/dns-query"),
                    MakeEntry(Protocol::TCP, "180.76.76.76:53"),
                    MakeEntry(Protocol::UDP, "180.76.76.76:53") } },
                { "360", {
                    MakeEntry(Protocol::DoH, "101.226.4.6:443", "doh.360.cn", "https://doh.360.cn/dns-query"),
                    MakeEntry(Protocol::DoT, "101.226.4.6:853", "dns.360.cn"),
                    MakeEntry(Protocol::TCP, "101.226.4.6:53"),
                    MakeEntry(Protocol::UDP, "101.226.4.6:53") } },
                { "114", {
                    MakeEntry(Protocol::DoH, "114.114.114.114:443", "dns.114.com", "https://dns.114.com/dns-query"),
                    MakeEntry(Protocol::TCP, "114.114.114.114:53"),
                    MakeEntry(Protocol::UDP, "114.114.114.114:53") } },
                { "tuna", {
                    MakeEntry(Protocol::DoH, "101.6.6.6:443", "doh.tuna.tsinghua.edu.cn", "https://doh.tuna.tsinghua.edu.cn/dns-query"),
                    MakeEntry(Protocol::DoT, "101.6.6.6:853", "dns.tuna.tsinghua.edu.cn"),
                    MakeEntry(Protocol::TCP, "101.6.6.6:53"),
                    MakeEntry(Protocol::UDP, "101.6.6.6:53") } },
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
                { "quad9", {
                    MakeEntry(Protocol::DoH, "9.9.9.9:443", "dns.quad9.net", "https://dns.quad9.net/dns-query"),
                    MakeEntry(Protocol::DoT, "9.9.9.9:853", "dns.quad9.net"),
                    MakeEntry(Protocol::TCP, "9.9.9.9:53"),
                    MakeEntry(Protocol::UDP, "9.9.9.9:53") } },
                { "adguard", {
                    MakeEntry(Protocol::DoH, "94.140.14.14:443", "dns.adguard.com", "https://dns.adguard.com/dns-query"),
                    MakeEntry(Protocol::DoT, "94.140.14.14:853", "dns.adguard.com"),
                    MakeEntry(Protocol::TCP, "94.140.14.14:53"),
                    MakeEntry(Protocol::UDP, "94.140.14.14:53") } },
                { "nextdns", {
                    MakeEntry(Protocol::DoH, "45.90.28.0:443", "dns.nextdns.io", "https://dns.nextdns.io/dns-query"),
                    MakeEntry(Protocol::DoT, "45.90.28.0:853", "dns.nextdns.io"),
                    MakeEntry(Protocol::TCP, "45.90.28.0:53"),
                    MakeEntry(Protocol::UDP, "45.90.28.0:53") } },
                { "mullvad", {
                    MakeEntry(Protocol::DoH, "194.242.2.2:443", "dns.mullvad.net", "https://dns.mullvad.net/dns-query"),
                    MakeEntry(Protocol::DoT, "194.242.2.2:853", "dns.mullvad.net"),
                    MakeEntry(Protocol::TCP, "194.242.2.2:53"),
                    MakeEntry(Protocol::UDP, "194.242.2.2:53") } },
            };
            return providers;
        }

        /* ========================================================================
         * CompletionState — atomic once-invocation guard
         * ======================================================================== */

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

        /* ========================================================================
         * DnsResolver — constructor and property setters
         * ======================================================================== */

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

        void DnsResolver::SetStunCandidates(ppp::vector<StunCandidate> candidates) noexcept {
            stun_candidates_ = std::move(candidates);
            stun_rotation_.store(0, std::memory_order_relaxed);
        }

        /* ========================================================================
         * ResolveAsyncWithFallback — provider fallback chain
         * ======================================================================== */

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

                    // Preserve the domestic semantic across the fallback chain so
                    // ECS injection is applied for the domestic tier (per
                    // docs/DNS_MODULE_DESIGN.md).  The tier is classified as
                    // domestic when its provider short-name matches the value
                    // configured via SetDefaultProviders().  When SetDefaultProviders
                    // has not been called the default is empty and the comparison
                    // returns false, preserving prior behaviour.
                    bool tier_domestic = false;
                    if (!resolver->default_domestic_.empty()) {
                        tier_domestic = NormalizeProviderName(name) ==
                                        NormalizeProviderName(resolver->default_domestic_);
                    }

                    resolver->ResolveAsync(name, tier_domestic,
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

        /* ========================================================================
         * Provider lookup
         * ======================================================================== */

        bool DnsResolver::HasProvider(const ppp::string& name) noexcept {
            return NULLPTR != GetProvider(name);
        }

        const ppp::vector<ServerEntry>* DnsResolver::GetProvider(const ppp::string& name) noexcept {
            ppp::string key = NormalizeProviderName(name);
            const auto& providers = Providers();
            auto tail = providers.find(key);
            return tail == providers.end() ? NULLPTR : &tail->second;
        }

        /* ========================================================================
         * AAAA short-circuit helpers
         *
         * Walk the DNS query header + question section to identify AAAA queries
         * (QTYPE == 28) and synthesize an empty NOERROR response that mirrors
         * the original question. This lets callers avoid an upstream round-trip
         * when the local data plane has no IPv6 connectivity.
         * ======================================================================== */

        /**
         * @brief Parses the question section to locate QTYPE/QCLASS offsets.
         * @return Offset just past QTYPE+QCLASS (i.e. end of question section), or 0 on failure.
         */
        static int LocateQuestionEnd(const Byte* packet, int length) noexcept {
            if (NULLPTR == packet || length < 12) {
                return 0;
            }
            int idx = 12;
            while (idx < length) {
                Byte label_len = packet[idx];
                if (label_len == 0) {
                    idx += 1;
                    if (idx + 4 > length) {
                        return 0;
                    }
                    return idx + 4; // QTYPE(2) + QCLASS(2)
                }
                if ((label_len & 0xC0) != 0) {
                    // Compression pointer in question section is unusual; not supported here.
                    return 0;
                }
                idx += 1 + label_len;
                if (idx > length) {
                    return 0;
                }
            }
            return 0;
        }

        bool DnsResolver::IsAaaaQuery(const Byte* packet, int length) noexcept {
            int qend = LocateQuestionEnd(packet, length);
            if (qend == 0) {
                return false;
            }
            // QDCOUNT must equal 1 to safely interpret a single question.
            int qdcount = (static_cast<int>(packet[4]) << 8) | static_cast<int>(packet[5]);
            if (qdcount != 1) {
                return false;
            }
            // QR bit must be 0 (it is a query, not a response).
            if ((packet[2] & 0x80) != 0) {
                return false;
            }
            int qtype_off = qend - 4;
            int qtype = (static_cast<int>(packet[qtype_off]) << 8) | static_cast<int>(packet[qtype_off + 1]);
            return qtype == 28; // AAAA
        }

        ppp::vector<Byte> DnsResolver::BuildAaaaBlockedResponse(const Byte* packet, int length) noexcept {
            int qend = LocateQuestionEnd(packet, length);
            if (qend == 0) {
                return ppp::vector<Byte>();
            }

            ppp::vector<Byte> response(static_cast<std::size_t>(qend));
            std::memcpy(response.data(), packet, static_cast<std::size_t>(qend));

            // Header rewrite: QR=1, AA=0, TC=0, RA=1, Z=0, RCODE=0 (NOERROR).
            // Preserve the original ID and the RD bit (bit 0 of byte 2).
            Byte rd = static_cast<Byte>(response[2] & 0x01);
            response[2] = static_cast<Byte>(0x80 | rd); // QR=1 + RD copied
            response[3] = 0x80;                          // RA=1, Z=0, RCODE=NOERROR

            // Counts: QDCOUNT=1 (echoed), ANCOUNT=NSCOUNT=ARCOUNT=0.
            response[4] = 0; response[5] = 1;
            response[6] = 0; response[7] = 0;
            response[8] = 0; response[9] = 0;
            response[10] = 0; response[11] = 0;

            return response;
        }

        /* ========================================================================
         * ResolveAsync — single-provider, protocol-cascading resolution
         *
         * When ECS is enabled and the query is domestic, the ECS OPT RR is
         * injected/merged.  If no exit IP is available yet, STUN detection
         * is attempted first (async) to discover the client's public IP.
         * ======================================================================== */

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
                ppp::telemetry::Log(Level::kDebug, "dns", "provider not found: %s", provider_name.data());
                ppp::telemetry::Count("dns.resolve.provider_miss", 1);
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            ppp::telemetry::Log(Level::kDebug, "dns", "resolve start provider=%s domestic=%d", provider_name.data(), (int)domestic);
            ppp::telemetry::Count("dns.resolve.start", 1);

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
            // When ecs_enabled_ is true and the query is domestic, append/merge
            // an OPT RR containing the ECS option so that authoritative servers
            // can return geo-optimised answers.
            if (ecs_enabled_ && domestic) {
                boost::asio::ip::address ecs_ip = GetEcsIp();
                if (ecs_ip.is_v4() && !ecs_ip.is_unspecified()) {
                    InjectEcsOptRr(*request, ecs_ip);
                }
                else {
                    // No exit IP available yet — attempt STUN detection as a
                    // last-resort fallback before proceeding without ECS.
                    std::weak_ptr<DnsResolver> weak_self = weak_from_this();
                    DetectExitIPViaStun(
                        [weak_self, request, entries, callback](const boost::asio::ip::address& stun_ip) noexcept {
                            if (stun_ip.is_v4() && !stun_ip.is_unspecified()) {
                                InjectEcsOptRr(*request, stun_ip);
                            }
                            std::shared_ptr<DnsResolver> self = weak_self.lock();
                            if (NULLPTR == self) {
                                callback(ppp::vector<Byte>());
                                return;
                            }
                            self->TryProtocols(entries, 0, request, callback, true);
                        });
                    return; /* TryProtocols is invoked inside the STUN callback. */
                }
            }

            TryProtocols(entries, 0, request, callback, domestic);
        }

        /* ========================================================================
         * ResolveAsyncWithEntries — resolve via explicit server entries (Phase A)
         * ======================================================================== */

        void DnsResolver::ResolveAsyncWithEntries(
            const ppp::vector<ServerEntry>& explicit_entries,
            bool domestic,
            const Byte* packet,
            int length,
            const ResolveCallback& callback) noexcept {

            if (NULLPTR == callback) {
                return;
            }

            if (NULLPTR == packet || length <= 0 || length > PPP_DNS_RESOLVER_TCP_MAX_SIZE) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            if (explicit_entries.empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            ppp::telemetry::Log(Level::kDebug, "dns", "resolve entries start count=%d domestic=%d",
                (int)explicit_entries.size(), (int)domestic);
            ppp::telemetry::Count("dns.resolve.start", 1);

            auto request = make_shared_object<ppp::vector<Byte> >();
            auto entries = make_shared_object<ppp::vector<ServerEntry> >();
            if (NULLPTR == request || NULLPTR == entries) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            try {
                request->assign(packet, packet + length);
                *entries = ExpandResolverEntries(explicit_entries);
            }
            catch (const std::exception&) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            if (entries->empty()) {
                boost::asio::post(context_, [callback]() noexcept { callback(ppp::vector<Byte>()); });
                return;
            }

            // ECS injection for domestic queries.
            if (ecs_enabled_ && domestic) {
                boost::asio::ip::address ecs_ip = GetEcsIp();
                if (ecs_ip.is_v4() && !ecs_ip.is_unspecified()) {
                    InjectEcsOptRr(*request, ecs_ip);
                }
                else {
                    std::weak_ptr<DnsResolver> weak_self = weak_from_this();
                    DetectExitIPViaStun(
                        [weak_self, request, entries, callback](const boost::asio::ip::address& stun_ip) noexcept {
                            if (stun_ip.is_v4() && !stun_ip.is_unspecified()) {
                                InjectEcsOptRr(*request, stun_ip);
                            }
                            std::shared_ptr<DnsResolver> self = weak_self.lock();
                            if (NULLPTR == self) {
                                callback(ppp::vector<Byte>());
                                return;
                            }
                            self->TryProtocols(entries, 0, request, callback, true);
                        });
                    return;
                }
            }

            TryProtocols(entries, 0, request, callback, domestic);
        }

        /* ========================================================================
         * Socket protection helper
         * ======================================================================== */

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

        /* ========================================================================
         * TryProtocols — cascading protocol fallback for a single provider
         * ======================================================================== */

        void DnsResolver::TryProtocols(std::shared_ptr<ppp::vector<ServerEntry> > entries, std::size_t index, std::shared_ptr<ppp::vector<Byte> > packet, const ResolveCallback& callback, bool domestic) noexcept {
            if (NULLPTR == entries || NULLPTR == packet || index >= entries->size()) {
                ppp::telemetry::Log(Level::kDebug, "dns", "resolve failed: all entries exhausted");
                ppp::telemetry::Count("dns.resolve.failure", 1);
                callback(ppp::vector<Byte>());
                return;
            }

            const ServerEntry& entry = (*entries)[index];
            static const char* kProtoNames[] = { "UDP", "TCP", "DoH", "DoT" };
            ppp::telemetry::Log(Level::kTrace, "dns", "try protocol=%s entry=%zu/%zu",
                kProtoNames[static_cast<int>(entry.protocol)], index, entries->size());

            std::weak_ptr<DnsResolver> weak_self = weak_from_this();
            ResolveCallback next = [weak_self, entries, index, packet, callback, domestic](ppp::vector<Byte> response) noexcept {
                if (!response.empty()) {
                    ppp::telemetry::Log(Level::kDebug, "dns", "resolve success entry=%zu bytes=%zu", index, response.size());
                    ppp::telemetry::Count("dns.resolve.success", 1);
                    callback(std::move(response));
                    return;
                }

                ppp::telemetry::Log(Level::kTrace, "dns", "protocol fallback from entry=%zu", index);
                ppp::telemetry::Count("dns.resolve.fallback", 1);

                std::shared_ptr<DnsResolver> self = weak_self.lock();
                if (NULLPTR == self) {
                    callback(ppp::vector<Byte>());
                    return;
                }

                self->TryProtocols(entries, index + 1, packet, callback, domestic);
            };

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

        /* ========================================================================
         * SendDoh — DNS-over-HTTPS via Boost.Beast + TLS
         * ======================================================================== */

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

        /* ========================================================================
         * SendDot — DNS-over-TLS via Boost.Asio SSL stream
         * ======================================================================== */

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

        /* ========================================================================
         * SendUdp — plain DNS over UDP
         * ======================================================================== */

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

        /* ========================================================================
         * SendTcp — plain DNS over TCP (with 2-byte length prefix)
         * ======================================================================== */

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

        /* ========================================================================
         * InjectEcsOptRr — EDNS Client Subnet OPT RR injection / merge
         *
         * Behaviour:
         *   ARCOUNT == 0 : append a fresh OPT RR with ECS option.
         *   ARCOUNT >  0 : scan additional records for an existing OPT RR (TYPE=41
         *                  at root label).  If found, replace or append the ECS
         *                  option within its RDATA.  If the packet cannot be
         *                  safely parsed, return false (packet unchanged).
         * ======================================================================== */

        bool DnsResolver::InjectEcsOptRr(ppp::vector<Byte>& packet, const boost::asio::ip::address& ecs_ip) noexcept {
            if (packet.size() < kDnsHeaderSize) {
                return false;
            }

            // Only support IPv4 for ECS injection.
            if (!ecs_ip.is_v4()) {
                return false;
            }

            // Read ARCOUNT (big-endian at offset 10).
            uint16_t arcount = (static_cast<uint16_t>(packet[10]) << 8) | static_cast<uint16_t>(packet[11]);

            /* ---------------------------------------------------------------
             * Fast path: ARCOUNT == 0 — append a fresh OPT RR (original logic).
             * --------------------------------------------------------------- */
            if (arcount == 0) {
                // Total OPT RR size = overhead(11) + RDATA(kEcsNewRdataLen=12) = 23 bytes
                static constexpr std::size_t kFreshOptSize = kOptRrOverhead + kEcsNewRdataLen;

                // Ensure total size won't exceed the classic 512-byte UDP limit.
                if (packet.size() + kFreshOptSize > 512) {
                    return false;
                }

                try {
                    std::size_t old_size = packet.size();
                    packet.resize(old_size + kFreshOptSize);
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

            /* ---------------------------------------------------------------
             * Merge path: ARCOUNT > 0 — attempt to find existing OPT RR and
             * replace/append the ECS option within its RDATA.
             *
             * We must safely parse through QDCOUNT + ANCOUNT + NSCOUNT
             * sections to reach the additional records, then scan for the
             * first OPT RR (TYPE=41 at root label).
             * --------------------------------------------------------------- */

            // Read section counts from the DNS header.
            uint16_t qdcount = (static_cast<uint16_t>(packet[4]) << 8) | static_cast<uint16_t>(packet[5]);
            uint16_t ancount = (static_cast<uint16_t>(packet[6]) << 8) | static_cast<uint16_t>(packet[7]);
            uint16_t nscount = (static_cast<uint16_t>(packet[8]) << 8) | static_cast<uint16_t>(packet[9]);

            const Byte* data = packet.data();
            std::size_t size  = packet.size();

            // Walk through QD section.
            std::size_t pos = SkipDnsQuestionSection(data, size, kDnsHeaderSize, qdcount);
            if (pos == 0) {
                return false; /* Parse error; leave packet unchanged. */
            }

            // Walk through AN section.
            pos = SkipDnsRrSection(data, size, pos, ancount);
            if (pos == 0) {
                return false;
            }

            // Walk through NS section.
            pos = SkipDnsRrSection(data, size, pos, nscount);
            if (pos == 0) {
                return false;
            }

            // Now `pos` points to the start of the additional records section.
            // Scan for an existing OPT RR (TYPE=41 at root label).
            for (uint16_t i = 0; i < arcount; ++i) {
                std::size_t rr_start = pos;

                // Verify the name is root (single 0x00 byte) — required for OPT RR.
                if (pos >= size || data[pos] != 0x00) {
                    // Not a root-label record; skip this RR normally.
                    std::size_t name_len = SkipDnsName(data, size, pos);
                    if (name_len == 0) {
                        return false;
                    }
                    pos += name_len;
                    if (pos + 10 > size) {
                        return false;
                    }
                    uint16_t rdlen = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                      static_cast<uint16_t>(data[pos + 9]);
                    pos += 10 + rdlen;
                    continue;
                }

                // Root label consumed (1 byte).
                pos += 1;
                if (pos + 10 > size) {
                    return false;
                }

                // Read TYPE (2 bytes).
                uint16_t rr_type = (static_cast<uint16_t>(data[pos]) << 8) |
                                    static_cast<uint16_t>(data[pos + 1]);

                if (rr_type != kOptType) {
                    // Not an OPT RR — skip the rest of this record.
                    uint16_t rdlen = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                      static_cast<uint16_t>(data[pos + 9]);
                    pos += 10 + rdlen;
                    continue;
                }

                /* Found an existing OPT RR.  Parse its RDATA and look for
                 * an existing ECS option (option-code 8). */

                // CLASS(2) + TTL(4) are at pos+2 .. pos+7.
                uint16_t rdlength = (static_cast<uint16_t>(data[pos + 8]) << 8) |
                                     static_cast<uint16_t>(data[pos + 9]);

                std::size_t rdata_start = pos + 10;
                if (rdata_start + rdlength > size) {
                    return false; /* RDATA extends beyond packet. */
                }

                // Scan EDNS options in the OPT RDATA to find ECS (option-code 8).
                std::size_t rdata_pos = 0;
                std::size_t ecs_option_offset = 0;  /* Offset within RDATA where ECS option starts. */
                std::size_t ecs_option_size   = 0;  /* Total size of existing ECS option (code+len+data). */
                bool found_ecs = false;

                while (rdata_pos + 4 <= rdlength) {
                    uint16_t opt_code = (static_cast<uint16_t>(data[rdata_start + rdata_pos]) << 8) |
                                         static_cast<uint16_t>(data[rdata_start + rdata_pos + 1]);
                    uint16_t opt_len  = (static_cast<uint16_t>(data[rdata_start + rdata_pos + 2]) << 8) |
                                         static_cast<uint16_t>(data[rdata_start + rdata_pos + 3]);

                    if (rdata_pos + 4 + opt_len > rdlength) {
                        return false; /* Option data extends beyond RDATA. */
                    }

                    if (opt_code == kEcsOptionCode) {
                        ecs_option_offset = rdata_pos;
                        ecs_option_size   = 4 + opt_len;
                        found_ecs = true;
                        /* Continue scanning to validate the rest of the options
                         * (we don't break because we need to verify the packet
                         * structure is intact). */
                    }

                    rdata_pos += 4 + opt_len;
                }

                /* Build the new ECS option data. */
                static constexpr std::size_t kNewEcsOptionSize = 4 + kEcsNewOptionLen; /* 4 (code+len) + 8 (data) */
                Byte new_ecs[kNewEcsOptionSize];
                {
                    Byte* q = new_ecs;
                    // Option Code: ECS (8)
                    *q++ = 0x00; *q++ = 0x08;
                    // Option Length: 8
                    *q++ = 0x00; *q++ = 0x08;
                    // Address Family: IPv4 (1)
                    *q++ = 0x00; *q++ = 0x01;
                    // Source Prefix-Length: 24
                    *q++ = 24;
                    // Scope Prefix-Length: 0
                    *q++ = 0;
                    // IPv4 address (last octet zeroed for /24)
                    boost::asio::ip::address_v4::bytes_type ab = ecs_ip.to_v4().to_bytes();
                    *q++ = ab[0];
                    *q++ = ab[1];
                    *q++ = ab[2];
                    *q++ = 0;
                }

                /* Calculate new RDLENGTH. */
                std::size_t new_rdlength;
                if (found_ecs) {
                    new_rdlength = rdlength - ecs_option_size + kNewEcsOptionSize;
                }
                else {
                    new_rdlength = rdlength + kNewEcsOptionSize;
                }

                if (new_rdlength > 65535) {
                    return false; /* Would overflow RDLENGTH field. */
                }

                /* Build the new RDATA in a temporary buffer. */
                try {
                    ppp::vector<Byte> new_rdata;
                    new_rdata.reserve(new_rdlength);

                    // Copy existing RDATA, skipping the old ECS option if present.
                    if (found_ecs) {
                        // Copy options before the ECS option.
                        if (ecs_option_offset > 0) {
                            new_rdata.insert(new_rdata.end(),
                                data + rdata_start,
                                data + rdata_start + ecs_option_offset);
                        }
                        // Copy options after the old ECS option.
                        std::size_t after_ecs = ecs_option_offset + ecs_option_size;
                        if (after_ecs < rdlength) {
                            new_rdata.insert(new_rdata.end(),
                                data + rdata_start + after_ecs,
                                data + rdata_start + rdlength);
                        }
                    }
                    else {
                        // No existing ECS — copy all existing options.
                        if (rdlength > 0) {
                            new_rdata.insert(new_rdata.end(),
                                data + rdata_start,
                                data + rdata_start + rdlength);
                        }
                    }

                    // Append the new ECS option.
                    new_rdata.insert(new_rdata.end(), new_ecs, new_ecs + kNewEcsOptionSize);

                    /* Resize the packet to replace the old RDATA region. */
                    std::size_t size_delta = new_rdata.size() - rdlength;
                    std::size_t old_packet_size = packet.size();
                    std::size_t after_rdata = rdata_start + rdlength;

                    if (size_delta > 0) {
                        // Packet grows — need to check size limit.
                        if (old_packet_size + size_delta > 65535) {
                            return false;
                        }
                        packet.resize(old_packet_size + size_delta);
                        // Shift trailing data right.
                        std::memmove(packet.data() + rdata_start + new_rdata.size(),
                                     packet.data() + after_rdata,
                                     old_packet_size - after_rdata);
                    }
                    else if (size_delta < 0) {
                        // Packet shrinks — shift trailing data left.
                        std::size_t abs_delta = static_cast<std::size_t>(-static_cast<ptrdiff_t>(size_delta));
                        std::memmove(packet.data() + rdata_start + new_rdata.size(),
                                     packet.data() + after_rdata,
                                     old_packet_size - after_rdata);
                        packet.resize(old_packet_size - abs_delta);
                    }
                    else {
                        // Same size — just overwrite in place.
                    }

                    // Write the new RDATA into the packet.
                    std::memcpy(packet.data() + rdata_start, new_rdata.data(), new_rdata.size());

                    // Update RDLENGTH in the OPT RR header.
                    packet[rr_start + 1 + 8] = static_cast<Byte>((new_rdlength >> 8) & 0xff);
                    packet[rr_start + 1 + 9] = static_cast<Byte>(new_rdlength & 0xff);

                    return true;
                }
                catch (const std::exception&) {
                    return false;
                }
            }

            /* No OPT RR found in additional section — conservatively skip. */
            return false;
        }

        /* ========================================================================
         * DetectExitIPViaStun — STUN Binding Request with multi-candidate rotation
         *
         * Tries candidates in round-robin order.  On each call, the starting
         * index is advanced so that repeated calls distribute load.
         * Falls back to the built-in default list when no candidates are set.
         * ======================================================================== */

        void DnsResolver::DetectExitIPViaStun(const ExitIpCallback& callback) noexcept {
            if (NULLPTR == callback) {
                return;
            }

            const ppp::vector<StunCandidate>& candidates =
                stun_candidates_.empty() ? DefaultStunCandidates() : stun_candidates_;

            if (candidates.empty()) {
                ppp::telemetry::Log(Level::kDebug, "dns", "STUN no candidates available");
                ppp::telemetry::Count("dns.stun.no_candidates", 1);
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            ppp::telemetry::Log(Level::kDebug, "dns", "STUN detection start candidates=%zu", candidates.size());
            ppp::telemetry::Count("dns.stun.start", 1);

            // Rotate starting index via atomic fetch_add.
            std::size_t start = stun_rotation_.fetch_add(1, std::memory_order_relaxed) % candidates.size();

            // Build the ordered candidate list starting from the rotated index.
            auto ordered = make_shared_object<ppp::vector<StunCandidate> >();
            if (NULLPTR == ordered) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }
            ordered->reserve(candidates.size());
            for (std::size_t i = 0; i < candidates.size(); ++i) {
                ordered->push_back(candidates[(start + i) % candidates.size()]);
            }

            // Build a fallback chain from last candidate to first.
            // Each layer tries one STUN candidate; on failure it invokes the next.
            // The terminal layer invokes the caller's callback with unspecified.
            auto resolver_weak = weak_from_this();
            auto chain = make_shared_object<ExitIpCallback>(
                [callback](const boost::asio::ip::address& addr) noexcept {
                    callback(addr);
                });
            if (NULLPTR == chain) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            for (int i = static_cast<int>(ordered->size()) - 1; i >= 0; --i) {
                StunCandidate cand = (*ordered)[static_cast<std::size_t>(i)];
                std::shared_ptr<ExitIpCallback> next = std::move(chain);
                chain = make_shared_object<ExitIpCallback>();
                if (NULLPTR == chain) {
                    boost::asio::post(context_, [callback]() noexcept {
                        callback(boost::asio::ip::address());
                    });
                    return;
                }

                *chain = [resolver_weak, cand, next](const boost::asio::ip::address& prev_result) noexcept {
                    if (!prev_result.is_unspecified()) {
                        ppp::telemetry::Log(Level::kDebug, "dns", "STUN success ip=%s port=%d",
                            cand.ip.to_string().c_str(), cand.port);
                        ppp::telemetry::Count("dns.stun.success", 1);
                        (*next)(prev_result);
                        return;
                    }
                    // Try this candidate.
                    std::shared_ptr<DnsResolver> resolver = resolver_weak.lock();
                    if (NULLPTR == resolver) {
                        (*next)(boost::asio::ip::address());
                        return;
                    }
                    ppp::telemetry::Log(Level::kTrace, "dns", "STUN trying candidate ip=%s:%d",
                        cand.ip.to_string().c_str(), cand.port);
                    resolver->TryStunCandidate(cand, *next);
                };
            }

            // Start the chain.
            (*chain)(boost::asio::ip::address());
        }

        /* ========================================================================
         * TryStunCandidate — STUN probe against a single candidate
         * ======================================================================== */

        void DnsResolver::TryStunCandidate(
            const StunCandidate& candidate,
            const ExitIpCallback& callback) noexcept {

            if (NULLPTR == callback) {
                return;
            }

            if (candidate.ip.is_unspecified()) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            udp::endpoint remote(candidate.ip, static_cast<unsigned short>(candidate.port));
            std::shared_ptr<udp::socket> socket = make_shared_object<udp::socket>(context_);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context_);
            std::shared_ptr<ppp::vector<Byte> > recv_buf = make_shared_object<ppp::vector<Byte> >(1024);
            std::shared_ptr<udp::endpoint> recv_ep = make_shared_object<udp::endpoint>();
            std::shared_ptr<std::atomic<bool> > completed = make_shared_object<std::atomic<bool> >(false);

            if (NULLPTR == socket || NULLPTR == timer || NULLPTR == recv_buf || NULLPTR == recv_ep || NULLPTR == completed) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            boost::system::error_code ec;
            socket->open(udp::v4(), ec);
            if (ec) {
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), true);
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);
            if (!ProtectSocket(socket->native_handle())) {
                ppp::net::Socket::Closesocket(socket);
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            /* Build the 20-byte STUN Binding Request (RFC 5389 §6). */
            auto request = make_shared_object<ppp::vector<Byte> >(20, 0);
            if (NULLPTR == request) {
                ppp::net::Socket::Closesocket(socket);
                boost::asio::post(context_, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            Byte* pkt = request->data();
            // Message Type: Binding Request (0x0001)
            pkt[0] = 0x00; pkt[1] = 0x01;
            // Message Length: 0 (no attributes)
            pkt[2] = 0x00; pkt[3] = 0x00;
            // Magic Cookie (0x2112A442)
            pkt[4] = 0x21; pkt[5] = 0x12; pkt[6] = 0xA4; pkt[7] = 0x42;
            // Transaction ID: 12 random bytes.
            pkt[8]  = 0xAA; pkt[9]  = 0xBB; pkt[10] = 0xCC; pkt[11] = 0xDD;
            pkt[12] = 0xEE; pkt[13] = 0xFF; pkt[14] = 0x00; pkt[15] = 0x11;
            pkt[16] = 0x22; pkt[17] = 0x33; pkt[18] = 0x44; pkt[19] = 0x55;

            /* Timeout handler. */
            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_STUN_TIMEOUT_MS));
            timer->async_wait([socket, completed, callback](const boost::system::error_code& timer_ec) noexcept {
                if (!timer_ec) {
                    bool expected = false;
                    if (completed->compare_exchange_strong(expected, true)) {
                        ppp::telemetry::Count("dns.stun.timeout", 1);
                        ppp::net::Socket::Closesocket(socket);
                        callback(boost::asio::ip::address());
                    }
                }
            });

            /* Send the STUN request. */
            socket->async_send_to(boost::asio::buffer(request->data(), request->size()), remote,
                [socket, timer, recv_buf, recv_ep, completed, callback](const boost::system::error_code& send_ec, std::size_t) noexcept {
                    if (send_ec) {
                        bool expected = false;
                        if (completed->compare_exchange_strong(expected, true)) {
                            ppp::telemetry::Count("dns.stun.send_fail", 1);
                            ppp::net::Socket::Cancel(*timer);
                            ppp::net::Socket::Closesocket(socket);
                            callback(boost::asio::ip::address());
                        }
                        return;
                    }

                    /* Wait for the STUN response. */
                    socket->async_receive_from(
                        boost::asio::buffer(recv_buf->data(), recv_buf->size()), *recv_ep,
                        [socket, timer, recv_buf, completed, callback](const boost::system::error_code& recv_ec, std::size_t recv_size) noexcept {
                            bool expected = false;
                            if (!completed->compare_exchange_strong(expected, true)) {
                                return; /* Already timed out or completed. */
                            }

                            ppp::net::Socket::Cancel(*timer);
                            ppp::net::Socket::Closesocket(socket);

                            if (recv_ec || recv_size < 20) {
                                ppp::telemetry::Count("dns.stun.recv_fail", 1);
                                callback(boost::asio::ip::address());
                                return;
                            }

                            const Byte* resp = recv_buf->data();

                            /* Validate STUN header. */
                            uint16_t msg_type = (static_cast<uint16_t>(resp[0]) << 8) |
                                                 static_cast<uint16_t>(resp[1]);
                            uint16_t msg_len  = (static_cast<uint16_t>(resp[2]) << 8) |
                                                 static_cast<uint16_t>(resp[3]);
                            uint32_t cookie   = (static_cast<uint32_t>(resp[4]) << 24) |
                                                 (static_cast<uint32_t>(resp[5]) << 16) |
                                                 (static_cast<uint32_t>(resp[6]) << 8)  |
                                                  static_cast<uint32_t>(resp[7]);

                            if (msg_type != kStunMsgTypeBindingResponse ||
                                cookie   != kStunMagicCookie ||
                                msg_len  > recv_size - 20) {
                                ppp::telemetry::Count("dns.stun.invalid_response", 1);
                                callback(boost::asio::ip::address());
                                return;
                            }

                            /* Scan attributes for XOR-MAPPED-ADDRESS (0x0020). */
                            const Byte* attrs = resp + 20;
                            std::size_t attrs_len = static_cast<std::size_t>(msg_len);
                            std::size_t attr_pos = 0;

                            while (attr_pos + 4 <= attrs_len) {
                                uint16_t attr_type = (static_cast<uint16_t>(attrs[attr_pos]) << 8) |
                                                      static_cast<uint16_t>(attrs[attr_pos + 1]);
                                uint16_t attr_len  = (static_cast<uint16_t>(attrs[attr_pos + 2]) << 8) |
                                                      static_cast<uint16_t>(attrs[attr_pos + 3]);

                                if (attr_pos + 4 + attr_len > attrs_len) {
                                    break; /* Malformed attribute. */
                                }

                                if (attr_type == kStunAttrXorMappedAddr && attr_len >= 8) {
                                    uint8_t family = attrs[attr_pos + 5];
                                    if (family == 0x01) { /* IPv4 */
                                        uint32_t xaddr = (static_cast<uint32_t>(attrs[attr_pos + 8]) << 24) |
                                                          (static_cast<uint32_t>(attrs[attr_pos + 9]) << 16) |
                                                          (static_cast<uint32_t>(attrs[attr_pos + 10]) << 8)  |
                                                           static_cast<uint32_t>(attrs[attr_pos + 11]);
                                        uint32_t addr = xaddr ^ kStunMagicCookie;

                                        boost::asio::ip::address_v4::bytes_type ab;
                                        ab[0] = static_cast<Byte>((addr >> 24) & 0xff);
                                        ab[1] = static_cast<Byte>((addr >> 16) & 0xff);
                                        ab[2] = static_cast<Byte>((addr >> 8)  & 0xff);
                                        ab[3] = static_cast<Byte>(addr & 0xff);

                                        callback(boost::asio::ip::address_v4(ab));
                                        return;
                                    }
                                }

                                /* Advance to next attribute (4-byte aligned). */
                                attr_pos += 4 + ((attr_len + 3) & ~static_cast<std::size_t>(3));
                            }

                            /* No XOR-MAPPED-ADDRESS found. */
                            ppp::telemetry::Count("dns.stun.no_xmapped", 1);
                            callback(boost::asio::ip::address());
                        });
                });
        }

        /* ========================================================================
         * ResolveHostnameAsync — bootstrap DNS helper (system UDP resolver)
         *
         * Sends a raw DNS A-record query to a well-known public resolver
         * (8.8.8.8) via UDP and returns the first A-record answer IP.
         * This is a reusable helper that does NOT depend on the provider
         * infrastructure and can be used during bootstrap when provider
         * hostnames need to be resolved before the full resolver is ready.
         *
         * Current usage: stub available for future bootstrap scenarios.
         * All providers already have hardcoded IP addresses, so this
         * method is not yet called in the normal resolution path.
         * ======================================================================== */

        /* Build a minimal DNS A-record query for a given hostname. */
        static bool BuildDnsAQuery(const ppp::string& hostname, ppp::vector<Byte>& out_packet) noexcept {
            /* DNS Header (12 bytes): ID=0, flags=standard query (0x0100),
             * QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0. */
            out_packet.clear();
            out_packet.resize(kDnsHeaderSize, 0);
            out_packet[0] = 0x00; out_packet[1] = 0x00; /* ID */
            out_packet[2] = 0x01; out_packet[3] = 0x00; /* Flags: standard query, RD=1 */
            out_packet[4] = 0x00; out_packet[5] = 0x01; /* QDCOUNT = 1 */
            /* ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 (already zero). */

            /* Encode hostname as DNS labels. */
            ppp::string host = ATrim(hostname);
            if (host.empty() || host.size() > 253) {
                return false;
            }

            /* Split by '.' and write each label. */
            std::size_t pos = 0;
            while (pos < host.size()) {
                std::size_t dot = host.find('.', pos);
                ppp::string label;
                if (dot == ppp::string::npos) {
                    label = host.substr(pos);
                    pos = host.size();
                }
                else {
                    label = host.substr(pos, dot - pos);
                    pos = dot + 1;
                }

                if (label.empty() || label.size() > 63) {
                    return false;
                }

                out_packet.push_back(static_cast<Byte>(label.size()));
                for (std::size_t j = 0; j < label.size(); ++j) {
                    out_packet.push_back(static_cast<Byte>(label[j]));
                }
            }
            out_packet.push_back(0x00); /* Root label */

            /* QTYPE = A (1), QCLASS = IN (1). */
            out_packet.push_back(0x00); out_packet.push_back(0x01); /* QTYPE  */
            out_packet.push_back(0x00); out_packet.push_back(0x01); /* QCLASS */

            return true;
        }

        /* Parse a DNS response and extract the first A-record IP address. */
        static boost::asio::ip::address_v4 ParseFirstARecord(const Byte* data, std::size_t size) noexcept {
            if (size < kDnsHeaderSize) {
                return boost::asio::ip::address_v4();
            }

            uint16_t ancount = (static_cast<uint16_t>(data[6]) << 8) | static_cast<uint16_t>(data[7]);
            uint16_t qdcount = (static_cast<uint16_t>(data[4]) << 8) | static_cast<uint16_t>(data[5]);

            std::size_t pos = SkipDnsQuestionSection(data, size, kDnsHeaderSize, qdcount);
            if (pos == 0) {
                return boost::asio::ip::address_v4();
            }

            for (uint16_t i = 0; i < ancount; ++i) {
                std::size_t name_len = SkipDnsName(data, size, pos);
                if (name_len == 0) {
                    return boost::asio::ip::address_v4();
                }
                pos += name_len;

                if (pos + 10 > size) {
                    return boost::asio::ip::address_v4();
                }

                uint16_t rr_type   = (static_cast<uint16_t>(data[pos])     << 8) | static_cast<uint16_t>(data[pos + 1]);
                /* uint16_t rr_class  = (static_cast<uint16_t>(data[pos + 2]) << 8) | static_cast<uint16_t>(data[pos + 3]); */
                /* uint32_t rr_ttl    = ... ; */
                uint16_t rdlength  = (static_cast<uint16_t>(data[pos + 8]) << 8) | static_cast<uint16_t>(data[pos + 9]);

                pos += 10;

                if (pos + rdlength > size) {
                    return boost::asio::ip::address_v4();
                }

                if (rr_type == 1 && rdlength == 4) {
                    /* A record with 4-byte IPv4 address. */
                    boost::asio::ip::address_v4::bytes_type ab;
                    ab[0] = data[pos]; ab[1] = data[pos + 1];
                    ab[2] = data[pos + 2]; ab[3] = data[pos + 3];
                    return boost::asio::ip::address_v4(ab);
                }

                pos += rdlength;
            }

            return boost::asio::ip::address_v4();
        }

        void DnsResolver::ResolveHostnameAsync(
            boost::asio::io_context& context,
            const ppp::string& hostname,
            const ExitIpCallback& callback) noexcept {

            if (NULLPTR == callback || hostname.empty()) {
                if (NULLPTR != callback) {
                    boost::asio::post(context, [callback]() noexcept {
                        callback(boost::asio::ip::address());
                    });
                }
                return;
            }

            /* Build the DNS A-record query. */
            auto query = make_shared_object<ppp::vector<Byte> >();
            if (NULLPTR == query || !BuildDnsAQuery(hostname, *query)) {
                boost::asio::post(context, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            /* Target: Google public DNS (8.8.8.8:53). */
            boost::system::error_code ec;
            boost::asio::ip::address dns_ip = boost::asio::ip::address_v4(0x08080808);
            udp::endpoint remote(dns_ip, PPP_DNS_SYS_PORT);

            std::shared_ptr<udp::socket> socket = make_shared_object<udp::socket>(context);
            std::shared_ptr<boost::asio::steady_timer> timer = make_shared_object<boost::asio::steady_timer>(context);
            std::shared_ptr<ppp::vector<Byte> > recv_buf = make_shared_object<ppp::vector<Byte> >(PPP_DNS_RESOLVER_UDP_BUFFER_SIZE);
            std::shared_ptr<udp::endpoint> recv_ep = make_shared_object<udp::endpoint>();
            std::shared_ptr<std::atomic<bool> > done = make_shared_object<std::atomic<bool> >(false);

            if (NULLPTR == socket || NULLPTR == timer || NULLPTR == recv_buf || NULLPTR == recv_ep || NULLPTR == done) {
                boost::asio::post(context, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            socket->open(udp::v4(), ec);
            if (ec) {
                boost::asio::post(context, [callback]() noexcept {
                    callback(boost::asio::ip::address());
                });
                return;
            }

            ppp::net::Socket::AdjustDefaultSocketOptional(socket->native_handle(), true);
            ppp::net::Socket::SetTypeOfService(socket->native_handle());
            ppp::net::Socket::SetSignalPipeline(socket->native_handle(), false);
            ppp::net::Socket::ReuseSocketAddress(socket->native_handle(), true);

            /* Timeout. */
            timer->expires_after(std::chrono::milliseconds(PPP_DNS_RESOLVER_TIMEOUT_MS));
            timer->async_wait([socket, done, callback](const boost::system::error_code& timer_ec) noexcept {
                if (!timer_ec) {
                    bool expected = false;
                    if (done->compare_exchange_strong(expected, true)) {
                        ppp::net::Socket::Closesocket(socket);
                        callback(boost::asio::ip::address());
                    }
                }
            });

            /* Send query. */
            socket->async_send_to(boost::asio::buffer(query->data(), query->size()), remote,
                [socket, timer, recv_buf, recv_ep, done, callback](const boost::system::error_code& send_ec, std::size_t) noexcept {
                    if (send_ec) {
                        bool expected = false;
                        if (done->compare_exchange_strong(expected, true)) {
                            ppp::net::Socket::Cancel(*timer);
                            ppp::net::Socket::Closesocket(socket);
                            callback(boost::asio::ip::address());
                        }
                        return;
                    }

                    /* Wait for response. */
                    socket->async_receive_from(
                        boost::asio::buffer(recv_buf->data(), recv_buf->size()), *recv_ep,
                        [socket, timer, recv_buf, done, callback](const boost::system::error_code& recv_ec, std::size_t recv_size) noexcept {
                            bool expected = false;
                            if (!done->compare_exchange_strong(expected, true)) {
                                return;
                            }

                            ppp::net::Socket::Cancel(*timer);
                            ppp::net::Socket::Closesocket(socket);

                            if (recv_ec || recv_size < kDnsHeaderSize) {
                                callback(boost::asio::ip::address());
                                return;
                            }

                            boost::asio::ip::address_v4 result = ParseFirstARecord(recv_buf->data(), recv_size);
                            if (result.is_unspecified()) {
                                callback(boost::asio::ip::address());
                            }
                            else {
                                callback(boost::asio::ip::address(result));
                            }
                        });
                });
        }

    } // namespace dns
} // namespace ppp
