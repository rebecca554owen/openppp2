#include <ppp/app/client/GeoRuleGenerator.h>
#include <ppp/io/File.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/Telemetry.h>
#include <ppp/auxiliary/StringAuxiliary.h>

#include <common/chnroutes2/chnroutes2.h>

/**
 * @file GeoRuleGenerator.cpp
 * @brief Phase G: GeoIP/GeoSite rule generation implementation.
 *
 * Optionally downloads and parses GeoIP/GeoSite dat cache files, then reads
 * text-format GeoIP (CIDR) and GeoSite (domain) source files,
 * generates merged bypass CIDR and DNS rule output files, appending
 * custom user rules/sources on top.
 *
 * @see GeoRuleGenerator.h for public API and design notes.
 */

using ppp::io::File;
using ppp::telemetry::Level;

namespace ppp {
    namespace app {
        namespace client {

            /**
             * @brief Reads a text file and returns non-empty, non-comment lines.
             *
             * Lines starting with '#' are treated as comments and skipped.
             * Inline comments (text after '#') are preserved since CIDR and
             * domain rules should not normally contain '#'.
             */
            int GeoRuleGenerator::ReadTextLines(const ppp::string& path, ppp::vector<ppp::string>& lines) noexcept {
                if (path.empty()) {
                    return 0;
                }

                ppp::string full_path = File::GetFullPath(File::RewritePath(path.data()).data());
                if (full_path.empty()) {
                    return 0;
                }

                if (!File::Exists(full_path.data())) {
                    ppp::telemetry::Log(Level::kInfo, "geo-rules",
                        "source file not found: %s", full_path.data());
                    return 0;
                }

                ppp::string content = File::ReadAllText(full_path.data());
                if (content.empty()) {
                    return 0;
                }

                ppp::vector<ppp::string> raw_lines;
                Tokenize<ppp::string>(content, raw_lines, "\r\n");

                int count = 0;
                for (auto& line : raw_lines) {
                    // Strip inline comments.
                    std::size_t hash_pos = line.find('#');
                    if (hash_pos != ppp::string::npos) {
                        if (hash_pos == 0) {
                            continue; // Pure comment line.
                        }
                        line = line.substr(0, hash_pos);
                    }

                    line = LTrim(RTrim(line));
                    if (!line.empty()) {
                        lines.emplace_back(std::move(line));
                        count++;
                    }
                }
                return count;
            }

            /**
             * @brief Downloads a Geo dat file from HTTP/HTTPS into the configured cache path.
             *
             * The downloaded dat file is intentionally treated as a cache artifact only;
             * binary dat parsing is still a future enhancement.  Text geoip/geosite inputs
             * remain the rule-generation source for Phase G.
             */
            bool GeoRuleGenerator::DownloadDatFile(const ppp::string& url, const ppp::string& output_path, const char* label) noexcept {
                using HttpClient = ppp::net::http::HttpClient;

                if (url.empty()) {
                    return true;
                }

                ppp::string dat_path = output_path;
                if (dat_path.empty()) {
                    dat_path = (NULLPTR != label && strcmp(label, "geosite") == 0) ? "GeoSite.dat" : "GeoIP.dat";
                }

                ppp::string full_path = File::GetFullPath(File::RewritePath(dat_path.data()).data());
                if (full_path.empty()) {
                    full_path = dat_path;
                }

                ppp::string host;
                ppp::string path;
                int port = ppp::net::IPEndPoint::MinPort;
                bool https = false;
                if (!HttpClient::VerifyUri(url, ppp::addressof(host), &port, ppp::addressof(path), &https)) {
                    ppp::telemetry::Log(Level::kInfo, "geo-rules",
                        "%s dat download URL invalid: %s", label ? label : "geo", url.data());
                    ppp::telemetry::Count("geo-rules.download_failed", 1);
                    return false;
                }

                if (!EnsureParentDirectory(full_path)) {
                    ppp::telemetry::Log(Level::kInfo, "geo-rules",
                        "failed to create directory for %s dat cache: %s", label ? label : "geo", full_path.data());
                    ppp::telemetry::Count("geo-rules.download_failed", 1);
                    return false;
                }

                ppp::telemetry::Log(Level::kInfo, "geo-rules",
                    "downloading %s dat: %s -> %s", label ? label : "geo", url.data(), full_path.data());

                HttpClient http_client((https ? "https://" : "http://") + host, chnroutes2_cacertpath_default());
                int http_status_code = -1;
                std::string body = http_client.Get(path, http_status_code);
                if (http_status_code < 200 || http_status_code >= 300 || body.empty()) {
                    ppp::telemetry::Log(Level::kInfo, "geo-rules",
                        "%s dat download failed: status=%d url=%s", label ? label : "geo", http_status_code, url.data());
                    ppp::telemetry::Count("geo-rules.download_failed", 1);
                    return false;
                }

                if (!File::WriteAllBytes(full_path.data(), body.data(), (int)body.size())) {
                    ppp::telemetry::Log(Level::kInfo, "geo-rules",
                        "%s dat write failed: %s", label ? label : "geo", full_path.data());
                    ppp::telemetry::Count("geo-rules.download_failed", 1);
                    return false;
                }

                ppp::telemetry::Log(Level::kInfo, "geo-rules",
                    "%s dat downloaded: %s (%d bytes)", label ? label : "geo", full_path.data(), (int)body.size());
                ppp::telemetry::Count("geo-rules.download_success", 1);
                return true;
            }

            /**
             * @brief Validates a CIDR string (IPv4 or IPv6).
             *
             * Accepts:
             *   - "A.B.C.D" (host address, treated as /32)
             *   - "A.B.C.D/N" (IPv4 CIDR)
             *   - "xxxx::/N" (IPv6 CIDR)
             *   - "xxxx::" (host address)
             */
            static bool IsValidCidr(const ppp::string& cidr) noexcept {
                if (cidr.empty()) {
                    return false;
                }

                // Find the slash separator.
                std::size_t slash = cidr.find('/');
                ppp::string addr_part = (slash != ppp::string::npos) ? cidr.substr(0, slash) : cidr;

                boost::system::error_code ec;
                boost::asio::ip::address addr = StringToAddress(addr_part.data(), ec);
                if (ec) {
                    return false;
                }

                if (addr.is_v4() || addr.is_v6()) {
                    return !ppp::net::IPEndPoint::IsInvalid(addr);
                }
                return false;
            }

            namespace {
                struct ProtoField final {
                    int field_number = 0;
                    int wire_type = 0;
                    uint64_t varint = 0;
                    const unsigned char* data = NULLPTR;
                    std::size_t size = 0;
                };

                static bool ReadVarint(const unsigned char*& p, const unsigned char* end, uint64_t& value) noexcept {
                    value = 0;
                    int shift = 0;
                    while (p < end && shift <= 63) {
                        unsigned char b = *p++;
                        value |= ((uint64_t)(b & 0x7f)) << shift;
                        if ((b & 0x80) == 0) {
                            return true;
                        }
                        shift += 7;
                    }
                    return false;
                }

                static bool SkipFixed(const unsigned char*& p, const unsigned char* end, std::size_t n) noexcept {
                    if ((std::size_t)(end - p) < n) {
                        return false;
                    }
                    p += n;
                    return true;
                }

                static bool NextProtoField(const unsigned char*& p, const unsigned char* end, ProtoField& f) noexcept {
                    if (p >= end) {
                        return false;
                    }

                    uint64_t key = 0;
                    if (!ReadVarint(p, end, key)) {
                        return false;
                    }

                    f = ProtoField();
                    f.field_number = (int)(key >> 3);
                    f.wire_type = (int)(key & 0x07);

                    switch (f.wire_type) {
                    case 0: // varint
                        return ReadVarint(p, end, f.varint);
                    case 1: // fixed64
                        return SkipFixed(p, end, 8);
                    case 2: { // length-delimited
                        uint64_t len = 0;
                        if (!ReadVarint(p, end, len) || len > (uint64_t)(end - p)) {
                            return false;
                        }
                        f.data = p;
                        f.size = (std::size_t)len;
                        p += len;
                        return true;
                    }
                    case 5: // fixed32
                        return SkipFixed(p, end, 4);
                    default:
                        return false;
                    }
                }

                static ppp::string ProtoString(const ProtoField& f) noexcept {
                    if (f.wire_type != 2 || NULLPTR == f.data || f.size < 1) {
                        return "";
                    }
                    return ppp::string((const char*)f.data, f.size);
                }

                static ppp::string NormalizeCountryCode(const ppp::string& country) noexcept {
                    ppp::string c = ToLower<ppp::string>(LTrim(RTrim(country)));
                    if (c.size() > 6 && memcmp(c.data(), "geoip:", 6) == 0) {
                        c = c.substr(6);
                    }
                    if (c.size() > 8 && memcmp(c.data(), "geosite:", 8) == 0) {
                        c = c.substr(8);
                    }
                    return c.empty() ? "cn" : c;
                }

                static bool LoadDatBytes(const ppp::string& path, std::shared_ptr<Byte>& bytes, int& length) noexcept {
                    length = 0;
                    if (path.empty()) {
                        return false;
                    }

                    ppp::string full_path = File::GetFullPath(File::RewritePath(path.data()).data());
                    if (full_path.empty()) {
                        full_path = path;
                    }
                    if (!File::Exists(full_path.data())) {
                        ppp::telemetry::Log(Level::kInfo, "geo-rules",
                            "dat file not found: %s", full_path.data());
                        return false;
                    }

                    bytes = File::ReadAllBytes(full_path.data(), length);
                    if (!bytes || length <= 0) {
                        ppp::telemetry::Log(Level::kInfo, "geo-rules",
                            "dat file read failed: %s", full_path.data());
                        return false;
                    }
                    return true;
                }

                static ppp::string IpBytesToString(const unsigned char* data, std::size_t size) noexcept {
                    try {
                        if (size == 4) {
                            boost::asio::ip::address_v4::bytes_type b = { { data[0], data[1], data[2], data[3] } };
                            std::string s = boost::asio::ip::address_v4(b).to_string();
                            return ppp::string(s.data(), s.size());
                        }
                        if (size == 16) {
                            boost::asio::ip::address_v6::bytes_type b;
                            for (std::size_t i = 0; i < 16; ++i) {
                                b[i] = data[i];
                            }
                            std::string s = boost::asio::ip::address_v6(b).to_string();
                            return ppp::string(s.data(), s.size());
                        }
                    }
                    catch (const std::exception&) {
                    }
                    return "";
                }

                static bool ParseGeoIpCidrMessage(const unsigned char* data, std::size_t size, ppp::string& cidr) noexcept {
                    const unsigned char* p = data;
                    const unsigned char* end = data + size;
                    ppp::string ip;
                    int prefix = -1;

                    ProtoField f;
                    while (NextProtoField(p, end, f)) {
                        if (f.field_number == 1 && f.wire_type == 2) {
                            ip = IpBytesToString(f.data, f.size);
                        }
                        elif(f.field_number == 2 && f.wire_type == 0) {
                            prefix = (int)f.varint;
                        }
                    }

                    if (ip.empty()) {
                        return false;
                    }
                    if (prefix < 0) {
                        prefix = (ip.find(':') == ppp::string::npos) ? 32 : 128;
                    }

                    cidr = ip + "/" + stl::to_string<ppp::string>(prefix);
                    return IsValidCidr(cidr);
                }

                static void ParseGeoIpEntry(const unsigned char* data, std::size_t size, const ppp::string& country, ppp::unordered_set<ppp::string>& cidrs, int& skipped) noexcept {
                    const unsigned char* p = data;
                    const unsigned char* end = data + size;
                    ppp::string code;
                    ppp::vector<ppp::string> entry_cidrs;

                    ProtoField f;
                    while (NextProtoField(p, end, f)) {
                        if (f.field_number == 1 && f.wire_type == 2) {
                            code = NormalizeCountryCode(ProtoString(f));
                        }
                        elif(f.field_number == 2 && f.wire_type == 2) {
                            ppp::string cidr;
                            if (ParseGeoIpCidrMessage(f.data, f.size, cidr)) {
                                entry_cidrs.emplace_back(std::move(cidr));
                            }
                            else {
                                skipped++;
                            }
                        }
                    }

                    if (code == country) {
                        for (auto& cidr : entry_cidrs) {
                            cidrs.emplace(std::move(cidr));
                        }
                    }
                }

                static ppp::string GeoSiteDomainToInput(int type, const ppp::string& value) noexcept {
                    ppp::string v = ToLower<ppp::string>(LTrim(RTrim(value)));
                    if (v.empty()) {
                        return "";
                    }

                    // v2ray geosite proto: Plain=0, Regex=1, Domain=2, Full=3.
                    switch (type) {
                    case 1:
                        return "regexp:" + value;
                    case 3:
                        return "full:" + v;
                    case 0:
                    case 2:
                    default:
                        return v;
                    }
                }

                static bool ParseGeoSiteDomainMessage(const unsigned char* data, std::size_t size, ppp::string& input) noexcept {
                    const unsigned char* p = data;
                    const unsigned char* end = data + size;
                    int type = 0;
                    ppp::string value;

                    ProtoField f;
                    while (NextProtoField(p, end, f)) {
                        if (f.field_number == 1 && f.wire_type == 0) {
                            type = (int)f.varint;
                        }
                        elif(f.field_number == 2 && f.wire_type == 2) {
                            value = ProtoString(f);
                        }
                    }

                    input = GeoSiteDomainToInput(type, value);
                    return !input.empty();
                }

                static void ParseGeoSiteEntry(const unsigned char* data, std::size_t size, const ppp::string& country, const ppp::string& domestic_provider, ppp::vector<ppp::string>& dns_rules, int& skipped) noexcept {
                    const unsigned char* p = data;
                    const unsigned char* end = data + size;
                    ppp::string code;
                    ppp::vector<ppp::string> inputs;

                    ProtoField f;
                    while (NextProtoField(p, end, f)) {
                        if (f.field_number == 1 && f.wire_type == 2) {
                            code = NormalizeCountryCode(ProtoString(f));
                        }
                        elif(f.field_number == 2 && f.wire_type == 2) {
                            ppp::string input;
                            if (ParseGeoSiteDomainMessage(f.data, f.size, input)) {
                                inputs.emplace_back(std::move(input));
                            }
                            else {
                                skipped++;
                            }
                        }
                    }

                    if (code == country) {
                        for (const auto& input : inputs) {
                            ppp::string rule = GeoRuleGenerator::NormalizeDomainToDnsRule(input, domestic_provider);
                            if (!rule.empty()) {
                                dns_rules.emplace_back(std::move(rule));
                            }
                            else {
                                skipped++;
                            }
                        }
                    }
                }
            }

            /**
             * @brief Processes a single GeoIP source, appending valid CIDR lines.
             *
             * Each non-comment line is validated as a CIDR (IPv4 or IPv6).
             * Invalid lines are skipped and counted in `skipped`.
             */
            void GeoRuleGenerator::ProcessGeoIpSource(const ppp::string& path, ppp::unordered_set<ppp::string>& cidrs, int& skipped) noexcept {
                ppp::vector<ppp::string> lines;
                ReadTextLines(path, lines);

                for (const auto& line : lines) {
                    if (IsValidCidr(line)) {
                        cidrs.emplace(line);
                    }
                    else {
                        skipped++;
                        ppp::telemetry::Log(Level::kDebug, "geo-rules",
                            "skipped invalid CIDR: %s", line.data());
                    }
                }
            }

            void GeoRuleGenerator::ProcessGeoIpDat(const ppp::string& path, const ppp::string& country, ppp::unordered_set<ppp::string>& cidrs, int& skipped) noexcept {
                std::shared_ptr<Byte> bytes;
                int length = 0;
                if (!LoadDatBytes(path, bytes, length)) {
                    return;
                }

                ppp::string normalized_country = NormalizeCountryCode(country);
                std::size_t before = cidrs.size();
                const unsigned char* p = (const unsigned char*)bytes.get();
                const unsigned char* end = p + length;

                ProtoField f;
                while (NextProtoField(p, end, f)) {
                    // GeoIPList: repeated GeoIP entry = 1.
                    if (f.field_number == 1 && f.wire_type == 2) {
                        ParseGeoIpEntry(f.data, f.size, normalized_country, cidrs, skipped);
                    }
                }

                ppp::telemetry::Log(Level::kInfo, "geo-rules",
                    "geoip dat parsed: country=%s cidrs=%d source=%s",
                    normalized_country.data(), (int)(cidrs.size() - before), path.data());
                ppp::telemetry::Count("geo-rules.geoip_dat_cidrs", (int)(cidrs.size() - before));
            }

            /**
             * @brief Normalizes a domain input line into a DNS rule line.
             *
             * Supported input formats:
             *   - "baidu.com"         → suffix rule: "baidu.com /<provider>/nic"
             *   - ".qq.com"           → suffix rule: "qq.com /<provider>/nic"
             *   - "domain:taobao.com" → suffix rule: "taobao.com /<provider>/nic"
             *   - "suffix:jd.com"     → suffix rule: "jd.com /<provider>/nic"
             *   - "full:example.cn"   → full rule:   "full:example.cn /<provider>/nic"
             *   - "regexp:^.*\\.cn$"  → regexp rule: "regexp:^.*\\.cn$ /<provider>/nic"
             *
             * The "nic" flag indicates domestic resolution through the
             * physical NIC (not through VPN tunnel).  This matches the
             * existing dns-rules.txt convention for CN domains.
             */
            ppp::string GeoRuleGenerator::NormalizeDomainToDnsRule(const ppp::string& line, const ppp::string& domestic_provider) noexcept {
                if (line.empty() || domestic_provider.empty()) {
                    return "";
                }

                ppp::string input = line;

                // Detect full: prefix.
                if (input.size() > 5 && memcmp(input.data(), "full:", 5) == 0) {
                    ppp::string domain = ToLower<ppp::string>(LTrim(RTrim(input.substr(5))));
                    if (domain.empty()) {
                        return "";
                    }
                    // full:example.cn /doh.pub/nic
                    return "full:" + domain + " /" + domestic_provider + "/nic";
                }

                // Detect regexp: prefix.
                if (input.size() > 7 && memcmp(input.data(), "regexp:", 7) == 0) {
                    ppp::string pattern = LTrim(RTrim(input.substr(7)));
                    if (pattern.empty()) {
                        return "";
                    }
                    // regexp: patterns pass through as-is (validation happens at Rule::Load time).
                    return "regexp:" + pattern + " /" + domestic_provider + "/nic";
                }

                // Detect domain: prefix.
                if (input.size() > 7 && memcmp(input.data(), "domain:", 7) == 0) {
                    ppp::string domain = ToLower<ppp::string>(LTrim(RTrim(input.substr(7))));
                    if (domain.empty()) {
                        return "";
                    }
                    return domain + " /" + domestic_provider + "/nic";
                }

                // Detect suffix: prefix.
                if (input.size() > 7 && memcmp(input.data(), "suffix:", 7) == 0) {
                    ppp::string domain = ToLower<ppp::string>(LTrim(RTrim(input.substr(7))));
                    if (domain.empty()) {
                        return "";
                    }
                    return domain + " /" + domestic_provider + "/nic";
                }

                // Strip leading dot (e.g. ".qq.com" → "qq.com").
                if (input.size() > 1 && input[0] == '.') {
                    input = input.substr(1);
                }

                ppp::string domain = ToLower<ppp::string>(LTrim(RTrim(input)));
                if (domain.empty()) {
                    return "";
                }

                // Ordinary domain → suffix rule.
                return domain + " /" + domestic_provider + "/nic";
            }

            /**
             * @brief Processes a single GeoSite source, generating DNS rule lines.
             */
            void GeoRuleGenerator::ProcessGeoSiteSource(const ppp::string& path, const ppp::string& domestic_provider, ppp::vector<ppp::string>& dns_rules, int& skipped) noexcept {
                ppp::vector<ppp::string> lines;
                ReadTextLines(path, lines);

                for (const auto& line : lines) {
                    ppp::string rule = NormalizeDomainToDnsRule(line, domestic_provider);
                    if (!rule.empty()) {
                        dns_rules.emplace_back(std::move(rule));
                    }
                    else {
                        skipped++;
                        ppp::telemetry::Log(Level::kDebug, "geo-rules",
                            "skipped invalid domain: %s", line.data());
                    }
                }
            }

            void GeoRuleGenerator::ProcessGeoSiteDat(const ppp::string& path, const ppp::string& country, const ppp::string& domestic_provider, ppp::vector<ppp::string>& dns_rules, int& skipped) noexcept {
                std::shared_ptr<Byte> bytes;
                int length = 0;
                if (!LoadDatBytes(path, bytes, length)) {
                    return;
                }

                ppp::string normalized_country = NormalizeCountryCode(country);
                std::size_t before = dns_rules.size();
                const unsigned char* p = (const unsigned char*)bytes.get();
                const unsigned char* end = p + length;

                ProtoField f;
                while (NextProtoField(p, end, f)) {
                    // GeoSiteList: repeated GeoSite entry = 1.
                    if (f.field_number == 1 && f.wire_type == 2) {
                        ParseGeoSiteEntry(f.data, f.size, normalized_country, domestic_provider, dns_rules, skipped);
                    }
                }

                ppp::telemetry::Log(Level::kInfo, "geo-rules",
                    "geosite dat parsed: country=%s rules=%d source=%s",
                    normalized_country.data(), (int)(dns_rules.size() - before), path.data());
                ppp::telemetry::Count("geo-rules.geosite_dat_rules", (int)(dns_rules.size() - before));
            }

            /**
             * @brief Ensures the parent directory of a file path exists.
             *
             * Extracts the directory portion and calls File::CreateDirectories().
             */
            bool GeoRuleGenerator::EnsureParentDirectory(const ppp::string& file_path) noexcept {
                if (file_path.empty()) {
                    return false;
                }

                ppp::string parent = File::GetParentPath(file_path.data());
                if (parent.empty()) {
                    return true; // No parent (relative path without directory).
                }

                return File::CreateDirectories(parent.data());
            }

            /**
             * @brief Runs the full geo-rules generation pipeline.
             */
            GeoRuleGenerateResult GeoRuleGenerator::Generate(const ppp::configurations::AppConfiguration& config, const ppp::vector<ppp::string>* bypass_sources) noexcept {
                GeoRuleGenerateResult result;

                const auto& gr = config.geo_rules;
                if (!gr.enabled) {
                    return result;
                }

                DownloadDatFile(gr.geoip_download_url, gr.geoip_dat, "geoip");
                DownloadDatFile(gr.geosite_download_url, gr.geosite_dat, "geosite");

                // Resolve effective domestic DNS provider.
                // Priority: geo-rules.dns-provider-domestic > dns.servers.domestic > "doh.pub".
                ppp::string domestic_provider = gr.dns_provider_domestic;
                if (domestic_provider.empty()) {
                    domestic_provider = config.dns.servers.domestic;
                }
                if (domestic_provider.empty()) {
                    domestic_provider = "doh.pub";
                }

                ppp::telemetry::Log(Level::kInfo, "geo-rules",
                    "generating geo-rules: country=%s provider=%s",
                    gr.country.data(), domestic_provider.data());

                // ----------------------------------------------------------
                // Phase 1: Collect CIDR lines from GeoIP sources.
                // ----------------------------------------------------------
                ppp::unordered_set<ppp::string> cidr_set;
                int skipped = 0;

                ProcessGeoIpDat(gr.geoip_dat, gr.country, cidr_set, skipped);

                for (const auto& geoip_src : gr.geoip) {
                    ProcessGeoIpSource(geoip_src, cidr_set, skipped);
                }

                // Merge existing client/command-line bypass sources into the generated
                // bypass output as well.  This keeps geo-rules as one de-duplicated
                // effective bypass list instead of registering command-line bypass and
                // geo output as separate route-list files.
                if (NULLPTR != bypass_sources) {
                    for (const auto& bypass_src : *bypass_sources) {
                        ProcessGeoIpSource(bypass_src, cidr_set, skipped);
                    }
                }

                ppp::telemetry::Log(Level::kDebug, "geo-rules",
                    "geoip sources: %d cidrs collected", (int)cidr_set.size());

                // ----------------------------------------------------------
                // Phase 2: Process append-bypass (inline CIDR or file paths).
                // ----------------------------------------------------------
                for (const auto& entry : gr.append_bypass) {
                    if (entry.empty()) {
                        continue;
                    }

                    // Heuristic: if the entry validates as a CIDR, treat as inline.
                    // Otherwise treat as a file path.
                    if (IsValidCidr(entry)) {
                        cidr_set.emplace(entry);
                    }
                    else {
                        // Treat as file path.
                        ProcessGeoIpSource(entry, cidr_set, skipped);
                    }
                }

                // ----------------------------------------------------------
                // Phase 3: Collect DNS rules from GeoSite sources.
                // ----------------------------------------------------------
                ppp::vector<ppp::string> dns_rule_lines;

                ProcessGeoSiteDat(gr.geosite_dat, gr.country, domestic_provider, dns_rule_lines, skipped);

                for (const auto& geosite_src : gr.geosite) {
                    ProcessGeoSiteSource(geosite_src, domestic_provider, dns_rule_lines, skipped);
                }

                ppp::telemetry::Log(Level::kDebug, "geo-rules",
                    "geosite sources: %d rules generated", (int)dns_rule_lines.size());

                // ----------------------------------------------------------
                // Phase 4: Process append-dns-rules.
                //   - Lines prefixed with "rules://" are loaded from file.
                //   - Lines already containing "/" are treated as complete rules and appended as-is.
                //   - Other lines are domain inputs normalized through NormalizeDomainToDnsRule.
                // ----------------------------------------------------------
                for (const auto& entry : gr.append_dns_rules) {
                    if (entry.empty()) {
                        continue;
                    }

                    // Check for rules:// file prefix.
                    if (entry.size() > 8 && memcmp(entry.data(), "rules://", 8) == 0) {
                        ppp::string file_path = LTrim(RTrim(entry.substr(8)));
                        ppp::vector<ppp::string> file_lines;
                        ReadTextLines(file_path, file_lines);
                        for (auto& fl : file_lines) {
                            // File lines are treated as complete rules if they contain "/".
                            if (fl.find('/') != ppp::string::npos) {
                                dns_rule_lines.emplace_back(std::move(fl));
                            }
                            else {
                                // Normalize as domain input.
                                ppp::string rule = NormalizeDomainToDnsRule(fl, domestic_provider);
                                if (!rule.empty()) {
                                    dns_rule_lines.emplace_back(std::move(rule));
                                }
                                else {
                                    skipped++;
                                }
                            }
                        }
                    }
                    elif(entry.find('/') != ppp::string::npos) {
                        // Already a complete rule line (e.g. "example.cn /doh.pub/nic").
                        dns_rule_lines.emplace_back(entry);
                    }
                    else {
                        // Treat as domain input.
                        ppp::string rule = NormalizeDomainToDnsRule(entry, domestic_provider);
                        if (!rule.empty()) {
                            dns_rule_lines.emplace_back(std::move(rule));
                        }
                        else {
                            skipped++;
                        }
                    }
                }

                // ----------------------------------------------------------
                // Phase 5: Write output files.
                // ----------------------------------------------------------
                ppp::string output_bypass = gr.output_bypass;
                ppp::string output_dns_rules = gr.output_dns_rules;

                if (output_bypass.empty()) {
                    output_bypass = "./generated/bypass-cn.txt";
                }
                if (output_dns_rules.empty()) {
                    output_dns_rules = "./generated/dns-rules-cn.txt";
                }

                // Resolve to absolute paths.
                ppp::string bypass_full = File::GetFullPath(File::RewritePath(output_bypass.data()).data());
                ppp::string dns_full    = File::GetFullPath(File::RewritePath(output_dns_rules.data()).data());

                if (bypass_full.empty()) {
                    bypass_full = output_bypass;
                }
                if (dns_full.empty()) {
                    dns_full = output_dns_rules;
                }

                // Write bypass file.
                if (!cidr_set.empty()) {
                    if (!EnsureParentDirectory(bypass_full)) {
                        ppp::telemetry::Log(Level::kInfo, "geo-rules",
                            "failed to create directory for %s", bypass_full.data());
                    }
                    else {
                        ppp::string content;
                        // Header comment.
                        content.append("# Auto-generated by geo-rules (Phase G)\n");
                        content.append("# Country: ");
                        content.append(gr.country);
                        content.append("\n");
                        content.append("# CIDR count: ");
                        content.append(stl::to_string<ppp::string>((int)cidr_set.size()));
                        content.append("\n\n");

                        for (const auto& cidr : cidr_set) {
                            content.append(cidr);
                            content.append("\n");
                        }

                        if (File::WriteAllBytes(bypass_full.data(), content.data(), (int)content.size())) {
                            result.output_bypass_path = bypass_full;
                            result.bypass_line_count = (int)cidr_set.size();
                            ppp::telemetry::Log(Level::kInfo, "geo-rules",
                                "bypass file written: %s (%d cidrs)",
                                bypass_full.data(), (int)cidr_set.size());
                        }
                        else {
                            ppp::telemetry::Log(Level::kInfo, "geo-rules",
                                "failed to write bypass file: %s", bypass_full.data());
                        }
                    }
                }

                // Write DNS rules file.
                if (!dns_rule_lines.empty()) {
                    if (!EnsureParentDirectory(dns_full)) {
                        ppp::telemetry::Log(Level::kInfo, "geo-rules",
                            "failed to create directory for %s", dns_full.data());
                    }
                    else {
                        ppp::string content;
                        // Header comment.
                        content.append("# Auto-generated by geo-rules (Phase G)\n");
                        content.append("# Country: ");
                        content.append(gr.country);
                        content.append("\n");
                        content.append("# Provider: ");
                        content.append(domestic_provider);
                        content.append("\n");
                        content.append("# Rule count: ");
                        content.append(stl::to_string<ppp::string>((int)dns_rule_lines.size()));
                        content.append("\n\n");

                        for (const auto& rule : dns_rule_lines) {
                            content.append(rule);
                            content.append("\n");
                        }

                        if (File::WriteAllBytes(dns_full.data(), content.data(), (int)content.size())) {
                            result.output_dns_rules_path = dns_full;
                            result.dns_rule_line_count = (int)dns_rule_lines.size();
                            ppp::telemetry::Log(Level::kInfo, "geo-rules",
                                "dns-rules file written: %s (%d rules)",
                                dns_full.data(), (int)dns_rule_lines.size());
                        }
                        else {
                            ppp::telemetry::Log(Level::kInfo, "geo-rules",
                                "failed to write dns-rules file: %s", dns_full.data());
                        }
                    }
                }

                result.skipped_lines = skipped;

                ppp::telemetry::Count("geo-rules.bypass_lines", result.bypass_line_count);
                ppp::telemetry::Count("geo-rules.dns_rules", result.dns_rule_line_count);
                ppp::telemetry::Count("geo-rules.skipped", result.skipped_lines);

                ppp::telemetry::Log(Level::kInfo, "geo-rules",
                    "geo-rules generation complete: bypass=%d dns=%d skipped=%d",
                    result.bypass_line_count, result.dns_rule_line_count, result.skipped_lines);

                return result;
            }

        } // namespace client
    } // namespace app
} // namespace ppp
