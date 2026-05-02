#include <ppp/configurations/AppConfiguration.h>
#include <ppp/cryptography/Ciphertext.h>
#include <ppp/cryptography/ssea.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/io/File.h>
#include <ppp/ssl/SSL.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/ipv6/IPv6Packet.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file AppConfiguration.cpp
 * @brief AppConfiguration loading, normalization, and JSON serialization implementation.
 */

using ppp::auxiliary::StringAuxiliary;
using ppp::auxiliary::JsonAuxiliary;
using ppp::cryptography::Ciphertext;
using ppp::io::File;
using ppp::io::FileAccess;
using ppp::net::Ipep;
using ppp::net::AddressFamily;
using ppp::net::IPEndPoint;
using ppp::threading::Thread;
using ppp::threading::Executors;

namespace {
    /**
     * @brief Indicates whether server-side IPv6 data-plane support is available on this platform.
     * @return True on Linux builds, otherwise false.
     */
    static bool                                             SupportsServerIPv6DataPlane() noexcept {
#if defined(_LINUX) && !defined(_ANDROID)
        return true;
#else
        return false;
#endif
    }

    /**
     * @brief Parses textual IPv6 mode into enum value.
     * @param mode Text mode value.
     * @return Parsed IPv6 mode; defaults to none.
     */
    static ppp::configurations::AppConfiguration::IPv6Mode  ParseIPv6Mode(const ppp::string& mode) noexcept {
        ppp::string value = ToLower(mode);
        if (value == "nat66") {
            return ppp::configurations::AppConfiguration::IPv6Mode_Nat66;
        }
        if (value == "gua") {
            return ppp::configurations::AppConfiguration::IPv6Mode_Gua;
        }
        return ppp::configurations::AppConfiguration::IPv6Mode_None;
    }

    /**
     * @brief Converts IPv6 mode enum to configuration string.
     * @param mode IPv6 mode.
     * @return Mode string used in JSON.
     */
    static ppp::string                                      IPv6ModeToString(ppp::configurations::AppConfiguration::IPv6Mode mode) noexcept {
        switch (mode) {
        case ppp::configurations::AppConfiguration::IPv6Mode_Nat66:
            return "nat66";
        case ppp::configurations::AppConfiguration::IPv6Mode_Gua:
            return "gua";
        default:
            return "";
        }
    }

    /**
     * @brief Restricts IPv6 mode to supported values.
     * @param mode Candidate mode.
     * @return Normalized mode value.
     */
    static ppp::configurations::AppConfiguration::IPv6Mode  NormalizeIPv6Mode(ppp::configurations::AppConfiguration::IPv6Mode mode) noexcept {
        switch (mode) {
        case ppp::configurations::AppConfiguration::IPv6Mode_Nat66:
        case ppp::configurations::AppConfiguration::IPv6Mode_Gua:
            return mode;
        default:
            return ppp::configurations::AppConfiguration::IPv6Mode_None;
        }
    }

    /**
     * @brief Parses an IPv6 CIDR string into prefix and prefix length.
     * @param cidr CIDR input.
     * @param prefix Output prefix string.
     * @param prefix_length Output prefix length.
     * @return True when a usable prefix is produced.
     */
    static bool                                             ParseIPv6Cidr(const ppp::string& cidr, ppp::string& prefix, int& prefix_length) noexcept {
        prefix.clear();
        prefix_length = 0;
        if (cidr.empty()) {
            return false;
        }

        std::size_t slash = cidr.find('/');
        if (slash == ppp::string::npos) {
            prefix = cidr;
            prefix_length = ppp::ipv6::IPv6_DEFAULT_PREFIX_LENGTH;
            return true;
        }

        prefix = cidr.substr(0, slash);
        
        /**
         * @brief Validate prefix length using strtol for proper error detection.
         * @note Reject invalid numeric strings and out-of-range values.
         */
        const ppp::string plen_str = cidr.substr(slash + 1);
        char* endptr = NULLPTR;
        long parsed = strtol(plen_str.c_str(), &endptr, 10);
        if (NULLPTR == endptr || endptr == plen_str.c_str() || *endptr != '\x0' || parsed < ppp::ipv6::IPv6_MIN_PREFIX_LENGTH || parsed > ppp::ipv6::IPv6_MAX_PREFIX_LENGTH)
        {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6PrefixInvalid);
            return false;
        }
        
        prefix_length = static_cast<int>(parsed);
        return !prefix.empty();
    }

    /**
     * @brief Computes the first host address inside an IPv6 prefix.
     * @param network Network prefix address.
     * @param prefix_length Prefix length.
     * @param host Output host address.
     * @return True when a valid host address is generated.
     */
    static bool                                             TryGetFirstHostIPv6(const boost::asio::ip::address_v6& network, int prefix_length, boost::asio::ip::address_v6& host) noexcept {
        prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, prefix_length));
        if (prefix_length >= ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
            return false;
        }

        boost::asio::ip::address_v6::bytes_type bytes = ppp::ipv6::ComputeNetworkAddress(network, prefix_length).to_bytes();
        for (int i = 15; i >= 0; --i) {
            if (bytes[i] != 0xff) {
                ++bytes[i];
                for (int j = i + 1; j < 16; ++j) {
                    bytes[j] = 0;
                }
                host = boost::asio::ip::address_v6(bytes);
                return true;
            }
        }
        return false;
    }
                                            
    /**
     * @brief Checks whether an IPv6 prefix is globally routable unicast.
     * @param prefix IPv6 prefix address.
     * @return True when prefix belongs to 2000::/3.
     */
    static bool                                             IsGlobalUnicastIPv6Prefix(const boost::asio::ip::address_v6& prefix) noexcept {
        boost::asio::ip::address_v6::bytes_type bytes = prefix.to_bytes();
        return (bytes[0] & 0xe0) == 0x20;
    }
                                            
    /**
     * @brief Clears all server IPv6 runtime settings.
     * @param config Configuration object to update.
     */
    static void                                             DisableServerIPv6(ppp::configurations::AppConfiguration& config) noexcept {
        config.server.ipv6.mode = ppp::configurations::AppConfiguration::IPv6Mode_None;
        config.server.ipv6.cidr.clear();
        config.server.ipv6.prefix_length = 0;
        config.server.ipv6.gateway.clear();
        config.server.ipv6.dns1.clear();
        config.server.ipv6.dns2.clear();
        config.server.ipv6.lease_time = 0;
        config.server.ipv6.static_addresses.clear();
    }
}

namespace ppp {
    namespace configurations {
        static constexpr int                            EVP_HEADER_MSS_MIN_MOD = 64 * 64 * 64;
        static constexpr int                            EVP_HEADER_MSS_MAX_MOD = 94 * 94 * 94;
        static constexpr int                            VEP_HEADER_MSS_MAX_MOD = 1 << 8;
        static constexpr int                            VEP_HEADER_MSS_MIN_MOD = 1 << 7;

        /**
         * @brief Constructs configuration with default values.
         */
        AppConfiguration::AppConfiguration() noexcept {
            Clear();
        }

        /**
         * @brief Resets every configuration section to defaults.
         */
        void AppConfiguration::Clear() noexcept {
            AppConfiguration& config = *this;
            config.concurrent = Thread::GetProcessorCount();
            config.cdn[0] = IPEndPoint::MinPort;
            config.cdn[1] = IPEndPoint::MinPort;
            config.ip.public_ = "";
            config.ip.interface_ = "";

            config.udp.dns.timeout = PPP_DEFAULT_DNS_TIMEOUT;
            config.udp.dns.redirect = "";
            config.udp.dns.ttl = PPP_DEFAULT_DNS_TTL;
            config.udp.dns.turbo = false;
            config.udp.dns.cache = true;
            config.udp.cwnd = 0;
            config.udp.rwnd = 0;
            config.udp.inactive.timeout = PPP_UDP_INACTIVE_TIMEOUT;
            config.udp.listen.port = IPEndPoint::MinPort;
            config.udp.static_.dns = true;
            config.udp.static_.quic = true;
            config.udp.static_.icmp = true;
            config.udp.static_.aggligator = 0;
            config.udp.static_.servers.clear();
            config.udp.static_.keep_alived[0] = PPP_UDP_KEEP_ALIVED_MIN_TIMEOUT;
            config.udp.static_.keep_alived[1] = PPP_UDP_KEEP_ALIVED_MAX_TIMEOUT;

            config.tcp.turbo = false;
            config.tcp.backlog = PPP_LISTEN_BACKLOG;
            config.tcp.fast_open = false;
            config.tcp.listen.port = IPEndPoint::MinPort;
            config.tcp.connect.timeout = PPP_TCP_CONNECT_TIMEOUT;
            config.tcp.connect.nexcept = PPP_TCP_CONNECT_NEXCEPT;
            config.tcp.inactive.timeout = PPP_TCP_INACTIVE_TIMEOUT;
            config.tcp.cwnd = 0;
            config.tcp.rwnd = 0;

            config.mux.connect.timeout = PPP_MUX_CONNECT_TIMEOUT;
            config.mux.inactive.timeout = PPP_MUX_INACTIVE_TIMEOUT;
            config.mux.keep_alived[0] = PPP_TCP_CONNECT_TIMEOUT;
            config.mux.keep_alived[1] = PPP_MUX_CONNECT_TIMEOUT;

            config.websocket.listen.ws = IPEndPoint::MinPort;
            config.websocket.listen.wss = IPEndPoint::MinPort;
            config.websocket.ssl.verify_peer = true;
            config.websocket.ssl.certificate_file = "";
            config.websocket.ssl.certificate_key_file = "";
            config.websocket.ssl.certificate_chain_file = "";
            config.websocket.ssl.certificate_key_password = "";
            config.websocket.ssl.ciphersuites = GetDefaultCipherSuites();
            config.websocket.host = "";
            config.websocket.path = "";
            config.websocket.http.error = "";
            config.websocket.http.request.clear();
            config.websocket.http.response.clear();

            config.key.kf = 154543927;
            config.key.kh = 12;
            config.key.kl = 10;
            config.key.kx = 128;
            config.key.sb = 0;

            config.key.protocol = PPP_DEFAULT_KEY_PROTOCOL;
            config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
            config.key.transport = PPP_DEFAULT_KEY_TRANSPORT;
            config.key.transport_key = BOOST_BEAST_VERSION_STRING;
            config.key.masked = true;
            config.key.plaintext = true;
            config.key.delta_encode = true;
            config.key.shuffle_data = true;

            config.server.log = "";
            config.server.node = 0;
            config.server.subnet = true;
            config.server.mapping = true;
            config.server.backend = "";
            config.server.backend_key = "";
            config.server.ipv6.mode = AppConfiguration::IPv6Mode_None;
            config.server.ipv6.cidr = "";
            config.server.ipv6.prefix_length = ppp::ipv6::IPv6_MAX_PREFIX_LENGTH;
            config.server.ipv6.gateway = "";
            config.server.ipv6.dns1 = "";
            config.server.ipv6.dns2 = "";
            config.server.ipv6.lease_time = 300;
            config.server.ipv6.static_addresses.clear();

            config.client.mappings.clear();
            config.client.guid = StringAuxiliary::Int128ToGuidString(MAKE_OWORD(UINT64_MAX, UINT64_MAX));
            config.client.server = "";
            config.client.server_proxy = "";
            config.client.bandwidth = 0;
            config.client.reconnections.timeout = PPP_TCP_CONNECT_TIMEOUT;
            config.client.http_proxy.bind = "";
            config.client.http_proxy.port = PPP_DEFAULT_HTTP_PROXY_PORT;
            config.client.socks_proxy.bind = "";
            config.client.socks_proxy.port = PPP_DEFAULT_SOCKS_PROXY_PORT;
            config.client.socks_proxy.password = "";
            config.client.socks_proxy.username = "";
#if defined(_WIN32)
            config.client.paper_airplane.tcp = true;
#endif

            config.virr.update_interval = 86400;
            config.virr.retry_interval = 300;
            config.vbgp.update_interval = 3600;

            config.telemetry.enabled = false;
            config.telemetry.level = 0;
            config.telemetry.count = false;
            config.telemetry.span = false;
            config.telemetry.endpoint = "";
            config.telemetry.log_file = "";
            config.telemetry.console_log = true;
            config.telemetry.console_metric = true;
            config.telemetry.console_span = true;

            memset(config._lcgmods, 0, sizeof(config._lcgmods));
        }

        template <class _Uty>
        /**
         * @brief Trims whitespace from each string pointer in an array.
         * @tparam _Uty Pointer array element type.
         * @param s Pointer array.
         * @param length Number of elements in @p s.
         */
        static void LRTrim(_Uty* s, int length) noexcept {
            for (int i = 0; i < length; i++) {
                *s[i] = LTrim(RTrim(*s[i]));
            }
        }

        /**
         * @brief Trims selected string fields from configuration groups.
         * @param config Configuration object.
         * @param level Selection level for field groups.
         */
        static void LRTrim(AppConfiguration& config, int level) noexcept {
            if (level) {
                ppp::string* strings[] = {
                    &config.ip.public_,
                    &config.ip.interface_,
                    &config.udp.dns.redirect,
                    &config.vmem.path,
                    &config.server.backend,
                    &config.server.backend_key,
                    &config.server.log,
                    &config.server.ipv6.cidr,
                    &config.server.ipv6.gateway,
                    &config.server.ipv6.dns1,
                    &config.server.ipv6.dns2,
                    &config.client.guid,
                    &config.client.server,
                    &config.client.server_proxy,
                    &config.client.http_proxy.bind,
                    &config.client.socks_proxy.bind,
                    &config.client.socks_proxy.password,
                    &config.client.socks_proxy.username,
                    &config.websocket.host,
                    &config.websocket.path,
                    &config.key.protocol,
                    &config.key.protocol_key,
                    &config.key.transport,
                    &config.key.transport_key,
                };
                LRTrim(strings, arraysizeof(strings));
            }
            else {
                std::string* strings[] = {
                    &config.websocket.ssl.certificate_file,
                    &config.websocket.ssl.certificate_key_file,
                    &config.websocket.ssl.certificate_chain_file,
                    &config.websocket.ssl.certificate_key_password,
                    &config.websocket.ssl.ciphersuites,
                };
                LRTrim(strings, arraysizeof(strings));
            }
        }

        /**
         * @brief Loads and deduplicates client mapping rules from JSON.
         * @param config Target configuration object.
         * @param json JSON mapping node (array or single object).
         * @return True when input shape is supported.
         */
        static bool LoadAllMappings(AppConfiguration& config, Json::Value& json) noexcept {
            using MappingConfiguration = AppConfiguration::MappingConfiguration;

            if (json.isObject()) {
                Json::Value json_array;
                json_array.append(json);

                json = json_array;
            }

            if (!json.isArray()) {
                return false;
            }

            Json::ArrayIndex json_length = json.size();
            ppp::unordered_map<boost::asio::ip::tcp::endpoint, MappingConfiguration> tcp_mappings;
            ppp::unordered_map<boost::asio::ip::udp::endpoint, MappingConfiguration> udp_mappings;

            for (Json::ArrayIndex json_index = 0; json_index < json_length; json_index++) {
                Json::Value& jo = json[json_index];
                if (!jo.isObject()) {
                    continue;
                }

                MappingConfiguration mapping;
                mapping.protocol_tcp_or_udp = ToLower(LTrim(RTrim(JsonAuxiliary::AsString(jo["protocol"])))) != "udp";
                mapping.local_ip = LTrim(RTrim(JsonAuxiliary::AsString(jo["local-ip"])));
                mapping.local_port = JsonAuxiliary::AsValue<int>(jo["local-port"]);
                mapping.remote_ip = LTrim(RTrim(JsonAuxiliary::AsString(jo["remote-ip"])));
                mapping.remote_port = JsonAuxiliary::AsValue<int>(jo["remote-port"]);

                if (mapping.local_port <= IPEndPoint::MinPort || mapping.local_port > IPEndPoint::MaxPort) {
                    continue;
                }

                if (mapping.remote_port <= IPEndPoint::MinPort || mapping.remote_port > IPEndPoint::MaxPort) {
                    continue;
                }

                if (mapping.local_ip.empty() || mapping.remote_ip.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address local_ip = StringToAddress(mapping.local_ip.data(), ec);
                if (ec) {
                    continue;
                }

                boost::asio::ip::address remote_ip = StringToAddress(mapping.remote_ip.data(), ec);
                if (ec) {
                    continue;
                }

                if (IPEndPoint::IsInvalid(local_ip)) {
                    continue;
                }

                if (!remote_ip.is_unspecified()) {
                    if (IPEndPoint::IsInvalid(remote_ip)) {
                        continue;
                    }
                }

                if (local_ip.is_multicast() || remote_ip.is_multicast()) {
                    continue;
                }

                mapping.local_ip = local_ip.to_string();
                mapping.remote_ip = remote_ip.to_string();

                if (mapping.protocol_tcp_or_udp) {
                    boost::asio::ip::tcp::endpoint remote_ep = boost::asio::ip::tcp::endpoint(remote_ip, mapping.remote_port);
                    tcp_mappings.emplace(remote_ep, mapping);
                }
                else {
                    boost::asio::ip::udp::endpoint remote_ep = boost::asio::ip::udp::endpoint(remote_ip, mapping.remote_port);
                    udp_mappings.emplace(remote_ep, mapping);
                }
            }

            ppp::vector<MappingConfiguration>& client_mappings = config.client.mappings;
            client_mappings.clear();

            for (auto&& [_, mapping] : tcp_mappings) {
                client_mappings.emplace_back(mapping);
            }

            for (auto&& [_, mapping] : udp_mappings) {
                client_mappings.emplace_back(mapping);
            }

            return true;
        }

        /**
         * @brief Normalizes and validates loaded configuration values.
         * @return True when normalization completes.
         */
        bool AppConfiguration::Loaded() noexcept {
            AppConfiguration& config = *this;
            if (config.concurrent < 1) {
                config.concurrent = Thread::GetProcessorCount();
            }

            config.server.node = std::max<int>(0, config.server.node);
            config.server.ipv6.prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, config.server.ipv6.prefix_length));
            config.udp.dns.ttl = std::max<int>(0, config.udp.dns.ttl);

            if (config.udp.dns.timeout < 1) {
                config.udp.dns.timeout = PPP_DEFAULT_DNS_TIMEOUT;
            }

            if (config.udp.inactive.timeout < 1) {
                config.udp.inactive.timeout = PPP_UDP_INACTIVE_TIMEOUT;
            }

            if (config.tcp.backlog < 1) {
                config.tcp.backlog = PPP_LISTEN_BACKLOG;
            }

            if (config.tcp.connect.timeout < 1) {
                config.tcp.connect.timeout = PPP_TCP_CONNECT_TIMEOUT;
            }

            if (config.tcp.connect.nexcept < 0) {
                config.tcp.connect.nexcept = PPP_TCP_CONNECT_NEXCEPT;
            }

            if (config.tcp.inactive.timeout < 1) {
                config.tcp.inactive.timeout = PPP_TCP_INACTIVE_TIMEOUT;
            }

            if (config.mux.connect.timeout < 1) {
                config.mux.connect.timeout = PPP_MUX_CONNECT_TIMEOUT;
            }

            if (config.mux.inactive.timeout < 1) {
                config.mux.inactive.timeout = PPP_MUX_INACTIVE_TIMEOUT;
            }

            if (config.mux.congestions < 0 || (config.mux.congestions > 0 && config.mux.congestions < PPP_MUX_MIN_CONGESTIONS)) {
                config.mux.congestions = PPP_MUX_DEFAULT_CONGESTIONS;
            }

            if (config.udp.static_.aggligator < 0) {
                config.udp.static_.aggligator = 0;
            }

            LRTrim(config, 0);
            LRTrim(config, 1);

            if (config.client.guid.empty()) {
                config.client.guid = StringAuxiliary::Int128ToGuidString(MAKE_OWORD(UINT64_MAX, UINT64_MAX));
            }

            if (config.client.reconnections.timeout < 1) {
                config.client.reconnections.timeout = PPP_TCP_CONNECT_TIMEOUT;
            }

            int* pts[] = {
                &config.tcp.listen.port,
                &config.websocket.listen.ws,
                &config.websocket.listen.wss,
                &config.client.http_proxy.port,
                &config.client.socks_proxy.port,
                &config.udp.listen.port
            };

            for (int i = 0; i < arraysizeof(pts); i++) {
                int& port = *pts[i];
                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }
            }

            for (int i = 0; i < arraysizeof(config.cdn); i++) {
                int& cdn = config.cdn[i];
                if (cdn < IPEndPoint::MinPort || cdn > IPEndPoint::MaxPort) {
                    cdn = IPEndPoint::MinPort;
                }
            }

            for (int i = 0; i < arraysizeof(config.udp.static_.keep_alived); i++) {
                int& keep_alived = config.udp.static_.keep_alived[i];
                keep_alived = std::max<int>(0, keep_alived);
            }

            for (int i = 0; i < arraysizeof(config.mux.keep_alived); i++) {
                int& keep_alived = config.mux.keep_alived[i];
                keep_alived = std::max<int>(0, keep_alived);
            }

            ppp::string* ips[] = {
                &config.ip.public_,
                &config.ip.interface_,
                &config.client.http_proxy.bind,
                &config.client.socks_proxy.bind,
            };
            for (int i = 0; i < arraysizeof(ips); i++) {
                ppp::string& ip = *ips[i];
                if (ip.empty()) {
                    continue;
                }

                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(ip.data(), ec);
                if (ec) {
                    ip = "";
                }
                elif(IPEndPoint::IsInvalid(address) && !(address.is_unspecified() && (address.is_v4() || address.is_v6()))) {
                    ip = "";
                }
                else {
                    ip = Ipep::ToAddressString<ppp::string>(address);
                }
            }

            config.server.ipv6.mode = NormalizeIPv6Mode(config.server.ipv6.mode);
            bool ipv6_server_enabled = config.server.ipv6.mode == AppConfiguration::IPv6Mode_Nat66 ||
                config.server.ipv6.mode == AppConfiguration::IPv6Mode_Gua;
            if (ipv6_server_enabled && !SupportsServerIPv6DataPlane()) {
                if (config.server.ipv6.mode == AppConfiguration::IPv6Mode_Nat66) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6Nat66Unavailable);
                }
                else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::PlatformNotSupportGUAMode);
                }
                return false;
            }

            ppp::string ipv6_prefix;
            ParseIPv6Cidr(config.server.ipv6.cidr, ipv6_prefix, config.server.ipv6.prefix_length);

            if (ipv6_server_enabled) {
                if (config.server.ipv6.mode == AppConfiguration::IPv6Mode_Nat66) {
                    if (ipv6_prefix.empty()) {
                        ipv6_prefix = ppp::ipv6::IPV6_DEFAULT_PREFIX;
                        config.server.ipv6.prefix_length = 64;
                    }
                }

                if (config.server.ipv6.prefix_length <= ppp::ipv6::IPv6_MIN_PREFIX_LENGTH || config.server.ipv6.prefix_length >= ppp::ipv6::IPv6_MAX_PREFIX_LENGTH) {
                    DisableServerIPv6(config);
                    ipv6_prefix = "";
                    ipv6_server_enabled = false;
                }
            }
            else {
                config.server.ipv6.mode = AppConfiguration::IPv6Mode_None;
            }

            if (ipv6_server_enabled) {
                boost::asio::ip::address_v6 cidr_prefix = boost::asio::ip::address_v6();
                boost::system::error_code cidr_ec;
                if (!ipv6_prefix.empty()) {
                    cidr_prefix = boost::asio::ip::make_address_v6(ipv6_prefix.c_str(), cidr_ec);
                    if (!cidr_ec) {
                        cidr_prefix = ppp::ipv6::ComputeNetworkAddress(cidr_prefix, config.server.ipv6.prefix_length);
                        ipv6_prefix = cidr_prefix.to_string();
                    }
                }

                bool invalid_server_prefix = cidr_ec || ipv6_prefix.empty() || cidr_prefix.is_unspecified() || cidr_prefix.is_multicast() || cidr_prefix.is_loopback();
                if (!invalid_server_prefix && config.server.ipv6.mode == AppConfiguration::IPv6Mode_Gua) {
                    invalid_server_prefix = !IsGlobalUnicastIPv6Prefix(cidr_prefix);
                }
                if (invalid_server_prefix) {
                    DisableServerIPv6(config);
                    ipv6_prefix.clear();
                    ipv6_server_enabled = false;
                }
            }

            if (ipv6_server_enabled) {
                boost::asio::ip::address_v6 cidr_prefix = boost::asio::ip::address_v6();
                boost::system::error_code cidr_ec;
                if (!ipv6_prefix.empty()) {
                    cidr_prefix = boost::asio::ip::make_address_v6(ipv6_prefix.c_str(), cidr_ec);
                }

                boost::system::error_code gateway_ec;
                boost::asio::ip::address configured_gateway = StringToAddress(config.server.ipv6.gateway, gateway_ec);
                boost::asio::ip::address_v6 effective_gateway_v6 = boost::asio::ip::address_v6();
                bool has_effective_gateway = false;
                if (gateway_ec || !configured_gateway.is_v6() || cidr_ec) {
                    config.server.ipv6.gateway.clear();
                }
                elif (!ppp::ipv6::PrefixMatch(configured_gateway.to_v6(), cidr_prefix, config.server.ipv6.prefix_length)) {
                    config.server.ipv6.gateway.clear();
                }
                elif (configured_gateway.to_v6() == cidr_prefix) {
                    config.server.ipv6.gateway.clear();
                }
                else {
                    effective_gateway_v6 = configured_gateway.to_v6();
                    has_effective_gateway = true;
                }

                if (!has_effective_gateway && !cidr_ec) {
                    has_effective_gateway = TryGetFirstHostIPv6(cidr_prefix, config.server.ipv6.prefix_length, effective_gateway_v6);
                }

                ppp::map<ppp::string, ppp::string> normalized_static_addresses;
                ppp::unordered_set<ppp::string> used_static_addresses;
                /**
                 * @brief Normalize static IPv6 leases to valid, unique, in-prefix addresses.
                 */
                for (const auto& kv : config.server.ipv6.static_addresses) {
                    Int128 static_guid_id = auxiliary::StringAuxiliary::GuidStringToInt128(kv.first);
                    if (static_guid_id == 0) {
                        continue;
                    }

                    boost::system::error_code static_ec;
                    boost::asio::ip::address static_address = StringToAddress(kv.second, static_ec);
                    if (static_ec || !static_address.is_v6()) {
                        continue;
                    }

                    boost::asio::ip::address_v6 static_v6 = static_address.to_v6();
                    if (cidr_ec || !ppp::ipv6::PrefixMatch(static_v6, cidr_prefix, config.server.ipv6.prefix_length)) {
                        continue;
                    }

                    if (has_effective_gateway && static_v6 == effective_gateway_v6) {
                        continue;
                    }

                    std::string normalized_address_std = static_v6.to_string();
                    ppp::string normalized_address(normalized_address_std.data(), normalized_address_std.size());
                    if (used_static_addresses.emplace(normalized_address).second) {
                        normalized_static_addresses[auxiliary::StringAuxiliary::Int128ToGuidString(static_guid_id)] = normalized_address;
                    }
                }
                config.server.ipv6.static_addresses = std::move(normalized_static_addresses);
            }

            if (!Ciphertext::Support(config.key.protocol)) {
                config.key.protocol = PPP_DEFAULT_KEY_PROTOCOL;
            }

            if (!Ciphertext::Support(config.key.transport)) {
                config.key.transport = PPP_DEFAULT_KEY_TRANSPORT;
            }

            if (config.key.protocol_key.empty()) {
                config.key.protocol_key = BOOST_BEAST_VERSION_STRING;
            }

            if (config.key.transport_key.empty()) {
                config.key.transport_key = BOOST_BEAST_VERSION_STRING;
            }

            if (!Ipep::IsDomainAddress(config.websocket.host) || config.websocket.path.empty() || config.websocket.path[0] != '/') {
                config.websocket.listen.ws = IPEndPoint::MinPort;
                config.websocket.listen.wss = IPEndPoint::MinPort;
            }
            elif(!ppp::ssl::SSL::VerifySslCertificate(config.websocket.ssl.certificate_file, config.websocket.ssl.certificate_key_file, config.websocket.ssl.certificate_chain_file)) {
                config.websocket.listen.wss = IPEndPoint::MinPort;
            }

            if (config.websocket.listen.wss == IPEndPoint::MinPort) {
                config.websocket.ssl.certificate_file = "";
                config.websocket.ssl.certificate_key_file = "";
                config.websocket.ssl.certificate_chain_file = "";
                config.websocket.ssl.certificate_key_password = "";
            }
            elif(config.websocket.ssl.ciphersuites.empty()) {
                config.websocket.ssl.ciphersuites = GetDefaultCipherSuites();
            }

            if (config.websocket.listen.ws == IPEndPoint::MinPort) {
                config.websocket.path = "";
                config.websocket.host = "";
                config.websocket.http.error = "";
                config.websocket.http.request.clear();
                config.websocket.http.response.clear();
            }

            config.server.ipv6.prefix_length = std::max<int>(ppp::ipv6::IPv6_MIN_PREFIX_LENGTH, std::min<int>(ppp::ipv6::IPv6_MAX_PREFIX_LENGTH, config.server.ipv6.prefix_length));
            config.server.ipv6.lease_time = std::max<int>(0, config.server.ipv6.lease_time);
            config.server.ipv6.cidr = ipv6_prefix;
            if (config.server.ipv6.prefix_length > 0) {
                config.server.ipv6.cidr.append("/");
                config.server.ipv6.cidr.append(stl::to_string<ppp::string>(config.server.ipv6.prefix_length));
            }

            {
                int destinationPort = IPEndPoint::MinPort;
                ppp::string destinationIP;

                ppp::string& redirect_string = config.udp.dns.redirect;
                if (!Ipep::ParseEndPoint(redirect_string, destinationIP, destinationPort)) {
                    redirect_string = "";
                }
                else {
                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(destinationIP.data(), ec);
                    if (ec) {
                        if (!Ipep::IsDomainAddress(destinationIP)) {
                            redirect_string = "";
                        }
                    }
                    elif(IPEndPoint::IsInvalid(address)) {
                        redirect_string = "";
                    }
                }
            }

            if (config.vmem.path.empty() || config.vmem.size < 1) {
                config.vmem.size = 0;
                config.vmem.path = "";
            }

            ppp::string& log = config.server.log;
            if (log.size() > 0) {
                log = File::GetFullPath(File::RewritePath(log.data()).data());
            }

            config.key.kh = std::max<int>(0, config.key.kh);
            config.key.kl = std::max<int>(0, config.key.kl);
            config.key.kx = std::max<int>(0, config.key.kx);
            config.key.kh = std::min<int>(16, config.key.kh);
            config.key.kl = std::min<int>(16, config.key.kl);
            config.key.sb = std::min<int>(std::max<int>(0, PPP_BUFFER_SIZE - PPP_BUFFER_SIZE_SKATEBOARDING), std::max<int>(0, config.key.sb));

            config.client.bandwidth = std::max<int64_t>(0, config.client.bandwidth);

            config.virr.retry_interval = std::max<int>(1, config.virr.retry_interval);
            config.virr.update_interval = std::max<int>(1, config.virr.update_interval);
            config.vbgp.update_interval = std::max<int>(1, config.vbgp.update_interval);

            config._lcgmods[LCGMOD_TYPE_TRANSMISSION] = ppp::cryptography::ssea::lcgmod(config.key.kf, EVP_HEADER_MSS_MIN_MOD, EVP_HEADER_MSS_MAX_MOD);
            config._lcgmods[LCGMOD_TYPE_STATIC] = ppp::cryptography::ssea::lcgmod(config.key.kf, VEP_HEADER_MSS_MIN_MOD, VEP_HEADER_MSS_MAX_MOD);
            return true;
        }

        /**
         * @brief Loads configuration from a JSON file path.
         * @param path Configuration file path.
         * @return True when file parsing and normalization succeed.
         */
        bool AppConfiguration::Load(const ppp::string& path) noexcept {
            Clear();
            if (path.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigPathInvalid);
            }

            ppp::string file_path = File::GetFullPath(File::RewritePath(path.data()).data());
            if (file_path.empty()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigPathInvalid);
            }

            ppp::string json_string = File::ReadAllText(file_path.data());
            if (json_string.empty()) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigFileEmpty);
                }

                return false;
            }

            Json::Value json = JsonAuxiliary::FromString(json_string);
            if (!json.isObject()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::AppConfigurationLoadJsonNotObject);
            }
            else {
                bool loaded = Load(json);
                if (!loaded && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigLoadFailed);
                }
                return loaded;
            }
        }

        template <typename TMap>
        /**
         * @brief Reads object/array JSON values into a key-value map.
         * @tparam TMap Map-like target container type.
         * @param json Source JSON node.
         * @param map Output map.
         * @return True when JSON type is object or array.
         */
        static bool ReadJsonAllTokensToMap(const Json::Value& json, TMap& map) noexcept {
            map.clear();

            if (json.isObject()) {
                for (ppp::string& k : json.getMemberNames()) {
                    Json::Value v = json[k.data()];
                    map[k] = LTrim(RTrim(JsonAuxiliary::AsString(v)));
                }

                return true;
            }
            elif(json.isArray()) {
                Json::ArrayIndex json_size = json.size();
                for (Json::ArrayIndex json_index = 0; json_index < json_size; json_index++) {
                    Json::Value v = json[json_index];
                    map[stl::to_string<ppp::string>(json_index)] = LTrim(RTrim(JsonAuxiliary::AsString(v)));
                }

                return true;
            }

            return false;
        }

        template <typename TSet>
        /**
         * @brief Reads object/array/string JSON values into a string set.
         * @tparam TSet Set-like target container type.
         * @param json Source JSON node.
         * @param s Output set.
         * @return True when JSON type is object or array.
         */
        static bool ReadJsonAllTokensToSet(const Json::Value& json, TSet& s) noexcept {
            s.clear();

            auto emplace =
                [](const ppp::string& v, TSet& s) noexcept {
                ppp::string x = LTrim(RTrim(JsonAuxiliary::AsString(v)));
                if (!x.empty()) {
                    s.emplace(x);
                }
                };

            if (json.isObject()) {
                for (ppp::string& k : json.getMemberNames()) {
                    Json::Value v = json[k.data()];
                    emplace(JsonAuxiliary::AsString(v), s);
                }

                return true;
            }
            elif(json.isArray()) {
                Json::ArrayIndex json_size = json.size();
                for (Json::ArrayIndex json_index = 0; json_index < json_size; json_index++) {
                    Json::Value v = json[json_index];
                    emplace(JsonAuxiliary::AsString(v), s);
                }

                return true;
            }
            elif(json.isString()) {
                emplace(JsonAuxiliary::AsString(json), s);
            }

            return false;
        }

        /**
         * @brief Validates that a string is an IP literal or domain name.
         * @param host_string Input host text.
         * @param out Optional parsed address output when host is an IP.
         * @return True when host is valid.
         */
        static bool IPOrHostIsValid(const ppp::string& host_string, boost::asio::ip::address* out = NULLPTR) noexcept {
            if (host_string.empty()) {
                return false;
            }

            boost::system::error_code ec;
            boost::asio::ip::address address = StringToAddress(host_string, ec);
            if (ec) {
                return ppp::net::Ipep::IsDomainAddress(host_string);
            }
            elif(address.is_v4() || address.is_v6()) {
                bool valid = !IPEndPoint::IsInvalid(address);
                if (NULLPTR != out && valid) {
                    *out = address;
                }

                return valid;
            }
            else {
                return false;
            }
        }

        /**
         * @brief Reads and validates endpoint strings into a normalized set.
         * @param json Source JSON node.
         * @param s Output endpoint set.
         * @return True when token extraction succeeds.
         */
        static bool ReadJsonAllAddressStringToSet(const Json::Value& json, ppp::unordered_set<ppp::string>& s) noexcept {
            s.clear();

            ppp::unordered_set<ppp::string> sets;
            if (!ReadJsonAllTokensToSet(json, sets)) {
                return false;
            }

            for (const ppp::string& server_string : sets) {
                if (server_string.empty()) {
                    continue;
                }

                ppp::string host_string;
                int port;

                if (!ppp::net::Ipep::ParseEndPoint(server_string, host_string, port)) {
                    continue;
                }

                if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    continue;
                }

                if (!IPOrHostIsValid(host_string)) {
                    continue;
                }

                host_string = LTrim(RTrim(host_string));
                if (!host_string.empty()) {
                    s.emplace(host_string + ":" + stl::to_string<ppp::string>(port));
                }
            }
            return true;
        }

        template <typename TValue>
        /**
         * @brief Assigns a JSON value when the node is present.
         * @tparam TValue Destination type.
         * @param destination Output destination value.
         * @param json Source JSON node.
         * @return True when assignment is performed.
         */
        static bool AssignIfPresent(TValue& destination, const Json::Value& json) noexcept {
            if (json.isNull()) {
                return false;
            }

            destination = JsonAuxiliary::AsValue<TValue>(json);
            return true;
        }

        /**
         * @brief Assigns a boolean JSON value when the node is present.
         * @param destination Output destination value.
         * @param json Source JSON node.
         * @return True when assignment is performed.
         */
        static bool AssignBoolIfPresent(bool& destination, const Json::Value& json) noexcept {
            if (json.isNull()) {
                return false;
            }

            destination = JsonAuxiliary::AsValue<bool>(json);
            return true;
        }

        /**
         * @brief Parses one route configuration object.
         * @param route Output route object.
         * @param json Source JSON node.
         * @return True when route data is valid.
         */
        static bool ReadJsonToRoute(AppConfiguration::RouteConfiguration& route, const Json::Value& json) noexcept {
            if (json.isNull()) {
                return false;
            }

            boost::asio::ip::address ngw;
            if (!IPOrHostIsValid(JsonAuxiliary::AsValue<ppp::string>(json["ngw"]), addressof(ngw))) {
                return false;
            }

            if (!ngw.is_v4()) {
                return false;
            }

            ppp::string path = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["path"])));
            if (path.empty()) {
                return false;
            }

            ppp::string vbgp = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["vbgp"])));
            if (!ppp::net::http::HttpClient::VerifyUri(vbgp, NULLPTR, NULLPTR, NULLPTR, NULLPTR)) {
                if (ppp::diagnostics::ErrorCode::Success != ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);
                }
                vbgp = ppp::string();
            }

            route.ngw = htonl(ngw.to_v4().to_uint());
            route.path = path;
            route.vbgp = vbgp;
#if defined(_LINUX)
            route.nic = LTrim(RTrim(JsonAuxiliary::AsValue<ppp::string>(json["nic"])));
#endif
            return true;
        }

        /**
         * @brief Loads route configuration list from JSON.
         * @param s Output route vector.
         * @param json Source JSON node.
         */
        static void LoadAllRoutes(ppp::vector<AppConfiguration::RouteConfiguration>& s, const Json::Value& json) noexcept {
            using RouteConfiguration = AppConfiguration::RouteConfiguration;

            s.clear();

            if (json.isArray()) {
                Json::ArrayIndex json_size = json.size();
                RouteConfiguration route;
                for (Json::ArrayIndex json_index = 0; json_index < json_size; json_index++) {
                    Json::Value v = json[json_index];
                    if (ReadJsonToRoute(route, v)) {
                        s.emplace_back(route);
                    }
                }
            }
            elif(json.isObject()) {
                RouteConfiguration route;
                if (ReadJsonToRoute(route, json)) {
                    s.emplace_back(route);
                }
            }
        }

        /**
         * @brief Loads configuration from a JSON object.
         * @param json Source JSON object.
         * @return True when loading and normalization succeed.
         */
        bool AppConfiguration::Load(Json::Value& json) noexcept {
            Clear();
            if (!json.isObject()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigTypeMismatch);
            }

            AppConfiguration& config = *this;
            config.concurrent = JsonAuxiliary::AsValue<int>(json["concurrent"]);
            config.cdn[0] = JsonAuxiliary::AsValue<int>(json["cdn"][0]);
            config.cdn[1] = JsonAuxiliary::AsValue<int>(json["cdn"][1]);

            config.ip.public_ = JsonAuxiliary::AsValue<ppp::string>(json["ip"]["public"]);
            config.ip.interface_ = JsonAuxiliary::AsValue<ppp::string>(json["ip"]["interface"]);

            config.vmem.size = JsonAuxiliary::AsValue<int64_t>(json["vmem"]["size"]);
            config.vmem.path = JsonAuxiliary::AsValue<ppp::string>(json["vmem"]["path"]);

            config.udp.inactive.timeout = JsonAuxiliary::AsValue<int>(json["udp"]["inactive"]["timeout"]);
            config.udp.dns.timeout = JsonAuxiliary::AsValue<int>(json["udp"]["dns"]["timeout"]);
            config.udp.dns.ttl = JsonAuxiliary::AsValue<int>(json["udp"]["dns"]["ttl"]);
            config.udp.dns.turbo = JsonAuxiliary::AsValue<bool>(json["udp"]["dns"]["turbo"]);
            config.udp.dns.cache = JsonAuxiliary::AsInt64(json["udp"]["dns"]["cache"], 1) != 0;
            config.udp.dns.redirect = JsonAuxiliary::AsValue<ppp::string>(json["udp"]["dns"]["redirect"]);
            config.udp.listen.port = JsonAuxiliary::AsValue<int>(json["udp"]["listen"]["port"]);
            config.udp.cwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["udp"]["cwnd"]));
            config.udp.rwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["udp"]["rwnd"]));
            AssignBoolIfPresent(config.udp.static_.dns, json["udp"]["static"]["dns"]);
            AssignBoolIfPresent(config.udp.static_.quic, json["udp"]["static"]["quic"]);
            AssignBoolIfPresent(config.udp.static_.icmp, json["udp"]["static"]["icmp"]);
            config.udp.static_.aggligator = JsonAuxiliary::AsValue<int>(json["udp"]["static"]["aggligator"]);
            config.udp.static_.keep_alived[0] = JsonAuxiliary::AsValue<int>(json["udp"]["static"]["keep-alived"][0]);
            config.udp.static_.keep_alived[1] = JsonAuxiliary::AsValue<int>(json["udp"]["static"]["keep-alived"][1]);
            if (!ReadJsonAllAddressStringToSet(json["udp"]["static"]["servers"], config.udp.static_.servers)) {
                ReadJsonAllAddressStringToSet(json["udp"]["static"]["server"], config.udp.static_.servers);
            }

            config.tcp.inactive.timeout = JsonAuxiliary::AsValue<int>(json["tcp"]["inactive"]["timeout"]);
            config.tcp.connect.timeout = JsonAuxiliary::AsValue<int>(json["tcp"]["connect"]["timeout"]);
            config.tcp.connect.nexcept = (int)JsonAuxiliary::AsInt64(json["tcp"]["connect"]["nexcept"], PPP_TCP_CONNECT_NEXCEPT);

            config.tcp.listen.port = JsonAuxiliary::AsValue<int>(json["tcp"]["listen"]["port"]);
            config.tcp.turbo = JsonAuxiliary::AsValue<bool>(json["tcp"]["turbo"]);
            config.tcp.backlog = JsonAuxiliary::AsValue<int>(json["tcp"]["backlog"]);
            config.tcp.fast_open = JsonAuxiliary::AsValue<bool>(json["tcp"]["fast-open"]);
            config.tcp.cwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["tcp"]["cwnd"]));
            config.tcp.rwnd = std::max<int>(0, JsonAuxiliary::AsValue<int>(json["tcp"]["rwnd"]));

            config.mux.inactive.timeout = JsonAuxiliary::AsValue<int>(json["mux"]["inactive"]["timeout"]);
            config.mux.connect.timeout = JsonAuxiliary::AsValue<int>(json["mux"]["connect"]["timeout"]);
            config.mux.congestions = (int)JsonAuxiliary::AsInt64(json["mux"]["congestions"], -1);
            config.mux.keep_alived[0] = JsonAuxiliary::AsValue<int>(json["mux"]["keep-alived"][0]);
            config.mux.keep_alived[1] = JsonAuxiliary::AsValue<int>(json["mux"]["keep-alived"][1]);

            config.websocket.listen.ws = JsonAuxiliary::AsValue<int>(json["websocket"]["listen"]["ws"]);
            config.websocket.listen.wss = JsonAuxiliary::AsValue<int>(json["websocket"]["listen"]["wss"]);
            config.websocket.ssl.certificate_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-file"]);
            config.websocket.ssl.certificate_key_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-key-file"]);
            config.websocket.ssl.certificate_chain_file = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-chain-file"]);
            config.websocket.ssl.certificate_key_password = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["certificate-key-password"]);
            config.websocket.ssl.ciphersuites = JsonAuxiliary::AsValue<std::string>(json["websocket"]["ssl"]["ciphersuites"]);
            if (!AssignBoolIfPresent(config.websocket.ssl.verify_peer, json["websocket"]["ssl"]["verify-peer"])) {
                AssignBoolIfPresent(config.websocket.ssl.verify_peer, json["websocket"]["verify-peer"]);
            }
            config.websocket.host = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["host"]);
            config.websocket.path = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["path"]);
            config.websocket.http.error = JsonAuxiliary::AsValue<ppp::string>(json["websocket"]["http"]["error"]);
            ReadJsonAllTokensToMap(json["websocket"]["http"]["request"], config.websocket.http.request);
            ReadJsonAllTokensToMap(json["websocket"]["http"]["response"], config.websocket.http.response);

            config.key.kf = JsonAuxiliary::AsValue<int>(json["key"]["kf"]);
            config.key.kl = JsonAuxiliary::AsValue<int>(json["key"]["kl"]);
            config.key.kh = JsonAuxiliary::AsValue<int>(json["key"]["kh"]);
            config.key.kx = JsonAuxiliary::AsValue<int>(json["key"]["kx"]);
            config.key.sb = JsonAuxiliary::AsValue<int>(json["key"]["sb"]);

            config.key.protocol = JsonAuxiliary::AsValue<ppp::string>(json["key"]["protocol"]);
            config.key.protocol_key = JsonAuxiliary::AsValue<ppp::string>(json["key"]["protocol-key"]);
            config.key.transport = JsonAuxiliary::AsValue<ppp::string>(json["key"]["transport"]);
            config.key.transport_key = JsonAuxiliary::AsValue<ppp::string>(json["key"]["transport-key"]);
            AssignBoolIfPresent(config.key.masked, json["key"]["masked"]);
            AssignBoolIfPresent(config.key.plaintext, json["key"]["plaintext"]);
            AssignBoolIfPresent(config.key.delta_encode, json["key"]["delta-encode"]);
            AssignBoolIfPresent(config.key.shuffle_data, json["key"]["shuffle-data"]);

            config.server.log = JsonAuxiliary::AsValue<ppp::string>(json["server"]["log"]);
            config.server.node = JsonAuxiliary::AsValue<int>(json["server"]["node"]);
            AssignBoolIfPresent(config.server.subnet, json["server"]["subnet"]);
            AssignBoolIfPresent(config.server.mapping, json["server"]["mapping"]);
            config.server.backend = JsonAuxiliary::AsValue<ppp::string>(json["server"]["backend"]);
            config.server.backend_key = JsonAuxiliary::AsValue<ppp::string>(json["server"]["backend-key"]);
            config.server.ipv6.mode = ParseIPv6Mode(JsonAuxiliary::AsValue<ppp::string>(json["server"]["ipv6"]["mode"]));
            AssignIfPresent(config.server.ipv6.cidr, json["server"]["ipv6"]["cidr"]);
            AssignIfPresent(config.server.ipv6.gateway, json["server"]["ipv6"]["gateway"]);
            AssignIfPresent(config.server.ipv6.dns1, json["server"]["ipv6"]["dns1"]);
            AssignIfPresent(config.server.ipv6.dns2, json["server"]["ipv6"]["dns2"]);
            AssignIfPresent(config.server.ipv6.lease_time, json["server"]["ipv6"]["lease-time"]);
            if (Json::Value& static_addresses = json["server"]["ipv6"]["static-addresses"]; static_addresses.isObject()) {
                config.server.ipv6.static_addresses.clear();
                for (Json::ValueConstIterator it = static_addresses.begin(); it != static_addresses.end(); ++it) {
                    config.server.ipv6.static_addresses[it.name()] = JsonAuxiliary::AsValue<ppp::string>(*it);
                }
            }

            LoadAllMappings(config, json["client"]["mappings"]);
            LoadAllRoutes(config.client.routes, json["client"]["routes"]);

            config.client.reconnections.timeout = JsonAuxiliary::AsValue<int>(json["client"]["reconnections"]["timeout"]);
            config.client.guid = JsonAuxiliary::AsValue<ppp::string>(json["client"]["guid"]);
            config.client.server = JsonAuxiliary::AsValue<ppp::string>(json["client"]["server"]);
            config.client.server_proxy = JsonAuxiliary::AsValue<ppp::string>(json["client"]["server-proxy"]);
            config.client.bandwidth = JsonAuxiliary::AsValue<int64_t>(json["client"]["bandwidth"]);
            config.client.http_proxy.port = JsonAuxiliary::AsValue<int>(json["client"]["http-proxy"]["port"]);
            config.client.http_proxy.bind = JsonAuxiliary::AsValue<ppp::string>(json["client"]["http-proxy"]["bind"]);
            config.client.socks_proxy.port = JsonAuxiliary::AsValue<int>(json["client"]["socks-proxy"]["port"]);
            config.client.socks_proxy.bind = JsonAuxiliary::AsValue<ppp::string>(json["client"]["socks-proxy"]["bind"]);
            config.client.socks_proxy.username = JsonAuxiliary::AsValue<ppp::string>(json["client"]["socks-proxy"]["username"]);
            config.client.socks_proxy.password = JsonAuxiliary::AsValue<ppp::string>(json["client"]["socks-proxy"]["password"]);
#if defined(_WIN32)
            AssignBoolIfPresent(config.client.paper_airplane.tcp, json["client"]["paper-airplane"]["tcp"]);
#endif

            AssignIfPresent(config.virr.update_interval, json["virr"]["update-interval"]);
            AssignIfPresent(config.virr.retry_interval, json["virr"]["retry-interval"]);
            AssignIfPresent(config.vbgp.update_interval, json["vbgp"]["update-interval"]);

            AssignBoolIfPresent(config.telemetry.enabled, json["telemetry"]["enabled"]);
            AssignIfPresent(config.telemetry.level, json["telemetry"]["level"]);
            AssignBoolIfPresent(config.telemetry.count, json["telemetry"]["count"]);
            AssignBoolIfPresent(config.telemetry.span, json["telemetry"]["span"]);
            AssignIfPresent(config.telemetry.endpoint, json["telemetry"]["endpoint"]);
            AssignIfPresent(config.telemetry.log_file, json["telemetry"]["log-file"]);
            AssignBoolIfPresent(config.telemetry.console_log, json["telemetry"]["console-log"]);
            AssignBoolIfPresent(config.telemetry.console_metric, json["telemetry"]["console-metric"]);
            AssignBoolIfPresent(config.telemetry.console_span, json["telemetry"]["console-span"]);

            bool loaded = Loaded();
            if (!loaded && ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::ConfigFieldInvalid);
            }
            return loaded;
        }

        /**
         * @brief Converts current configuration to a JSON object.
         * @return Serialized JSON tree.
         */
        Json::Value AppConfiguration::ToJson() noexcept {
            Json::Value root;
            AppConfiguration& config = *this;

            // Set concurrent
            root["concurrent"] = config.concurrent;

            // Set cdn array
            Json::Value cdn(Json::arrayValue);
            cdn.append(config.cdn[0]);
            cdn.append(config.cdn[1]);
            root["cdn"] = cdn;

            // Set ip structure
            Json::Value ip;
            ip["public"] = config.ip.public_;
            ip["interface"] = config.ip.interface_;
            root["ip"] = ip;

            // Set vmem structure
            Json::Value vmem;
            vmem["size"] = config.vmem.size;
            vmem["path"] = config.vmem.path;
            root["vmem"] = vmem;

            // Set udp structure
            Json::Value udp;
            udp["inactive"]["timeout"] = config.udp.inactive.timeout;
            udp["dns"]["timeout"] = config.udp.dns.timeout;
            udp["dns"]["ttl"] = config.udp.dns.ttl;
            udp["dns"]["turbo"] = config.udp.dns.turbo;
            udp["dns"]["cache"] = config.udp.dns.cache;
            udp["dns"]["redirect"] = config.udp.dns.redirect;
            udp["listen"]["port"] = config.udp.listen.port;
            udp["cwnd"] = config.udp.cwnd;
            udp["rwnd"] = config.udp.rwnd;

            // Set keep-alived structure
            Json::Value config_udp_static_keep_alived(Json::arrayValue);
            config_udp_static_keep_alived.append(config.udp.static_.keep_alived[0]);
            config_udp_static_keep_alived.append(config.udp.static_.keep_alived[1]);
            udp["static"]["keep-alived"] = config_udp_static_keep_alived;

            // Set servers structure
            Json::Value servers(Json::arrayValue);
            for (const ppp::string& server : config.udp.static_.servers) {
                if (!server.empty()) {
                    servers.append(server);
                }
            }

            udp["static"]["servers"] = servers;
            udp["static"]["server"] = servers;
            udp["static"]["dns"] = config.udp.static_.dns;
            udp["static"]["quic"] = config.udp.static_.quic;
            udp["static"]["icmp"] = config.udp.static_.icmp;
            udp["static"]["aggligator"] = config.udp.static_.aggligator;
            root["udp"] = udp;

            // Set tcp structure
            Json::Value tcp;
            tcp["inactive"]["timeout"] = config.tcp.inactive.timeout;
            tcp["connect"]["timeout"] = config.tcp.connect.timeout;
            tcp["connect"]["nexcept"] = config.tcp.connect.nexcept;
            tcp["listen"]["port"] = config.tcp.listen.port;
            tcp["turbo"] = config.tcp.turbo;
            tcp["backlog"] = config.tcp.backlog;
            tcp["fast-open"] = config.tcp.fast_open;
            tcp["cwnd"] = config.tcp.cwnd;
            tcp["rwnd"] = config.tcp.rwnd;
            root["tcp"] = tcp;

            // Set mux structure
            Json::Value mux;
            mux["inactive"]["timeout"] = config.mux.inactive.timeout;
            mux["connect"]["timeout"] = config.mux.connect.timeout;
            mux["congestions"] = config.mux.congestions;

            // Set keep-alived structure
            Json::Value config_mux_keep_alived(Json::arrayValue);
            config_mux_keep_alived.append(config.mux.keep_alived[0]);
            config_mux_keep_alived.append(config.mux.keep_alived[1]);
            mux["keep-alived"] = config_mux_keep_alived;

            root["mux"] = mux;

            // Set websocket structure
            Json::Value websocket;
            websocket["listen"]["ws"] = config.websocket.listen.ws;
            websocket["listen"]["wss"] = config.websocket.listen.wss;
            websocket["ssl"]["certificate-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_file);
            websocket["ssl"]["certificate-key-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_key_file);
            websocket["ssl"]["certificate-chain-file"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_chain_file);
            websocket["ssl"]["certificate-key-password"] = stl::transform<ppp::string>(config.websocket.ssl.certificate_key_password);
            websocket["ssl"]["ciphersuites"] = stl::transform<ppp::string>(config.websocket.ssl.ciphersuites);
            websocket["ssl"]["verify-peer"] = config.websocket.ssl.verify_peer;
            websocket["verify-peer"] = config.websocket.ssl.verify_peer;
            websocket["http"]["error"] = stl::transform<ppp::string>(config.websocket.http.error);

            // Set websocket structure
            Json::Value& request = websocket["http"]["request"];
            for (auto&& [k, v] : config.websocket.http.request) {
                request[k.data()] = stl::transform<ppp::string>(v);
            }

            // Set response structure
            Json::Value& response = websocket["http"]["response"];
            for (auto&& [k, v] : config.websocket.http.response) {
                response[k.data()] = stl::transform<ppp::string>(v);
            }

            websocket["host"] = config.websocket.host;
            websocket["path"] = config.websocket.path;
            root["websocket"] = websocket;

            // Set key structure
            Json::Value key;
            key["kf"] = config.key.kf;
            key["kl"] = config.key.kl;
            key["kh"] = config.key.kh;
            key["kx"] = config.key.kx;
            key["sb"] = config.key.sb;

            key["protocol"] = config.key.protocol;
            key["protocol-key"] = config.key.protocol_key;
            key["transport"] = config.key.transport;
            key["transport-key"] = config.key.transport_key;
            key["masked"] = config.key.masked;
            key["plaintext"] = config.key.plaintext;
            key["delta-encode"] = config.key.delta_encode;
            key["shuffle-data"] = config.key.shuffle_data;
            root["key"] = key;

            // Set server structure
            Json::Value server;
            server["log"] = config.server.log;
            server["node"] = config.server.node;
            server["subnet"] = config.server.subnet;
            server["mapping"] = config.server.mapping;
            server["backend"] = config.server.backend; /* ws://192.168.0.24/ppp/webhook */
            server["backend-key"] = config.server.backend_key;
            server["ipv6"]["mode"] = IPv6ModeToString(config.server.ipv6.mode);
            server["ipv6"]["cidr"] = config.server.ipv6.cidr;
            server["ipv6"]["gateway"] = config.server.ipv6.gateway;
            server["ipv6"]["dns1"] = config.server.ipv6.dns1;
            server["ipv6"]["dns2"] = config.server.ipv6.dns2;
            server["ipv6"]["lease-time"] = config.server.ipv6.lease_time;
            Json::Value static_addresses;
            for (const auto& kv : config.server.ipv6.static_addresses) {
                static_addresses[kv.first] = kv.second;
            }
            server["ipv6"]["static-addresses"] = static_addresses;
            root["server"] = server;

            // Set client structure
            Json::Value client;
            Json::Value& mappings = client["mappings"];
            for (MappingConfiguration& mapping : config.client.mappings) {
                Json::Value jo;
                jo["protocol"] = mapping.protocol_tcp_or_udp ? "tcp" : "udp";
                jo["local-ip"] = mapping.local_ip;
                jo["local-port"] = mapping.local_port;
                jo["remote-ip"] = mapping.remote_ip;
                jo["remote-port"] = mapping.remote_port;
                mappings.append(jo);
            }

            // Set routes structure
            Json::Value& routes = client["routes"];
            for (RouteConfiguration& route : config.client.routes) {
                Json::Value jo;
                jo["ngw"] = Ipep::ToAddressString<ppp::string>(Ipep::ToAddress(route.ngw));
#if defined(_LINUX)
                jo["nic"] = route.nic;
#endif
                jo["path"] = route.path;
                jo["vbgp"] = route.vbgp;
                routes.append(jo);
            }

            client["http-proxy"]["bind"] = config.client.http_proxy.bind;
            client["http-proxy"]["port"] = config.client.http_proxy.port;
            client["socks-proxy"]["bind"] = config.client.socks_proxy.bind;
            client["socks-proxy"]["port"] = config.client.socks_proxy.port;
            client["socks-proxy"]["password"] = config.client.socks_proxy.password;
            client["socks-proxy"]["username"] = config.client.socks_proxy.username;
            client["reconnections"]["timeout"] = config.client.reconnections.timeout;
            client["guid"] = config.client.guid;
            client["server"] = config.client.server;
            client["server-proxy"] = config.client.server_proxy;
            client["bandwidth"] = config.client.bandwidth;
#if defined(_WIN32)
            client["paper-airplane"]["tcp"] = config.client.paper_airplane.tcp;
#endif

            root["client"] = client;

            Json::Value virr;
            virr["update-interval"] = config.virr.update_interval;
            virr["retry-interval"] = config.virr.retry_interval;
            root["virr"] = virr;

            Json::Value vbgp;
            vbgp["update-interval"] = config.vbgp.update_interval;
            root["vbgp"] = vbgp;

            Json::Value telemetry;
            telemetry["enabled"] = config.telemetry.enabled;
            telemetry["level"] = config.telemetry.level;
            telemetry["count"] = config.telemetry.count;
            telemetry["span"] = config.telemetry.span;
            telemetry["endpoint"] = config.telemetry.endpoint;
            telemetry["log-file"] = config.telemetry.log_file;
            telemetry["console-log"] = config.telemetry.console_log;
            telemetry["console-metric"] = config.telemetry.console_metric;
            telemetry["console-span"] = config.telemetry.console_span;
            root["telemetry"] = telemetry;

            return root;
        }

        /**
         * @brief Converts current configuration to JSON text.
         * @return Serialized JSON string.
         */
        ppp::string AppConfiguration::ToString() noexcept {
            Json::Value json = ToJson();
            return JsonAuxiliary::ToString(json);
        }

        namespace extensions {
            /**
             * @brief Verifies whether encryption algorithm fields are configured.
             * @param configuration Configuration object.
             * @return True when protocol/transport names and keys are all non-empty.
             */
            bool IsHaveCiphertext(const AppConfiguration& configuration) noexcept {
                return
                    !configuration.key.protocol.empty() &&
                    !configuration.key.protocol_key.empty() &&
                    !configuration.key.transport.empty() &&
                    !configuration.key.transport_key.empty();
            }
        }
    }
}
