#pragma once

#include <ppp/stdafx.h>
#include <ppp/threading/BufferswapAllocator.h>

#include <json/json.h>

/**
 * @file AppConfiguration.h
 * @brief Application configuration model and serialization APIs.
 */

namespace ppp {
    namespace configurations {
        /**
         * @brief Stores runtime and networking configuration for the application.
         */
        class AppConfiguration final {
        public:
            /**
             * @brief Port mapping rule configuration.
             *
             * Describes one static port-forwarding entry that maps a local
             * service port to a remote port exposed through the virtual Ethernet
             * tunnel.  Both TCP and UDP mappings are supported.
             */
            struct MappingConfiguration final {
                bool                                                        protocol_tcp_or_udp; ///< True selects TCP mapping; false selects UDP mapping.
                ppp::string                                                 local_ip;            ///< Local bind address for the forwarded service (empty = any).
                int                                                         local_port;          ///< Local port of the service being forwarded.
                ppp::string                                                 remote_ip;           ///< Remote peer address to reach through the tunnel (may be empty).
                int                                                         remote_port;         ///< Remote port exposed on the tunnel peer side.
            };

            /**
             * @brief Route source configuration for client route imports.
             *
             * Specifies an external route file or a vBGP peer whose prefixes the
             * client should install after establishing the tunnel.
             */
            struct RouteConfiguration final {
#if defined(_LINUX)
                ppp::string                                                 nic;   ///< Linux NIC name used as the route output interface.
#endif
                uint32_t                                                    ngw;   ///< Next-hop gateway IPv4 address in host byte order; 0 means use tunnel default.
                ppp::string                                                 path;  ///< Path to a static route file listing CIDR prefixes to import.
                ppp::string                                                 vbgp;  ///< vBGP peer address string; empty disables dynamic route learning.
            };

            /**
             * @brief IPv6 address assignment mode for server-side data plane.
             *
             * Controls which IPv6 provisioning strategy the server uses when
             * allocating an IPv6 prefix or address for a connected client.
             */
            enum IPv6Mode {
                IPv6Mode_None  = 0,   ///< IPv6 provisioning is disabled; clients receive IPv4 only.
                IPv6Mode_Nat66 = 1,   ///< NAT66 is used to translate a ULA prefix to a global prefix.
                IPv6Mode_Gua   = 2,   ///< Globally Unique Address (GUA) is delegated directly to the client.
            };

        public:
            int                                                             concurrent;   ///< Number of concurrent IO worker threads; typically set to CPU core count.
            int                                                             cdn[2];       ///< CDN acceleration port pair [plain, tls]; 0 disables the respective CDN path.
            struct {
                ppp::string                                                 public_;      ///< Public-facing IPv4/IPv6 address advertised to remote peers.
                ppp::string                                                 interface_;   ///< Local network interface address used for binding sockets.
            }                                                               ip;           ///< IP address binding configuration.
            struct {
                struct {
                    int                                                     timeout;      ///< Idle timeout in seconds before a UDP session is torn down.
                }                                                           inactive;
                struct {
                    int                                                     timeout;      ///< DNS query timeout in seconds.
                    int                                                     ttl;          ///< DNS response TTL in seconds used for local cache entries.
                    bool                                                    turbo;        ///< Enable turbo (parallel/aggressive) DNS query mode.
                    bool                                                    cache;        ///< Enable local DNS response caching.
                    ppp::string                                             redirect;     ///< Upstream DNS server address to redirect queries to; empty = system default.
                }                                                           dns;
                struct {
                    int                                                     port;         ///< UDP listen port; 0 lets the OS choose an ephemeral port.
                }                                                           listen;
                struct {
                    int                                                     keep_alived[2]; ///< Keep-alive interval range [min, max] in seconds for static UDP mappings.
                    bool                                                    dns;            ///< Forward DNS traffic through the static channel.
                    bool                                                    quic;           ///< Enable QUIC acceleration for static UDP sessions.
                    bool                                                    icmp;           ///< Allow ICMP echo through the static channel.
                    int                                                     aggligator;     ///< Aggligator aggregation factor; 0 disables UDP link aggregation.
                    ppp::unordered_set<ppp::string>                         servers;        ///< Set of static server addresses used as tunnel uplink endpoints.
                }                                                           static_;
                int                                                         cwnd;           ///< UDP congestion window size in packets; 0 means system default.
                int                                                         rwnd;           ///< UDP receive window size in packets; 0 means system default.
            }                                                               udp;            ///< UDP protocol and session parameters.
            struct {
                struct {
                    int                                                     timeout;        ///< Idle timeout in seconds before an established TCP session is closed.
                }                                                           inactive;
                struct {
                    int                                                     timeout;        ///< TCP connect handshake timeout in seconds.
                    int                                                     nexcept;        ///< Maximum allowed consecutive connect exceptions before circuit-break.
                }                                                           connect;
                struct {
                    int                                                     port;           ///< TCP listen port; 0 lets the OS choose an ephemeral port.
                }                                                           listen;
                bool                                                        turbo;          ///< Enable TCP turbo mode (Nagle disabled, immediate flush).
                int                                                         backlog;        ///< Listen backlog depth for the TCP acceptor socket.
                int                                                         cwnd;           ///< TCP congestion window size override; 0 means kernel default.
                int                                                         rwnd;           ///< TCP receive window size override; 0 means kernel default.
                bool                                                        fast_open;      ///< Enable TCP Fast Open (TFO) for reduced handshake latency.
            }                                                               tcp;            ///< TCP protocol and session parameters.
            struct {
                struct {
                    int                                                     timeout;        ///< Idle timeout in seconds for a MUX sub-channel.
                }                                                           inactive;
                struct {
                    int                                                     timeout;        ///< MUX connect handshake timeout in seconds.
                }                                                           connect;
                int                                                         congestions;    ///< MUX congestion control level; higher values reduce burst aggressiveness.
                int                                                         keep_alived[2]; ///< MUX keep-alive interval range [min, max] in seconds.
            }                                                               mux;            ///< Multiplexed connection channel parameters.
            struct {
                struct {
                    int                                                     ws;             ///< Plain WebSocket listen port (ws://); 0 disables plain WS.
                    int                                                     wss;            ///< Secure WebSocket listen port (wss://); 0 disables WSS.
                }                                                           listen;
                struct {
                    std::string                                             certificate_file;          ///< Path to PEM-encoded TLS certificate file.
                    std::string                                             certificate_key_file;      ///< Path to PEM-encoded private key file matching the certificate.
                    std::string                                             certificate_chain_file;    ///< Path to PEM-encoded intermediate CA chain file.
                    std::string                                             certificate_key_password;  ///< Passphrase protecting the private key; empty if key is unencrypted.
                    std::string                                             ciphersuites;              ///< Colon-separated TLS 1.3 cipher suite list; empty = OpenSSL default.
                    bool                                                    verify_peer;               ///< Require and verify client certificate when true.
                }                                                           ssl;
                ppp::string                                                 host;           ///< Expected HTTP `Host` header value for WebSocket upgrade validation.
                ppp::string                                                 path;           ///< WebSocket upgrade path (e.g. "/ws"); must begin with '/'.
                struct {
                    std::string                                             error;          ///< Body returned for non-WebSocket HTTP requests (plain text or HTML).
                    ppp::map<ppp::string, ppp::string>                      request;        ///< Extra HTTP headers injected into the client upgrade request.
                    ppp::map<ppp::string, ppp::string>                      response;       ///< Extra HTTP headers injected into the server upgrade response.
                }                                                           http;
            }                                                               websocket;      ///< WebSocket transport (WS/WSS) parameters.
            struct {
                int                                                         kf;             ///< Key-frame interval (packets between re-key events).
                int                                                         kh;             ///< Key hash iterations for KDF strengthening.
                int                                                         kl;             ///< Key length in bits (e.g. 128, 256).
                int                                                         kx;             ///< Key exchange algorithm selector.
                int                                                         sb;             ///< Shuffle block size used by `shuffle_data` mode.
                ppp::string                                                 protocol;       ///< Protocol-layer cipher algorithm name (e.g. "aes-256-cfb").
                ppp::string                                                 protocol_key;   ///< Passphrase used to derive the protocol-layer cipher key.
                ppp::string                                                 transport;      ///< Transport-layer cipher algorithm name (e.g. "aes-128-cfb").
                ppp::string                                                 transport_key;  ///< Passphrase used to derive the transport-layer cipher key.
                bool                                                        masked;         ///< Apply a masking XOR pass over packet headers when true.
                bool                                                        plaintext;      ///< Transmit data in plaintext (no encryption) when true; for debugging only.
                bool                                                        delta_encode;   ///< Apply delta encoding to payload bytes before encryption.
                bool                                                        shuffle_data;   ///< Randomly reorder payload blocks within each packet when true.
            }                                                               key;            ///< Cryptographic key and cipher configuration.
            struct {
                int64_t                                                     size;           ///< Virtual memory file size in bytes; 0 disables vmem backing.
                ppp::string                                                 path;           ///< File path used for memory-mapped virtual memory backing store.
            }                                                               vmem;           ///< Virtual memory (disk-backed buffer) configuration.
            struct {
                int                                                         node;           ///< Server node identifier used for clustering and session routing.
                ppp::string                                                 log;            ///< Path to the structured event log file; empty disables logging.
                bool                                                        subnet;         ///< Advertise client subnets between sessions when true.
                bool                                                        mapping;        ///< Enable server-side static port mapping support when true.
                ppp::string                                                 backend;        ///< URL or address of the authentication/management backend.
                ppp::string                                                 backend_key;    ///< HMAC key used to sign backend API requests.
                struct {
                    IPv6Mode                                                mode;           ///< IPv6 provisioning strategy for connected clients.
                    ppp::string                                             cidr;           ///< IPv6 CIDR prefix pool from which client addresses are allocated.
                    int                                                     prefix_length;  ///< Prefix length delegated to each client (e.g. 64 for /64).
                    ppp::string                                             gateway;        ///< IPv6 gateway address announced to clients.
                    ppp::string                                             dns1;           ///< Primary IPv6 DNS server address announced to clients.
                    ppp::string                                             dns2;           ///< Secondary IPv6 DNS server address announced to clients.
                    int                                                     lease_time;     ///< IPv6 address lease duration in seconds.
                    ppp::map<ppp::string, ppp::string>                      static_addresses; ///< Map of client GUID to statically assigned IPv6 address string.
                }                                                           ipv6;
            }                                                               server;         ///< Server-mode specific parameters.
            struct {
                ppp::string                                                 guid;           ///< Client GUID string used for authentication and session tracking.
                ppp::string                                                 server;         ///< Primary VPN server address in "host:port" format.
                ppp::string                                                 server_proxy;   ///< HTTP/SOCKS proxy address used to reach the VPN server; empty = direct.
                int64_t                                                     bandwidth;      ///< Client-side bandwidth cap in bits per second; 0 = unlimited.
                struct {
                    int                                                     timeout;        ///< Seconds to wait before attempting a reconnection after disconnect.
                }                                                           reconnections;
#if defined(_WIN32)
                struct {
                    bool                                                    tcp;            ///< Enable Paper Airplane TCP acceleration driver on Windows when true.
                }                                                           paper_airplane;
#endif
                ppp::vector<MappingConfiguration>                           mappings;       ///< List of static port mapping rules activated on connect.
                ppp::vector<RouteConfiguration>                             routes;         ///< List of route sources imported after tunnel establishment.
                struct {
                    int                                                     port;           ///< HTTP proxy listen port; 0 disables the local HTTP proxy.
                    ppp::string                                             bind;           ///< HTTP proxy bind address; empty = loopback only.
                }                                                           http_proxy;
                struct {
                    int                                                     port;           ///< SOCKS5 proxy listen port; 0 disables the local SOCKS5 proxy.
                    ppp::string                                             bind;           ///< SOCKS5 proxy bind address; empty = loopback only.
                    ppp::string                                             username;       ///< SOCKS5 authentication username; empty = no authentication.
                    ppp::string                                             password;       ///< SOCKS5 authentication password; empty = no authentication.
                }                                                           socks_proxy;
            }                                                               client;         ///< Client-mode specific parameters.
            struct {
                int                                                         update_interval; ///< VIRR (virtual interface routing refresh) update interval in seconds.
                int                                                         retry_interval;  ///< Interval in seconds between VIRR retries on failure.
            }                                                               virr;            ///< Virtual interface routing refresh (VIRR) configuration.
            struct {
                int                                                         update_interval; ///< vBGP route announcement refresh interval in seconds.
            }                                                               vbgp;            ///< Virtual BGP (vBGP) route propagation configuration.
            struct {
                bool                                                        enabled;        ///< Enable telemetry output when true; default false for zero-cost on low-end hardware.
                int                                                         level;          ///< Minimum verbosity level to output: 0=INFO, 1=VERB, 2=DEBUG, 3=TRACE.
                bool                                                        count;          ///< Enable counter metrics when true.
                bool                                                        span;           ///< Enable trace spans when true.
                ppp::string                                                 endpoint;       ///< Optional OTLP/gRPC endpoint; empty uses built-in stderr backend.
                ppp::string                                                 log_file;       ///< Optional local log file path; empty disables file output.
            }                                                               telemetry;       ///< Optional telemetry/observability configuration.
        public:
            /**
             * @brief Initializes configuration fields to default values.
             */
            AppConfiguration() noexcept;

        public:
            /**
             * @brief Resets all fields to built-in defaults.
             */
            void                                                            Clear() noexcept;
            /**
             * @brief Loads configuration data from a JSON object.
             * @param json Source JSON object.
             * @return True when loading and normalization succeed.
             */
            bool                                                            Load(Json::Value& json) noexcept;
            /**
             * @brief Loads configuration data from a JSON file path.
             * @param path Path to the configuration file.
             * @return True when loading and normalization succeed.
             */
            bool                                                            Load(const ppp::string& path) noexcept;

        public:
            /**
             * @brief Internal LCG modifier slot identifiers.
             *
             * Each slot holds a precomputed linear-congruential modifier value
             * derived from the configured key parameters.  The value is used to
             * vary packet framing offsets at runtime, making traffic patterns
             * less predictable.
             */
            enum LcgmodType {
                LCGMOD_TYPE_TRANSMISSION,   ///< Modifier applied to the protocol transmission layer framing.
                LCGMOD_TYPE_STATIC,         ///< Modifier applied to static UDP channel framing.
                LCGMOD_TYPE_MAX             ///< Sentinel value equal to the number of defined modifier slots.
            };
            /**
             * @brief Gets the computed LCG modifier for a type.
             * @param tp Modifier type.
             * @return Computed modifier value.
             */
            int                                                             Lcgmod(LcgmodType tp) noexcept { return _lcgmods[(int)tp]; }

        public:
            /**
             * @brief Gets the current buffer allocator.
             * @return Shared pointer to the allocator.
             */
            std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferAllocator() noexcept { return this->_BufferAllocator; }
            /**
             * @brief Replaces the current buffer allocator.
             * @param allocator New allocator instance.
             * @return Previous allocator instance.
             */
            std::shared_ptr<ppp::threading::BufferswapAllocator>            SetBufferAllocator(const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator) noexcept {
                std::shared_ptr<ppp::threading::BufferswapAllocator> result = std::move(this->_BufferAllocator);
                this->_BufferAllocator = allocator;
                return result;
            }

        public:
            /**
             * @brief Serializes configuration to a JSON value.
             * @return JSON object representation.
             */
            Json::Value                                                     ToJson() noexcept;
            /**
             * @brief Serializes configuration to a JSON string.
             * @return JSON string representation.
             */
            ppp::string                                                     ToString() noexcept;

        private:
            /**
             * @brief Validates and normalizes loaded values.
             * @return True after normalization completes.
             * @note Called internally by both `Load` overloads after JSON parsing.
             *       Clamps out-of-range integers, derives LCG modifiers, and
             *       initialises the buffer allocator when not already set.
             */
            bool                                                            Loaded() noexcept;

        private:
            int                                                             _lcgmods[LCGMOD_TYPE_MAX]; ///< Precomputed LCG modifier values indexed by `LcgmodType`.
            std::shared_ptr<ppp::threading::BufferswapAllocator>            _BufferAllocator;           ///< Shared buffer pool for packet allocation; may be null until explicitly set.
        };

        namespace extensions {
            /**
             * @brief Checks whether protocol and transport cipher settings are present.
             * @param configuration Configuration instance to check.
             * @return True when required cipher fields are all non-empty.
             */
            bool                                                            IsHaveCiphertext(const AppConfiguration& configuration) noexcept;
            /**
             * @brief Pointer overload for @ref IsHaveCiphertext.
             * @param configuration Optional configuration pointer.
             * @return True when pointer is valid and ciphertext fields are present.
             */
            inline bool                                                     IsHaveCiphertext(const AppConfiguration* configuration) noexcept { return NULLPTR != configuration ? IsHaveCiphertext(*configuration) : false; }
        }
    }
}
