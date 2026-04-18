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
             */
            struct MappingConfiguration final {
                bool                                                        protocol_tcp_or_udp;
                ppp::string                                                 local_ip;
                int                                                         local_port;
                ppp::string                                                 remote_ip;
                int                                                         remote_port;
            };

            /**
             * @brief Route source configuration for client route imports.
             */
            struct RouteConfiguration final {
#if defined(_LINUX)
                ppp::string                                                 nic;
#endif
                uint32_t                                                    ngw;
                ppp::string                                                 path;
                ppp::string                                                 vbgp;
            };

            /**
             * @brief IPv6 address assignment mode for server-side data plane.
             */
            enum IPv6Mode {
                IPv6Mode_None = 0,
                IPv6Mode_Nat66 = 1,
                IPv6Mode_Gua = 2,
            };

        public:
            int                                                             concurrent;
            int                                                             cdn[2];
            struct {
                ppp::string                                                 public_;
                ppp::string                                                 interface_;
            }                                                               ip;
            struct {
                struct {
                    int                                                     timeout;
                }                                                           inactive;
                struct {
                    int                                                     timeout;
                    int                                                     ttl;
                    bool                                                    turbo;
                    bool                                                    cache;
                    ppp::string                                             redirect;
                }                                                           dns;
                struct {
                    int                                                     port;
                }                                                           listen;
                struct {
                    int                                                     keep_alived[2];
                    bool                                                    dns;
                    bool                                                    quic;
                    bool                                                    icmp;
                    int                                                     aggligator;
                    ppp::unordered_set<ppp::string>                         servers;
                }                                                           static_;
                int                                                         cwnd;
                int                                                         rwnd;
            }                                                               udp;
            struct {
                struct {
                    int                                                     timeout;
                }                                                           inactive;
                struct {
                    int                                                     timeout;
                    int                                                     nexcept;
                }                                                           connect;
                struct {
                    int                                                     port;
                }                                                           listen;
                bool                                                        turbo;
                int                                                         backlog;
                int                                                         cwnd;
                int                                                         rwnd;
                bool                                                        fast_open;
            }                                                               tcp;
            struct {
                struct {
                    int                                                     timeout;
                }                                                           inactive;
                struct {
                    int                                                     timeout;
                }                                                           connect;
                int                                                         congestions;
                int                                                         keep_alived[2];
            }                                                               mux;
            struct {
                struct {
                    int                                                     ws;
                    int                                                     wss;
                }                                                           listen;
                struct {
                    std::string                                             certificate_file;
                    std::string                                             certificate_key_file;
                    std::string                                             certificate_chain_file;
                    std::string                                             certificate_key_password;
                    std::string                                             ciphersuites;
                    bool                                                    verify_peer;
                }                                                           ssl;
                ppp::string                                                 host;
                ppp::string                                                 path;
                struct {
                    std::string                                             error;
                    ppp::map<ppp::string, ppp::string>                      request;
                    ppp::map<ppp::string, ppp::string>                      response;
                }                                                           http;
            }                                                               websocket;
            struct {
                int                                                         kf;
                int                                                         kh;
                int                                                         kl;
                int                                                         kx;
                int                                                         sb;
                ppp::string                                                 protocol;
                ppp::string                                                 protocol_key;
                ppp::string                                                 transport;
                ppp::string                                                 transport_key;
                bool                                                        masked;
                bool                                                        plaintext;
                bool                                                        delta_encode;
                bool                                                        shuffle_data;
            }                                                               key;
            struct {
                int64_t                                                     size;
                ppp::string                                                 path;
            }                                                               vmem;
            struct {
                int                                                         node;
                ppp::string                                                 log;
                bool                                                        subnet;
                bool                                                        mapping;
                ppp::string                                                 backend;
                ppp::string                                                 backend_key;
                struct {
                    IPv6Mode                                                mode;
                    ppp::string                                             cidr;
                    int                                                     prefix_length;
                    ppp::string                                             gateway;
                    ppp::string                                             dns1;
                    ppp::string                                             dns2;
                    int                                                     lease_time;
                    ppp::map<ppp::string, ppp::string>                      static_addresses;
                }                                                           ipv6;
            }                                                               server;
            struct {
                ppp::string                                                 guid;
                ppp::string                                                 server;
                ppp::string                                                 server_proxy;
                int64_t                                                     bandwidth;
                struct {
                    int                                                     timeout;
                }                                                           reconnections;
#if defined(_WIN32)
                struct {
                    bool                                                    tcp;
                }                                                           paper_airplane;
#endif
                ppp::vector<MappingConfiguration>                           mappings;
                ppp::vector<RouteConfiguration>                             routes;
                struct {
                    int                                                     port;
                    ppp::string                                             bind;
                }                                                           http_proxy;
                struct {
                    int                                                     port;
                    ppp::string                                             bind;
                    ppp::string                                             username;
                    ppp::string                                             password;
                }                                                           socks_proxy;
            }                                                               client;
            struct {
                int                                                         update_interval;
                int                                                         retry_interval;
            }                                                               virr;
            struct {
                int                                                         update_interval;
            }                                                               vbgp;
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
             */
            enum LcgmodType {
                LCGMOD_TYPE_TRANSMISSION,
                LCGMOD_TYPE_STATIC,
                LCGMOD_TYPE_MAX
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
             */
            bool                                                            Loaded() noexcept;

        private:
            int                                                             _lcgmods[LCGMOD_TYPE_MAX];
            std::shared_ptr<ppp::threading::BufferswapAllocator>            _BufferAllocator;
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
