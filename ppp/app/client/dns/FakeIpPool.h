#pragma once

/**
 * @file FakeIpPool.h
 * @brief Clash-style fake-ip allocation and hostname mapping (Plan C).
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                class FakeIpPool final {
                public:
                    FakeIpPool() noexcept {}

                    /** @brief Configures the assignable IPv4 range (e.g. "198.18.0.1/16"). */
                    bool Configure(const ppp::string& cidr) noexcept;

                    void Clear() noexcept;

                    bool IsEnabled() const noexcept { return enabled_; }

                    /** @brief Returns true when @p ip_host is inside the configured pool. */
                    bool ContainsHostOrder(uint32_t ip_host) const noexcept;

                    /** @brief Allocates or returns an existing fake IP for @p hostname (lowercase). */
                    uint32_t Allocate(const ppp::string& hostname) noexcept;

                    /** @brief Stores the resolved real IPv4 (network byte order) for @p hostname. */
                    void SetRealIp(const ppp::string& hostname, uint32_t real_ip_network) noexcept;

                    /** @brief Looks up the real destination if known; 0 when unresolved. */
                    uint32_t LookupRealIpHostOrder(uint32_t fake_ip_host) const noexcept;

                    ppp::string LookupHostname(uint32_t fake_ip_host) const noexcept;

                    /** @brief Route prefix for OS routing (network byte order). */
                    uint32_t RouteNetwork() const noexcept { return route_network_; }

                    int RoutePrefix() const noexcept { return route_prefix_; }

                private:
                    struct Entry {
                        ppp::string hostname;
                        uint32_t fake_ip_host = 0;
                        uint32_t real_ip_host = 0;
                    };

                    bool enabled_ = false;
                    uint32_t pool_network_host_ = 0;
                    uint32_t pool_mask_host_ = 0;
                    uint32_t pool_start_host_ = 0;
                    uint32_t pool_end_host_ = 0;
                    uint32_t route_network_ = 0;
                    int route_prefix_ = 0;
                    uint32_t cursor_host_ = 0;
                    ppp::unordered_map<uint32_t, Entry> by_fake_ip_;
                    ppp::unordered_map<ppp::string, uint32_t> by_hostname_;
                };

            }
        }
    }
}
