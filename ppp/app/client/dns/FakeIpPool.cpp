#include "FakeIpPool.h"

#include <ppp/net/Ipep.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static bool ParseCidr(
                    const ppp::string& cidr,
                    uint32_t& network_host,
                    uint32_t& mask_host,
                    int& prefix) noexcept {

                    ppp::string text = ATrim(cidr);
                    if (text.empty()) {
                        return false;
                    }

                    std::size_t slash = text.find('/');
                    if (slash == ppp::string::npos) {
                        return false;
                    }

                    ppp::string ip_text = ATrim(text.substr(0, slash));
                    ppp::string prefix_text = ATrim(text.substr(slash + 1));
                    prefix = atoi(prefix_text.data());
                    if (prefix < 1 || prefix > 32) {
                        return false;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address_v4 addr =
                        boost::asio::ip::make_address_v4(ip_text, ec);
                    if (ec) {
                        return false;
                    }

                    network_host = addr.to_uint();
                    if (prefix == 32) {
                        mask_host = 0xFFFFFFFFu;
                    }
                    else {
                        mask_host = (0xFFFFFFFFu << (32 - prefix));
                    }

                    network_host &= mask_host;
                    return true;
                }

                bool FakeIpPool::Configure(const ppp::string& cidr) noexcept {
                    uint32_t network_host = 0;
                    uint32_t mask_host = 0;
                    int prefix = 0;
                    if (!ParseCidr(cidr, network_host, mask_host, prefix)) {
                        Clear();
                        return false;
                    }

                    std::lock_guard<std::mutex> lock(sync_);
                    by_fake_ip_.clear();
                    by_hostname_.clear();
                    enabled_ = true;
                    pool_network_host_ = network_host;
                    pool_mask_host_ = mask_host;
                    pool_start_host_ = network_host + 4;
                    pool_end_host_ = network_host | (~mask_host);
                    if (pool_end_host_ <= pool_start_host_) {
                        pool_start_host_ = network_host + 1;
                    }
                    cursor_host_ = pool_start_host_;
                    route_network_ = htonl(network_host);
                    route_prefix_ = prefix;
                    return true;
                }

                void FakeIpPool::Clear() noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    enabled_ = false;
                    pool_network_host_ = 0;
                    pool_mask_host_ = 0;
                    pool_start_host_ = 0;
                    pool_end_host_ = 0;
                    route_network_ = 0;
                    route_prefix_ = 0;
                    cursor_host_ = 0;
                    by_fake_ip_.clear();
                    by_hostname_.clear();
                }

                bool FakeIpPool::IsEnabled() const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    return enabled_;
                }

                bool FakeIpPool::ContainsHostOrder(uint32_t ip_host) const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_) {
                        return false;
                    }
                    return (ip_host & pool_mask_host_) == pool_network_host_;
                }

                uint32_t FakeIpPool::Allocate(const ppp::string& hostname) noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_ || hostname.empty()) {
                        return 0;
                    }

                    auto found = by_hostname_.find(hostname);
                    if (found != by_hostname_.end()) {
                        return found->second;
                    }

                    uint32_t candidate = cursor_host_;
                    for (std::size_t i = 0; i <= (pool_end_host_ - pool_start_host_); ++i) {
                        if (candidate > pool_end_host_) {
                            candidate = pool_start_host_;
                        }
                        if (by_fake_ip_.find(candidate) == by_fake_ip_.end()) {
                            break;
                        }
                        ++candidate;
                    }

                    cursor_host_ = candidate + 1;
                    if (cursor_host_ > pool_end_host_) {
                        cursor_host_ = pool_start_host_;
                    }

                    Entry entry;
                    entry.hostname = hostname;
                    entry.fake_ip_host = candidate;
                    by_fake_ip_[candidate] = entry;
                    by_hostname_[hostname] = candidate;
                    return candidate;
                }

                void FakeIpPool::SetRealIp(const ppp::string& hostname, uint32_t real_ip_network) noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_ || hostname.empty() || real_ip_network == 0) {
                        return;
                    }

                    auto found = by_hostname_.find(hostname);
                    if (found == by_hostname_.end()) {
                        return;
                    }

                    by_fake_ip_[found->second].real_ip_host = real_ip_network;
                }

                uint32_t FakeIpPool::LookupRealIpHostOrder(uint32_t fake_ip_host) const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    auto found = by_fake_ip_.find(fake_ip_host);
                    if (found == by_fake_ip_.end()) {
                        return 0;
                    }
                    return found->second.real_ip_host;
                }

                ppp::string FakeIpPool::LookupHostname(uint32_t fake_ip_host) const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    auto found = by_fake_ip_.find(fake_ip_host);
                    if (found == by_fake_ip_.end()) {
                        return {};
                    }
                    return found->second.hostname;
                }

                bool FakeIpPool::GetRoute(uint32_t& route_network, int& route_prefix) const noexcept {
                    std::lock_guard<std::mutex> lock(sync_);
                    if (!enabled_) {
                        route_network = 0;
                        route_prefix = 0;
                        return false;
                    }

                    route_network = route_network_;
                    route_prefix = route_prefix_;
                    return true;
                }

            }
        }
    }
}
