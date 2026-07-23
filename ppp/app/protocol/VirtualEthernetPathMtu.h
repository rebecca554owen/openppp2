#pragma once

/**
 * @file VirtualEthernetPathMtu.h
 * @brief Validates IPv4 ICMP PMTU errors and stores bounded per-destination PMTU observations.
 */

#include <ppp/stdafx.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/native/ip.h>

namespace ppp {
    namespace app {
        namespace protocol {
            struct IcmpPathMtuError {
                UInt32 OuterSource = 0;
                UInt32 OuterDestination = 0;
                UInt32 QuotedSource = 0;
                UInt32 QuotedDestination = 0;
                Byte QuotedProtocol = 0;
                UInt16 NextHopMtu = 0;
                bool IsPathMtuUpdate = false;
            };

            /**
             * @brief Parses a forwardable IPv4 ICMP control error without modifying packet bytes.
             * @details Only Fragmentation Needed (3/4) and Time Exceeded in Transit (11/0)
             * are accepted. The quoted IPv4 header and eight bytes of its payload are required.
             */
            static inline bool TryParseIcmpPathMtuError(const Byte* packet, int packet_length,
                IcmpPathMtuError& error) noexcept {
                if (NULLPTR == packet || packet_length < ppp::net::native::ip_hdr::IP_HLEN) {
                    return false;
                }

                const ppp::net::native::ip_hdr* outer =
                    reinterpret_cast<const ppp::net::native::ip_hdr*>(packet);
                const int outer_header_length = (outer->v_hl & 0x0f) << 2;
                const int outer_length = ntohs(outer->len);
                if ((outer->v_hl >> 4) != ppp::net::native::ip_hdr::IP_VER ||
                    outer_header_length < ppp::net::native::ip_hdr::IP_HLEN ||
                    outer_header_length > packet_length || outer_length < outer_header_length ||
                    outer_length > packet_length || outer->proto != ppp::net::native::ip_hdr::IP_PROTO_ICMP ||
                    ppp::net::native::inet_chksum(const_cast<ppp::net::native::ip_hdr*>(outer), outer_header_length) != 0) {
                    return false;
                }

                const int icmp_length = outer_length - outer_header_length;
                if (icmp_length < (int)sizeof(ppp::net::native::icmp_hdr) +
                        ppp::net::native::ip_hdr::IP_HLEN + 8) {
                    return false;
                }

                const Byte* icmp_bytes = packet + outer_header_length;
                const ppp::net::native::icmp_hdr* icmp =
                    reinterpret_cast<const ppp::net::native::icmp_hdr*>(icmp_bytes);
                const bool is_fragmentation_needed =
                    icmp->icmp_type == ppp::net::native::IcmpType::ICMP_DUR && icmp->icmp_code == 4;
                const bool is_time_exceeded =
                    icmp->icmp_type == ppp::net::native::IcmpType::ICMP_TE && icmp->icmp_code == 0;
                if ((!is_fragmentation_needed && !is_time_exceeded) ||
                    ppp::net::native::inet_chksum(const_cast<ppp::net::native::icmp_hdr*>(icmp), icmp_length) != 0) {
                    return false;
                }

                const Byte* quoted_bytes = icmp_bytes + sizeof(ppp::net::native::icmp_hdr);
                const int quoted_length = icmp_length - (int)sizeof(ppp::net::native::icmp_hdr);
                const ppp::net::native::ip_hdr* quoted =
                    reinterpret_cast<const ppp::net::native::ip_hdr*>(quoted_bytes);
                const int quoted_header_length = (quoted->v_hl & 0x0f) << 2;
                if ((quoted->v_hl >> 4) != ppp::net::native::ip_hdr::IP_VER ||
                    quoted_header_length < ppp::net::native::ip_hdr::IP_HLEN ||
                    quoted_header_length + 8 > quoted_length ||
                    ntohs(quoted->len) < quoted_header_length + 8) {
                    return false;
                }

                UInt16 next_hop_mtu = 0;
                if (is_fragmentation_needed) {
                    std::memcpy(&next_hop_mtu, icmp_bytes + 6, sizeof(next_hop_mtu));
                    next_hop_mtu = ntohs(next_hop_mtu);
                    // RFC 1191 requires an IPv4 next-hop MTU. Values below the IPv4
                    // minimum are unusable and must not poison the PMTU cache.
                    if (next_hop_mtu < 576) {
                        return false;
                    }
                }

                error.OuterSource = outer->src;
                error.OuterDestination = outer->dest;
                error.QuotedSource = quoted->src;
                error.QuotedDestination = quoted->dest;
                error.QuotedProtocol = quoted->proto;
                error.NextHopMtu = next_hop_mtu;
                error.IsPathMtuUpdate = is_fragmentation_needed;
                return true;
            }

            /** @brief Bounded cache of recently observed IPv4 path MTUs. */
            class VirtualEthernetPathMtuCache {
            private:
                struct Entry {
                    UInt16 Mtu = 0;
                    UInt64 ExpiresAt = 0;
                };

            public:
                static constexpr UInt64 kLifetimeMilliseconds = 10ULL * 60ULL * 1000ULL;
                static constexpr size_t kMaximumEntries = 256;

                bool Observe(UInt32 destination, UInt16 mtu, UInt64 now) noexcept {
                    if (destination == 0 || mtu < 576) {
                        return false;
                    }

                    std::lock_guard<std::mutex> scope(sync_);
                    PruneExpiredLocked(now);
                    auto it = entries_.find(destination);
                    if (it == entries_.end()) {
                        if (entries_.size() >= kMaximumEntries) {
                            entries_.erase(entries_.begin());
                        }
                        entries_.emplace(destination, Entry{mtu, now + kLifetimeMilliseconds});
                        return true;
                    }

                    const bool lowered = mtu < it->second.Mtu;
                    if (lowered) {
                        it->second.Mtu = mtu;
                    }
                    it->second.ExpiresAt = now + kLifetimeMilliseconds;
                    return lowered;
                }

                int Lookup(UInt32 destination, UInt64 now) noexcept {
                    std::lock_guard<std::mutex> scope(sync_);
                    auto it = entries_.find(destination);
                    if (it == entries_.end()) {
                        return 0;
                    }
                    if (it->second.ExpiresAt <= now) {
                        entries_.erase(it);
                        return 0;
                    }
                    return it->second.Mtu;
                }

                void Clear() noexcept {
                    std::lock_guard<std::mutex> scope(sync_);
                    entries_.clear();
                }

            private:
                void PruneExpiredLocked(UInt64 now) noexcept {
                    for (auto it = entries_.begin(); it != entries_.end();) {
                        if (it->second.ExpiresAt <= now) {
                            it = entries_.erase(it);
                        }
                        else {
                            ++it;
                        }
                    }
                }

            private:
                std::mutex sync_;
                ppp::unordered_map<UInt32, Entry> entries_;
            };

            /** @brief Returns the process-wide PMTU cache used by virtual ethernet packet paths. */
            static inline VirtualEthernetPathMtuCache& GetVirtualEthernetPathMtuCache() noexcept {
                static VirtualEthernetPathMtuCache cache;
                return cache;
            }
        }
    }
}
