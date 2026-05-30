#pragma once

/**
 * @file P2PZeroRTTCache.h
 * @brief In-memory cache for zero-RTT P2P reconnection.
 *
 * SECURITY NOTE (#11): Cached session keys carry nonce-reuse risk if a
 * reconnect reuses the same key with a reset nonce counter. To prevent
 * this, the cache stores only the session_id, token_key, peer endpoint,
 * and cipher — NOT the AEAD session_key.  On reconnect, a fresh
 * per-channel key must be derived via HKDF with a unique channel salt
 * (e.g., session_id || fresh_nonce). If safe key derivation is not
 * possible, zero-RTT reconnect is disabled (fail closed).
 *
 * Cache TTL: 300 seconds. After expiry, entries are purged.
 *
 * @license GPL-3.0
 */

#include <ppp/p2p/P2PDefs.h>
#include <ppp/Int128.h>
#include <ppp/stdafx.h>
#include <boost/asio.hpp>
#include <mutex>

namespace ppp {
    namespace p2p {

        /**
         * @brief Cached P2P session state for zero-RTT reconnect.
         *
         * Does NOT store the AEAD session_key to prevent nonce reuse (#11).
         */
        struct P2PSessionCache {
            Int128                                  session_id;
            Int128                                  peer_session_id;
            uint8_t                                 token_key[SESSION_KEY_SIZE] = {};
            boost::asio::ip::udp::endpoint          peer_endpoint;
            P2PCipher                               cipher = P2PCipher::ChaCha20Poly1305;
            uint64_t                                cached_at_ms = 0;
            bool                                    valid = false;
        };

        /**
         * @brief Thread-safe cache for zero-RTT P2P reconnection.
         */
        class P2PZeroRTTCache final {
        public:
            void Store(uint32_t virtual_ip, const P2PSessionCache& session) noexcept {
                if (virtual_ip == 0 || !session.valid) {
                    return;
                }
                P2PSessionCache entry = session;
                entry.cached_at_ms = ppp::GetTickCount();
                entry.valid = true;
                std::lock_guard<std::mutex> lock(mutex_);
                cache_[virtual_ip] = std::move(entry);
            }

            P2PSessionCache Lookup(uint32_t virtual_ip) noexcept {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = cache_.find(virtual_ip);
                if (it == cache_.end()) {
                    return P2PSessionCache{};
                }
                P2PSessionCache& entry = it->second;
                uint64_t now = ppp::GetTickCount();
                if (now - entry.cached_at_ms > static_cast<uint64_t>(ZERO_RTT_CACHE_TTL_SECONDS) * 1000) {
                    cache_.erase(it);
                    return P2PSessionCache{};
                }
                return entry;
            }

            void Invalidate(uint32_t virtual_ip) noexcept {
                std::lock_guard<std::mutex> lock(mutex_);
                cache_.erase(virtual_ip);
            }

            void PurgeExpired() noexcept {
                uint64_t now = ppp::GetTickCount();
                std::lock_guard<std::mutex> lock(mutex_);
                for (auto it = cache_.begin(); it != cache_.end(); ) {
                    if (now - it->second.cached_at_ms > static_cast<uint64_t>(ZERO_RTT_CACHE_TTL_SECONDS) * 1000) {
                        it = cache_.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            void Clear() noexcept {
                std::lock_guard<std::mutex> lock(mutex_);
                cache_.clear();
            }

        private:
            std::mutex                                      mutex_;
            ppp::unordered_map<uint32_t, P2PSessionCache>   cache_;
        };

    }
}
