#include <ppp/app/client/QuicRejectRateLimiter.h>

#include <cstring>

namespace ppp {
    namespace app {
        namespace client {

            ppp::string QuicRejectRateLimiter::BuildKey(
                const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept {

                ppp::string key;
                if (NULLPTR == packet || NULLPTR == frame) {
                    return key;
                }

                ppp::UInt32 source_ip = packet->Source;
                ppp::UInt32 destination_ip = packet->Destination;
                ppp::UInt16 source_port = static_cast<ppp::UInt16>(frame->Source.Port);
                ppp::UInt16 destination_port = static_cast<ppp::UInt16>(frame->Destination.Port);

                key.resize((sizeof(source_ip) << 1) + (sizeof(source_port) << 1));
                char* out = &key[0];
                memcpy(out, &source_ip, sizeof(source_ip));
                out += sizeof(source_ip);
                memcpy(out, &destination_ip, sizeof(destination_ip));
                out += sizeof(destination_ip);
                memcpy(out, &source_port, sizeof(source_port));
                out += sizeof(source_port);
                memcpy(out, &destination_port, sizeof(destination_port));
                return key;
            }

            bool QuicRejectRateLimiter::ShouldEmit(const ppp::string& key, ppp::UInt64 now) noexcept {
                auto existing = table_.find(key);
                if (existing != table_.end()) {
                    if (now - existing->second < kWindowMs) {
                        return false;
                    }

                    existing->second = now;
                    return true;
                }

                if (table_.size() >= kMaxEntries) {
                    for (auto tail = table_.begin(); tail != table_.end();) {
                        if (now - tail->second >= kWindowMs) {
                            tail = table_.erase(tail);
                        }
                        else {
                            ++tail;
                        }
                    }

                    if (table_.size() >= kMaxEntries) {
                        table_.erase(table_.begin());
                    }
                }

                table_.emplace(key, now);
                return true;
            }

            void QuicRejectRateLimiter::Clear() noexcept {
                table_.clear();
            }

        }
    }
}
