#pragma once

#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/collections/Dictionary.h>

namespace ppp {
    namespace app {
        namespace client {

            class QuicRejectRateLimiter {
            public:
                static constexpr ppp::UInt64 kWindowMs = 1000;
                static constexpr size_t kMaxEntries = 1024;

                ppp::string BuildKey(
                    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame) noexcept;

                bool ShouldEmit(const ppp::string& key, ppp::UInt64 now) noexcept;

                void Clear() noexcept;

            private:
                ppp::unordered_map<ppp::string, ppp::UInt64> table_;
            };

        }
    }
}
