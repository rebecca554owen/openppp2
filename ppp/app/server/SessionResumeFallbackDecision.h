#pragma once

#include <cstdint>

namespace ppp {
    namespace app {
        namespace server {

            enum class SessionResumeFallbackReason : std::uint8_t {
                LookupMiss,
                BeginRejected,
                OtherResumeFailure,
            };

            enum class SessionResumeFallbackDecision : std::uint8_t {
                Fresh,
                Reject,
            };

            constexpr SessionResumeFallbackDecision DecideSessionResumeFallback(
                SessionResumeFallbackReason reason) noexcept {
                return reason == SessionResumeFallbackReason::LookupMiss
                    ? SessionResumeFallbackDecision::Fresh
                    : SessionResumeFallbackDecision::Reject;
            }

        }
    }
}
