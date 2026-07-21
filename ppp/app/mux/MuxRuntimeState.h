#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace ppp::app::mux {

struct MuxRuntimeState final {
    std::string requested_mode;      ///< User/config preset: compat|flow|balance|stripe
    std::string effective_mode;      ///< Negotiated preset after capability intersection
    std::string receiver_ordering;   ///< compat|flow_v2
    std::string scheduler;           ///< competition|round_robin (derived from effective_mode)
    std::string pool_policy;         ///< fixed|adaptive (derived from effective_mode + turbo)
    bool turbo = false;              ///< flow turbo active (adaptive pool / best-link SYN)
    std::uint16_t active_links = 0;
    std::string fallback_reason;
};

inline const char* MuxSchedulerName(const std::string& mode) noexcept {
    return mode == "stripe" ? "round_robin" : "competition";
}

inline const char* MuxPoolPolicyName(const std::string& mode, bool turbo) noexcept {
    return (mode == "flow" && turbo) ? "adaptive" : "fixed";
}

inline void FillMuxPresentation(MuxRuntimeState& state) noexcept {
    state.scheduler = MuxSchedulerName(state.effective_mode);
    state.pool_policy = MuxPoolPolicyName(state.effective_mode, state.turbo);
}

inline bool IsMuxLinkActive(bool handshake_complete, bool retiring) noexcept {
    return handshake_complete && !retiring;
}

/** True when the preset needs negotiated per-flow DSN ordering. */
inline bool ModeRequiresFlowV2(const std::string& mode, bool turbo) noexcept {
    return mode == "balance" || mode == "stripe" || (mode == "flow" && turbo);
}

/**
 * Negotiate effective preset + receiver ordering.
 * @param local_supports_flow_v2 Implementation capability (independent of current preset).
 * @param peer_supports_flow_v2 Peer advertised capability bit.
 * @param turbo Local turbo request (only meaningful with flow preset).
 */
inline MuxRuntimeState NegotiateMuxRuntimeState(
    std::string requested_mode,
    bool local_supports_flow_v2,
    bool peer_supports_flow_v2,
    std::uint16_t active_links = 0,
    bool turbo = false) {
    MuxRuntimeState state;
    state.requested_mode = std::move(requested_mode);
    state.effective_mode = state.requested_mode;
    state.active_links = active_links;
    state.turbo = turbo && state.requested_mode == "flow";

    const bool known = state.requested_mode == "compat" ||
        state.requested_mode == "flow" ||
        state.requested_mode == "balance" ||
        state.requested_mode == "stripe";
    if (!known) {
        state.effective_mode = "compat";
        state.receiver_ordering = "compat";
        state.turbo = false;
        state.fallback_reason = "unsupported_requested_mode";
        FillMuxPresentation(state);
        return state;
    }

    const bool requires_flow_v2 = ModeRequiresFlowV2(state.requested_mode, state.turbo);
    if (requires_flow_v2 && (!local_supports_flow_v2 || !peer_supports_flow_v2)) {
        // balance/stripe cannot run without flow_v2; fall back the whole preset.
        // flow without turbo does not require flow_v2, so it is not handled here.
        if (state.requested_mode == "balance" || state.requested_mode == "stripe") {
            state.effective_mode = "compat";
            state.receiver_ordering = "compat";
            state.turbo = false;
            state.fallback_reason = local_supports_flow_v2
                ? "peer_missing_flow_v2"
                : "local_missing_flow_v2";
            FillMuxPresentation(state);
            return state;
        }
    }

    // flow keeps its preset even if ordering stays compat (old peer or no turbo).
    const bool uses_flow_v2 = ModeRequiresFlowV2(state.effective_mode, state.turbo) &&
        local_supports_flow_v2 && peer_supports_flow_v2;
    state.receiver_ordering = uses_flow_v2 ? "flow_v2" : "compat";
    if (state.requested_mode == "flow" && state.turbo && !uses_flow_v2 &&
        state.fallback_reason.empty() && (!local_supports_flow_v2 || !peer_supports_flow_v2)) {
        state.fallback_reason = local_supports_flow_v2
            ? "peer_missing_flow_v2"
            : "local_missing_flow_v2";
        // Keep effective_mode=flow; turbo features that need flow_v2 degrade safely.
    }

    FillMuxPresentation(state);
    return state;
}

} // namespace ppp::app::mux
