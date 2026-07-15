#pragma once

#include <cstdint>
#include <string>
#include <utility>

namespace ppp::app::mux {

struct MuxRuntimeState final {
    std::string requested_mode;
    std::string effective_mode;
    std::string receiver_ordering;
    std::uint16_t active_links = 0;
    std::string fallback_reason;
};

inline bool IsMuxLinkActive(bool handshake_complete, bool retiring) noexcept {
    return handshake_complete && !retiring;
}

inline MuxRuntimeState NegotiateMuxRuntimeState(
    std::string requested_mode,
    bool local_supports_flow_v2,
    bool peer_supports_flow_v2,
    std::uint16_t active_links = 0) {
    MuxRuntimeState state;
    state.requested_mode = std::move(requested_mode);
    state.effective_mode = state.requested_mode;
    state.active_links = active_links;

    const bool known = state.requested_mode == "compat" ||
        state.requested_mode == "flow" ||
        state.requested_mode == "balance" ||
        state.requested_mode == "stripe";
    if (!known) {
        state.effective_mode = "compat";
        state.receiver_ordering = "compat";
        state.fallback_reason = "unsupported_requested_mode";
        return state;
    }

    const bool requires_flow_v2 = state.requested_mode == "balance" ||
        state.requested_mode == "stripe";
    if (requires_flow_v2 && (!local_supports_flow_v2 || !peer_supports_flow_v2)) {
        state.effective_mode = "compat";
        state.receiver_ordering = "compat";
        state.fallback_reason = local_supports_flow_v2
            ? "peer_missing_flow_v2"
            : "local_missing_flow_v2";
        return state;
    }

    const bool uses_flow_v2 = state.requested_mode != "compat" &&
        local_supports_flow_v2 && peer_supports_flow_v2;
    state.receiver_ordering = uses_flow_v2 ? "flow_v2" : "compat";
    return state;
}

} // namespace ppp::app::mux
