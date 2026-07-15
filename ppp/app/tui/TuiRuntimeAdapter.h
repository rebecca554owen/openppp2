#pragma once

#include <ppp/app/runtime/RuntimeSnapshot.h>

#include <string>
#include <vector>

namespace ppp::app::tui {

inline const char* PhaseDisplayName(runtime::RuntimePhase phase) noexcept {
    switch (phase) {
    case runtime::RuntimePhase::Idle: return "Idle";
    case runtime::RuntimePhase::Starting: return "Starting";
    case runtime::RuntimePhase::PreparingHost: return "Preparing host";
    case runtime::RuntimePhase::Connecting: return "Connecting";
    case runtime::RuntimePhase::Handshaking: return "Handshaking";
    case runtime::RuntimePhase::ApplyingPolicy: return "Applying policy";
    case runtime::RuntimePhase::Connected: return "Connected";
    case runtime::RuntimePhase::Reconnecting: return "Reconnecting";
    case runtime::RuntimePhase::Stopping: return "Stopping";
    case runtime::RuntimePhase::Failed: return "Failed";
    default: return "Unknown";
    }
}

inline std::vector<std::string> BuildStatusLines(
    const runtime::RuntimeSnapshot& snapshot) {
    std::vector<std::string> lines;
    lines.emplace_back(PhaseDisplayName(snapshot.phase));

    if (!snapshot.effective_mux_mode.empty()) {
        lines.emplace_back("effective mux=" + snapshot.effective_mux_mode);
    }
    if (!snapshot.requested_mux_mode.empty() &&
        snapshot.requested_mux_mode != snapshot.effective_mux_mode) {
        lines.emplace_back("requested mux=" + snapshot.requested_mux_mode);
    }
    if (!snapshot.mux_fallback_reason.empty()) {
        lines.emplace_back("fallback=" + snapshot.mux_fallback_reason);
    }
    if (!snapshot.mux_receiver_ordering.empty()) {
        lines.emplace_back("receiver ordering=" + snapshot.mux_receiver_ordering);
    }
    if (snapshot.mux_active_links > 0) {
        lines.emplace_back("active mux links=" + std::to_string(snapshot.mux_active_links));
    }

    if (snapshot.phase == runtime::RuntimePhase::Failed) {
        std::string error = "error code=" + std::to_string(snapshot.last_error.code);
        error += " severity=";
        error += snapshot.last_error.severity.empty() ? "-" : snapshot.last_error.severity;
        error += " key=";
        error += snapshot.last_error.user_message_key.empty()
            ? "-"
            : snapshot.last_error.user_message_key;
        lines.emplace_back(std::move(error));
        if (!snapshot.last_error.diagnostic_detail.empty()) {
            lines.emplace_back(snapshot.last_error.diagnostic_detail);
        }
    }
    return lines;
}

inline bool ContainsLine(
    const std::vector<std::string>& lines,
    const char* needle) noexcept {
    if (needle == nullptr) {
        return false;
    }
    for (const std::string& line : lines) {
        if (line.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

}
