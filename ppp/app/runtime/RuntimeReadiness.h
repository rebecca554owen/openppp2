#pragma once

#include <ppp/app/runtime/RuntimePhase.h>

namespace ppp::app::runtime {

struct RuntimeReadiness final {
    bool session = false;
    bool adapter = false;
    bool route = false;
    bool dns = false;
    bool policy = false;

    bool IsFullyReady() const noexcept {
        return session && adapter && route && dns && policy;
    }
};

inline RuntimePhase GateConnectedPhase(
    RuntimePhase requested,
    const RuntimeReadiness& readiness) noexcept {
    if (requested == RuntimePhase::Connected && !readiness.IsFullyReady()) {
        return RuntimePhase::ApplyingPolicy;
    }
    return requested;
}

}
