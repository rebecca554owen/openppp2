#pragma once

#include <ppp/app/runtime/RuntimeError.h>
#include <ppp/app/runtime/RuntimePhase.h>

#include <cstdint>
#include <string>

namespace ppp {
    namespace app {
        namespace runtime {

            struct RuntimeSnapshot final {
                static constexpr std::uint32_t SchemaVersion = 1;

                std::uint32_t schema_version = SchemaVersion;
                std::uint64_t generation = 0;
                std::uint64_t monotonic_ms = 0;
                RuntimePhase phase = RuntimePhase::Idle;
                std::string role;
                std::string server;
                std::string transport;
                std::string requested_mux_mode;
                std::string effective_mux_mode;
                std::string mux_fallback_reason;
                std::string p2p_state;
                std::string effective_path;
                RuntimeError last_error;
            };

        }
    }
}
