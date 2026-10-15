#pragma once

#include <cstdint>
#include <cstddef>

namespace ppp {
    namespace telemetry {

        /**
         * @brief Severity levels, ordered from least to most verbose.
         * @note  `kWarn` is appended last rather than ordered by severity so that
         *        the numeric values already persisted in configs (`"level": 0` in
         *        appsettings.json) and accepted by the console command
         *        (`telemetry level 0|1|2|3`) keep their existing meaning.
         *        Warn() bypasses this filter entirely.
         */
        enum class Level : uint8_t {
            kInfo   = 0,
            kVerb   = 1,
            kDebug  = 2,
            kTrace  = 3,
            kWarn   = 4,
        };

        struct Attribute;

        class SpanScope;

        void Log(Level level, const char* component, const char* fmt, ...) noexcept;

        /**
         * @brief Emits a configuration-grade warning the operator must see.
         * @note  Not gated on the telemetry `enabled` flag (which defaults to
         *        false), so a downgraded cipher or a degraded TCP stack cannot be
         *        silently swallowed in a default deployment.
         */
        void Warn(const char* component, const char* fmt, ...) noexcept;

        void Count(const char* metric, int64_t delta) noexcept;
        void Gauge(const char* metric, int64_t value) noexcept;
        void Histogram(const char* metric, int64_t value) noexcept;

    }
}
