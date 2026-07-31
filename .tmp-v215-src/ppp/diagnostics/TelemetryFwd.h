#pragma once

#include <cstdint>
#include <cstddef>

namespace ppp {
    namespace telemetry {

        enum class Level : uint8_t {
            kInfo   = 0,
            kVerb   = 1,
            kDebug  = 2,
            kTrace  = 3,
        };

        struct Attribute;

        class SpanScope;

        void Log(Level level, const char* component, const char* fmt, ...) noexcept;
        void Count(const char* metric, int64_t delta) noexcept;
        void Gauge(const char* metric, int64_t value) noexcept;
        void Histogram(const char* metric, int64_t value) noexcept;

    }
}
