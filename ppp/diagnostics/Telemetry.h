#pragma once

/**
 * @file Telemetry.h
 * @brief Zero-cost telemetry facade for optional observability.
 *
 * @details When PPP_TELEMETRY is disabled (default), all calls compile to inline no-ops.
 *          When enabled, they delegate to a backend implementation.
 *          This facade never allocates, never throws, and never blocks on the hot path.
 */

#include <cstdint>
#include <cstdarg>

#ifndef PPP_TELEMETRY
# define PPP_TELEMETRY 0
#endif

namespace ppp {
    namespace telemetry {

        /**
         * @brief Telemetry verbosity levels.
         */
        enum class Level : uint8_t {
            kInfo   = 0, ///< Startup, major state changes (least verbose).
            kVerb   = 1, ///< Branch decisions, policy hits.
            kDebug  = 2, ///< Handshake, mux, transit tun details.
            kTrace  = 3, ///< Per-packet or per-event (most verbose, highest cost).
        };

        /**
         * @brief RAII trace span scope.
         *
         * @details When telemetry tracing is enabled, constructing this object
         *          starts a span and destroying it emits the completed span with
         *          start/end timestamps and generated trace/span identifiers.
         */
        class SpanScope final {
        public:
#if PPP_TELEMETRY
            SpanScope(const char* name, const char* session_id = nullptr) noexcept;
            ~SpanScope() noexcept;
            SpanScope(SpanScope&& other) noexcept;
            SpanScope& operator=(SpanScope&& other) noexcept = delete;
            SpanScope(const SpanScope&) = delete;
            SpanScope& operator=(const SpanScope&) = delete;

        private:
            const char*                                                   name_           = nullptr;
            const char*                                                   session_id_     = nullptr;
            uint64_t                                                      start_time_ns_  = 0;
            uint64_t                                                      trace_id_hi_    = 0;
            uint64_t                                                      trace_id_lo_    = 0;
            uint64_t                                                      span_id_        = 0;
            uint64_t                                                      parent_span_id_ = 0;
            bool                                                          active_         = false;
#else
            SpanScope(const char*, const char* = nullptr) noexcept {}
            ~SpanScope() noexcept = default;
            SpanScope(SpanScope&&) noexcept = default;
            SpanScope& operator=(SpanScope&&) noexcept = delete;
            SpanScope(const SpanScope&) = delete;
            SpanScope& operator=(const SpanScope&) = delete;
#endif
        };

#if PPP_TELEMETRY

        void Log(Level level, const char* component, const char* fmt, ...) noexcept;
        void Count(const char* metric, int64_t delta) noexcept;
        void Gauge(const char* metric, int64_t value) noexcept;
        void Histogram(const char* metric, int64_t value) noexcept;
        void TraceSpan(const char* name, const char* session_id) noexcept;
        void SetEnabled(bool enabled) noexcept;
        void SetCountEnabled(bool enabled) noexcept;
        void SetSpanEnabled(bool enabled) noexcept;
        void SetMinLevel(int level) noexcept;
        void Configure(const char* endpoint) noexcept;
        void SetLogFile(const char* path) noexcept;
        void Flush(int timeout_ms = 3000) noexcept;

#else

        inline void Log(Level, const char*, const char*, ...) noexcept {}
        inline void Count(const char*, int64_t) noexcept {}
        inline void Gauge(const char*, int64_t) noexcept {}
        inline void Histogram(const char*, int64_t) noexcept {}
        inline void TraceSpan(const char*, const char*) noexcept {}
        inline void SetEnabled(bool) noexcept {}
        inline void SetCountEnabled(bool) noexcept {}
        inline void SetSpanEnabled(bool) noexcept {}
        inline void SetMinLevel(int) noexcept {}
        inline void Configure(const char*) noexcept {}
        inline void SetLogFile(const char*) noexcept {}
        inline void Flush(int) noexcept {}

#endif

    }
}
