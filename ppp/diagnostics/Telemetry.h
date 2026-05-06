#pragma once

/**
 * @file Telemetry.h
 * @brief Always-compiled telemetry facade for observability.
 *
 * @details All telemetry code is unconditionally compiled.  Runtime behavior
 *          is controlled by the g_enabled flag which defaults to false.
 *          The JSON config field "telemetry": { "enabled": true } activates
 *          the backend at application startup.
 *
 *          This facade never allocates, never throws, and never blocks on
 *          the hot path when telemetry is disabled at runtime.
 */

#include <cstdint>
#include <cstdarg>
#include <cstddef>

/* Always compiled — kept for any external code that checks the macro. */
#ifndef PPP_TELEMETRY
# define PPP_TELEMETRY 1
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

        struct Attribute final {
            const char* key;
            const char* value;
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
        };

        void Log(Level level, const char* component, const char* fmt, ...) noexcept;
        void LogWithAttributes(Level level, const char* component, const Attribute* attrs, size_t attr_count, const char* fmt, ...) noexcept;
        void Count(const char* metric, int64_t delta) noexcept;
        void Gauge(const char* metric, int64_t value) noexcept;
        void Histogram(const char* metric, int64_t value) noexcept;
        void TraceSpan(const char* name, const char* session_id) noexcept;
        void SetEnabled(bool enabled) noexcept;
        void SetCountEnabled(bool enabled) noexcept;
        void SetSpanEnabled(bool enabled) noexcept;
        void SetConsoleLogEnabled(bool enabled) noexcept;
        void SetConsoleMetricEnabled(bool enabled) noexcept;
        void SetConsoleSpanEnabled(bool enabled) noexcept;
        bool IsConsoleLogEnabled() noexcept;
        bool IsConsoleMetricEnabled() noexcept;
        bool IsConsoleSpanEnabled() noexcept;
        int  GetMinLevel() noexcept;
        void SetMinLevel(int level) noexcept;
        void Configure(const char* endpoint) noexcept;
        void SetLogFile(const char* path) noexcept;
        void Flush(int timeout_ms = 3000) noexcept;
        void Shutdown() noexcept;

    }
}
