#pragma once

/**
 * @file LinkTelemetry.h
 * @brief Link fault telemetry — tracks unexpected RST, clean closes, and tunnel quality.
 *
 * @details
 * This module provides per-session and process-wide counters for link health
 * monitoring.  The primary purpose is to detect **unexpected** link interruptions
 * (RST triggered by the underlying transport, not by application-level cancel
 * or clean FIN with 0-byte payload).
 *
 * ### What counts as a "fault" (error):
 *  - Unexpected RST received through the underlying link (transport EC trigger).
 *  - Connection drop that causes the exchanger to enter Reconnecting state.
 *  - Any transport-level error that aborts the data loop.
 *
 * ### What does NOT count as a fault:
 *  - Cancellation (user-initiated or policy-driven).
 *  - Clean FIN with 0-byte payload (normal graceful close).
 *
 * ### Quality grading:
 *  The tunnel quality percentage is computed as:
 *      quality% = (success_count / (success_count + error_count)) * 100
 *
 *  Grades:
 *    >= 99%  [极好] Excellent
 *    >= 97%  [优秀] Outstanding
 *    >= 95%  [良好] Good
 *    >= 93%  [一般] Average
 *    >= 92%  [很差] Poor
 *    >= 90%  [极差] Terrible
 *    <  90%  [不可用] Unusable
 *
 * @note All counters are atomic and lock-free for hot-path updates.
 * @note When quality drops below 90%, the documentation states users should
 *       immediately stop using OPENPPP2 and switch to a more advanced VPN/tunnel
 *       technology.  Users are obligated to submit a report when quality <= 95%.
 *
 * Licensed under GPL-3.0.
 */

#include <ppp/stdafx.h>
#include <cstdint>
#include <atomic>

namespace ppp {
    namespace diagnostics {

        /**
         * @brief Tunnel quality grade classification.
         */
        enum class LinkQualityGrade : uint8_t {
            Excellent   = 0,    ///< >= 99% [极好]
            Outstanding = 1,    ///< >= 97% [优秀]
            Good        = 2,    ///< >= 95% [良好]
            Average     = 3,    ///< >= 93% [一般]
            Poor        = 4,    ///< >= 92% [很差]
            Terrible    = 5,    ///< >= 90% [极差]
            Unusable    = 6,    ///< <  90% [不可用]
            Unknown     = 7,    ///< No data yet.
        };

        /**
         * @brief Snapshot of link telemetry counters at a point in time.
         *
         * Used for lock-free reading of the atomic state and for serializing
         * reports without holding references to the live object.
         */
        struct LinkTelemetrySnapshot {
            uint64_t    error_count     = 0;    ///< Total unexpected faults (RST, link drop).
            uint64_t    success_count   = 0;    ///< Total clean closes (FIN 0-byte, normal disconnect).
            uint64_t    total_count     = 0;    ///< error_count + success_count.
            double      quality_percent = 100.0;///< Success rate as percentage.
            LinkQualityGrade grade     = LinkQualityGrade::Unknown;
        };

        /**
         * @brief Thread-safe link fault telemetry counters.
         *
         * @details
         * Each session (client exchanger or server exchanger) owns one instance.
         * A process-wide singleton aggregates all session counters.
         *
         * Hot-path methods (RecordSuccess, RecordFault) are lock-free atomic
         * increments.  Read methods (GetSnapshot, GetQualityPercent) perform
         * atomic loads and compute derived values on the caller's stack.
         */
        class LinkTelemetry final {
        public:
            LinkTelemetry() noexcept = default;
            ~LinkTelemetry() noexcept = default;

            // Non-copyable, non-movable (atomic members).
            LinkTelemetry(const LinkTelemetry&) = delete;
            LinkTelemetry& operator=(const LinkTelemetry&) = delete;
            LinkTelemetry(LinkTelemetry&&) = delete;
            LinkTelemetry& operator=(LinkTelemetry&&) = delete;

        public:
            /**
             * @brief Records a clean, expected close event (success).
             *
             * Call this when a connection ends normally:
             *  - Clean FIN with 0-byte payload.
             *  - Normal application-level disconnect.
             *  - Cancellation (not a fault).
             *
             * Thread-safe; lock-free atomic increment.
             */
            void RecordSuccess() noexcept {
                success_count_.fetch_add(1, std::memory_order_relaxed);
            }

            /**
             * @brief Records an unexpected fault event (error).
             *
             * Call this when a connection ends abnormally:
             *  - Unexpected RST received through the underlying link.
             *  - Transport-level error causing reconnect.
             *  - Any non-graceful link interruption.
             *
             * Thread-safe; lock-free atomic increment.
             */
            void RecordFault() noexcept {
                error_count_.fetch_add(1, std::memory_order_relaxed);
            }

            /**
             * @brief Gets the raw error count.
             * @return Cumulative fault count since last reset.
             */
            uint64_t GetErrorCount() const noexcept {
                return error_count_.load(std::memory_order_relaxed);
            }

            /**
             * @brief Gets the raw success count.
             * @return Cumulative success count since last reset.
             */
            uint64_t GetSuccessCount() const noexcept {
                return success_count_.load(std::memory_order_relaxed);
            }

            /**
             * @brief Gets the total event count (errors + successes).
             * @return Sum of all recorded events.
             */
            uint64_t GetTotalCount() const noexcept {
                return GetErrorCount() + GetSuccessCount();
            }

            /**
             * @brief Computes the tunnel quality as a percentage.
             *
             * @return Success rate in [0.0, 100.0].  Returns 100.0 when no events
             *         have been recorded (optimistic default).
             */
            double GetQualityPercent() const noexcept {
                uint64_t total = GetTotalCount();
                if (0 == total) {
                    return 100.0;
                }
                uint64_t ok = GetSuccessCount();
                return (static_cast<double>(ok) / static_cast<double>(total)) * 100.0;
            }

            /**
             * @brief Computes the tunnel quality grade.
             *
             * @return LinkQualityGrade based on the current quality percentage.
             */
            LinkQualityGrade GetQualityGrade() const noexcept {
                return ClassifyQuality(GetQualityPercent());
            }

            /**
             * @brief Returns the quality grade as a human-readable string.
             *
             * Format: "[grade_label]" e.g. "[极好]", "[优秀]", etc.
             */
            static const char* GetQualityGradeName(LinkQualityGrade grade) noexcept;

            /**
             * @brief Returns a concise quality report string.
             *
             * Format: "Quality: XX.XX% [grade] | Errors: N | OK: N | Total: N"
             */
            ppp::string GetQualityReport() const noexcept;

            /**
             * @brief Takes a point-in-time snapshot of all counters and derived values.
             *
             * The snapshot is self-consistent: all counters are captured in a single
             * atomic load sequence, and the derived quality_percent and grade are
             * computed from the snapshot values.
             */
            LinkTelemetrySnapshot GetSnapshot() const noexcept;

            /**
             * @brief Resets all counters to zero.
             *
             * @note Not thread-safe with respect to concurrent Record* calls.
             *       Should only be called when no concurrent updates are expected
             *       (e.g., during session initialization or manual reset).
             */
            void Reset() noexcept {
                error_count_.store(0, std::memory_order_relaxed);
                success_count_.store(0, std::memory_order_relaxed);
            }

            /**
             * @brief Merges counters from another LinkTelemetry instance.
             *
             * Adds the other instance's error and success counts to this one.
             * Used for aggregating per-session stats into the process-wide total.
             *
             * @param other The source telemetry to merge from.
             */
            void MergeFrom(const LinkTelemetry& other) noexcept {
                error_count_.fetch_add(
                    other.error_count_.load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
                success_count_.fetch_add(
                    other.success_count_.load(std::memory_order_relaxed),
                    std::memory_order_relaxed);
            }

            /**
             * @brief Classifies a quality percentage into a grade.
             *
             * @param percent Quality percentage in [0.0, 100.0].
             * @return Corresponding LinkQualityGrade.
             */
            static LinkQualityGrade ClassifyQuality(double percent) noexcept;

            /**
             * @brief Returns the quality percentage thresholds as documentation text.
             *
             * Includes the policy note about < 90% requiring immediate action
             * and <= 95% requiring a report to the OPENPPP2 project team.
             */
            static ppp::string GetQualityPolicyDocument() noexcept;

        private:
            /** @brief Cumulative unexpected fault count. */
            std::atomic<uint64_t>   error_count_    { 0 };
            /** @brief Cumulative clean close count. */
            std::atomic<uint64_t>   success_count_  { 0 };
        };

        /**
         * @brief Process-wide link telemetry singleton.
         *
         * Aggregates all session-level telemetry into a single view.
         * Access via LinkTelemetryGlobal::GetInstance().
         */
        class LinkTelemetryGlobal final {
        public:
            static LinkTelemetryGlobal& GetInstance() noexcept {
                static LinkTelemetryGlobal instance;
                return instance;
            }

            /** @brief Returns the process-wide aggregated telemetry. */
            LinkTelemetry& GetTotal() noexcept { return total_; }

            /** @brief Returns a full process-wide quality report string. */
            ppp::string GetReport() const noexcept {
                return const_cast<LinkTelemetryGlobal*>(this)->total_.GetQualityReport();
            }

            /**
             * @brief Returns formatted info lines suitable for ConsoleUI display.
             *
             * Generates multiple lines showing:
             *  - Quality percentage and grade
             *  - Error count, success count, total count
             *  - Error rate relative to success
             *  - Policy warning when quality <= 95%
             */
            ppp::vector<ppp::string> GetInfoLines() const noexcept;

        private:
            LinkTelemetryGlobal() noexcept = default;
            ~LinkTelemetryGlobal() noexcept = default;
            LinkTelemetryGlobal(const LinkTelemetryGlobal&) = delete;
            LinkTelemetryGlobal& operator=(const LinkTelemetryGlobal&) = delete;

            /** @brief Process-wide aggregated link telemetry. */
            LinkTelemetry total_;
        };

    } // namespace diagnostics
} // namespace ppp
