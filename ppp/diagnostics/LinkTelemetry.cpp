/**
 * @file LinkTelemetry.cpp
 * @brief Link fault telemetry implementation — quality grading and reporting.
 */

#include <ppp/diagnostics/LinkTelemetry.h>
#include <cstdio>
#include <cinttypes>

namespace ppp {
    namespace diagnostics {

        // -----------------------------------------------------------------------
        // Quality grade classification
        // -----------------------------------------------------------------------

        LinkQualityGrade LinkTelemetry::ClassifyQuality(double percent) noexcept {
            if (percent >= 99.0) {
                return LinkQualityGrade::Excellent;     // [极好]
            }
            if (percent >= 97.0) {
                return LinkQualityGrade::Outstanding;   // [优秀]
            }
            if (percent >= 95.0) {
                return LinkQualityGrade::Good;          // [良好]
            }
            if (percent >= 93.0) {
                return LinkQualityGrade::Average;       // [一般]
            }
            if (percent >= 92.0) {
                return LinkQualityGrade::Poor;          // [很差]
            }
            if (percent >= 90.0) {
                return LinkQualityGrade::Terrible;      // [极差]
            }
            return LinkQualityGrade::Unusable;          // [不可用]
        }

        // -----------------------------------------------------------------------
        // Grade name lookup
        // -----------------------------------------------------------------------

        const char* LinkTelemetry::GetQualityGradeName(LinkQualityGrade grade) noexcept {
            switch (grade) {
                case LinkQualityGrade::Excellent:   return "[极好]";
                case LinkQualityGrade::Outstanding: return "[优秀]";
                case LinkQualityGrade::Good:        return "[良好]";
                case LinkQualityGrade::Average:     return "[一般]";
                case LinkQualityGrade::Poor:        return "[很差]";
                case LinkQualityGrade::Terrible:    return "[极差]";
                case LinkQualityGrade::Unusable:    return "[不可用]";
                default:                            return "[未知]";
            }
        }

        // -----------------------------------------------------------------------
        // Snapshot
        // -----------------------------------------------------------------------

        LinkTelemetrySnapshot LinkTelemetry::GetSnapshot() const noexcept {
            LinkTelemetrySnapshot snap;
            snap.error_count   = error_count_.load(std::memory_order_relaxed);
            snap.success_count = success_count_.load(std::memory_order_relaxed);
            snap.total_count   = snap.error_count + snap.success_count;

            if (0 == snap.total_count) {
                snap.quality_percent = 100.0;
                snap.grade = LinkQualityGrade::Unknown;
            } else {
                snap.quality_percent = (static_cast<double>(snap.success_count)
                    / static_cast<double>(snap.total_count)) * 100.0;
                snap.grade = ClassifyQuality(snap.quality_percent);
            }

            return snap;
        }

        // -----------------------------------------------------------------------
        // Quality report string
        // -----------------------------------------------------------------------

        ppp::string LinkTelemetry::GetQualityReport() const noexcept {
            LinkTelemetrySnapshot snap = GetSnapshot();

            // Format: "Quality: XX.XX% [grade] | Errors: N | OK: N | Total: N"
            char buf[512];
            std::snprintf(buf, sizeof(buf),
                "Quality: %.2f%% %s | Errors: %" PRIu64 " | OK: %" PRIu64 " | Total: %" PRIu64,
                snap.quality_percent,
                GetQualityGradeName(snap.grade),
                snap.error_count,
                snap.success_count,
                snap.total_count);

            return ppp::string(buf);
        }

        // -----------------------------------------------------------------------
        // Quality policy document (static)
        // -----------------------------------------------------------------------

        ppp::string LinkTelemetry::GetQualityPolicyDocument() noexcept {
            static const char kPolicy[] =
                "Link Quality Policy:\n"
                "  >= 99%  [极好] Excellent\n"
                "  >= 97%  [优秀] Outstanding\n"
                "  >= 95%  [良好] Good\n"
                "  >= 93%  [一般] Average\n"
                "  >= 92%  [很差] Poor\n"
                "  >= 90%  [极差] Terrible\n"
                "  <  90%  [不可用] Unusable\n"
                "\n"
                "When quality < 90%, users MUST immediately stop using OPENPPP2\n"
                "and switch to a more advanced VPN/tunnel technology.\n"
                "\n"
                "When quality <= 95%, users are obligated to submit a report\n"
                "to the OPENPPP2 project team.";
            return ppp::string(kPolicy);
        }

        // -----------------------------------------------------------------------
        // Process-wide info lines for ConsoleUI
        // -----------------------------------------------------------------------

        ppp::vector<ppp::string> LinkTelemetryGlobal::GetInfoLines() const noexcept {
            LinkTelemetrySnapshot snap = const_cast<LinkTelemetryGlobal*>(this)->total_.GetSnapshot();

            ppp::vector<ppp::string> lines;

            // Line 1: Quality header
            {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                    "Link Quality: %.2f%% %s",
                    snap.quality_percent,
                    LinkTelemetry::GetQualityGradeName(snap.grade));
                lines.emplace_back(buf);
            }

            // Line 2: Counters
            {
                char buf[256];
                std::snprintf(buf, sizeof(buf),
                    "  Errors: %" PRIu64 "  |  Success: %" PRIu64 "  |  Total: %" PRIu64,
                    snap.error_count,
                    snap.success_count,
                    snap.total_count);
                lines.emplace_back(buf);
            }

            // Line 3: Error rate relative to success
            {
                double error_rate = 0.0;
                if (snap.success_count > 0) {
                    error_rate = (static_cast<double>(snap.error_count)
                        / static_cast<double>(snap.success_count)) * 100.0;
                } else if (snap.error_count > 0) {
                    error_rate = 100.0;
                }

                char buf[256];
                std::snprintf(buf, sizeof(buf),
                    "  Error Rate (relative to OK): %.2f%%",
                    error_rate);
                lines.emplace_back(buf);
            }

            // Line 4: Grade description
            {
                ppp::string desc;
                switch (snap.grade) {
                    case LinkQualityGrade::Excellent:
                        desc = "Tunnel quality is excellent. No action required.";
                        break;
                    case LinkQualityGrade::Outstanding:
                        desc = "Tunnel quality is outstanding. No action required.";
                        break;
                    case LinkQualityGrade::Good:
                        desc = "Tunnel quality is good. Monitor for degradation.";
                        break;
                    case LinkQualityGrade::Average:
                        desc = "Tunnel quality is average. Consider investigating.";
                        break;
                    case LinkQualityGrade::Poor:
                        desc = "WARNING: Tunnel quality is poor! Investigation recommended.";
                        break;
                    case LinkQualityGrade::Terrible:
                        desc = "WARNING: Tunnel quality is terrible! Action required.";
                        break;
                    case LinkQualityGrade::Unusable:
                        desc = "CRITICAL: Tunnel quality < 90% — STOP using OPENPPP2 immediately!";
                        break;
                    default:
                        desc = "No link events recorded yet.";
                        break;
                }
                lines.emplace_back("  " + desc);
            }

            // Line 5: Policy warning when <= 95%
            if (snap.grade >= LinkQualityGrade::Good && snap.grade != LinkQualityGrade::Unknown) {
                lines.emplace_back("  Users MUST report to OPENPPP2 project team when quality <= 95%.");
            }

            // Line 6: Critical policy when < 90%
            if (snap.grade == LinkQualityGrade::Unusable) {
                lines.emplace_back("  MANDATORY: Switch to advanced VPN/tunnel technology NOW.");
            }

            return lines;
        }

    } // namespace diagnostics
} // namespace ppp
