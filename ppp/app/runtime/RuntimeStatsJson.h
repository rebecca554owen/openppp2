#pragma once

#include <ppp/app/runtime/RuntimeSnapshotJson.h>
#include <ppp/app/mux/MuxRuntimeCounters.h>

#include <json/json.h>

#include <cstdint>
#include <string>

namespace ppp {
    namespace app {
        namespace runtime {

            struct RuntimeLinkStats final {
                double quality_percent = 100.0;
                std::string grade = "Unknown";
                std::uint64_t error_count = 0;
                std::uint64_t success_count = 0;
            };

            struct RuntimeStatsSample final {
                static constexpr std::uint32_t SchemaVersion = 1;

                std::uint64_t monotonic_ms = 0;
                std::uint64_t rx_bytes = 0;
                std::uint64_t tx_bytes = 0;
                RuntimeLinkStats link;
                RuntimeSnapshot runtime;
                ppp::app::mux::MuxRuntimeCounters mux_counters;
            };

            inline std::string SerializeRuntimeStats(
                const RuntimeStatsSample& sample) noexcept {
                Json::Value root(Json::objectValue);
                root["type"] = "ppp-stats";
                root["version"] = RuntimeStatsSample::SchemaVersion;
                root["monotonic_ms"] = Json::UInt64(sample.monotonic_ms);
                root["rx_bytes"] = Json::UInt64(sample.rx_bytes);
                root["tx_bytes"] = Json::UInt64(sample.tx_bytes);

                Json::Value link(Json::objectValue);
                link["quality_percent"] = sample.link.quality_percent;
                link["grade"] = detail::ToRuntimeJsonString(sample.link.grade);
                link["error_count"] = Json::UInt64(sample.link.error_count);
                link["success_count"] = Json::UInt64(sample.link.success_count);
                root["link"] = std::move(link);

                // The mux counters keep the telemetry vocabulary: every key is
                // the telemetry counter it mirrors, so the stats NDJSON and the
                // telemetry export can be read side by side.
                Json::Value counters(Json::objectValue);
                counters["mux.link.send"] = Json::UInt64(sample.mux_counters.tx_frames);
                counters["mux.link.recv"] = Json::UInt64(sample.mux_counters.rx_frames);
                counters["mux.rx.flow.unknown_cid"] = Json::UInt64(sample.mux_counters.rx_flow_unknown_cid);
                counters["mux.rx.flow.refused"] = Json::UInt64(sample.mux_counters.rx_flow_refused);
                counters["mux.rx.flow.reack"] = Json::UInt64(sample.mux_counters.rx_flow_reack);
                counters["mux.rx.closed_flow.drop"] = Json::UInt64(sample.mux_counters.rx_closed_flow_drop);
                counters["mux.rx.closed_flow.reack"] = Json::UInt64(sample.mux_counters.rx_closed_flow_reack);
                counters["mux.rx.flow.reset"] = Json::UInt64(sample.mux_counters.rx_flow_reset);
                counters["mux.rx.compat.gap_timeout"] = Json::UInt64(sample.mux_counters.rx_gap_timeout);
                counters["mux.rx.flow.max_open"] = Json::UInt64(sample.mux_counters.rx_flow_max_open);
                counters["mux.tx.flow.after_fin"] = Json::UInt64(sample.mux_counters.tx_flow_after_fin);
                counters["mux.rtx.pto"] = Json::UInt64(sample.mux_counters.tx_rtx_pto);
                counters["mux.rtx.exhausted"] = Json::UInt64(sample.mux_counters.tx_rtx_exhausted);
                counters["mux.rtx.exhausted.connection"] = Json::UInt64(sample.mux_counters.tx_rtx_exhausted_connection);
                counters["mux.rx.flow.refuse_post_failed"] = Json::UInt64(sample.mux_counters.rx_flow_refuse_post_failed);
                counters["mux.rx.syn_ok.refused"] = Json::UInt64(sample.mux_counters.rx_syn_ok_refused);
                counters["mux.rx.syn_ok.refused.no_socket"] = Json::UInt64(sample.mux_counters.rx_syn_ok_refused_no_socket);
                counters["mux.tx.flow.overflow"] = Json::UInt64(sample.mux_counters.tx_flow_overflow);
                counters["mux.tx.ctrl.cap"] = Json::UInt64(sample.mux_counters.tx_ctrl_cap);
                counters["mux.tx.ctrl.cap.reject"] = Json::UInt64(sample.mux_counters.tx_ctrl_cap_rejected);
                counters["mux.ack.suppressed"] = Json::UInt64(sample.mux_counters.tx_ack_suppressed);
                counters["mux.rx.unknown_cmd"] = Json::UInt64(sample.mux_counters.rx_unknown_cmd);
                counters["mux.rtt.link.count"] = Json::UInt64(sample.mux_counters.rtt_link_count);
                counters["mux.rtt.link.min_srtt_ms"] = Json::UInt64(sample.mux_counters.rtt_link_min_srtt_ms);
                counters["mux.rtt.link.max_srtt_ms"] = Json::UInt64(sample.mux_counters.rtt_link_max_srtt_ms);
                counters["mux.rtt.link.spread_ms"] = Json::UInt64(sample.mux_counters.rtt_link_spread_ms);
                counters["mux.rtt.link.heterogeneous"] = Json::UInt64(sample.mux_counters.rtt_link_heterogeneous);
                root["mux_counters"] = std::move(counters);

                Json::Reader reader;
                Json::Value runtime(Json::objectValue);
                const std::string runtime_json = SerializeRuntimeSnapshot(sample.runtime);
                if (reader.parse(
                    runtime_json.data(),
                    runtime_json.data() + runtime_json.size(),
                    runtime) && runtime.isObject()) {
                    root["runtime"] = std::move(runtime);
                }

                Json::FastWriter writer;
                const Json::String encoded = writer.write(root);
                std::string json = detail::FromRuntimeJsonString(encoded);
                while (!json.empty() && (json.back() == '\n' || json.back() == '\r')) {
                    json.pop_back();
                }
                return json;
            }

        }
    }
}
