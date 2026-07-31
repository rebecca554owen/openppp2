#pragma once

#include <ppp/app/runtime/RuntimeSnapshotJson.h>

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
