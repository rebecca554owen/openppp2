#include <ppp/app/protocol/VirtualEthernetInformation.h>

#include <cstring>

using ppp::auxiliary::JsonAuxiliary;

namespace ppp {
    namespace app {
        namespace protocol {
            VirtualEthernetInformation::VirtualEthernetInformation() noexcept {
                Clear();
            }

            static ppp::string STATIC_TO_STRRING(VirtualEthernetInformation& information, bool styled) noexcept {
                Json::Value json;
                information.ToJson(json);

                if (styled) {
                    return JsonAuxiliary::ToStyledString(json);
                }
                else {
                    return JsonAuxiliary::ToString(json);
                }
            }

            ppp::string VirtualEthernetInformation::ToString() noexcept {
                return STATIC_TO_STRRING(*this, true);
            }

            ppp::string VirtualEthernetInformation::ToJson() noexcept {
                return STATIC_TO_STRRING(*this, false);
            }

            void VirtualEthernetInformation::ToJson(Json::Value& json) noexcept {
                json["BandwidthQoS"]    = stl::to_string<ppp::string>(this->BandwidthQoS);
                json["ExpiredTime"]     = this->ExpiredTime;
                json["IncomingTraffic"] = stl::to_string<ppp::string>(this->IncomingTraffic);
                json["OutgoingTraffic"] = stl::to_string<ppp::string>(this->OutgoingTraffic);
            }

            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const Json::Value& json) noexcept {
                if (!json.isObject()) {
                    return NULLPTR;
                }

                std::shared_ptr<VirtualEthernetInformation> infomartion = make_shared_object<VirtualEthernetInformation>();
                if (NULLPTR == infomartion) {
                    return NULLPTR;
                }

                infomartion->ExpiredTime     = JsonAuxiliary::AsValue<long long>(json["ExpiredTime"]);
                infomartion->BandwidthQoS    = JsonAuxiliary::AsValue<long long>(json["BandwidthQoS"]);
                infomartion->IncomingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["IncomingTraffic"]);
                infomartion->OutgoingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["OutgoingTraffic"]);
                return infomartion;
            }

            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const ppp::string& json) noexcept {
                if (json.empty()) {
                    return NULLPTR;
                }

                Json::Value config = JsonAuxiliary::FromString(json);
                return FromJson(config);
            }

            void VirtualEthernetInformation::Clear() noexcept {
                this->ExpiredTime     = 0;
                this->BandwidthQoS    = 0;
                this->IncomingTraffic = 0;
                this->OutgoingTraffic = 0;
            }

            void VirtualEthernetInformationExtensions::Clear() noexcept {
                AssignedIPv6Mode = IPv6Mode_None;
                AssignedIPv6PrefixLength = 0;
                AssignedIPv6Flags = 0;
                AssignedIPv6Address = boost::asio::ip::address();
                AssignedIPv6Gateway = boost::asio::ip::address();
                AssignedIPv6Dns1 = boost::asio::ip::address();
                AssignedIPv6Dns2 = boost::asio::ip::address();
            }

            bool VirtualEthernetInformationExtensions::HasAny() const noexcept {
                return AssignedIPv6Mode != IPv6Mode_None ||
                    AssignedIPv6PrefixLength != 0 ||
                    AssignedIPv6Flags != 0 ||
                    AssignedIPv6Address.is_v6() ||
                    AssignedIPv6Gateway.is_v6() ||
                    AssignedIPv6Dns1.is_v6() ||
                    AssignedIPv6Dns2.is_v6();
            }

            bool VirtualEthernetInformationExtensions::Equals(const VirtualEthernetInformationExtensions& other) const noexcept {
                return AssignedIPv6Mode == other.AssignedIPv6Mode &&
                    AssignedIPv6PrefixLength == other.AssignedIPv6PrefixLength &&
                    AssignedIPv6Flags == other.AssignedIPv6Flags &&
                    AssignedIPv6Address == other.AssignedIPv6Address &&
                    AssignedIPv6Gateway == other.AssignedIPv6Gateway &&
                    AssignedIPv6Dns1 == other.AssignedIPv6Dns1 &&
                    AssignedIPv6Dns2 == other.AssignedIPv6Dns2;
            }

            void VirtualEthernetInformationExtensions::ToJson(Json::Value& json) const noexcept {
                json["AssignedIPv6Mode"] = AssignedIPv6Mode;
                json["AssignedIPv6PrefixLength"] = AssignedIPv6PrefixLength;
                json["AssignedIPv6Flags"] = AssignedIPv6Flags;

                if (AssignedIPv6Address.is_v6()) {
                    std::string value = AssignedIPv6Address.to_string();
                    json["AssignedIPv6Address"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Gateway.is_v6()) {
                    std::string value = AssignedIPv6Gateway.to_string();
                    json["AssignedIPv6Gateway"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Dns1.is_v6()) {
                    std::string value = AssignedIPv6Dns1.to_string();
                    json["AssignedIPv6Dns1"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Dns2.is_v6()) {
                    std::string value = AssignedIPv6Dns2.to_string();
                    json["AssignedIPv6Dns2"] = Json::Value(value.c_str());
                }
            }

            ppp::string VirtualEthernetInformationExtensions::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            bool VirtualEthernetInformationExtensions::FromJson(VirtualEthernetInformationExtensions& value, const ppp::string& json) noexcept {
                if (json.empty()) {
                    value.Clear();
                    return false;
                }

                return FromJson(value, JsonAuxiliary::FromString(json));
            }

            bool VirtualEthernetInformationExtensions::FromJson(VirtualEthernetInformationExtensions& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    return false;
                }

                value.AssignedIPv6Mode = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6Mode"], 0));
                value.AssignedIPv6PrefixLength = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6PrefixLength"], 0));
                value.AssignedIPv6Flags = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6Flags"], 0));

                boost::system::error_code ec;
                boost::asio::ip::address address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Address"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Address = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Gateway"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Gateway = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Dns1"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Dns1 = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6Dns2"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6Dns2 = address;
                }

                return value.HasAny();
            }
        }
    }
}
