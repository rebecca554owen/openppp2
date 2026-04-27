/**
 * @file VirtualEthernetInformation.cpp
 * @brief Implements serialization and parsing for virtual ethernet information models.
 * @license GPL-3.0
 */

#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/diagnostics/Error.h>

#include <cstring>

using ppp::auxiliary::JsonAuxiliary;

namespace ppp {
    namespace app {
        namespace protocol {
            VirtualEthernetInformation::VirtualEthernetInformation() noexcept {
                Clear();
            }

            /**
             * @brief Converts a virtual ethernet information object into JSON text.
             * @param information Source information object.
             * @param styled True for pretty-printed JSON; false for compact JSON.
             * @return Serialized JSON string.
             */
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

            /** @brief Serializes this object into formatted JSON text. */
            ppp::string VirtualEthernetInformation::ToString() noexcept {
                return STATIC_TO_STRRING(*this, true);
            }

            /** @brief Serializes this object into compact JSON text. */
            ppp::string VirtualEthernetInformation::ToJson() noexcept {
                return STATIC_TO_STRRING(*this, false);
            }

            /** @brief Writes this object fields into a JSON value. */
            void VirtualEthernetInformation::ToJson(Json::Value& json) noexcept {
                json["BandwidthQoS"]    = stl::to_string<ppp::string>(this->BandwidthQoS);
                json["ExpiredTime"]     = this->ExpiredTime;
                json["IncomingTraffic"] = stl::to_string<ppp::string>(this->IncomingTraffic);
                json["OutgoingTraffic"] = stl::to_string<ppp::string>(this->OutgoingTraffic);
            }

            /** @brief Builds an information object from a JSON value object. */
            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const Json::Value& json) noexcept {
                if (!json.isObject()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetInformationFromJsonInvalidObject);
                    return NULLPTR;
                }

                std::shared_ptr<VirtualEthernetInformation> infomartion = make_shared_object<VirtualEthernetInformation>();
                if (NULLPTR == infomartion) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionCreateFailed);
                    return NULLPTR;
                }

                infomartion->ExpiredTime     = JsonAuxiliary::AsValue<long long>(json["ExpiredTime"]);
                infomartion->BandwidthQoS    = JsonAuxiliary::AsValue<long long>(json["BandwidthQoS"]);
                infomartion->IncomingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["IncomingTraffic"]);
                infomartion->OutgoingTraffic = JsonAuxiliary::AsValue<unsigned long long>(json["OutgoingTraffic"]);
                return infomartion;
            }

            /** @brief Builds an information object from JSON text. */
            std::shared_ptr<VirtualEthernetInformation> VirtualEthernetInformation::FromJson(const ppp::string& json) noexcept {
                if (json.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetInformationFromJsonTextEmpty);
                    return NULLPTR;
                }

                Json::Value config = JsonAuxiliary::FromString(json);
                return FromJson(config);
            }

            /** @brief Resets all information fields to defaults. */
            void VirtualEthernetInformation::Clear() noexcept {
                this->ExpiredTime     = 0;
                this->BandwidthQoS    = 0;
                this->IncomingTraffic = 0;
                this->OutgoingTraffic = 0;
            }

            /** @brief Resets all IPv6 extension fields to defaults. */
            void VirtualEthernetInformationExtensions::Clear() noexcept {
                AssignedIPv6Mode = IPv6Mode_None;
                AssignedIPv6AddressPrefixLength = 0;
                AssignedIPv6Flags = 0;
                AssignedIPv6Address = boost::asio::ip::address();
                AssignedIPv6Gateway = boost::asio::ip::address();
                AssignedIPv6RoutePrefix = boost::asio::ip::address();
                AssignedIPv6RoutePrefixLength = 0;
                AssignedIPv6Dns1 = boost::asio::ip::address();
                AssignedIPv6Dns2 = boost::asio::ip::address();
                IPv6StatusCode = IPv6Status_None;
                RequestedIPv6Address = boost::asio::ip::address();
                IPv6StatusMessage.clear();
            }

            /** @brief Returns whether any IPv6 extension field is currently populated. */
            bool VirtualEthernetInformationExtensions::HasAny() const noexcept {
                return AssignedIPv6Mode != IPv6Mode_None ||
                    AssignedIPv6AddressPrefixLength != 0 ||
                    AssignedIPv6Flags != 0 ||
                    AssignedIPv6Address.is_v6() ||
                    AssignedIPv6Gateway.is_v6() ||
                    AssignedIPv6RoutePrefix.is_v6() ||
                    AssignedIPv6RoutePrefixLength != 0 ||
                    AssignedIPv6Dns1.is_v6() ||
                    AssignedIPv6Dns2.is_v6() ||
                    RequestedIPv6Address.is_v6() ||
                    IPv6StatusCode != IPv6Status_None ||
                    !IPv6StatusMessage.empty();
            }

            /** @brief Writes IPv6 extension fields to a JSON object. */
            void VirtualEthernetInformationExtensions::ToJson(Json::Value& json) const noexcept {
                json["AssignedIPv6Mode"] = AssignedIPv6Mode;
                json["AssignedIPv6AddressPrefixLength"] = AssignedIPv6AddressPrefixLength;
                json["AssignedIPv6Flags"] = AssignedIPv6Flags;
                json["AssignedIPv6RoutePrefixLength"] = AssignedIPv6RoutePrefixLength;
                json["IPv6StatusCode"] = IPv6StatusCode;

                if (AssignedIPv6Address.is_v6()) {
                    std::string value = AssignedIPv6Address.to_string();
                    json["AssignedIPv6Address"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Gateway.is_v6()) {
                    std::string value = AssignedIPv6Gateway.to_string();
                    json["AssignedIPv6Gateway"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6RoutePrefix.is_v6()) {
                    std::string value = AssignedIPv6RoutePrefix.to_string();
                    json["AssignedIPv6RoutePrefix"] = Json::Value(value.c_str());
                }

                if (RequestedIPv6Address.is_v6()) {
                    std::string value = RequestedIPv6Address.to_string();
                    json["RequestedIPv6Address"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Dns1.is_v6()) {
                    std::string value = AssignedIPv6Dns1.to_string();
                    json["AssignedIPv6Dns1"] = Json::Value(value.c_str());
                }

                if (AssignedIPv6Dns2.is_v6()) {
                    std::string value = AssignedIPv6Dns2.to_string();
                    json["AssignedIPv6Dns2"] = Json::Value(value.c_str());
                }

                if (!IPv6StatusMessage.empty()) {
                    json["IPv6StatusMessage"] = Json::Value(IPv6StatusMessage.c_str());
                }
            }

            /** @brief Serializes IPv6 extension fields into compact JSON text. */
            ppp::string VirtualEthernetInformationExtensions::ToJson() const noexcept {
                Json::Value json;
                ToJson(json);
                return JsonAuxiliary::ToString(json);
            }

            /** @brief Parses IPv6 extensions from JSON text into the target value. */
            bool VirtualEthernetInformationExtensions::FromJson(VirtualEthernetInformationExtensions& value, const ppp::string& json) noexcept {
                if (json.empty()) {
                    value.Clear();
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetInformationExtensionsFromJsonTextEmpty);
                    return false;
                }

                return FromJson(value, JsonAuxiliary::FromString(json));
            }

            /** @brief Parses IPv6 extensions from a JSON object into the target value. */
            bool VirtualEthernetInformationExtensions::FromJson(VirtualEthernetInformationExtensions& value, const Json::Value& json) noexcept {
                value.Clear();
                if (!json.isObject()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ProtocolDecodeFailed);
                    return false;
                }

                value.AssignedIPv6Mode = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6Mode"], 0));
                if (value.AssignedIPv6Mode != IPv6Mode_None &&
                    value.AssignedIPv6Mode != IPv6Mode_Nat66 &&
                    value.AssignedIPv6Mode != IPv6Mode_Gua) {
                    value.AssignedIPv6Mode = IPv6Mode_None;
                }
                value.AssignedIPv6AddressPrefixLength = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6AddressPrefixLength"], JsonAuxiliary::AsInt64(json["AssignedIPv6PrefixLength"], 0)));
                value.AssignedIPv6Flags = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6Flags"], 0));
                value.AssignedIPv6RoutePrefixLength = static_cast<Byte>(JsonAuxiliary::AsInt64(json["AssignedIPv6RoutePrefixLength"], 0));
                value.IPv6StatusCode = static_cast<Byte>(JsonAuxiliary::AsInt64(json["IPv6StatusCode"], 0));

                /**
                 * @brief Parse IPv6 address fields with strict validation.
                 *
                 * Each candidate string is converted into a boost address and accepted
                 * only when conversion succeeds and the address family is IPv6.
                 */
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
                address = StringToAddress(JsonAuxiliary::AsString(json["AssignedIPv6RoutePrefix"]), ec);
                if (!ec && address.is_v6()) {
                    value.AssignedIPv6RoutePrefix = address;
                }

                ec.clear();
                address = StringToAddress(JsonAuxiliary::AsString(json["RequestedIPv6Address"]), ec);
                if (!ec && address.is_v6()) {
                    value.RequestedIPv6Address = address;
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

                value.IPv6StatusMessage = JsonAuxiliary::AsString(json["IPv6StatusMessage"]);

                return value.HasAny();
            }
        }
    }
}
