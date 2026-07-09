/**
 * @file PeerPrefixRoute.h
 * @brief Shared peer prefix route entry helpers for site-to-site gateway routing.
 * @license GPL-3.0
 */

#pragma once

#include <ppp/stdafx.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/native/rib.h>

namespace ppp {
    namespace app {
        namespace protocol {

            using auxiliary::JsonAuxiliary;

            /**
             * @brief One IPv4 prefix route entry (network/prefix, optional via gateway peer).
             */
            struct PeerPrefixRouteEntry final {
                ppp::string network; ///< Network address, e.g. "10.0.0.0".
                int         prefix = 0; ///< Prefix length, e.g. 24.
                ppp::string via;     ///< Gateway peer virtual IPv4, e.g. "10.1.0.2"; empty for announce-only.

                void Clear() noexcept {
                    network.clear();
                    prefix = 0;
                    via.clear();
                }

                bool HasAny() const noexcept {
                    return !network.empty() && prefix > 0;
                }

                bool HasVia() const noexcept {
                    return !via.empty();
                }

                void ToJson(Json::Value& json) const noexcept {
                    if (!network.empty()) {
                        json["network"] = Json::Value(network.c_str());
                    }
                    if (prefix > 0) {
                        json["prefix"] = prefix;
                    }
                    if (!via.empty()) {
                        json["via"] = Json::Value(via.c_str());
                    }
                }

                static bool FromJson(PeerPrefixRouteEntry& value, const Json::Value& json) noexcept {
                    value.Clear();
                    if (!json.isObject()) {
                        return false;
                    }

                    value.network = JsonAuxiliary::AsString(json["network"]);
                    value.prefix = static_cast<int>(JsonAuxiliary::AsInt64(json["prefix"], 0));
                    value.via = JsonAuxiliary::AsString(json["via"]);
                    return value.HasAny();
                }

                uint32_t NetworkHost() const noexcept {
                    if (network.empty()) {
                        return 0;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(network, ec);
                    if (ec || !address.is_v4()) {
                        return 0;
                    }

                    uint32_t raw = htonl(address.to_v4().to_uint());
                    uint32_t mask = net::IPEndPoint::PrefixToNetmask(prefix);
                    return raw & mask;
                }

                uint32_t ViaHost() const noexcept {
                    if (via.empty()) {
                        return 0;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address address = StringToAddress(via, ec);
                    if (ec || !address.is_v4()) {
                        return 0;
                    }
                    return htonl(address.to_v4().to_uint());
                }

                bool MatchesDestination(uint32_t destination) const noexcept {
                    if (!HasAny()) {
                        return false;
                    }

                    uint32_t network = NetworkHost();
                    if (network == 0 || prefix <= 0 || prefix > net::native::MAX_PREFIX_VALUE_V4) {
                        return false;
                    }

                    uint32_t mask = net::IPEndPoint::PrefixToNetmask(prefix);
                    return (destination & mask) == (network & mask);
                }
            };

            /**
             * @brief Client-to-server prefix announcement (gateway registration).
             */
            struct PeerRouteAnnounceMessage final {
                bool enabled = false;
                ppp::string action; ///< "register".
                ppp::vector<PeerPrefixRouteEntry> prefixes;

                void Clear() noexcept {
                    enabled = false;
                    action.clear();
                    prefixes.clear();
                }

                bool HasAny() const noexcept {
                    return enabled || !action.empty() || !prefixes.empty();
                }

                void ToJson(Json::Value& json) const noexcept {
                    json["enabled"] = enabled;
                    if (!action.empty()) {
                        json["action"] = Json::Value(action.c_str());
                    }
                    if (!prefixes.empty()) {
                        Json::Value items(Json::arrayValue);
                        for (const auto& prefix : prefixes) {
                            Json::Value item;
                            prefix.ToJson(item);
                            items.append(item);
                        }
                        json["prefixes"] = items;
                    }
                }

                static bool FromJson(PeerRouteAnnounceMessage& value, const Json::Value& json) noexcept {
                    value.Clear();
                    if (!json.isObject()) {
                        return false;
                    }

                    value.enabled = JsonAuxiliary::AsValue<bool>(json["enabled"]);
                    value.action = JsonAuxiliary::AsString(json["action"]);
                    if (json.isMember("prefixes") && json["prefixes"].isArray()) {
                        for (const auto& item : json["prefixes"]) {
                            PeerPrefixRouteEntry entry;
                            if (PeerPrefixRouteEntry::FromJson(entry, item) && entry.HasAny()) {
                                value.prefixes.emplace_back(std::move(entry));
                            }
                        }
                    }
                    return value.HasAny();
                }
            };

            /**
             * @brief Server-to-client prefix routing snapshot.
             */
            struct PeerRouteTableMessage final {
                bool enabled = false;
                ppp::string action; ///< "snapshot".
                ppp::vector<PeerPrefixRouteEntry> routes;

                void Clear() noexcept {
                    enabled = false;
                    action.clear();
                    routes.clear();
                }

                bool HasAny() const noexcept {
                    return enabled || !action.empty() || !routes.empty();
                }

                void ToJson(Json::Value& json) const noexcept {
                    json["enabled"] = enabled;
                    if (!action.empty()) {
                        json["action"] = Json::Value(action.c_str());
                    }
                    if (!routes.empty()) {
                        Json::Value items(Json::arrayValue);
                        for (const auto& route : routes) {
                            Json::Value item;
                            route.ToJson(item);
                            items.append(item);
                        }
                        json["routes"] = items;
                    }
                }

                static bool FromJson(PeerRouteTableMessage& value, const Json::Value& json) noexcept {
                    value.Clear();
                    if (!json.isObject()) {
                        return false;
                    }

                    value.enabled = JsonAuxiliary::AsValue<bool>(json["enabled"]);
                    value.action = JsonAuxiliary::AsString(json["action"]);
                    if (json.isMember("routes") && json["routes"].isArray()) {
                        for (const auto& item : json["routes"]) {
                            PeerPrefixRouteEntry entry;
                            if (PeerPrefixRouteEntry::FromJson(entry, item) && entry.HasAny()) {
                                value.routes.emplace_back(std::move(entry));
                            }
                        }
                    }
                    return value.HasAny();
                }
            };

        }
    }
}
