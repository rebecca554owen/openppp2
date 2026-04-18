/**
 * @file VirtualEthernetInformation.h
 * @brief Declares quota and IPv6 extension data models for virtual ethernet sessions.
 * @license GPL-3.0
 */

#pragma once

#include <ppp/stdafx.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace app {
        namespace protocol {
#pragma pack(push, 1)
            /**
             * @brief Contains traffic quota and expiration metadata for a virtual ethernet session.
             */
            struct  
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            VirtualEthernetInformation 
            {
            public:
                /** @brief Maximum QoS throughput in Kbps units; 0 means unlimited. */
                Int64  BandwidthQoS    = 0; // Maximum Quality of Service (QoS) bandwidth throughput speed per second, 0 for unlimited, 1 for 1 Kbps.
                /** @brief Remaining inbound traffic allowance; 0 means unlimited. */
                UInt64 IncomingTraffic = 0; // The remaining network traffic allowance that can be allowed for incoming clients, 0 is unlimited.
                /** @brief Remaining outbound traffic allowance; 0 means unlimited. */
                UInt64 OutgoingTraffic = 0; // The remaining network traffic allowance that can be allowed for outgoing clients, 0 is unlimited.
                /** @brief Expiration timestamp in seconds since epoch; 0 means no expiry. */
                UInt32 ExpiredTime     = 0; // The time duration during which clients are expired time from using PPP (Point-to-Point Protocol) VPN services, 0 for no restrictions, measured in seconds.

            public:
                /** @brief Constructs an information object with cleared defaults. */
                VirtualEthernetInformation() noexcept;

            public:
                /** @brief Resets all quota and expiration fields. */
                void                                                Clear() noexcept;
                /** @brief Serializes this object into a JSON value container. */
                void                                                ToJson(Json::Value& json) noexcept;
                /** @brief Serializes this object into compact JSON text. */
                ppp::string                                         ToJson() noexcept;
                /** @brief Serializes this object into formatted JSON text. */
                ppp::string                                         ToString() noexcept;
                /** @brief Checks validity against current time. */
                bool                                                Valid() noexcept                                          { return Valid((UInt32)(GetTickCount() / 1000)); }
                /** @brief Checks validity against a provided timestamp. */
                bool                                                Valid(UInt32 now) noexcept                                { return Valid(this, now); }
                /** @brief Validates quotas and expiration values for a data instance. */
                static bool                                         Valid(VirtualEthernetInformation* i, UInt32 now) noexcept { return (i->IncomingTraffic > 0 && i->OutgoingTraffic > 0) && (i->ExpiredTime != 0 && i->ExpiredTime > now); }

            public:
                /** @brief Deserializes an information object from JSON text. */
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const ppp::string& json) noexcept;
                /** @brief Deserializes an information object from a JSON value. */
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const Json::Value& json) noexcept;
            };
#pragma pack(pop)

            /**
             * @brief Holds optional IPv6 assignment and status extensions for a session.
             */
            struct VirtualEthernetInformationExtensions {
                /** @brief IPv6 allocation mode indicators. */
                enum IPv6Mode {
                    IPv6Mode_None                                      = 0,
                    IPv6Mode_Nat66                                     = 1,
                    IPv6Mode_Gua                                       = 2,
                };

                /** @brief Bit flags for IPv6 behavior controls. */
                enum IPv6Flags {
                    IPv6Flag_None                                      = 0,
                    IPv6Flag_NeighborProxy                             = 1 << 0,
                };

                /** @brief Selected IPv6 mode for this session. */
                Byte                                                AssignedIPv6Mode = IPv6Mode_None;
                /** @brief Prefix length for assigned IPv6 address. */
                Byte                                                AssignedIPv6AddressPrefixLength = 0;
                /** @brief IPv6 feature flags for this assignment. */
                Byte                                                AssignedIPv6Flags = 0;
                /** @brief Assigned client IPv6 address. */
                boost::asio::ip::address                            AssignedIPv6Address;
                /** @brief Assigned IPv6 gateway address. */
                boost::asio::ip::address                            AssignedIPv6Gateway;
                /** @brief Assigned routed IPv6 prefix address. */
                boost::asio::ip::address                            AssignedIPv6RoutePrefix;
                /** @brief Prefix length of routed IPv6 prefix. */
                Byte                                                AssignedIPv6RoutePrefixLength = 0;
                /** @brief Primary assigned IPv6 DNS server. */
                boost::asio::ip::address                            AssignedIPv6Dns1;
                /** @brief Secondary assigned IPv6 DNS server. */
                boost::asio::ip::address                            AssignedIPv6Dns2;
                /** @brief IPv6 provisioning status code. */
                Byte                                                IPv6StatusCode = 0;
                /** @brief IPv6 address requested by the client. */
                boost::asio::ip::address                            RequestedIPv6Address;
                /** @brief Human-readable IPv6 status message. */
                ppp::string                                         IPv6StatusMessage;

                /** @brief Detailed IPv6 provisioning outcomes. */
                enum IPv6Status {
                    IPv6Status_None                                 = 0,
                    IPv6Status_Applied                              = 1,
                    IPv6Status_ServerAssigned                       = 2,
                    IPv6Status_ClientRequested                      = 3,
                    IPv6Status_UnsupportedClient                    = 4,
                    IPv6Status_Rejected                             = 5,
                    IPv6Status_Failed                               = 6,
                };

                /** @brief Resets all extension fields to defaults. */
                void                                                Clear() noexcept;
                /** @brief Returns true when any extension field is populated. */
                bool                                                HasAny() const noexcept;
                /** @brief Serializes extensions into a JSON value object. */
                void                                                ToJson(Json::Value& json) const noexcept;
                /** @brief Serializes extensions into compact JSON text. */
                ppp::string                                         ToJson() const noexcept;
                /** @brief Deserializes extensions from JSON text. */
                static bool                                         FromJson(VirtualEthernetInformationExtensions& value, const ppp::string& json) noexcept;
                /** @brief Deserializes extensions from a JSON value object. */
                static bool                                         FromJson(VirtualEthernetInformationExtensions& value, const Json::Value& json) noexcept;
            };
        }
    }
}
