#pragma once

#include <ppp/stdafx.h>
#include <ppp/auxiliary/JsonAuxiliary.h>
#include <ppp/net/IPEndPoint.h>

namespace ppp {
    namespace app {
        namespace protocol {
#pragma pack(push, 1)
            struct  
#if defined(__GNUC__) || defined(__clang__)
                __attribute__((packed)) 
#endif
            VirtualEthernetInformation 
            {
            public:
                Int64  BandwidthQoS    = 0; // Maximum Quality of Service (QoS) bandwidth throughput speed per second, 0 for unlimited, 1 for 1 Kbps.
                UInt64 IncomingTraffic = 0; // The remaining network traffic allowance that can be allowed for incoming clients, 0 is unlimited.
                UInt64 OutgoingTraffic = 0; // The remaining network traffic allowance that can be allowed for outgoing clients, 0 is unlimited.
                UInt32 ExpiredTime     = 0; // The time duration during which clients are expired time from using PPP (Point-to-Point Protocol) VPN services, 0 for no restrictions, measured in seconds.

            public:
                VirtualEthernetInformation() noexcept;

            public:
                void                                                Clear() noexcept;
                void                                                ToJson(Json::Value& json) noexcept;
                ppp::string                                         ToJson() noexcept;
                ppp::string                                         ToString() noexcept;
                bool                                                Valid() noexcept                                          { return Valid((UInt32)(GetTickCount() / 1000)); }
                bool                                                Valid(UInt32 now) noexcept                                { return Valid(this, now); }
                static bool                                         Valid(VirtualEthernetInformation* i, UInt32 now) noexcept { return (i->IncomingTraffic > 0 && i->OutgoingTraffic > 0) && (i->ExpiredTime != 0 && i->ExpiredTime > now); }

            public:
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const ppp::string& json) noexcept;
                static std::shared_ptr<VirtualEthernetInformation>  FromJson(const Json::Value& json) noexcept;
            };
#pragma pack(pop)

            struct VirtualEthernetInformationExtensions {
                enum IPv6Mode {
                    IPv6Mode_None                                      = 0,
                    IPv6Mode_Prefix                                    = 1,
                    IPv6Mode_Nat                                       = 2,
                };

                enum IPv6Flags {
                    IPv6Flag_None                                      = 0,
                    IPv6Flag_RoutedPrefix                              = 1 << 0,
                    IPv6Flag_NeighborProxy                             = 1 << 1,
                };

                Byte                                                AssignedIPv6Mode = IPv6Mode_None;
                Byte                                                AssignedIPv6PrefixLength = 0;
                Byte                                                AssignedIPv6Flags = 0;
                boost::asio::ip::address                            AssignedIPv6Address;
                boost::asio::ip::address                            AssignedIPv6Gateway;
                boost::asio::ip::address                            AssignedIPv6Dns1;
                boost::asio::ip::address                            AssignedIPv6Dns2;

                void                                                Clear() noexcept;
                bool                                                HasAny() const noexcept;
                void                                                ToJson(Json::Value& json) const noexcept;
                ppp::string                                         ToJson() const noexcept;
                static bool                                         FromJson(VirtualEthernetInformationExtensions& value, const ppp::string& json) noexcept;
                static bool                                         FromJson(VirtualEthernetInformationExtensions& value, const Json::Value& json) noexcept;
            };
        }
    }
}
