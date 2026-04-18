#pragma once

#include <ppp/stdafx.h>
#include <ppp/net/IPEndPoint.h>

/// @file rib.h
/// @brief Route Information Base (RIB) and Forwarding Information Base (FIB) APIs.

namespace ppp
{
    namespace net
    {
        namespace native
        {
            /// @brief Single route entry with destination prefix and next-hop gateway.
            typedef struct
            {
                /// @brief Destination network address (IPv4).
                uint32_t                                                Destination;
                /// @brief Prefix length for the destination route.
                int                                                     Prefix;
                /// @brief Next-hop gateway address (IPv4).
                uint32_t                                                NextHop;
            }                                                           RouteEntry;

            /// @brief Route entry container for one destination key.
            typedef ppp::vector<RouteEntry>                             RouteEntries;
            /// @brief Routing table keyed by destination network address.
            typedef ppp::unordered_map<uint32_t, RouteEntries>          RouteEntriesTable;

            /// @brief Minimum accepted prefix length.
            static constexpr int                                        MIN_PREFIX_VALUE    = 0;
            /// @brief Maximum accepted IPv4 prefix length.
            static constexpr int                                        MAX_PREFIX_VALUE    = 32;
            /// @brief Alias of maximum IPv4 prefix length.
            static constexpr int                                        MAX_PREFIX_VALUE_V4 = MAX_PREFIX_VALUE;
            /// @brief Maximum accepted IPv6 prefix length.
            static constexpr int                                        MAX_PREFIX_VALUE_V6 = 128;

            /// @brief Route Information Base storing configured routes.
            class RouteInformationTable
            {
            public:
                /// @brief Adds or updates a route entry.
                /// @param ip Destination network address.
                /// @param prefix Prefix length.
                /// @param gw Next-hop gateway address.
                /// @return true if route is inserted or updated; otherwise false.
                bool                                                    AddRoute(uint32_t ip, int prefix, uint32_t gw) noexcept;
                /// @brief Parses CIDR and adds a route entry.
                /// @param cidr CIDR text such as "192.168.1.0/24".
                /// @param gw Next-hop gateway address.
                /// @return true on success; otherwise false.
                bool                                                    AddRoute(const ppp::string& cidr, uint32_t gw) noexcept;
                /// @brief Parses multiple CIDRs and adds routes.
                /// @param cidrs Delimited CIDR list.
                /// @param gw Next-hop gateway address.
                /// @return true if all valid routes are processed successfully.
                bool                                                    AddAllRoutes(const ppp::string& cidrs, uint32_t gw) noexcept;
                /// @brief Loads CIDR entries from file and adds routes.
                /// @param path File path containing IP list or CIDR lines.
                /// @param gw Next-hop gateway address.
                /// @return true on success; otherwise false.
                bool                                                    AddAllRoutesByIPList(const ppp::string& path, uint32_t gw) noexcept;
                /// @brief Checks whether the table contains at least one route.
                /// @return true if non-empty; otherwise false.
                bool                                                    IsAvailable() noexcept { return routes.begin() != routes.end(); }

            public:
                /// @brief Deletes all routes for a destination key.
                /// @param ip Destination address key.
                /// @return true if any route is removed; otherwise false.
                bool                                                    DeleteRoute(uint32_t ip) noexcept;
                /// @brief Deletes routes matching destination and gateway.
                /// @param ip Destination address key.
                /// @param gw Next-hop gateway filter.
                /// @return true if any route is removed; otherwise false.
                bool                                                    DeleteRoute(uint32_t ip, uint32_t gw) noexcept;
                /// @brief Deletes a specific destination/prefix/gateway route.
                /// @param ip Destination network address.
                /// @param prefix Prefix length.
                /// @param gw Next-hop gateway address.
                /// @return true if matching route is removed; otherwise false.
                bool                                                    DeleteRoute(uint32_t ip, int prefix, uint32_t gw) noexcept;

            public:
                /// @brief Gets mutable access to all stored routes.
                /// @return Internal route table.
                RouteEntriesTable&                                      GetAllRoutes() noexcept;
                /// @brief Clears all route entries.
                void                                                    Clear() noexcept;

            private:
                /// @brief Backing container for route entries.
                RouteEntriesTable                                       routes;
            };

            /// @brief Forwarding Information Base for next-hop lookup.
            class ForwardInformationTable
            {
            public:
                /// @brief Constructs an empty forwarding table.
                ForwardInformationTable() noexcept = default;
                /// @brief Constructs forwarding table from a route table snapshot.
                /// @param rib Source route information table.
                ForwardInformationTable(RouteInformationTable& rib) noexcept;

            public:
                /// @brief Resolves next hop for a destination address.
                /// @param ip Destination address.
                /// @return Next-hop address, or zero if not found.
                uint32_t                                                GetNextHop(uint32_t ip) noexcept;
                /// @brief Resolves next hop using longest-prefix match on full range.
                /// @param ip Destination address.
                /// @param routes Route table to query.
                /// @return Next-hop address, or zero if not found.
                static uint32_t                                         GetNextHop(uint32_t ip, RouteEntriesTable& routes) noexcept;
                /// @brief Resolves next hop using prefix-range constrained lookup.
                /// @param ip Destination address.
                /// @param min_prefix_value Minimum prefix length to consider.
                /// @param max_prefix_value Maximum prefix length to consider.
                /// @param routes Route table to query.
                /// @return Next-hop address, or zero if not found.
                static uint32_t                                         GetNextHop(uint32_t ip, int min_prefix_value, int max_prefix_value, RouteEntriesTable& routes) noexcept;
                /// @brief Rebuilds forwarding entries from a route table.
                /// @param rib Source route information table.
                void                                                    Fill(RouteInformationTable& rib) noexcept;
                /// @brief Clears all forwarding entries.
                void                                                    Clear() noexcept;
                /// @brief Gets mutable access to all forwarding routes.
                /// @return Internal forwarding table.
                RouteEntriesTable&                                      GetAllRoutes() noexcept;
                /// @brief Checks whether the forwarding table contains routes.
                /// @return true if non-empty; otherwise false.
                bool                                                    IsAvailable() noexcept { return routes.begin() != routes.end(); }

            private:
                /// @brief Backing container for forwarding entries.
                RouteEntriesTable                                       routes;
            };
        }
    }
}
