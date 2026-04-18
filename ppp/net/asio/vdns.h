#pragma once

/**
 * @file vdns.h
 * @brief Virtual DNS asynchronous resolver and cache interfaces.
 */

#include <ppp/stdafx.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

#include <common/dnslib/message.h>

namespace ppp {
    namespace net {
        namespace asio {
            namespace vdns {

                /** @brief Vector of DNS server UDP endpoints. */
                typedef ppp::vector<boost::asio::ip::udp::endpoint>                             IPEndPointVector;
                /** @brief Shared pointer to DNS server endpoint vector. */
                typedef std::shared_ptr<IPEndPointVector>                                       IPEndPointVectorPtr;

                /** @brief Global DNS server list used by resolver operations. */
                extern IPEndPointVectorPtr                                                      servers;
                /** @brief Cache TTL in seconds. */
                extern int                                                                      ttl;
                /** @brief Global switch for virtual DNS feature enablement. */
                extern bool                                                                     enabled;

                /** @brief DNS address record family selector. */
                enum AddressFamily {
                    /** @brief Undefined family. */
                    kNone = 0,
                    /** @brief IPv4 A record. */
                    kA = 1,
                    /** @brief IPv6 AAAA record. */
                    kAAAA = 2
                };

                /**
                 * @brief Queries cached DNS result and returns a single address.
                 * @param hostname Domain name to resolve.
                 * @param address Output address (IPv4 preferred).
                 * @return True when cache contains a valid address.
                 */
                bool                                                                            QueryCache(const char* hostname, boost::asio::ip::address& address) noexcept;

                /**
                 * @brief Builds DNS response answers from cache for a given family.
                 * @param hostname Domain name to resolve.
                 * @param messsage DNS message to receive answer records.
                 * @param af Requested address family.
                 * @return Normalized hostname on success, empty string otherwise.
                 */
                ppp::string                                                                     QueryCache2(const char* hostname, ::dns::Message& messsage, AddressFamily af) noexcept;

                /**
                 * @brief Inserts DNS response packet data into the cache.
                 * @param packet Raw DNS response packet bytes.
                 * @param packet_size Packet length in bytes.
                 * @return True when packet is parsed and cache is updated.
                 */
                bool                                                                            AddCache(const Byte* packet, int packet_size) noexcept;

                /**
                 * @brief Checks whether a hostname represents reverse DNS lookup domain.
                 * @param hostname Domain name to test.
                 * @return True when hostname ends with .in-addr.arpa or .ip6.arpa.
                 */
                bool                                                                            IsReverseQuery(const char* hostname) noexcept;

                /**
                 * @brief Resolves hostname asynchronously and returns one address.
                 * @param context IO context used for async operations.
                 * @param hostname Domain name or literal address.
                 * @param timeout Query timeout in milliseconds.
                 * @param destinations DNS server endpoints.
                 * @param cb Completion callback receiving one address.
                 * @return True when request is accepted.
                 */
                bool                                                                            ResolveAsync(
                    boost::asio::io_context& context,
                    const char* hostname,
                    int                                                                         timeout,
                    const ppp::vector<boost::asio::ip::udp::endpoint>& destinations,
                    const ppp::function<void(const boost::asio::ip::address&)>& cb) noexcept;

                /**
                 * @brief Resolves hostname asynchronously and returns all addresses.
                 * @param context IO context used for async operations.
                 * @param hostname Domain name or literal address.
                 * @param timeout Query timeout in milliseconds.
                 * @param destinations DNS server endpoints.
                 * @param cb Completion callback receiving all resolved addresses.
                 * @return True when request is accepted.
                 */
                bool                                                                            ResolveAsync2(
                    boost::asio::io_context& context,
                    const char* hostname,
                    int                                                                         timeout,
                    const ppp::vector<boost::asio::ip::udp::endpoint>& destinations,
                    const ppp::function<void(const ppp::unordered_set<boost::asio::ip::address>&)>& cb) noexcept;

                /** @brief Removes expired entries from the DNS cache. */
                void                                                                            UpdateAsync() noexcept;

            } // namespace vdns
        } // namespace asio
    } // namespace net
} // namespace ppp
