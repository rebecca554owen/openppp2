#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/native/rib.h>

/**
 * @file Firewall.h
 * @brief Declares a thread-safe firewall rule container for ports, domains, and IP segments.
 *
 * @ref ppp::net::Firewall evaluates drop decisions for inbound or outbound traffic
 * based on three independent rule categories:
 *
 *  1. **Port rules** — block a specific port for all protocols, TCP only, or UDP only.
 *  2. **Domain rules** — block a domain by exact match or suffix match
 *     (e.g. "evil.com" blocks "sub.evil.com" as well).
 *  3. **Network segment rules** — block IP ranges expressed as CIDR blocks.
 *     Both IPv4 and IPv6 ranges are supported via @ref ppp::Int128 keys.
 *
 * Rule evaluation order (checked in sequence by @ref IsDropNetworkDomains):
 *   1. Exact domain match in @ref network_domains_.
 *   2. Suffix match (.parent.com form) in @ref network_domains_.
 *   3. IP parse of @p host → segment lookup via @ref IsDropNetworkSegment.
 *
 * All public mutating methods acquire the internal mutex; all query methods also
 * lock before reading, making the class safe to use from multiple threads.
 *
 * Rules are loaded from text configuration using @ref LoadWithRules or
 * @ref LoadWithFile.  Lines beginning with '#' are treated as comments.
 * Supported rule syntax examples:
 * @code
 *   port:80               # block TCP+UDP port 80
 *   tcp:443               # block TCP port 443
 *   udp:53                # block UDP port 53
 *   192.168.1.0/24        # block CIDR segment
 *   evil.com              # block domain (exact + suffix)
 * @endcode
 */

namespace ppp 
{
    namespace net 
    {
        /**
         * @brief Stores and evaluates drop rules for network ports, domains, and CIDR segments.
         *
         * Instantiate with the default constructor, populate rules via Load* or Drop*
         * methods, then call Is* query methods from any thread to evaluate traffic.
         *
         * @note  All virtual methods may be overridden by derived classes to add logging,
         *        telemetry, or alternative matching strategies.
         */
        class Firewall  
        {
        public:
            /** @brief Mutex type used to protect all internal rule tables. */
            typedef std::mutex                                      SynchronizedObject;
            /** @brief RAII lock guard type for @ref SynchronizedObject. */
            typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
            /**
             * @brief Mapping of normalized network base address to prefix length.
             *
             * Key: 128-bit integer encoding of the masked network base address
             *      (IPv4 addresses are placed in the lower 32 bits; IPv6 occupies all 128).
             * Value: CIDR prefix length for the associated block.
             */
            typedef ppp::unordered_map<Int128, int>                 NetworkSegmentTable;
            /**
             * @brief Set of blocked domain name strings.
             *
             * Entries are stored in their normalized (lowercased, dot-prefixed suffix)
             * form so that both exact and suffix matching can be performed with a single
             * hash lookup pattern.
             */
            typedef ppp::unordered_set<ppp::string>                 NetworkDomainsTable;

        public:
            /** @brief Creates an empty firewall with no rules loaded. */
            Firewall() noexcept = default;
            /** @brief Destroys the firewall; all rule containers are freed. */
            virtual ~Firewall() noexcept = default;

        public:
            /**
             * @brief Adds a drop rule that blocks a port for all protocols (TCP and UDP).
             * @param port  Port number to block [1, 65535].
             * @return      true if the port was not already present and is now inserted;
             *              false if the rule already existed.
             * @note        Blocked in @ref ports_ (protocol-agnostic set).
             */
            virtual bool                                            DropNetworkPort(int port) noexcept;

            /**
             * @brief Adds a drop rule that blocks a port for a specific protocol.
             * @param port        Port number to block [1, 65535].
             * @param tcp_or_udp  true to block TCP; false to block UDP.
             * @return            true if the rule is newly inserted; false if already present.
             * @note              Blocked in @ref ports_tcp_ or @ref ports_udp_ respectively.
             */
            virtual bool                                            DropNetworkPort(int port, bool tcp_or_udp) noexcept;

            /**
             * @brief Adds a drop rule for a network segment.
             *
             * The host bits of @p ip are masked to the network base address before
             * storing; overlapping entries may be merged if the new prefix is stricter.
             *
             * @param ip      IPv4 or IPv6 address; host bits are cleared using @p prefix.
             * @param prefix  CIDR prefix length [0, 32] for IPv4 or [0, 128] for IPv6.
             * @return        true if a new or updated rule was stored; false otherwise.
             */
            virtual bool                                            DropNetworkSegment(const boost::asio::ip::address& ip, int prefix) noexcept;

            /**
             * @brief Adds a drop rule for a domain name.
             *
             * Both the exact domain and the ".domain" suffix form are inserted so that
             * @ref IsSameNetworkDomains can detect subdomain matches efficiently.
             *
             * @param host  Domain string to block (e.g. "evil.com").
             * @return      true if the rule was newly inserted; false if already present.
             */
            virtual bool                                            DropNetworkDomains(const ppp::string& host) noexcept;

            /**
             * @brief Removes all configured firewall rules.
             *
             * Acquires the lock and clears @ref ports_, @ref ports_tcp_, @ref ports_udp_,
             * @ref network_domains_, and @ref network_segments_.
             */
            virtual void                                            Clear() noexcept;

            /**
             * @brief Loads firewall rules from a text file.
             * @param path  Filesystem path to the rule file.
             * @return      true if the file was read and at least one rule was loaded.
             * @note        Delegates to @ref LoadWithRules after reading file content.
             */
            bool                                                    LoadWithFile(const ppp::string& path) noexcept;

            /**
             * @brief Loads firewall rules from raw configuration text.
             *
             * Parses each non-empty, non-comment line and calls the appropriate
             * Drop* method.  Unrecognized lines are silently skipped.
             *
             * @param configuration  Multi-line rule text (see file-level documentation for syntax).
             * @return               true if at least one valid rule was parsed and added.
             */
            virtual bool                                            LoadWithRules(const ppp::string& configuration) noexcept;

        public:
            /**
             * @brief Checks whether a port is blocked globally or by protocol.
             *
             * Evaluation order:
             *   1. Check @ref ports_ (protocol-agnostic).
             *   2. Check @ref ports_tcp_ or @ref ports_udp_ depending on @p tcp_or_udp.
             *
             * @param port        Port number to test.
             * @param tcp_or_udp  true to also test TCP-specific rules; false for UDP-specific.
             * @return            true if any matching drop rule exists; false otherwise.
             */
            virtual bool                                            IsDropNetworkPort(int port, bool tcp_or_udp) noexcept;

            /**
             * @brief Checks whether a host is blocked by domain or IP segment rules.
             *
             * Evaluation order:
             *   1. @ref IsSameNetworkDomains for exact and suffix domain matching.
             *   2. If @p host is parseable as an IP literal, calls @ref IsDropNetworkSegment.
             *
             * @param host  Domain name or IP address string.
             * @return      true if any matching drop rule exists; false otherwise.
             */
            virtual bool                                            IsDropNetworkDomains(const ppp::string& host) noexcept;

            /**
             * @brief Checks whether an IP address matches any blocked segment.
             *
             * Iterates @ref network_segments_ and applies the CIDR mask to determine
             * whether @p ip falls within any blocked range.
             *
             * @param ip  IPv4 or IPv6 address to test.
             * @return    true if any segment rule covers @p ip; false otherwise.
             */
            virtual bool                                            IsDropNetworkSegment(const boost::asio::ip::address& ip) noexcept;

        public:
            /**
             * @brief Evaluates exact and suffix domain matches through a callback.
             *
             * Generates up to two lookup keys for @p host:
             *   1. Exact match: @p host itself.
             *   2. Suffix match: "." + parent domain components (e.g. ".evil.com").
             *
             * @p contains is called for each candidate key; if it returns true the
             * method returns true immediately.
             *
             * @param host      Domain name to evaluate (e.g. "sub.evil.com").
             * @param contains  Callback receiving each candidate domain string; returns
             *                  true when the candidate is present in the rule table.
             * @return          true if any candidate matches; false otherwise.
             * @note            This static helper is exposed for unit-testing and for
             *                  derived classes that implement custom rule stores.
             */
            static bool                                             IsSameNetworkDomains(const ppp::string& host, const ppp::function<bool(const ppp::string& s)>& contains) noexcept;

        private:
            /** @brief Synchronizes concurrent access to all mutable rule containers. */
            SynchronizedObject                                      syncobj_;
            /** @brief Set of port numbers blocked regardless of protocol. */
            ppp::unordered_set<int>                                 ports_;
            /** @brief Set of port numbers blocked for TCP traffic only. */
            ppp::unordered_set<int>                                 ports_tcp_;
            /** @brief Set of port numbers blocked for UDP traffic only. */
            ppp::unordered_set<int>                                 ports_udp_;
            /** @brief Normalized domain strings for exact and suffix block matching. */
            NetworkDomainsTable                                     network_domains_;
            /** @brief CIDR network block rules keyed by masked base address. */
            NetworkSegmentTable                                     network_segments_;
        };
    }
}
