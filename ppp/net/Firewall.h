#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/net/native/rib.h>

/**
 * @file Firewall.h
 * @brief Declares a thread-safe firewall rule container for ports, domains, and IP segments.
 */

namespace ppp 
{
    namespace net 
    {
        /**
         * @brief Stores and evaluates drop rules for network ports, domains, and CIDR segments.
         */
        class Firewall  
        {
        public:
            /** @brief Mutex type used to protect internal rule tables. */
            typedef std::mutex                                      SynchronizedObject;
            /** @brief RAII lock guard type for @ref SynchronizedObject. */
            typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
            /** @brief Mapping of normalized network base address to prefix length. */
            typedef ppp::unordered_map<Int128, int>                 NetworkSegmentTable;
            /** @brief Domain names blocked by exact or suffix match evaluation. */
            typedef ppp::unordered_set<ppp::string>                 NetworkDomainsTable;

        public:
            /** @brief Creates an empty firewall. */
            Firewall() noexcept = default;
            /** @brief Destroys the firewall instance. */
            virtual ~Firewall() noexcept = default;

        public:
            /**
             * @brief Adds a drop rule that blocks a port for all protocols.
             * @param port Port number to block.
             * @return true if a new rule is inserted; otherwise false.
             */
            virtual bool                                            DropNetworkPort(int port) noexcept;
            /**
             * @brief Adds a drop rule that blocks a port for a specific protocol.
             * @param port Port number to block.
             * @param tcp_or_udp true for TCP, false for UDP.
             * @return true if a new rule is inserted; otherwise false.
             */
            virtual bool                                            DropNetworkPort(int port, bool tcp_or_udp) noexcept;
            /**
             * @brief Adds a drop rule for a network segment.
             * @param ip IPv4 or IPv6 address to normalize as a network base.
             * @param prefix CIDR prefix length.
             * @return true if a new or stricter rule is stored; otherwise false.
             */
            virtual bool                                            DropNetworkSegment(const boost::asio::ip::address& ip, int prefix) noexcept;
            /**
             * @brief Adds a drop rule for a domain name.
             * @param host Domain string to block.
             * @return true if a new domain rule is inserted; otherwise false.
             */
            virtual bool                                            DropNetworkDomains(const ppp::string& host) noexcept;
            /** @brief Removes all configured firewall rules. */
            virtual void                                            Clear() noexcept;
            /**
             * @brief Loads firewall rules from a text file.
             * @param path Rule file path.
             * @return true if at least one valid rule is loaded; otherwise false.
             */
            bool                                                    LoadWithFile(const ppp::string& path) noexcept;
            /**
             * @brief Loads firewall rules from raw configuration text.
             * @param configuration Rule text content.
             * @return true if at least one valid rule is loaded; otherwise false.
             */
            virtual bool                                            LoadWithRules(const ppp::string& configuration) noexcept;

        public:
            /**
             * @brief Checks whether a port is blocked globally or by protocol.
             * @param port Port number to test.
             * @param tcp_or_udp true to test TCP-specific rules, false for UDP-specific rules.
             * @return true if blocked; otherwise false.
             */
            virtual bool                                            IsDropNetworkPort(int port, bool tcp_or_udp) noexcept;
            /**
             * @brief Checks whether a host is blocked by domain or IP segment rules.
             * @param host Host name or IP string.
             * @return true if blocked; otherwise false.
             */
            virtual bool                                            IsDropNetworkDomains(const ppp::string& host) noexcept;
            /**
             * @brief Checks whether an IP address matches any blocked segment.
             * @param ip IPv4 or IPv6 address to test.
             * @return true if blocked; otherwise false.
             */
            virtual bool                                            IsDropNetworkSegment(const boost::asio::ip::address& ip) noexcept;

        public:
            /**
             * @brief Evaluates exact and suffix domain matches through a callback.
             * @param host Host name to evaluate.
             * @param contains Callback that tests whether a candidate segment exists.
             * @return true if a match is found; otherwise false.
             */
            static bool                                             IsSameNetworkDomains(const ppp::string& host, const ppp::function<bool(const ppp::string& s)>& contains) noexcept;

        private:
            /** @brief Synchronizes access to all mutable rule containers. */
            SynchronizedObject                                      syncobj_;
            /** @brief Global blocked ports (protocol-agnostic). */
            ppp::unordered_set<int>                                 ports_;
            /** @brief TCP-specific blocked ports. */
            ppp::unordered_set<int>                                 ports_tcp_;
            /** @brief UDP-specific blocked ports. */
            ppp::unordered_set<int>                                 ports_udp_;
            /** @brief Normalized blocked domain table. */
            NetworkDomainsTable                                     network_domains_;
            /** @brief Blocked network base addresses with stored prefix lengths. */
            NetworkSegmentTable                                     network_segments_;
        };
    }
}
