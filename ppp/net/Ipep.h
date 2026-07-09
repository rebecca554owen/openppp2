#pragma once 

/**
 * @file Ipep.h
 * @brief High-level helpers for parsing, resolving, and normalizing IP endpoints.
 *
 * @ref ppp::net::Ipep is a pure-static utility class that builds on top of
 * @ref ppp::net::IPEndPoint and Boost.Asio to provide:
 *
 *  - Synchronous and asynchronous DNS / hostname resolution via @ref GetEndPoint
 *    and @ref GetAddressByHostName.
 *  - Parsing of host:port strings, CIDR blocks, and comma-separated address lists.
 *  - Bidirectional IPv4 ↔ IPv6-mapped conversion for Boost endpoint types.
 *  - Network / host byte-order swap with compile-time endian detection.
 *  - System DNS configuration (platform-specific overloads).
 *
 * @note All members are static; the class is never instantiated.
 */

#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/asio/vdns.h>

namespace ppp {
    namespace net {
        /**
         * @brief Utility class for endpoint parsing, DNS resolution, and address conversion.
         *
         * All methods are static and noexcept unless otherwise documented.
         * Thread-safety: stateless helpers are inherently thread-safe.  Async variants
         * dispatch work through the supplied @p io_context and invoke callbacks on the
         * context's executor thread.
         */
        class Ipep final {
        public:
            /**
             * @brief Callback used by async host resolution APIs.
             *
             * @param result  Shared pointer to the resolved endpoint, or NULLPTR on failure.
             */
            typedef ppp::function<void(const std::shared_ptr<IPEndPoint>&)>     GetAddressByHostNameCallback;

        public:
            /**
             * @brief Parses an endpoint string and optionally resolves the host part.
             * @param address   String in "host:port" or "host" format.
             * @param resolver  true to perform a blocking DNS lookup for non-IP hostnames.
             * @return          Resolved or parsed @ref IPEndPoint; invalid endpoint on failure.
             */
            static IPEndPoint                                                   GetEndPoint(const ppp::string& address, bool resolver = true) noexcept;

            /**
             * @brief Resolves host with explicit port to an endpoint.
             * @param host      Hostname or IP address string.
             * @param port      Destination port in host byte order.
             * @param resolver  true to perform a blocking DNS lookup.
             * @return          Resolved @ref IPEndPoint; invalid endpoint on failure.
             */
            static IPEndPoint                                                   GetEndPoint(const ppp::string& host, int port, bool resolver = true) noexcept;

            /**
             * @brief Resolves host using a specific io_context and explicit port.
             * @param context   Boost.Asio io_context used to drive the resolver.
             * @param host      Hostname or IP address string.
             * @param port      Destination port in host byte order.
             * @param resolver  true to perform a synchronous DNS lookup via @p context.
             * @return          Resolved @ref IPEndPoint; invalid endpoint on failure.
             */
            static IPEndPoint                                                   GetEndPoint(boost::asio::io_context& context, const ppp::string& host, int port, bool resolver = true) noexcept;

        public:
            /**
             * @brief Parses textual endpoint into a UDP endpoint.
             * @param address  String in "host:port" format.
             * @return         Parsed UDP endpoint; default-constructed on failure.
             */
            static boost::asio::ip::udp::udp::endpoint                          ParseEndPoint(const ppp::string& address) noexcept;

            /**
             * @brief Parses endpoint and optionally outputs parsed host string.
             * @param address             Input "host:port" string.
             * @param destinationAddress  If non-null, receives the extracted host part.
             * @return                    Parsed UDP endpoint; default-constructed on failure.
             */
            static boost::asio::ip::udp::udp::endpoint                          ParseEndPoint(const ppp::string& address, ppp::string* destinationAddress) noexcept;

            /**
             * @brief Parses endpoint into host and port components.
             * @param address             Input "host:port" string.
             * @param destinationAddress  Receives the extracted host part.
             * @param destinationPort     Receives the extracted port in host byte order.
             * @return                    true on successful parse; false if format is invalid.
             */
            static bool                                                         ParseEndPoint(const ppp::string& address, ppp::string& destinationAddress, int& destinationPort) noexcept;

            /**
             * @brief Performs lightweight QUIC long-header packet recognition.
             *
             * Checks the first byte of @p p for the QUIC long-header bit pattern to
             * determine whether the datagram is a QUIC packet destined for @p destinationEP.
             *
             * @param destinationEP  Destination endpoint of the datagram.
             * @param p              Raw datagram payload pointer.
             * @param length         Length of the datagram in bytes.
             * @return               true if the packet looks like a QUIC long-header datagram.
             */
            static bool                                                         PacketIsQUIC(const IPEndPoint& destinationEP, Byte* p, int length) noexcept;

        public:
            /**
             * @brief Converts endpoint to canonical `host:port` / `[host]:port` form.
             * @param ep  Source endpoint.
             * @return    Formatted string; IPv6 addresses are bracketed per RFC 2732.
             */
            static ppp::string                                                  ToIpepAddress(const IPEndPoint& ep) noexcept;

            /**
             * @brief Pointer overload of @ref ToIpepAddress(const IPEndPoint&).
             * @param ep  Pointer to source endpoint; NULLPTR returns empty string.
             * @return    Formatted string; empty on null pointer.
             */
            static ppp::string                                                  ToIpepAddress(const IPEndPoint* ep) noexcept;

            /**
             * @brief Converts comma-separated endpoint list to address-only list.
             * @param addresses  Comma-separated "host:port" strings.
             * @param out        Receives the host-part strings (no port).
             * @return           true if at least one entry was extracted.
             */
            static bool                                                         ToEndPoint(const ppp::string& addresses, ppp::vector<ppp::string>& out) noexcept;

            /**
             * @brief Parses textual IP and optionally rejects broadcast addresses.
             * @param ip        IPv4 or IPv6 string.
             * @param boardcast true to accept broadcast addresses; false to reject them
             *                  (returns unspecified address on rejection).
             * @return          Boost IP address; unspecified address on parse failure.
             */
            static boost::asio::ip::address                                     ToAddress(const ppp::string& ip, bool boardcast) noexcept;

            /**
             * @brief Converts IPv4 integer to Boost address.
             * @param ip  IPv4 address in **host byte order**.
             * @return    Equivalent boost::asio::ip::address_v4 wrapped as ip::address.
             */
            static boost::asio::ip::address                                     ToAddress(uint32_t ip) noexcept;

        public:
            template <class TString, class TProtocol>
            /**
             * @brief Converts a Boost endpoint address to string.
             * @tparam TString    String type to return.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param destinationEP  Source endpoint.
             * @return              Dotted-decimal or colon-hex address string.
             */
            static TString                                                      ToAddressString(const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept {
                int address_bytes_size = 0;
                IPEndPoint address_endpoint = IPEndPoint::ToEndPoint(destinationEP);

                Byte* address_bytes = address_endpoint.GetAddressBytes(address_bytes_size);
                return IPEndPoint::ToAddressString<TString>(address_endpoint.GetAddressFamily(), address_bytes, address_bytes_size);
            }

            template <class TString>
            /**
             * @brief Converts Boost address to string via a temporary endpoint.
             * @tparam TString  String type to return.
             * @param addressIP  Boost IP address.
             * @return           Dotted-decimal or colon-hex string.
             */
            static TString                                                      ToAddressString(const boost::asio::ip::address& addressIP) noexcept { return ToAddressString<TString>(boost::asio::ip::tcp::endpoint(addressIP, IPEndPoint::MinPort)); }

        public:
            /**
             * @brief Checks whether input is a valid host literal or domain-like name.
             * @param domain  Input string.
             * @return        true if the string contains at least one dot and is not a
             *                parseable IP literal; suitable for DNS resolution.
             */
            static bool                                                         IsDomainAddress(const ppp::string& domain) noexcept;

#if defined(_WIN32)
            /**
             * @brief Sets DNS servers for a specific network interface (Windows).
             * @param interface_index  Windows adapter interface index.
             * @param addresses        List of DNS server address strings.
             * @return                 true if the DNS configuration is updated successfully.
             * @note                   Requires elevated privileges on most Windows versions.
             */
            static bool                                                         SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& addresses) noexcept;
#else
            /**
             * @brief Sets system DNS servers (non-Windows platforms).
             * @param addresses  List of DNS server address strings.
             * @return           true if /etc/resolv.conf is updated successfully.
             * @note             Requires write permission to /etc/resolv.conf.
             */
            static bool                                                         SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept;
#endif

        public:
            /**
             * @brief Parsed CIDR entry including IP address and prefix length.
             *
             * Structure layout:
             *   Address = boost::asio::ip::address,  ///< Network address (host order)
             *   Cidr    = int,                        ///< Prefix length [0, 128]
             */
            struct AddressRange {
                boost::asio::ip::address                                        Address; ///< Network base address.
                int                                                             Cidr = 0; ///< CIDR prefix length.
            };

            /**
             * @brief Parses a single CIDR string into @ref AddressRange.
             * @param cidr_ip_string  String in "a.b.c.d/prefix" format.
             * @param address_range   Receives the parsed address and prefix.
             * @return                true on successful parse.
             */
            static bool                                                         ParseCidr(const ppp::string& cidr_ip_string, AddressRange& address_range) noexcept;

            /**
             * @brief Parses a single CIDR string into address and prefix outputs.
             * @param cidr_ip_string  String in "a.b.c.d/prefix" format.
             * @param destination     Receives the parsed base address.
             * @param cidr            Receives the parsed prefix length.
             * @return                true on successful parse.
             */
            static bool                                                         ParseCidr(const ppp::string& cidr_ip_string, boost::asio::ip::address& destination, int& cidr) noexcept;

            /**
             * @brief Parses multiple CIDR lines and appends unique entries.
             * @param path           Newline-separated CIDR block text (not a file path).
             * @param address_ranges Output list receiving parsed @ref AddressRange entries.
             * @return               Number of successfully parsed entries appended.
             */
            static int                                                          ParseAllCidrs(const ppp::string& path, ppp::vector<AddressRange>& address_ranges) noexcept;

            /**
             * @brief Reads a file and parses all CIDR entries from it.
             * @param file_name      Path to a text file containing CIDR blocks (one per line).
             * @param address_ranges Output list receiving parsed @ref AddressRange entries.
             * @return               Number of successfully parsed entries, or -1 on file error.
             */
            static int                                                          ParseAllCidrsFromFileName(const ppp::string& file_name, ppp::vector<AddressRange>& address_ranges) noexcept;

        public:
            /**
             * @brief Converts IPv4 integers to Boost address list.
             * @param in   Input list of IPv4 addresses in host byte order.
             * @param out  Receives the equivalent boost::asio::ip::address objects.
             */
            static void                                                         ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<boost::asio::ip::address>& out) noexcept;

            /**
             * @brief Converts IPv4 integers to textual address list.
             * @param in   Input list of IPv4 addresses in host byte order.
             * @param out  Receives dotted-decimal strings.
             */
            static void                                                         ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<ppp::string>& out) noexcept;

            /**
             * @brief Converts textual addresses to IPv4 integer list.
             * @param in   Input list of dotted-decimal strings.
             * @param out  Receives IPv4 addresses in host byte order.
             */
            static void                                                         ToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<uint32_t>& out) noexcept;
            
        public:
            /**
             * @brief Joins address list into comma-separated string.
             * @param addresses  Input list of Boost IP addresses.
             * @return           Comma-separated address string.
             */
            static ppp::string                                                  ToAddresses(ppp::vector<boost::asio::ip::address>& addresses) noexcept;

            /**
             * @brief Extracts unique IP addresses from arbitrary text.
             * @param addresses  Whitespace- or comma-separated address text.
             * @param out        Receives unique parsed Boost IP addresses.
             * @return           Number of addresses added to @p out.
             */
            static int                                                          ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept;

            /**
             * @brief Extracts unique IP addresses from text using predicate filter.
             * @param addresses  Whitespace- or comma-separated address text.
             * @param out        Receives addresses that pass @p predicate.
             * @param predicate  Callback returning true to include an address.
             * @return           Number of addresses added to @p out.
             */
            static int                                                          ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept;

            /**
             * @brief Extracts only valid unicast-like addresses from text.
             *
             * Excludes unspecified, loopback, multicast, and broadcast addresses.
             *
             * @param addresses  Whitespace- or comma-separated address text.
             * @param out        Receives unique routable unicast addresses.
             * @return           Number of addresses added to @p out.
             */
            static int                                                          ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept;

            /**
             * @brief Predicate-enabled overload of @ref ToAddresses2.
             * @param addresses  Whitespace- or comma-separated address text.
             * @param out        Receives addresses passing both validity and @p predicate checks.
             * @param predicate  Additional callback returning true to include an address.
             * @return           Number of addresses added to @p out.
             */
            static int                                                          ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept;

        public:
            /**
             * @brief Converts address list to string list.
             * @param in  Input Boost address list.
             * @return    List of dotted-decimal or colon-hex strings.
             */
            static ppp::vector<ppp::string>                                     AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in) noexcept;

            /**
             * @brief Appends converted address strings to output list.
             * @param in   Input Boost address list.
             * @param out  Receives appended string representations.
             */
            static void                                                         AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in, ppp::vector<ppp::string>& out) noexcept;

            /**
             * @brief Converts string list to Boost address list.
             * @param in  Input list of address strings.
             * @return    List of parsed Boost IP addresses (unparseable entries are skipped).
             */
            static ppp::vector<boost::asio::ip::address>                        StringsTransformToAddresses(const ppp::vector<ppp::string>& in) noexcept;

            /**
             * @brief Appends parsed Boost addresses to output list.
             * @param in   Input list of address strings.
             * @param out  Receives parsed Boost IP addresses.
             */
            static void                                                         StringsTransformToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<boost::asio::ip::address>& out) noexcept;

        public:
            template <class TProtocol>
            /**
             * @brief Converts IPv4-mapped IPv6 endpoint to IPv4 endpoint.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param addressEP   Source endpoint (may be IPv4 or IPv6).
             * @return            IPv4 endpoint if mapping applies; otherwise unchanged.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   V6ToV4(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept { return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(addressEP))); }

            template <class TProtocol>
            /**
             * @brief Converts IPv4 endpoint to IPv4-mapped IPv6 endpoint.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param addressEP   Source IPv4 endpoint.
             * @return            IPv6-mapped endpoint (::ffff:a.b.c.d form).
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   V4ToV6(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept { return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V4ToV6(IPEndPoint::ToEndPoint(addressEP))); }

            template <class TProtocol>
            /**
             * @brief Builds hash code from endpoint address bytes and port.
             *
             * Computes a FNV-inspired XOR-fold hash over the raw address bytes,
             * then XORs in the port value.  Suitable for use in unordered containers.
             *
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param addressEP   Endpoint to hash.
             * @return            Hash value; 0 for unrecognized address types.
             */
            static std::size_t                                                  GetHashCode(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept {
                std::size_t h = 0;
                boost::asio::ip::address address = addressEP.address();
                if (address.is_v4()) {
                    boost::asio::ip::address_v4 in4 = address.to_v4();
                    boost::asio::ip::address_v4::bytes_type bytes = in4.to_bytes();
                    h = ppp::GetHashCode((char*)bytes.data(), bytes.size());
                }
                elif(address.is_v6()) {
                    boost::asio::ip::address_v6 in6 = address.to_v6();
                    boost::asio::ip::address_v6::bytes_type bytes = in6.to_bytes();
                    h = ppp::GetHashCode((char*)bytes.data(), bytes.size());
                }
                else {
                    return h;
                }

                h ^= addressEP.port();
                return h;
            }

        public:
            template <class TProtocol>
            /**
             * @brief Resolves local host name to local endpoint at given port.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param resolver    Boost resolver to use for the lookup.
             * @param port        Port in host byte order.
             * @return            Resolved local endpoint; default-constructed on failure.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   LocalAddress(boost::asio::ip::basic_resolver<TProtocol>& resolver, int port) noexcept { return ppp::net::asio::GetAddressByHostName<TProtocol>(resolver, ppp::net::IPEndPoint::GetHostName(), port); }

        public:
            /**
             * @brief Asynchronously resolves host name and returns @ref IPEndPoint.
             *
             * Posts a DNS resolution request through @p context.  On completion,
             * @p callback is invoked on the executor thread with the result.
             *
             * @param context   Boost.Asio io_context driving the async resolver.
             * @param hostname  Hostname or IP literal to resolve.
             * @param port      Port to associate with the resolved address.
             * @param callback  Called with resolved endpoint; NULLPTR pointer on failure.
             * @return          true if the request was successfully posted.
             */
            static bool                                                         GetAddressByHostName(boost::asio::io_context& context, const ppp::string& hostname, int port, const GetAddressByHostNameCallback& callback) noexcept;

            /**
             * @brief Parses DNS server list and enforces optional minimum server count.
             * @param s             Comma- or whitespace-separated DNS address string.
             * @param addresses     Receives parsed DNS server addresses.
             * @param at_least_two  true to pad output to at least two entries using the
             *                      first address as duplicate when fewer are parsed.
             * @return              Number of valid addresses parsed.
             */
            static int                                                          ToDnsAddresses(const ppp::string& s, ppp::vector<boost::asio::ip::address>& addresses, bool at_least_two = false) noexcept; 

        public:
            template <class T>
            /**
             * @brief Converts integral value from network byte order to host byte order.
             *
             * On big-endian platforms the value is returned unchanged.  On little-endian
             * platforms the bytes are reversed via a byte-copy loop to avoid strict-aliasing
             * violations.
             *
             * @tparam T       Integral type (e.g. uint16_t, uint32_t, uint64_t).
             * @param network  Value in network (big-endian) byte order.
             * @return         Value in host byte order.
             */
            static T                                                            NetworkToHostOrder(const T& network) noexcept {
#if (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__) /* *((char*)(&__BYTE_ORDER__)) */
                return network;
#else
                T hostorder{};
                char* __dst = (char*)&reinterpret_cast<const char&>(hostorder);
                char* __src = (char*)&reinterpret_cast<const char&>(network);

                __src += sizeof(network);
                for (int i = 0; i < sizeof(network); i++) {
                    __src--;
                    *__dst = *__src;
                    __dst++; /* *__dst++ = *--__src; */
                }
                return hostorder;
#endif
            }
        
            template <class T>
            /**
             * @brief Converts integral value from host byte order to network byte order.
             *
             * Network-to-host and host-to-network swaps are identical byte reversal
             * operations, so this is a direct alias for @ref NetworkToHostOrder.
             *
             * @tparam T     Integral type.
             * @param host   Value in host byte order.
             * @return       Value in network (big-endian) byte order.
             */
            static T                                                            HostToNetworkOrder(const T& host) noexcept { return NetworkToHostOrder<T>(host); }

        public:
            /**
             * @brief Parses CIDR prefix text or netmask text into prefix length.
             * @param cidr_number_string  Either a plain prefix integer ("24") or a
             *                            dotted-decimal netmask ("255.255.255.0").
             * @return                    Equivalent CIDR prefix length, or -1 on failure.
             */
            static int                                                          NetmaskToPrefix(const ppp::string& cidr_number_string) noexcept;

            /**
             * @brief Fixes host/gateway in subnet derived from IP and mask.
             *
             * Applies bitwise AND of @p ip and @p mask to derive the network base address,
             * returning the result as the "fixed" host or gateway address.
             *
             * @param ip    Host IP address.
             * @param mask  Subnet mask.
             * @return      Corrected network address.
             */
            static boost::asio::ip::address                                     FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept;

            /**
             * @brief Fixes host/gateway using explicit IP, GW, and subnet mask.
             *
             * Applies bitwise AND of @p ip and @p mask and compares with @p gw and @p mask
             * to determine whether the gateway is on the same subnet; returns the correct
             * host address accordingly.
             *
             * @param ip    Host IP address.
             * @param gw    Default gateway address.
             * @param mask  Subnet mask.
             * @return      Corrected host address for the given subnet.
             */
            static boost::asio::ip::address                                     FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& gw, const boost::asio::ip::address& mask) noexcept;
        };
    }
}

namespace std {
#if BOOST_VERSION < 107600
    /**
     * @brief std::hash specialization for boost::asio::ip::address_v4.
     * @note  Provided for Boost versions prior to 1.76.0 which lack a built-in hash.
     */
    template <>
    struct hash<boost::asio::ip::address_v4> {
    public:
        /** @brief Hashes an IPv4 address as an unsigned integer. */
        std::size_t operator()(const boost::asio::ip::address_v4& addr) const noexcept {
            return std::hash<unsigned int>()(addr.to_uint());
        }
    };

    /**
     * @brief std::hash specialization for boost::asio::ip::address_v6.
     * @note  Provided for Boost versions prior to 1.76.0.
     */
    template <>
    struct hash<boost::asio::ip::address_v6> {
    public:
        /** @brief Hashes an IPv6 address by combining all 16 bytes via FNV-style mixing. */
        std::size_t operator()(const boost::asio::ip::address_v6& addr) const noexcept {
            const boost::asio::ip::address_v6::bytes_type bytes = addr.to_bytes();
            std::size_t result = static_cast<std::size_t>(addr.scope_id());
            combine_4_bytes(result, &bytes[0]);
            combine_4_bytes(result, &bytes[4]);
            combine_4_bytes(result, &bytes[8]);
            combine_4_bytes(result, &bytes[12]);
            return result;
        }
    
    private:
        /** @brief Mixes four consecutive bytes into @p seed using Boost-style golden ratio constant. */
        static void combine_4_bytes(std::size_t& seed, const unsigned char* bytes) noexcept {
            const std::size_t bytes_hash =
                (static_cast<std::size_t>(bytes[0]) << 24) |
                (static_cast<std::size_t>(bytes[1]) << 16) |
                (static_cast<std::size_t>(bytes[2]) << 8) |
                (static_cast<std::size_t>(bytes[3]));
            seed ^= bytes_hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
    };

    /**
     * @brief std::hash specialization for boost::asio::ip::address.
     * @note  Delegates to address_v4 or address_v6 specialization based on version.
     */
    template <>
    struct hash<boost::asio::ip::address> {
    public:
        /** @brief Hashes a generic Boost IP address by dispatching to the family-specific hasher. */
        std::size_t operator()(const boost::asio::ip::address& addr) const noexcept {
            return addr.is_v4()
                ? std::hash<boost::asio::ip::address_v4>()(addr.to_v4())
                : std::hash<boost::asio::ip::address_v6>()(addr.to_v6());
        }
    };
#endif

    /**
     * @brief std::hash specialization for boost::asio::ip::tcp::endpoint.
     *
     * Delegates to @ref ppp::net::Ipep::GetHashCode for consistent hashing
     * across the entire ppp::net layer.
     */
    template <>
    struct hash<boost::asio::ip::tcp::endpoint> {
    public:
        /** @brief Hashes a TCP endpoint by address bytes and port. */
        std::size_t operator()(const boost::asio::ip::tcp::endpoint& v) const noexcept {
            return ppp::net::Ipep::GetHashCode(v);
        }
    };

    /**
     * @brief std::hash specialization for boost::asio::ip::udp::endpoint.
     *
     * Delegates to @ref ppp::net::Ipep::GetHashCode for consistent hashing
     * across the entire ppp::net layer.
     */
    template <>
    struct hash<boost::asio::ip::udp::endpoint> {
    public:
        /** @brief Hashes a UDP endpoint by address bytes and port. */
        std::size_t operator()(const boost::asio::ip::udp::endpoint& v) const noexcept {
            return ppp::net::Ipep::GetHashCode(v);
        }
    };
}
