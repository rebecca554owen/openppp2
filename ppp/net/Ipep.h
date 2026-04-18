#pragma once 

/**
 * @file Ipep.h
 * @brief High-level helpers for parsing, resolving, and normalizing IP endpoints.
 */

#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/asio.h>
#include <ppp/net/asio/vdns.h>

namespace ppp {
    namespace net {
        /**
         * @brief Utility class for endpoint parsing, DNS resolution, and address conversion.
         */
        class Ipep final {
        public:
            /** @brief Callback used by async host resolution APIs. */
            typedef ppp::function<void(const std::shared_ptr<IPEndPoint>&)>     GetAddressByHostNameCallback;

        public:
            /** @brief Parses an endpoint string and resolves host if requested. */
            static IPEndPoint                                                   GetEndPoint(const ppp::string& address, bool resolver = true) noexcept;
            /** @brief Resolves host with explicit port to an endpoint. */
            static IPEndPoint                                                   GetEndPoint(const ppp::string& host, int port, bool resolver = true) noexcept;
            /** @brief Resolves host with explicit io_context and port. */
            static IPEndPoint                                                   GetEndPoint(boost::asio::io_context& context, const ppp::string& host, int port, bool resolver = true) noexcept;

        public:
            /** @brief Parses textual endpoint into UDP endpoint. */
            static boost::asio::ip::udp::udp::endpoint                          ParseEndPoint(const ppp::string& address) noexcept;
            /** @brief Parses endpoint and optionally outputs parsed host string. */
            static boost::asio::ip::udp::udp::endpoint                          ParseEndPoint(const ppp::string& address, ppp::string* destinationAddress) noexcept;
            /** @brief Parses endpoint into host and port components. */
            static bool                                                         ParseEndPoint(const ppp::string& address, ppp::string& destinationAddress, int& destinationPort) noexcept;
            /** @brief Performs lightweight QUIC long-header packet recognition. */
            static bool                                                         PacketIsQUIC(const IPEndPoint& destinationEP, Byte* p, int length) noexcept;

        public:
            /** @brief Converts endpoint to canonical `host:port` / `[host]:port` form. */
            static ppp::string                                                  ToIpepAddress(const IPEndPoint& ep) noexcept;
            /** @brief Pointer overload of @ref ToIpepAddress(const IPEndPoint&). */
            static ppp::string                                                  ToIpepAddress(const IPEndPoint* ep) noexcept;
            /** @brief Converts comma-separated endpoint list to address-only list. */
            static bool                                                         ToEndPoint(const ppp::string& addresses, ppp::vector<ppp::string>& out) noexcept;
            /** @brief Parses textual IP and optionally rejects broadcast addresses. */
            static boost::asio::ip::address                                     ToAddress(const ppp::string& ip, bool boardcast) noexcept;
            /** @brief Converts IPv4 integer to Boost address. */
            static boost::asio::ip::address                                     ToAddress(uint32_t ip) noexcept;

        public:
            template <class TString, class TProtocol>
            /** @brief Converts a Boost endpoint address to string. */
            static TString                                                      ToAddressString(const boost::asio::ip::basic_endpoint<TProtocol>& destinationEP) noexcept {
                int address_bytes_size = 0;
                IPEndPoint address_endpoint = IPEndPoint::ToEndPoint(destinationEP);

                Byte* address_bytes = address_endpoint.GetAddressBytes(address_bytes_size);
                return IPEndPoint::ToAddressString<TString>(address_endpoint.GetAddressFamily(), address_bytes, address_bytes_size);
            }

            template <class TString>
            /** @brief Converts Boost address to string via a temporary endpoint. */
            static TString                                                      ToAddressString(const boost::asio::ip::address& addressIP) noexcept { return ToAddressString<TString>(boost::asio::ip::tcp::endpoint(addressIP, IPEndPoint::MinPort)); }

        public:
            /** @brief Checks whether input is a valid host literal or domain-like name. */
            static bool                                                         IsDomainAddress(const ppp::string& domain) noexcept;
#if defined(_WIN32)
            /** @brief Sets DNS servers for a specific network interface (Windows). */
            static bool                                                         SetDnsAddresses(int interface_index, const ppp::vector<ppp::string>& addresses) noexcept;
#else
            /** @brief Sets system DNS servers (non-Windows platforms). */
            static bool                                                         SetDnsAddresses(const ppp::vector<ppp::string>& addresses) noexcept;
#endif

        public:
            /** @brief Parsed CIDR entry including IP address and prefix length. */
            struct AddressRange {
                boost::asio::ip::address                                        Address;
                int                                                             Cidr = 0;
            };
            /** @brief Parses a single CIDR string into @ref AddressRange. */
            static bool                                                         ParseCidr(const ppp::string& cidr_ip_string, AddressRange& address_range) noexcept;
            /** @brief Parses a single CIDR string into address and prefix outputs. */
            static bool                                                         ParseCidr(const ppp::string& cidr_ip_string, boost::asio::ip::address& destination, int& cidr) noexcept;
            /** @brief Parses multiple CIDR lines and appends unique entries. */
            static int                                                          ParseAllCidrs(const ppp::string& path, ppp::vector<AddressRange>& address_ranges) noexcept;
            /** @brief Reads a file and parses all CIDR entries from it. */
            static int                                                          ParseAllCidrsFromFileName(const ppp::string& file_name, ppp::vector<AddressRange>& address_ranges) noexcept;

        public:
            /** @brief Converts IPv4 integers to Boost address list. */
            static void                                                         ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<boost::asio::ip::address>& out) noexcept;
            /** @brief Converts IPv4 integers to textual address list. */
            static void                                                         ToAddresses(const ppp::vector<uint32_t>& in, ppp::vector<ppp::string>& out) noexcept;
            /** @brief Converts textual addresses to IPv4 integer list. */
            static void                                                         ToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<uint32_t>& out) noexcept;
            
        public:
            /** @brief Joins address list into comma-separated string. */
            static ppp::string                                                  ToAddresses(ppp::vector<boost::asio::ip::address>& addresses) noexcept;
            /** @brief Extracts unique IP addresses from arbitrary text. */
            static int                                                          ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept;
            /** @brief Extracts unique IP addresses from text using predicate filter. */
            static int                                                          ToAddresses(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept;
            /** @brief Extracts only valid unicast-like addresses from text. */
            static int                                                          ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out) noexcept;
            /** @brief Predicate-enabled overload of @ref ToAddresses2. */
            static int                                                          ToAddresses2(const ppp::string& addresses, ppp::vector<boost::asio::ip::address>& out, const ppp::function<bool(boost::asio::ip::address&)>& predicate) noexcept;

        public:
            /** @brief Converts address list to string list. */
            static ppp::vector<ppp::string>                                     AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in) noexcept;
            /** @brief Appends converted address strings to output list. */
            static void                                                         AddressesTransformToStrings(const ppp::vector<boost::asio::ip::address>& in, ppp::vector<ppp::string>& out) noexcept;
            /** @brief Converts string list to Boost address list. */
            static ppp::vector<boost::asio::ip::address>                        StringsTransformToAddresses(const ppp::vector<ppp::string>& in) noexcept;
            /** @brief Appends parsed Boost addresses to output list. */
            static void                                                         StringsTransformToAddresses(const ppp::vector<ppp::string>& in, ppp::vector<boost::asio::ip::address>& out) noexcept;

        public:
            template <class TProtocol>
            /** @brief Converts IPv4-mapped IPv6 endpoint to IPv4 endpoint. */
            static boost::asio::ip::basic_endpoint<TProtocol>                   V6ToV4(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept { return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(addressEP))); }

            template <class TProtocol>       
            /** @brief Converts IPv4 endpoint to IPv4-mapped IPv6 endpoint. */
            static boost::asio::ip::basic_endpoint<TProtocol>                   V4ToV6(const boost::asio::ip::basic_endpoint<TProtocol>& addressEP) noexcept { return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V4ToV6(IPEndPoint::ToEndPoint(addressEP))); }

            template <class TProtocol>       
            /** @brief Builds hash code from endpoint address bytes and port. */
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
            /** @brief Resolves local host name to local endpoint at given port. */
            static boost::asio::ip::basic_endpoint<TProtocol>                   LocalAddress(boost::asio::ip::basic_resolver<TProtocol>& resolver, int port) noexcept { return ppp::net::asio::GetAddressByHostName<TProtocol>(resolver, ppp::net::IPEndPoint::GetHostName(), port); }

        public:
            /** @brief Asynchronously resolves host name and returns @ref IPEndPoint. */
            static bool                                                         GetAddressByHostName(boost::asio::io_context& context, const ppp::string& hostname, int port, const GetAddressByHostNameCallback& callback) noexcept;
            /** @brief Parses DNS server list and enforces optional minimum server count. */
            static int                                                          ToDnsAddresses(const ppp::string& s, ppp::vector<boost::asio::ip::address>& addresses, bool at_least_two = false) noexcept; 

        public:     
            template <class T>      
            /** @brief Converts integral value from network byte order to host byte order. */
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
            /** @brief Converts integral value from host byte order to network byte order. */
            static T                                                            HostToNetworkOrder(const T& host) noexcept { return NetworkToHostOrder<T>(host); }

        public:
            /** @brief Parses CIDR prefix text or netmask text into prefix length. */
            static int                                                          NetmaskToPrefix(const ppp::string& cidr_number_string) noexcept;
            /** @brief Fixes host/gateway in subnet derived from IP and mask. */
            static boost::asio::ip::address                                     FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept;
            /** @brief Fixes host/gateway using explicit IP, GW, and subnet mask. */
            static boost::asio::ip::address                                     FixedIPAddress(const boost::asio::ip::address& ip, const boost::asio::ip::address& gw, const boost::asio::ip::address& mask) noexcept;
        };
    }
}

namespace std {
#if BOOST_VERSION < 107600
    template <>
    struct hash<boost::asio::ip::address_v4> {
    public:
        std::size_t operator()(const boost::asio::ip::address_v4& addr) const noexcept {
            return std::hash<unsigned int>()(addr.to_uint());
        }
    };

    template <>
    struct hash<boost::asio::ip::address_v6> {
    public:
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
        static void combine_4_bytes(std::size_t& seed, const unsigned char* bytes) noexcept {
            const std::size_t bytes_hash =
                (static_cast<std::size_t>(bytes[0]) << 24) |
                (static_cast<std::size_t>(bytes[1]) << 16) |
                (static_cast<std::size_t>(bytes[2]) << 8) |
                (static_cast<std::size_t>(bytes[3]));
            seed ^= bytes_hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
        }
    };

    template <>
    struct hash<boost::asio::ip::address> {
    public:
        std::size_t operator()(const boost::asio::ip::address& addr) const noexcept {
            return addr.is_v4()
                ? std::hash<boost::asio::ip::address_v4>()(addr.to_v4())
                : std::hash<boost::asio::ip::address_v6>()(addr.to_v6());
        }
    };
#endif

    template <>
    struct hash<boost::asio::ip::tcp::endpoint> {
    public:
        std::size_t operator()(const boost::asio::ip::tcp::endpoint& v) const noexcept {
            return ppp::net::Ipep::GetHashCode(v);
        }
    };

    template <>
    struct hash<boost::asio::ip::udp::endpoint> {
    public:
        std::size_t operator()(const boost::asio::ip::udp::endpoint& v) const noexcept {
            return ppp::net::Ipep::GetHashCode(v);
        }
    };
}
