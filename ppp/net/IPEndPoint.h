#pragma once

/**
 * @file IPEndPoint.h
 * @brief Endpoint abstraction for IPv4/IPv6 address and port operations.
 *
 * @ref ppp::net::IPEndPoint is a lightweight, copy-constructible value type that
 * stores either an IPv4 (4-byte) or IPv6 (16-byte) address together with a port
 * number in host byte order.
 *
 * Design notes:
 * - Internal address storage is always 16 bytes regardless of address family;
 *   IPv4 addresses occupy the first 4 bytes.
 * - All addresses returned by @ref GetAddress() are in **network byte order**
 *   (big-endian) consistent with POSIX sockaddr_in.sin_addr.s_addr.
 * - Template helpers (ToEndPoint, WrapAddressV4, WrapAddressV6, …) accept any
 *   Boost.Asio protocol type (tcp, udp, icmp) via the @p TProtocol parameter.
 * - V6ToV4 / V4ToV6 implement RFC 4291 IPv4-mapped IPv6 address encoding.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        /**
         * @brief IP address family used by @ref IPEndPoint.
         */
        enum AddressFamily {
            InterNetwork   = AF_INET,   ///< IPv4 (AF_INET).
            InterNetworkV6 = AF_INET6,  ///< IPv6 (AF_INET6).
        };

        /**
         * @brief Represents an immutable port with mutable IPv4/IPv6 address bytes.
         *
         * Structure layout:
         *   _AddressBytes  = Byte[16],      ///< Raw address bytes (network byte order)
         *   _AddressFamily = AddressFamily, ///< InterNetwork or InterNetworkV6
         *   Port           = const int,     ///< Transport port in host order [0, 65535]
         *
         * @note Port is declared `const int` but modified via a placement trick during
         *       construction and assignment; do not attempt to write to it directly.
         */
        struct IPEndPoint {
        private:
            /** @brief Raw address bytes (always 16 bytes; IPv4 uses first 4 bytes). */
            mutable Byte                                                        _AddressBytes[sizeof(struct in6_addr)]; // 16
            /** @brief Address family that determines how @ref _AddressBytes is interpreted. */
            AddressFamily                                                       _AddressFamily;

        public:
            /** @brief Transport port in host byte order; range [MinPort, MaxPort]. */
            const int                                                           Port;
            /**
             * @brief IPv6 scope ID (zone index) for link-local addresses.
             *
             * @details Zero for global / unique-local / multicast addresses.
             *          Set automatically by ToEndPoint(Boost endpoint) and by
             *          the Socket_ConvertSockaddrToEndpoint helper.
             *
             * @note    A non-zero scope_id is only meaningful when _AddressFamily
             *          is InterNetworkV6.
             */
            unsigned long                                                       ScopeId = 0;

        public:
            static constexpr int    MinPort          = 0;           ///< Minimum valid port number.
            static constexpr int    MaxPort          = UINT16_MAX;  ///< Maximum valid port number (65535).
            static constexpr UInt32 AnyAddress       = INADDR_ANY;  ///< IPv4 wildcard address (0.0.0.0).
            static constexpr UInt32 NoneAddress      = INADDR_NONE; ///< IPv4 "none" sentinel (255.255.255.255).
            static constexpr UInt32 LoopbackAddress  = INADDR_LOOPBACK;   ///< IPv4 loopback (127.0.0.1).
            static constexpr UInt32 BroadcastAddress = INADDR_BROADCAST;  ///< IPv4 limited broadcast (255.255.255.255).

        public:
            /**
             * @brief Initializes endpoint as invalid/none with port 0.
             *
             * Produces an IPv4 endpoint with address INADDR_NONE and port 0, which
             * @ref IsInvalid considers invalid.  Useful as a sentinel default value.
             */
            IPEndPoint() noexcept
                : IPEndPoint(NoneAddress, IPEndPoint::MinPort) {

            }

            /**
             * @brief Creates an IPv4 endpoint from 32-bit address and port.
             * @param address  IPv4 address in **network byte order** (big-endian).
             * @param port     Port in host byte order; clamped to [MinPort, MaxPort].
             */
            IPEndPoint(UInt32 address, int port) noexcept
                : _AddressFamily(AddressFamily::InterNetwork)
                , Port(port) {
                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                *(Int32*)&this->Port = port;
                *(UInt32*)this->_AddressBytes = address;
            }

            /**
             * @brief Creates an endpoint from textual address and port.
             * @param address  Null-terminated IPv4 or IPv6 text (e.g. "192.168.1.1", "::1").
             * @param port     Port in host byte order.
             * @note           Falls back to INADDR_NONE on parse failure.
             */
            IPEndPoint(const char* address, int port) noexcept;

            /**
             * @brief Creates an endpoint from raw address bytes.
             * @param af            Address family (InterNetwork or InterNetworkV6).
             * @param address_bytes Pointer to raw address data (network byte order).
             * @param address_size  Byte length: 4 for IPv4, 16 for IPv6.
             * @param port          Port in host byte order.
             * @note                Bytes beyond @p address_size are zero-padded.
             */
            IPEndPoint(AddressFamily af, const void* address_bytes, int address_size, int port) noexcept;

        public:
            /**
             * @brief Creates IPv4 any-address endpoint (0.0.0.0:port).
             * @param port  Port in host byte order.
             * @return      Endpoint bound to all interfaces on @p port.
             */
            static IPEndPoint                                                   Any(int port) noexcept {
                return IPEndPoint(IPEndPoint::AnyAddress, port);
            }
            /**
             * @brief Creates IPv4 loopback endpoint (127.0.0.1:port).
             * @param port  Port in host byte order.
             * @return      Endpoint bound to the loopback interface on @p port.
             */
            static IPEndPoint                                                   Loopback(int port) noexcept {
                return IPEndPoint(IPEndPoint::LoopbackAddress, port);
            }
            /**
             * @brief Creates IPv4 broadcast endpoint (255.255.255.255:port).
             * @param port  Port in host byte order.
             * @return      Endpoint representing the limited broadcast address.
             */
            static IPEndPoint                                                   Broadcast(int port) noexcept {
                return IPEndPoint(IPEndPoint::BroadcastAddress, port);
            }
            /**
             * @brief Creates IPv4 none-address endpoint (255.255.255.255:port).
             * @param port  Port in host byte order.
             * @return      Sentinel invalid endpoint.
             */
            static IPEndPoint                                                   None(int port) noexcept {
                return IPEndPoint(IPEndPoint::NoneAddress, port);
            }
            /**
             * @brief Creates IPv6 any-address endpoint (:::port).
             * @param port  Port in host byte order.
             * @return      IPv6 endpoint bound to all interfaces on @p port.
             */
            static IPEndPoint                                                   IPv6Any(int port) noexcept {
                boost::asio::ip::tcp::endpoint localEP(boost::asio::ip::address_v6::any(), port);
                return ToEndPoint(localEP);
            }
            /**
             * @brief Creates IPv6 loopback endpoint (::1:port).
             * @param port  Port in host byte order.
             * @return      IPv6 loopback endpoint on @p port.
             */
            static IPEndPoint                                                   IPv6Loopback(int port) noexcept {
                boost::asio::ip::tcp::endpoint localEP(boost::asio::ip::address_v6::loopback(), port);
                return ToEndPoint(localEP);
            }
            /**
             * @brief Creates IPv6 none-address endpoint (mapped to IPv6 any).
             * @param port  Port in host byte order.
             * @return      IPv6 "none" sentinel (currently aliases to IPv6Any).
             */
            static IPEndPoint                                                   IPv6None(int port) noexcept {
                return IPv6Any(port);
            }

        public:
            /**
             * @brief Checks whether this endpoint is considered broadcast.
             * @return  true when the address is INADDR_NONE (the none/broadcast sentinel).
             * @note    Delegates to @ref IsNone; broadcast detection is IPv4-specific.
             */
            bool                                                                IsBroadcast() noexcept {
                return this->IsNone();
            }
            /**
             * @brief Checks whether address bytes represent the none/broadcast value.
             * @return  true for IPv4 INADDR_NONE (0xffffffff) or IPv6 all-0xff bytes.
             */
            bool                                                                IsNone() noexcept {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    int len;
                    const Byte* p = this->GetAddressBytes(len);
                    // All 128 bits must be 1 for IPv6 "none" sentinel.
                    static const Byte kNoneV6[16] = {
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
                    };
                    return 16 == len && 0 == memcmp(p, kNoneV6, 16);
                }
                else {
                    return this->GetAddress() == IPEndPoint::NoneAddress;
                }
            }
            /**
             * @brief Checks whether this endpoint is any/unspecified address.
             * @return  true for IPv4 0.0.0.0 or IPv6 :: (all zero bytes).
             */
            bool                                                                IsAny() noexcept {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    int len;
                    Int64* p = (Int64*)this->GetAddressBytes(len);
                    return p[0] == 0 && p[1] == 0;
                }
                else {
                    return this->GetAddress() == IPEndPoint::AnyAddress;
                }
            }
            /**
             * @brief Checks whether this endpoint is a loopback address.
             * @return  true for IPv4 127.x.x.x or the IPv6 ::1 loopback address.
             */
            bool                                                                IsLoopback() noexcept {
                int len;
                Byte* p = this->GetAddressBytes(len); // IN6_IS_ADDR_LOOPBACK
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    return boost::asio::ip::address_v6(*(boost::asio::ip::address_v6::bytes_type*)p).is_loopback();
                }
                else {
                    return *this->_AddressBytes == 127; // 127.0.0.0/8
                }
            }
            /**
             * @brief Checks whether endpoint address belongs to multicast range.
             * @return  true for IPv4 224.0.0.0/4 or IPv6 ff00::/8 addresses.
             */
            bool                                                                IsMulticast() noexcept {
                return ToEndPoint<boost::asio::ip::tcp>(*this).address().is_multicast();
            }

        public:
            /**
             * @brief Copies raw address bytes into a binary string.
             * @return  Binary string containing 4 bytes (IPv4) or 16 bytes (IPv6).
             */
            ppp::string                                                         GetAddressBytes() const noexcept {
                int datalen;
                Byte* data = this->GetAddressBytes(datalen);
                return ppp::string((char*)data, datalen);
            }

            /**
             * @brief Gets mutable raw address bytes and effective length.
             * @param len  Receives 4 for IPv4 or 16 for IPv6.
             * @return     Pointer into the internal @ref _AddressBytes buffer.
             * @note       The returned pointer is valid for the lifetime of this endpoint.
             */
            Byte*                                                               GetAddressBytes(int& len) const {
                if (this->_AddressFamily == AddressFamily::InterNetworkV6) {
                    len = sizeof(this->_AddressBytes);
                    return this->_AddressBytes;
                }
                else {
                    len = sizeof(UInt32);
                    return this->_AddressBytes;
                }
            }

            /**
             * @brief Gets IPv4 address value from internal storage.
             * @return  IPv4 address in **network byte order**; only meaningful for IPv4 family.
             */
            UInt32                                                              GetAddress() const noexcept {
                return *(UInt32*)this->_AddressBytes;
            }

            /**
             * @brief Gets the current address family.
             * @return  @ref AddressFamily::InterNetwork or @ref AddressFamily::InterNetworkV6.
             */
            AddressFamily                                                       GetAddressFamily() const noexcept {
                return this->_AddressFamily;
            }

            /**
             * @brief Compares this endpoint with another endpoint instance.
             * @param value  Endpoint to compare against.
             * @return       true when both family, address bytes, and port are identical.
             */
            bool                                                                Equals(const IPEndPoint& value) const {
                IPEndPoint* reft = (IPEndPoint*)&reinterpret_cast<const char&>(value);
                IPEndPoint* left = (IPEndPoint*)this;
                if (left == reft) {
                    return true;
                }

                return *left == *reft;
            }

        public:
            /**
             * @brief Compares address family and raw address bytes for equality.
             * @param right  Right-hand endpoint.
             * @return       true when family and address bytes match (port is not compared).
             * @note         Port is intentionally excluded from the address comparison.
             */
            bool                                                                operator == (const IPEndPoint& right) const noexcept {
                if (this->_AddressFamily != right._AddressFamily) {
                    return false;
                }

                Byte* x = this->_AddressBytes;
                Byte* y = right._AddressBytes;
                if (x == y) {
                    return true;
                }

                if (this->_AddressFamily == AddressFamily::InterNetworkV6) {
                    UInt64* qx = (UInt64*)x;
                    UInt64* qy = (UInt64*)y;
                    return qx[0] == qy[0] && qx[1] == qy[1];
                }
                return *(UInt32*)x == *(UInt32*)y;
            }

            /**
             * @brief Negated equality comparison.
             * @param right  Right-hand endpoint.
             * @return       true when @ref operator== returns false.
             */
            bool                                                                operator != (const IPEndPoint& right) const noexcept {
                bool b = (*this) == right;
                return !b;
            }

            /**
             * @brief Assigns address family, port, and address bytes from another endpoint.
             * @param right  Source endpoint to copy from.
             * @return       Reference to this endpoint after assignment.
             */
            IPEndPoint&                                                         operator = (const IPEndPoint& right) {
                this->_AddressFamily = right._AddressFamily;
                constantof(this->Port) = right.Port;

                int address_bytes_size;
                Byte* address_bytes = right.GetAddressBytes(address_bytes_size);
                memcpy(this->_AddressBytes, address_bytes, address_bytes_size);

                return *this;
            }

        public:
            template <typename TString>
            /**
             * @brief Converts raw address bytes to a textual representation.
             * @tparam TString       String type to return (e.g. ppp::string, std::string).
             * @param af             Address family determining the interpretation of @p address_bytes.
             * @param address_bytes  Raw address bytes in network byte order.
             * @param address_size   Number of bytes; must be ≥4 for IPv4 or ≥16 for IPv6.
             * @return               Dotted-decimal (IPv4) or colon-hex (IPv6) string;
             *                       "0.0.0.0" on any failure.
             */
            static TString                                                      ToAddressString(AddressFamily af, const Byte* address_bytes, int address_size) noexcept {
                if (NULLPTR == address_bytes || address_size < 1) {
                    return "0.0.0.0";
                }

                if (af == AddressFamily::InterNetworkV6) {
                    if (address_size < (int)sizeof(struct in6_addr)) {
                        return "0.0.0.0";
                    }

                    char sz[INET6_ADDRSTRLEN];
                    if (!inet_ntop(AF_INET6, (struct in6_addr*)address_bytes, sz, sizeof(sz))) {
                        return "0.0.0.0";
                    }
                    return sz;
                }
                else {
                    if (address_size < (int)sizeof(struct in_addr)) {
                        return "0.0.0.0";
                    }

                    char sz[INET_ADDRSTRLEN];
                    if (!inet_ntop(AF_INET, (struct in_addr*)address_bytes, sz, sizeof(sz))) {
                        return "0.0.0.0";
                    }
                    return sz; // inet_ntoa(*(struct in_addr*)address);
                }
            }

        public:
            /**
             * @brief Converts current endpoint address to text.
             * @return  Dotted-decimal (IPv4) or colon-hex (IPv6) string representation.
             */
            ppp::string                                                         ToAddressString() noexcept {
                int address_bytes_size;
                Byte* address_bytes = GetAddressBytes(address_bytes_size);
                return ToAddressString<ppp::string>(this->_AddressFamily, address_bytes, address_bytes_size);
            }

            /**
             * @brief Computes a simple additive hash over family, port, and address bytes.
             * @return  Hash code suitable for use in hash-table buckets.
             * @note    Not cryptographically strong; intended for hash-map keying only.
             */
            int                                                                 GetHashCode() const noexcept {
                int h = this->GetAddressFamily() + this->Port;
                int l = 0;
                Byte* p = this->GetAddressBytes(l);
                for (int i = 0; i < l; i++) {
                    h += *p++;
                }
                return h;
            }

            /**
             * @brief Converts endpoint to `host:port` or `[host]:port` text.
             * @return  IPv6 addresses are bracketed per RFC 2732 (e.g. "[::1]:80").
             */
            ppp::string                                                         ToString() noexcept;

        public:
            /**
             * @brief Gets local host name from system APIs.
             * @return  System host name string, or empty string on failure.
             */
            static ppp::string                                                  GetHostName() noexcept;

        public:
            /**
             * @brief Converts IPv4 numeric address to text.
             * @param address  IPv4 address in **network byte order**.
             * @return         Dotted-decimal string (e.g. "192.168.1.1").
             */
            static ppp::string                                                  ToAddressString(UInt32 address) noexcept {
                return ToAddressString<ppp::string>(AddressFamily::InterNetwork, (Byte*)&address, sizeof(address));
            }

            /**
             * @brief Converts serialized address bytes to text by family.
             * @param af            Address family selecting IPv4 or IPv6 formatting.
             * @param address_bytes Binary address blob (4 or 16 bytes).
             * @return              Human-readable address string.
             */
            static ppp::string                                                  ToAddressString(AddressFamily af, const ppp::string& address_bytes) noexcept {
                return ToAddressString<ppp::string>(af, (Byte*)address_bytes.data(), (int)address_bytes.size());
            }

            /**
             * @brief Converts IPv4 prefix length to netmask in network byte order.
             * @param prefix  CIDR prefix length [0, 32].
             * @return        Netmask in **network byte order** (e.g. prefix=24 → 0xffffff00).
             */
            static UInt32                                                       PrefixToNetmask(int prefix) noexcept {
                UInt32 mask = prefix ? (~0UL << (32 - prefix)) : 0L;
                return htonl(mask);
            }

            /**
             * @brief Converts IPv4 netmask in network byte order to prefix length.
             * @param mask  Netmask in **network byte order**.
             * @return      CIDR prefix length (number of set bits).
             */
            static int                                                          NetmaskToPrefix(UInt32 mask) noexcept {
                return NetmaskToPrefix(reinterpret_cast<unsigned char*>(&mask), sizeof(mask));
            }

            /**
             * @brief Converts arbitrary netmask bytes to number of set bits.
             * @param bytes       Pointer to the netmask byte array.
             * @param bytes_size  Length of the byte array.
             * @return            Total number of set bits (prefix length).
             */
            static int                                                          NetmaskToPrefix(unsigned char* bytes, int bytes_size) noexcept {
                if (NULLPTR == bytes || bytes_size < 1) {
                    return 0;
                }

                int prefix = 0;
                for (int i = 0; i < bytes_size; i++) {
                    int b = bytes[i];
                    while (b) {
                        prefix += b & 1; 
                        b >>= 1;
                    }
                }
                return prefix;
            }

            /**
             * @brief Validates endpoint pointer for routable unicast semantics.
             * @param p  Pointer to endpoint; null is considered invalid.
             * @return   true when @p p is null, none, any, or multicast (not a valid unicast).
             */
            static bool                                                         IsInvalid(const IPEndPoint* p) noexcept {
                IPEndPoint* __p = (IPEndPoint*)p;
                if (NULLPTR == __p) {
                    return true;
                }

                if (__p->IsNone()) {
                    return true;
                }

                if (__p->IsAny()) {
                    return true;
                }

                if (__p->IsMulticast()) {
                    return true;
                }
                return false;
            }

            /**
             * @brief Validates endpoint value for routable unicast semantics.
             * @param value  Endpoint to validate.
             * @return       true when the address is not a routable unicast.
             */
            static bool                                                         IsInvalid(const IPEndPoint& value) noexcept {
                return IPEndPoint::IsInvalid(addressof(value));
            }

            /**
             * @brief Validates a Boost address by converting to temporary endpoint.
             * @param address  Boost IP address to test.
             * @return         true when the address is not a routable unicast.
             */
            static bool                                                         IsInvalid(const boost::asio::ip::address& address) noexcept {
                return IsInvalid(IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(address, IPEndPoint::MinPort + 1)));
            }
        
        public:
            template <class TProtocol>
            /**
             * @brief Converts an endpoint to a target address family.
             *
             * If the address is already in the requested family it is returned unchanged.
             * Otherwise V6ToV4 or V4ToV6 mapping is applied.
             *
             * @tparam TProtocol     Boost.Asio protocol type (tcp, udp, …).
             * @param addressFamily  Desired target family.
             * @param remoteEP       Source endpoint to transform.
             * @return               Endpoint in the requested address family.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   Transform(AddressFamily addressFamily, const boost::asio::ip::basic_endpoint<TProtocol>& remoteEP) noexcept {
                boost::asio::ip::address address = remoteEP.address();
                if (addressFamily == AddressFamily::InterNetwork) {
                    if (address.is_v4()) {
                        return remoteEP;
                    }
                    else {
                        return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(remoteEP)));
                    }
                }
                else {
                    if (address.is_v6()) {
                        return remoteEP;
                    }
                    else {
                        return IPEndPoint::ToEndPoint<TProtocol>(IPEndPoint::V4ToV6(IPEndPoint::ToEndPoint(remoteEP)));
                    }
                }
            }
        
            template <class TProtocol>
            /**
             * @brief Converts @ref IPEndPoint to Boost endpoint.
             * @tparam TProtocol  Boost.Asio protocol type (tcp, udp, …).
             * @param endpoint    Source @ref IPEndPoint value.
             * @return            Equivalent Boost endpoint.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   ToEndPoint(const IPEndPoint& endpoint) noexcept {
                AddressFamily af = endpoint.GetAddressFamily();
                if (af == AddressFamily::InterNetwork) {
                    return WrapAddressV4<TProtocol>(endpoint.GetAddress(), endpoint.Port);
                }
                else {
                    int len;
                    const Byte* address = endpoint.GetAddressBytes(len);
                    return WrapAddressV6<TProtocol>(address, len, endpoint.Port, endpoint.ScopeId);
                }
            }
        
            template <class TProtocol>
            /**
             * @brief Converts Boost endpoint to @ref IPEndPoint.
             * @tparam TProtocol  Boost.Asio protocol type (tcp, udp, …).
             * @param endpoint    Source Boost endpoint.
             * @return            Equivalent @ref IPEndPoint value.
             */
            static IPEndPoint                                                   ToEndPoint(const boost::asio::ip::basic_endpoint<TProtocol>& endpoint) noexcept {
                boost::asio::ip::address address = endpoint.address();
                if (address.is_v4()) {
                    return IPEndPoint(ntohl(address.to_v4().to_uint()), endpoint.port());
                }
                elif(address.is_v6()) {
                    boost::asio::ip::address_v6 v6 = address.to_v6();
                    boost::asio::ip::address_v6::bytes_type bytes = v6.to_bytes();
                    IPEndPoint ep(AddressFamily::InterNetworkV6, bytes.data(), (int)bytes.size(), endpoint.port());
                    ep.ScopeId = v6.scope_id();
                    return ep;
                }
                else {
                    return IPEndPoint(IPEndPoint::AnyAddress, endpoint.port());
                }
            }
        
            template <class TProtocol>
            /**
             * @brief Parses address text and port into a Boost endpoint.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param address     Null-terminated IPv4 or IPv6 text; NULLPTR → "0.0.0.0".
             * @param port        Port in host byte order; clamped to [MinPort, MaxPort].
             * @return            Parsed Boost endpoint; INADDR_NONE on parse failure.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   NewAddress(const char* address, int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (NULLPTR == address || *address == '\x0') {
                    address = "0.0.0.0";
                }

                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                boost::system::error_code ec_;
                boost::asio::ip::address ba_ = StringToAddress(address, ec_);
                if (ec_) {
                    ba_ = boost::asio::ip::address_v4(IPEndPoint::NoneAddress);
                }

                return protocol_endpoint(ba_, port);
            }
        
            template <class TProtocol>
            /**
             * @brief Builds IPv4 Boost endpoint from numeric address and port.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param address     IPv4 address in **network byte order**.
             * @param port        Port in host byte order.
             * @return            IPv4 Boost endpoint with host-order address conversion applied.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   WrapAddressV4(UInt32 address, int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                return protocol_endpoint(boost::asio::ip::address_v4(ntohl(address)), port);
            }
        
            template <class TProtocol>
            /**
             * @brief Builds IPv6 Boost endpoint from raw bytes and port.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param address     Pointer to 16 raw IPv6 address bytes (network byte order).
             * @param size        Number of bytes available; excess bytes are zero-padded.
             * @param port        Port in host byte order.
             * @return            IPv6 Boost endpoint.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   WrapAddressV6(const void* address, int size, int port, unsigned long scope_id = 0) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (NULLPTR == address || size < 1 || port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    return protocol_endpoint();
                }

                boost::asio::ip::address_v6::bytes_type address_bytes;
                unsigned char* p = address_bytes.data();
                memcpy(p, address, std::min<int>(size, static_cast<int>(address_bytes.size())));
                memset(p, 0, address_bytes.size() - std::min<int>(size, static_cast<int>(address_bytes.size())));

                return protocol_endpoint(boost::asio::ip::address_v6(address_bytes, scope_id), port);
            }

            template <class TProtocol>
            /**
             * @brief Builds IPv4 any-address endpoint for a protocol.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param port        Port in host byte order; clamped to [MinPort, MaxPort].
             * @return            Endpoint with address_v4::any() and @p port.
             */
            static boost::asio::ip::basic_endpoint<TProtocol>                   AnyAddressV4(int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                return protocol_endpoint(boost::asio::ip::address_v4::any(), port);
            }
        
            template <class TProtocol>
            /**
             * @brief Compares two Boost endpoints including address and port.
             * @tparam TProtocol  Boost.Asio protocol type.
             * @param x           First endpoint.
             * @param y           Second endpoint.
             * @return            true when both address and port are identical.
             */
            static bool                                                         Equals(const boost::asio::ip::basic_endpoint<TProtocol>& x, const boost::asio::ip::basic_endpoint<TProtocol>& y) noexcept {
                if (x != y) {
                    return false;
                }

                return x.address() == y.address() && x.port() == y.port();
            }
        
        public:
            /**
             * @brief Converts IPv4-mapped IPv6 endpoint to IPv4 when possible.
             *
             * Applies RFC 4291 §2.5.5.2 detection: if the upper 80 bits are zero and
             * bits 80–95 are 0xffff, the endpoint is IPv4-mapped and the IPv4 address
             * is extracted.  Non-mapped IPv6 addresses are returned unchanged.
             *
             * @param destinationEP  Source endpoint.
             * @return               Equivalent IPv4 endpoint, or @p destinationEP unchanged.
             */
            static IPEndPoint                                                   V6ToV4(const IPEndPoint& destinationEP) noexcept {
                if (destinationEP.GetAddressFamily() == AddressFamily::InterNetwork) {
                    return destinationEP;
                }

#pragma pack(push, 1)
                struct  
#if defined(__GNUC__) || defined(__clang__)
                    __attribute__((packed)) 
#endif
                IPV62V4ADDR {
                    uint64_t R1;
                    uint16_t R2;
                    uint16_t R3;
                    uint32_t R4;
                };
#pragma pack(pop)

                int len;
                IPV62V4ADDR* in = (IPV62V4ADDR*)destinationEP.GetAddressBytes(len);
                if (in->R1 || in->R2 || in->R3 != UINT16_MAX) {
                    return destinationEP;
                }
                else {
                    return IPEndPoint(in->R4, destinationEP.Port);
                }
            }

            /**
             * @brief Converts IPv4 endpoint to IPv4-mapped IPv6 endpoint.
             *
             * Produces an IPv6 address in the ::ffff:a.b.c.d form per RFC 4291 §2.5.5.2.
             * An already-IPv6 endpoint is returned unchanged.
             *
             * @param destinationEP  Source IPv4 endpoint.
             * @return               IPv4-mapped IPv6 endpoint, or @p destinationEP if already IPv6.
             */
            static IPEndPoint                                                   V4ToV6(const IPEndPoint& destinationEP) noexcept {
                if (destinationEP.GetAddressFamily() == AddressFamily::InterNetworkV6) {
                    return destinationEP;
                }

#pragma pack(push, 1)
                struct  
#if defined(__GNUC__) || defined(__clang__)
                    __attribute__((packed)) 
#endif
                IPV62V4ADDR {
                    uint64_t R1;
                    uint16_t R2;
                    uint16_t R3;
                    uint32_t R4;
                };
#pragma pack(pop)

                IPV62V4ADDR in;
                in.R1 = 0;
                in.R2 = 0;
                in.R3 = UINT16_MAX;
                in.R4 = destinationEP.GetAddress();
                return IPEndPoint(AddressFamily::InterNetworkV6, &in, sizeof(IPV62V4ADDR), destinationEP.Port);
            }
        };
    }
}
