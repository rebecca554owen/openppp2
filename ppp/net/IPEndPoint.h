#pragma once

/**
 * @file IPEndPoint.h
 * @brief Endpoint abstraction for IPv4/IPv6 address and port operations.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace net {
        /**
         * @brief IP address family used by @ref IPEndPoint.
         */
        enum AddressFamily {
            InterNetwork = AF_INET,
            InterNetworkV6 = AF_INET6,
        };

        /**
         * @brief Represents an immutable port with mutable IPv4/IPv6 address bytes.
         */
        struct IPEndPoint {
        private:
            /** @brief Raw address bytes (always allocated with IPv6 size). */
            mutable Byte                                                        _AddressBytes[sizeof(struct in6_addr)]; // 16
            /** @brief Address family that determines how @ref _AddressBytes is interpreted. */
            AddressFamily                                                       _AddressFamily;

        public:
            /** @brief Transport port in host order. */
            const int                                                           Port;

        public:
            static constexpr int                                                MinPort          = 0;
            static constexpr int                                                MaxPort          = UINT16_MAX;
            static constexpr UInt32                                             AnyAddress       = INADDR_ANY;
            static constexpr UInt32                                             NoneAddress      = INADDR_NONE;
            static constexpr UInt32                                             LoopbackAddress  = INADDR_LOOPBACK;
            static constexpr UInt32                                             BroadcastAddress = INADDR_BROADCAST;

        public:
            /** @brief Initializes endpoint as invalid/none with port 0. */
            IPEndPoint() noexcept
                : IPEndPoint(NoneAddress, IPEndPoint::MinPort) {

            }
            /**
             * @brief Creates an IPv4 endpoint from 32-bit address and port.
             * @param address IPv4 address in network byte order.
             * @param port Port in host order.
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
             * @param address IPv4/IPv6 text.
             * @param port Port in host order.
             */
            IPEndPoint(const char* address, int port) noexcept;
            /**
             * @brief Creates an endpoint from raw address bytes.
             * @param af Address family.
             * @param address_bytes Raw address bytes.
             * @param address_size Number of bytes available in @p address_bytes.
             * @param port Port in host order.
             */
            IPEndPoint(AddressFamily af, const void* address_bytes, int address_size, int port) noexcept;

        public:
            /** @brief Creates IPv4 any-address endpoint. */
            static IPEndPoint                                                   Any(int port) noexcept {
                return IPEndPoint(IPEndPoint::AnyAddress, port);
            }
            /** @brief Creates IPv4 loopback endpoint. */
            static IPEndPoint                                                   Loopback(int port) noexcept {
                return IPEndPoint(IPEndPoint::LoopbackAddress, port);
            }
            /** @brief Creates IPv4 broadcast endpoint. */
            static IPEndPoint                                                   Broadcast(int port) noexcept {
                return IPEndPoint(IPEndPoint::BroadcastAddress, port);
            }
            /** @brief Creates IPv4 none-address endpoint. */
            static IPEndPoint                                                   None(int port) noexcept {
                return IPEndPoint(IPEndPoint::NoneAddress, port);
            }
            /** @brief Creates IPv6 any-address endpoint. */
            static IPEndPoint                                                   IPv6Any(int port) noexcept {
                boost::asio::ip::tcp::endpoint localEP(boost::asio::ip::address_v6::any(), port);
                return ToEndPoint(localEP);
            }
            /** @brief Creates IPv6 loopback endpoint. */
            static IPEndPoint                                                   IPv6Loopback(int port) noexcept {
                boost::asio::ip::tcp::endpoint localEP(boost::asio::ip::address_v6::loopback(), port);
                return ToEndPoint(localEP);
            }
            /** @brief Creates IPv6 none-address endpoint (mapped to IPv6 any). */
            static IPEndPoint                                                   IPv6None(int port) noexcept {
                return IPv6Any(port);
            }

        public:     
            /** @brief Checks whether this endpoint is considered broadcast. */
            bool                                                                IsBroadcast() noexcept {
                return this->IsNone();
            }
            /** @brief Checks whether address bytes represent the none/broadcast value. */
            bool                                                                IsNone() noexcept {
                if (AddressFamily::InterNetwork != this->_AddressFamily) {
                    int len;
                    Byte* p = this->GetAddressBytes(len);
                    return *p == 0xff;
                }
                else {
                    return this->GetAddress() == IPEndPoint::NoneAddress;
                }
            }
            /** @brief Checks whether this endpoint is any/unspecified address. */
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
            /** @brief Checks whether this endpoint is a loopback address. */
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
            /** @brief Checks whether endpoint address belongs to multicast range. */
            bool                                                                IsMulticast() noexcept {
                return ToEndPoint<boost::asio::ip::tcp>(*this).address().is_multicast();
            }

        public:     
            /** @brief Copies raw address bytes into a binary string. */
            ppp::string                                                         GetAddressBytes() const noexcept {
                int datalen;
                Byte* data = this->GetAddressBytes(datalen);
                return ppp::string((char*)data, datalen);
            }
            /**
             * @brief Gets mutable raw address bytes and effective length.
             * @param len Receives 4 for IPv4 or 16 for IPv6.
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
            /** @brief Gets IPv4 address value from internal storage. */
            UInt32                                                              GetAddress() const noexcept {
                return *(UInt32*)this->_AddressBytes;
            }
            /** @brief Gets the current address family. */
            AddressFamily                                                       GetAddressFamily() const noexcept {
                return this->_AddressFamily;
            }
            /** @brief Compares this endpoint with another endpoint instance. */
            bool                                                                Equals(const IPEndPoint& value) const {
                IPEndPoint* reft = (IPEndPoint*)&reinterpret_cast<const char&>(value);
                IPEndPoint* left = (IPEndPoint*)this;
                if (left == reft) {
                    return true;
                }

                return *left == *reft;
            }

        public:     
            /** @brief Compares address family and raw address bytes. */
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
            /** @brief Negated equality comparison. */
            bool                                                                operator != (const IPEndPoint& right) const noexcept {
                bool b = (*this) == right;
                return !b;
            }
            /** @brief Assigns address family, port, and address bytes from another endpoint. */
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
             * @tparam TString String type to return.
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
            /** @brief Converts current endpoint address to text. */
            ppp::string                                                         ToAddressString() noexcept {
                int address_bytes_size;
                Byte* address_bytes = GetAddressBytes(address_bytes_size);
                return ToAddressString<ppp::string>(this->_AddressFamily, address_bytes, address_bytes_size);
            }
            /** @brief Computes a simple additive hash over family, port, and address bytes. */
            int                                                                 GetHashCode() const noexcept {
                int h = this->GetAddressFamily() + this->Port;
                int l = 0;
                Byte* p = this->GetAddressBytes(l);
                for (int i = 0; i < l; i++) {
                    h += *p++;
                }
                return h;
            }
            /** @brief Converts endpoint to `host:port` or `[host]:port` text. */
            ppp::string                                                         ToString() noexcept;

        public:
            /** @brief Gets local host name from system APIs. */
            static ppp::string                                                  GetHostName() noexcept;

        public:
            /** @brief Converts IPv4 numeric address to text. */
            static ppp::string                                                  ToAddressString(UInt32 address) noexcept {
                return ToAddressString<ppp::string>(AddressFamily::InterNetwork, (Byte*)&address, sizeof(address));
            }
            /** @brief Converts serialized address bytes to text by family. */
            static ppp::string                                                  ToAddressString(AddressFamily af, const ppp::string& address_bytes) noexcept {
                return ToAddressString<ppp::string>(af, (Byte*)address_bytes.data(), (int)address_bytes.size());
            }
            /** @brief Converts IPv4 prefix length to netmask in network order. */
            static UInt32                                                       PrefixToNetmask(int prefix) noexcept {
                UInt32 mask = prefix ? (~0UL << (32 - prefix)) : 0L;
                return htonl(mask);
            }
            /** @brief Converts IPv4 netmask in network order to prefix length. */
            static int                                                          NetmaskToPrefix(UInt32 mask) noexcept {
                return NetmaskToPrefix(reinterpret_cast<unsigned char*>(&mask), sizeof(mask));
            }
            /** @brief Converts arbitrary netmask bytes to number of set bits. */
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
            /** @brief Validates endpoint pointer for routable unicast semantics. */
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
            /** @brief Validates endpoint value for routable unicast semantics. */
            static bool                                                         IsInvalid(const IPEndPoint& value) noexcept {
                return IPEndPoint::IsInvalid(addressof(value));
            }
            /** @brief Validates a Boost address by converting to temporary endpoint. */
            static bool                                                         IsInvalid(const boost::asio::ip::address& address) noexcept {
                return IsInvalid(IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(address, IPEndPoint::MinPort + 1)));
            }
        
        public:     
            template <class TProtocol>       
            /**
             * @brief Converts an endpoint to a target address family.
             * @tparam TProtocol Boost protocol type.
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
            /** @brief Converts @ref IPEndPoint to Boost endpoint. */
            static boost::asio::ip::basic_endpoint<TProtocol>                   ToEndPoint(const IPEndPoint& endpoint) noexcept {
                AddressFamily af = endpoint.GetAddressFamily();
                if (af == AddressFamily::InterNetwork) {
                    return WrapAddressV4<TProtocol>(endpoint.GetAddress(), endpoint.Port);
                }
                else {
                    int len;
                    const Byte* address = endpoint.GetAddressBytes(len);
                    return WrapAddressV6<TProtocol>(address, len, endpoint.Port);
                }
            }
        
            template <class TProtocol>       
            /** @brief Converts Boost endpoint to @ref IPEndPoint. */
            static IPEndPoint                                                   ToEndPoint(const boost::asio::ip::basic_endpoint<TProtocol>& endpoint) noexcept {
                boost::asio::ip::address address = endpoint.address();
                if (address.is_v4()) {
                    return IPEndPoint(ntohl(address.to_v4().to_uint()), endpoint.port());
                }
                elif(address.is_v6()) {
                    boost::asio::ip::address_v6::bytes_type bytes = address.to_v6().to_bytes();
                    return IPEndPoint(AddressFamily::InterNetworkV6, bytes.data(), (int)bytes.size(), endpoint.port());
                }
                else {
                    return IPEndPoint(IPEndPoint::AnyAddress, endpoint.port());
                }
            }
        
            template <class TProtocol>       
            /** @brief Parses address text and port into a Boost endpoint. */
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
            /** @brief Builds IPv4 Boost endpoint from numeric address and port. */
            static boost::asio::ip::basic_endpoint<TProtocol>                   WrapAddressV4(UInt32 address, int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                return protocol_endpoint(boost::asio::ip::address_v4(ntohl(address)), port);
            }
        
            template <class TProtocol>       
            /** @brief Builds IPv6 Boost endpoint from raw bytes and port. */
            static boost::asio::ip::basic_endpoint<TProtocol>                   WrapAddressV6(const void* address, int size, int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (size < 0) {
                    size = 0;
                }

                boost::asio::ip::address_v6::bytes_type address_bytes;
                unsigned char* p = address_bytes.data();
                memcpy(p, address, size);
                memset(p, 0, address_bytes.size() - size);

                return protocol_endpoint(boost::asio::ip::address_v6(address_bytes), port);
            }
        
            template <class TProtocol>       
            /** @brief Builds IPv4 any-address endpoint for a protocol. */
            static boost::asio::ip::basic_endpoint<TProtocol>                   AnyAddressV4(int port) noexcept {
                typedef boost::asio::ip::basic_endpoint<TProtocol> protocol_endpoint;

                if (port < IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                    port = IPEndPoint::MinPort;
                }

                return protocol_endpoint(boost::asio::ip::address_v4::any(), port);
            }
        
            template <class TProtocol>       
            /** @brief Compares two Boost endpoints including address and port. */
            static bool                                                         Equals(const boost::asio::ip::basic_endpoint<TProtocol>& x, const boost::asio::ip::basic_endpoint<TProtocol>& y) noexcept {
                if (x != y) {
                    return false;
                }

                return x.address() == y.address() && x.port() == y.port();
            }
        
        public:     
            /** @brief Converts IPv4-mapped IPv6 endpoint to IPv4 when possible. */
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
            /** @brief Converts IPv4 endpoint to IPv4-mapped IPv6 endpoint. */
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
