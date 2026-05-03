#include <stdio.h>
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#include <WS2tcpip.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <string>

#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>

/**
 * @file IPEndPoint.cpp
 * @brief Implements endpoint construction, host name lookup, and endpoint string conversion.
 */

namespace ppp {
    namespace net {
        /**
         * @brief Constructs an endpoint from textual IP address and port.
         * @param address IPv4/IPv6 address string.
         * @param port Network port.
         */
        IPEndPoint::IPEndPoint(const char* address, int port) noexcept
            : _AddressFamily(AddressFamily::InterNetwork)
            , Port(port) {
            
            if (NULLPTR == address || *address == '\x0') {
                this->_AddressFamily = AddressFamily::InterNetwork;
                *(UInt32*)this->_AddressBytes = IPEndPoint::NoneAddress;
            }
            else {
                /** @brief Try IPv6 first, then IPv4, and fallback to unspecified IPv4 address. */
                struct in_addr addr4;  /* char ipv6_buf[INET6_ADDRSTRLEN];                         */
                struct in6_addr addr6; /* inet_ntop(AF_INET6, &addr6, ipv6_buf, INET6_ADDRSTRLEN); */
                if (inet_pton(AF_INET6, address, &addr6) > 0) {
                    this->_AddressFamily = AddressFamily::InterNetworkV6;  
                    memcpy(this->_AddressBytes, addr6.s6_addr, sizeof(addr6.s6_addr));
                }
                elif(inet_pton(AF_INET, address, &addr4) > 0) {
                    *(UInt32*)this->_AddressBytes = addr4.s_addr;
                    this->_AddressFamily = AddressFamily::InterNetwork;
                }
                else {
                    this->_AddressFamily = AddressFamily::InterNetwork;
                    *(UInt32*)this->_AddressBytes = IPEndPoint::NoneAddress;
                }
            }
        }

        /**
         * @brief Constructs an endpoint from raw address bytes.
         * @param af Address family.
         * @param address_bytes Pointer to address bytes.
         * @param address_size Byte length of provided address data.
         * @param port Network port.
         */
        IPEndPoint::IPEndPoint(AddressFamily af, const void* address_bytes, int address_size, int port) noexcept
            : _AddressFamily(af)
            , Port(port) {
            int limit_size = 0;
            if (af == AddressFamily::InterNetworkV6) {
                limit_size = sizeof(struct in6_addr);
            }
            else {
                af = AddressFamily::InterNetwork;
                limit_size = sizeof(struct in_addr);
            }

            memset(this->_AddressBytes, 0, limit_size);
            if (NULLPTR != address_bytes && address_size > 0) {
                memcpy(this->_AddressBytes, address_bytes, std::min<int>(address_size, limit_size));
            }
            
            this->_AddressFamily = af;
        }

        /**
         * @brief Retrieves the local host name.
         * @return Host name, or `localhost` as fallback.
         */
        ppp::string IPEndPoint::GetHostName() noexcept {
            /** @brief Use a fixed buffer for system host name retrieval. */
            char hostname[256];
            hostname[0x00] = '\x0';
            hostname[0xff] = '\x0';

            if (::gethostname(hostname, sizeof(hostname)) != 0) {
                *hostname = '\x0';
            }

            if (*hostname != '\x0') {
                return hostname;
            }
            else {
                return "localhost";
            }
        }

        /**
         * @brief Converts endpoint to `address:port` style text.
         * @return Formatted endpoint string.
         */
        ppp::string IPEndPoint::ToString() noexcept {
            return Ipep::ToIpepAddress(this);
        }
    }
}
