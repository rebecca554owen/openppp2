#include "DnsReachabilityParse.h"

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                static ppp::string TrimCopy(const ppp::string& text) {
                    std::size_t begin = 0;
                    while (begin < text.size() && std::isspace(static_cast<unsigned char>(text[begin]))) {
                        ++begin;
                    }
                    std::size_t end = text.size();
                    while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1]))) {
                        --end;
                    }
                    return text.substr(begin, end - begin);
                }

                bool ParseReachabilityIpv4(const ppp::string& address, uint32_t& ipnet) noexcept {
                    ipnet = 0;
                    if (address.empty()) {
                        return false;
                    }

                    ppp::string host = TrimCopy(address);
                    const std::size_t colon = host.rfind(':');
                    if (colon != ppp::string::npos && colon > 0) {
                        host = TrimCopy(host.substr(0, colon));
                    }
                    if (host.empty()) {
                        return false;
                    }

                    boost::system::error_code ec;
                    const boost::asio::ip::address ip = boost::asio::ip::make_address(host, ec);
                    if (ec || !ip.is_v4() || ip.is_unspecified() || ip.is_loopback() || ip.is_multicast()) {
                        return false;
                    }

                    ipnet = htonl(ip.to_v4().to_uint());
                    return true;
                }

            }
        }
    }
}
