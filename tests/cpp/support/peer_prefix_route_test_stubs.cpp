#include <ppp/stdafx.h>
#include <boost/asio/ip/address.hpp>

namespace ppp {

boost::asio::ip::address StringToAddress(const char* s, boost::system::error_code& ec) noexcept {
    return boost::asio::ip::make_address(s, ec);
}

}  // namespace ppp
