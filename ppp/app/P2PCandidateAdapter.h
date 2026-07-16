#pragma once

#include <ppp/p2p/P2PRelayOfferCoordinator.h>

#include <boost/asio/ip/udp.hpp>
#include <string>

namespace ppp::app {

bool P2PCandidateFromEndpoint(
    const boost::asio::ip::udp::endpoint& endpoint,
    ppp::p2p::P2PCandidateV1& output) noexcept;

std::string P2PEndpointToString(
    const boost::asio::ip::udp::endpoint& endpoint) noexcept;

}
