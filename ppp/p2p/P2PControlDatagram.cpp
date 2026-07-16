#include <ppp/p2p/P2PControlDatagram.h>

#include <utility>

namespace ppp::p2p {

bool CreateAuthenticatedProbeDatagram(
    P2PClientOfferSession& session,
    const P2PCandidateEndpoint& source,
    const P2PCandidateEndpoint& destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    std::vector<std::uint8_t>& output) noexcept {
    P2PControlPacket probe;
    if (!session.CreateAuthenticatedProbe(
            source, destination, now_ms, generation, probe)) {
        return false;
    }

    std::vector<std::uint8_t> datagram;
    if (!SerializeP2PControlPacket(probe, datagram)) {
        return false;
    }
    output.swap(datagram);
    return true;
}

bool HandleAuthenticatedControlDatagram(
    P2PClientOfferSession& session,
    const std::vector<std::uint8_t>& datagram,
    const P2PCandidateEndpoint& observed_source,
    const P2PCandidateEndpoint& observed_destination,
    std::uint64_t now_ms,
    std::uint64_t generation,
    P2PControlDatagramResult& output) noexcept {
    P2PControlPacket packet;
    if (!ParseP2PControlPacket(datagram, packet)) {
        return false;
    }

    P2PControlDatagramResult result;
    if (packet.type == P2PControlType::Probe) {
        P2PControlPacket ack;
        if (!session.CreateAuthenticatedProbeAck(
                packet, observed_source, observed_destination,
                now_ms, generation, ack) ||
            !SerializeP2PControlPacket(ack, result.reply)) {
            return false;
        }
        result.action = P2PControlDatagramAction::Reply;
    }
    else if (packet.type == P2PControlType::ProbeAck) {
        auto proof = session.AuthenticateProbeAck(
            packet, observed_source, observed_destination,
            now_ms, generation);
        if (!proof) {
            return false;
        }
        result.action = P2PControlDatagramAction::AuthenticatedAck;
        result.authenticated_ack.emplace(std::move(*proof));
    }
    else {
        return false;
    }

    output = std::move(result);
    return true;
}

}
