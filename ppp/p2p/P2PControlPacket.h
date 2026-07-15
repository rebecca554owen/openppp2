#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ppp::p2p {

enum class P2PControlType : std::uint8_t {
    Probe = 1,
    ProbeAck = 2,
    MigrateChallenge = 3,
    MigrateAck = 4,
};

struct P2PCandidateEndpoint {
    std::uint8_t address_family = 0;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;

    friend bool operator==(const P2PCandidateEndpoint& a,
                           const P2PCandidateEndpoint& b) noexcept {
        return a.address_family == b.address_family &&
               a.address == b.address && a.port == b.port;
    }
};

struct P2PControlPacket {
    static constexpr std::size_t WireSize = 126;

    std::uint8_t version = 0;
    P2PControlType type = P2PControlType::Probe;
    std::array<std::uint8_t, 32> offer_hash{};
    std::uint8_t sender_role = 0;
    std::uint8_t receiver_role = 0;
    std::uint8_t direction = 0;
    std::array<std::uint8_t, 16> connection_epoch{};
    P2PCandidateEndpoint source;
    P2PCandidateEndpoint destination;
    std::uint32_t sequence = 0;
    std::array<std::uint8_t, 12> nonce{};
    std::uint8_t ttl_seconds = 0;
    std::array<std::uint8_t, 16> token{};
};

inline bool IsCanonicalP2PCandidate(
    const P2PCandidateEndpoint& candidate) noexcept {
    if ((candidate.address_family != 4 && candidate.address_family != 6) ||
        candidate.port == 0) {
        return false;
    }
    if (candidate.address_family == 4) {
        for (std::size_t i = 0; i < 10; ++i) {
            if (candidate.address[i] != 0) return false;
        }
        if (candidate.address[10] != 0xff || candidate.address[11] != 0xff) {
            return false;
        }
    }
    return true;
}

namespace detail {
inline bool ParseCandidate(const std::vector<std::uint8_t>& bytes,
                           std::size_t offset,
                           P2PCandidateEndpoint& candidate) noexcept {
    candidate.address_family = bytes[offset];
    for (std::size_t i = 0; i < candidate.address.size(); ++i) {
        candidate.address[i] = bytes[offset + 1 + i];
    }
    candidate.port = static_cast<std::uint16_t>(bytes[offset + 17]) << 8 |
                     static_cast<std::uint16_t>(bytes[offset + 18]);
    return IsCanonicalP2PCandidate(candidate);
}
}

inline bool ParseP2PControlPacket(const std::vector<std::uint8_t>& bytes,
                                  P2PControlPacket& packet) noexcept {
    if (bytes.size() != P2PControlPacket::WireSize || bytes[0] != 1 ||
        bytes[2] != 0 || bytes[3] != 0 || bytes[36] > 1 ||
        bytes[37] > 1 || bytes[36] == bytes[37] || bytes[38] > 1 ||
        bytes[38] != bytes[36] ||
        bytes[109] < 1 || bytes[109] > 30) {
        return false;
    }
    if (bytes[1] < static_cast<std::uint8_t>(P2PControlType::Probe) ||
        bytes[1] > static_cast<std::uint8_t>(P2PControlType::MigrateAck)) {
        return false;
    }

    P2PControlPacket parsed;
    parsed.version = bytes[0];
    parsed.type = static_cast<P2PControlType>(bytes[1]);
    for (std::size_t i = 0; i < parsed.offer_hash.size(); ++i) {
        parsed.offer_hash[i] = bytes[4 + i];
    }
    parsed.sender_role = bytes[36];
    parsed.receiver_role = bytes[37];
    parsed.direction = bytes[38];
    for (std::size_t i = 0; i < parsed.connection_epoch.size(); ++i) {
        parsed.connection_epoch[i] = bytes[39 + i];
    }
    if (!detail::ParseCandidate(bytes, 55, parsed.source) ||
        !detail::ParseCandidate(bytes, 74, parsed.destination)) {
        return false;
    }
    parsed.sequence = static_cast<std::uint32_t>(bytes[93]) << 24 |
                      static_cast<std::uint32_t>(bytes[94]) << 16 |
                      static_cast<std::uint32_t>(bytes[95]) << 8 |
                      static_cast<std::uint32_t>(bytes[96]);
    for (std::size_t i = 0; i < parsed.nonce.size(); ++i) {
        parsed.nonce[i] = bytes[97 + i];
    }
    parsed.ttl_seconds = bytes[109];
    for (std::size_t i = 0; i < parsed.token.size(); ++i) {
        parsed.token[i] = bytes[110 + i];
    }
    packet = parsed;
    return true;
}

}
