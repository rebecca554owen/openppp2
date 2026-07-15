#define BOOST_TEST_MODULE p2p_control_packet_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PControlPacket.h>

#include <vector>

using namespace ppp::p2p;

namespace {
std::vector<std::uint8_t> ValidProbe() {
    std::vector<std::uint8_t> bytes(P2PControlPacket::WireSize, 0);
    bytes[0] = 1;
    bytes[1] = static_cast<std::uint8_t>(P2PControlType::Probe);
    bytes[4 + 32] = 0;
    bytes[4 + 33] = 1;
    bytes[4 + 34] = 0;
    bytes[4 + 35 + 16] = 4;
    bytes[4 + 35 + 16 + 1 + 10] = 0xff;
    bytes[4 + 35 + 16 + 1 + 11] = 0xff;
    bytes[4 + 35 + 16 + 17] = 0x12;
    bytes[4 + 35 + 16 + 18] = 0x34;
    bytes[4 + 35 + 16 + 19] = 6;
    bytes[4 + 35 + 16 + 19 + 17] = 0x56;
    bytes[4 + 35 + 16 + 19 + 18] = 0x78;
    bytes[109] = 30;
    for (std::size_t i = 0; i < 16; ++i) bytes[110 + i] = 0xa0 + i;
    return bytes;
}
}

BOOST_AUTO_TEST_CASE(parses_a_bounded_version_one_probe_vector) {
    P2PControlPacket packet;
    const auto bytes = ValidProbe();
    BOOST_REQUIRE(ParseP2PControlPacket(bytes, packet));
    BOOST_TEST(packet.version == 1u);
    BOOST_TEST(packet.source.address_family == 4u);
    BOOST_TEST(packet.source.port == 0x1234u);
    BOOST_TEST(packet.ttl_seconds == 30u);
    BOOST_TEST(packet.token[0] == 0xa0u);
    BOOST_TEST(packet.token[15] == 0xafu);
}

BOOST_AUTO_TEST_CASE(rejects_unknown_version_and_message_type) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[0] = 2;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[1] = 0xff;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
}

BOOST_AUTO_TEST_CASE(rejects_reserved_bits_and_bytes) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[2] = 1;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[3] = 1;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
}

BOOST_AUTO_TEST_CASE(rejects_every_truncated_vector_and_oversized_vector) {
    P2PControlPacket packet;
    const auto valid = ValidProbe();
    for (std::size_t size = 0; size < valid.size(); ++size) {
        BOOST_TEST(!ParseP2PControlPacket(
            std::vector<std::uint8_t>(valid.begin(), valid.begin() + size), packet));
    }
    auto oversized = valid;
    oversized.push_back(0);
    BOOST_TEST(!ParseP2PControlPacket(oversized, packet));
}

BOOST_AUTO_TEST_CASE(rejects_invalid_roles_direction_ttl_and_address_family) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[4 + 32] = 2;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[4 + 33] = 0;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[4 + 34] = 2;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[109] = 0;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
    bytes = ValidProbe();
    bytes[4 + 35 + 16] = 5;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));
}

BOOST_AUTO_TEST_CASE(rejects_noncanonical_ipv4_and_direction_role_mismatch) {
    P2PControlPacket packet;
    auto bytes = ValidProbe();
    bytes[4 + 34] = 1;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));

    bytes = ValidProbe();
    const auto source = 4 + 35 + 16;
    bytes[source] = 4;
    bytes[source + 1 + 10] = 0;
    bytes[source + 1 + 11] = 0;
    bytes[source + 1 + 10] = 0xff;
    BOOST_TEST(!ParseP2PControlPacket(bytes, packet));

    bytes[source + 1 + 11] = 0xff;
    BOOST_TEST(ParseP2PControlPacket(bytes, packet));
}
