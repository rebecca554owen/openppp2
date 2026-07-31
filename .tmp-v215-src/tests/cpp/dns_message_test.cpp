#define BOOST_TEST_MODULE dns_message_test
#include <boost/test/included/unit_test.hpp>

#include "message.h"

namespace {
    std::vector<uint8_t> HeaderWithCounts(uint16_t qd, uint16_t an, uint16_t ns, uint16_t ar) {
        std::vector<uint8_t> packet(12, 0);
        packet[0] = 0x12;
        packet[1] = 0x34;
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[4] = static_cast<uint8_t>(qd >> 8);
        packet[5] = static_cast<uint8_t>(qd);
        packet[6] = static_cast<uint8_t>(an >> 8);
        packet[7] = static_cast<uint8_t>(an);
        packet[8] = static_cast<uint8_t>(ns >> 8);
        packet[9] = static_cast<uint8_t>(ns);
        packet[10] = static_cast<uint8_t>(ar >> 8);
        packet[11] = static_cast<uint8_t>(ar);
        return packet;
    }
}

BOOST_AUTO_TEST_CASE(dns_message_rejects_impossible_answer_count_without_allocating) {
    std::vector<uint8_t> packet = HeaderWithCounts(0, 0xffff, 0, 0);
    dns::Message message;
    BOOST_TEST(static_cast<int>(message.decode(packet.data(), packet.size())) == static_cast<int>(dns::BufferResult::BufferOverflow));
    BOOST_TEST(message.answers.empty());
}

BOOST_AUTO_TEST_CASE(dns_message_rejects_impossible_authority_count_without_allocating) {
    std::vector<uint8_t> packet = HeaderWithCounts(0, 0, 0xffff, 0);
    dns::Message message;
    BOOST_TEST(static_cast<int>(message.decode(packet.data(), packet.size())) == static_cast<int>(dns::BufferResult::BufferOverflow));
    BOOST_TEST(message.authorities.empty());
}

BOOST_AUTO_TEST_CASE(dns_message_rejects_impossible_additional_count_without_allocating) {
    std::vector<uint8_t> packet = HeaderWithCounts(0, 0, 0, 0xffff);
    dns::Message message;
    BOOST_TEST(static_cast<int>(message.decode(packet.data(), packet.size())) == static_cast<int>(dns::BufferResult::BufferOverflow));
    BOOST_TEST(message.additions.empty());
}

BOOST_AUTO_TEST_CASE(dns_message_accepts_minimal_empty_rr) {
    std::vector<uint8_t> packet = HeaderWithCounts(0, 1, 0, 0);
    packet.insert(packet.end(), {
        0x00,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3c,
        0x00, 0x00,
    });

    dns::Message message;
    BOOST_TEST(static_cast<int>(message.decode(packet.data(), packet.size())) == static_cast<int>(dns::BufferResult::NoError));
    BOOST_TEST(message.answers.size() == 1u);
}
