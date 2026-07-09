#define BOOST_TEST_MODULE dns_buffer_test
#include <boost/test/included/unit_test.hpp>

#include <vector>

#include "buffer.h"

// Aim: encode then decode a simple domain name without corruption.
BOOST_AUTO_TEST_CASE(dns_buffer_roundtrip_domain) {
    std::vector<uint8_t> storage(512);
    dns::Buffer encoder(storage.data(), storage.size());
    encoder.writeDomainName("example.com");
    BOOST_REQUIRE(!encoder.isBroken());

    dns::Buffer decoder(storage.data(), encoder.pos());
    const std::string decoded = decoder.readDomainName();
    BOOST_REQUIRE(!decoder.isBroken());
    BOOST_TEST(decoded == "example.com");
}

// Aim: truncated label length byte marks the decoder as broken.
BOOST_AUTO_TEST_CASE(dns_buffer_rejects_truncated_label) {
    uint8_t raw[] = {0x10, 'e', 'x', 'a'};
    dns::Buffer decoder(raw, sizeof(raw));
    (void)decoder.readDomainName();
    BOOST_TEST(decoder.isBroken());
}

// Aim: encoding a long domain into a tiny buffer sets overflow/broken state.
BOOST_AUTO_TEST_CASE(dns_buffer_rejects_overflow_on_encode) {
    uint8_t storage[4] = {};
    dns::Buffer encoder(storage, sizeof(storage));
    encoder.writeDomainName("this-name-is-way-too-long.example.com");
    BOOST_TEST(encoder.isBroken());
}
