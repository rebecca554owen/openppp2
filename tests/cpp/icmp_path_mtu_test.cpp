#define BOOST_TEST_MODULE icmp_path_mtu_test
#include <boost/test/included/unit_test.hpp>

#include <cstring>

#include <ppp/app/protocol/VirtualEthernetPathMtu.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>

using ppp::Byte;
using ppp::app::protocol::IcmpPathMtuError;
using ppp::app::protocol::TryParseIcmpPathMtuError;
using ppp::app::protocol::GetVirtualEthernetPathMtuCache;
using ppp::app::protocol::ComputeDynamicTcpMss;
using ppp::app::protocol::kVEthernetTunnelOverhead;
using ppp::net::native::icmp_hdr;
using ppp::net::native::ip_hdr;

namespace {

constexpr int kOuterHeaderLength = 20;
constexpr int kIcmpHeaderLength = 8;
constexpr int kQuotedHeaderLength = 20;
constexpr int kQuotedTransportLength = 8;
constexpr int kPacketLength = kOuterHeaderLength + kIcmpHeaderLength +
    kQuotedHeaderLength + kQuotedTransportLength;
constexpr ppp::UInt32 kRouter = 0xc0000201; // 192.0.2.1
constexpr ppp::UInt32 kClient = 0x0a000002; // 10.0.0.2
constexpr ppp::UInt32 kRemote = 0xc6336401; // 198.51.100.1

void BuildIcmpError(Byte* packet, Byte type, Byte code, unsigned short mtu) {
    std::memset(packet, 0, kPacketLength);

    ip_hdr* outer = reinterpret_cast<ip_hdr*>(packet);
    outer->v_hl = 0x45;
    outer->len = htons(kPacketLength);
    outer->ttl = 64;
    outer->proto = ip_hdr::IP_PROTO_ICMP;
    outer->src = htonl(kRouter);
    outer->dest = htonl(kClient);

    icmp_hdr* icmp = reinterpret_cast<icmp_hdr*>(packet + kOuterHeaderLength);
    icmp->icmp_type = type;
    icmp->icmp_code = code;
    icmp->icmp_id = 0;
    icmp->icmp_seq = htons(mtu);

    ip_hdr* quoted = reinterpret_cast<ip_hdr*>(packet + kOuterHeaderLength + kIcmpHeaderLength);
    quoted->v_hl = 0x45;
    quoted->len = htons(kQuotedHeaderLength + kQuotedTransportLength);
    quoted->ttl = 64;
    quoted->proto = ip_hdr::IP_PROTO_UDP;
    quoted->src = htonl(kClient);
    quoted->dest = htonl(kRemote);

    icmp->icmp_chksum = ppp::net::native::inet_chksum(icmp,
        kPacketLength - kOuterHeaderLength);
    outer->chksum = ppp::net::native::inet_chksum(outer, kOuterHeaderLength);
}

} // namespace

BOOST_AUTO_TEST_CASE(parses_fragmentation_needed_and_preserves_next_hop_mtu) {
    Byte packet[kPacketLength];
    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 4, 1300);

    IcmpPathMtuError error;
    BOOST_REQUIRE(TryParseIcmpPathMtuError(packet, kPacketLength, error));
    BOOST_TEST(error.IsPathMtuUpdate);
    BOOST_TEST(error.NextHopMtu == 1300);
    BOOST_TEST(error.OuterDestination == htonl(kClient));
    BOOST_TEST(error.QuotedSource == htonl(kClient));
    BOOST_TEST(error.QuotedDestination == htonl(kRemote));
    BOOST_TEST(error.QuotedProtocol == ip_hdr::IP_PROTO_UDP);
}

BOOST_AUTO_TEST_CASE(accepts_time_exceeded_without_pmtu_update) {
    Byte packet[kPacketLength];
    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_TE, 0, 0);

    IcmpPathMtuError error;
    BOOST_REQUIRE(TryParseIcmpPathMtuError(packet, kPacketLength, error));
    BOOST_TEST(!error.IsPathMtuUpdate);
    BOOST_TEST(error.NextHopMtu == 0);
}

BOOST_AUTO_TEST_CASE(rejects_invalid_checksum_unsupported_code_and_short_quote) {
    Byte packet[kPacketLength];
    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 4, 1300);
    packet[kOuterHeaderLength + kIcmpHeaderLength + kQuotedHeaderLength] ^= 0x01;

    IcmpPathMtuError error;
    BOOST_TEST(!TryParseIcmpPathMtuError(packet, kPacketLength, error));

    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 3, 1300);
    BOOST_TEST(!TryParseIcmpPathMtuError(packet, kPacketLength, error));

    BuildIcmpError(packet, ppp::net::native::IcmpType::ICMP_DUR, 4, 1300);
    BOOST_TEST(!TryParseIcmpPathMtuError(packet, kPacketLength - 1, error));
}

BOOST_AUTO_TEST_CASE(cache_only_lowers_pmtu_and_expires) {
    auto& cache = GetVirtualEthernetPathMtuCache();
    cache.Clear();
    const ppp::UInt32 destination = htonl(kRemote);
    const ppp::UInt64 now = 1000;

    BOOST_TEST(cache.Observe(destination, 1300, now));
    BOOST_TEST(cache.Lookup(destination, now) == 1300);
    BOOST_TEST(!cache.Observe(destination, 1400, now + 1));
    BOOST_TEST(cache.Lookup(destination, now + 1) == 1300);
    BOOST_TEST(ComputeDynamicTcpMss(true, kVEthernetTunnelOverhead,
        cache.Lookup(destination, now + 1)) == 1260);
    BOOST_TEST(cache.Lookup(destination,
        now + ppp::app::protocol::VirtualEthernetPathMtuCache::kLifetimeMilliseconds + 2) == 0);
}
