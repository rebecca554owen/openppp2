// XTCP-ZERO-WINDOW-CONTRACT: the pinned upstream XTCP tree has no explicit
// receive-resume API. App backpressure is expressed the RFC 1122 way: the
// receiver rolls RCV.NXT back and advertises a ZERO window, and the peer
// resumes the flow by re-sending the unacknowledged data (RTO
// retransmission) or with an RFC 1122 persist probe. This test pins that
// contract, which the openppp2 runtime relies on after the pin move.
#include <xtcp/buf/bufref.h>
#include <xtcp/core/tcp.h>

#include <algorithm>
#include <cstdio>
#include <vector>

using namespace xtcp::core;

namespace {

int failures = 0;

#define CHECK(value) do { \
    if (!(value)) { ++failures; std::fprintf(stderr, "FAIL %d: %s\n", __LINE__, #value); } \
} while (0)

void Put32(Byte* p, UInt32 v) {
    p[0] = Byte(v >> 24); p[1] = Byte(v >> 16);
    p[2] = Byte(v >> 8); p[3] = Byte(v);
}

constexpr UInt32 kWindow = 65535;

struct Probe {
    TcpConn conn;
    std::vector<std::vector<Byte>> ack_packets;
    std::vector<Byte> received;
    bool allow_tail = false;

    Probe(TcpState state, UInt32 irs) : conn(state, Endpoint4(), Endpoint4(), 100, irs,
                                            [this](xtcp::buf::BufRef&& ref) {
                                                ack_packets.emplace_back(ref.Data(), ref.Data() + ref.Len());
                                            }) {
        conn.SetSackOk(true);
        conn.SetRecvHandler([this](const Byte* data, UInt32 n) {
            if (received.size() >= 1000 && !allow_tail) return false;
            received.insert(received.end(), data, data + n);
            return true;
        });
    }

    static Endpoint& Endpoint4() {
        static Endpoint endpoint;
        endpoint.family = 4;
        endpoint.addr[0] = 0x0a000001;
        endpoint.port = 443;
        return endpoint;
    }

    void Segment(UInt32 seq, Byte fill, UInt32 len) {
        std::vector<Byte> packet(20 + len, 0);
        packet[0] = 0x01; packet[1] = 0xbb;
        packet[2] = 0x01; packet[3] = 0xbb;
        Put32(packet.data() + 4, seq);
        Put32(packet.data() + 8, 101);
        packet[12] = 0x50;
        packet[13] = Byte(kFlagAck);
        std::fill(packet.begin() + 20, packet.end(), fill);
        conn.OnSegment(packet.data(), static_cast<UInt32>(packet.size()));
    }
};

bool SackContains(const std::vector<std::vector<Byte>>& output, UInt32 begin, UInt32 end) {
    for (const std::vector<Byte>& data : output) {
        if (data.size() < 40) continue;
        const UInt32 tcp_offset = (data[0] & 15U) * 4U;
        if (data.size() < tcp_offset + 20U) continue;
        const UInt32 tcp_end = tcp_offset + (data[tcp_offset + 12] >> 4U) * 4U;
        UInt32 offset = tcp_offset + 20U;
        while (offset < tcp_end) {
            const Byte kind = data[offset];
            if (kind == 0) break;
            if (kind == 1) {
                ++offset;
                continue;
            }
            if (offset + 1 >= tcp_end) break;
            const Byte length = data[offset + 1];
            if (length < 2 || offset + length > tcp_end) break;
            if (kind == 5 && length >= 10) {
                const UInt32 left = (UInt32(data[offset + 2]) << 24) |
                                    (UInt32(data[offset + 3]) << 16) |
                                    (UInt32(data[offset + 4]) << 8) |
                                    UInt32(data[offset + 5]);
                const UInt32 right = (UInt32(data[offset + 6]) << 24) |
                                     (UInt32(data[offset + 7]) << 16) |
                                     (UInt32(data[offset + 8]) << 8) |
                                     UInt32(data[offset + 9]);
                if (left == begin && right == end) return true;
            }
            offset += length;
        }
    }
    return false;
}

// Out-of-order tail buffered, the in-order segment is accepted, the tail is
// rejected while it drains: RCV.NXT rolls back to the frontier and the
// receiver advertises a zero window. The peer then re-sends the
// unacknowledged tail and the flow resumes without losing a byte.
void RunCase(TcpState state, UInt32 irs) {
    Probe probe(state, irs);
    const UInt32 future = irs + 1001;
    probe.Segment(future, 1, 1000);
    CHECK(probe.conn.RcvNxt() == irs + 1);
    CHECK(SackContains(probe.ack_packets, future, future + 1000));
    // The buffered out-of-order bytes are receive memory already consumed.
    CHECK(probe.conn.AdvertisedWindow() == kWindow - 1000);

    // The in-order segment is accepted; the out-of-order tail that drains
    // right after it is rejected by the app: RCV.NXT rolls back to the
    // frontier and a zero window is advertised (RFC 1122 s4.2.3.4).
    probe.Segment(irs + 1, 0, 1000);
    CHECK(probe.received.size() == 1000);
    CHECK(probe.conn.RcvNxt() == irs + 1001);
    CHECK(probe.conn.AdvertisedWindow() == 0);

    // No explicit resume API upstream: the peer re-sends the unacknowledged
    // tail (RTO retransmission / RFC 1122 persist probe). The app accepts.
    probe.allow_tail = true;
    probe.Segment(future, 1, 1000);
    std::vector<Byte> expected(1000, Byte(0));
    expected.insert(expected.end(), 1000, Byte(1));
    CHECK(probe.received == expected);
    CHECK(probe.conn.RcvNxt() == irs + 2001);
    CHECK(probe.conn.AdvertisedWindow() == kWindow);
}

// The peer keeps probing while the app is still backpressured: the window
// stays zero and nothing is delivered until the app accepts.
void RunRejectTwiceCase(TcpState state, UInt32 irs) {
    Probe probe(state, irs);
    probe.Segment(irs + 1, 0, 1000);
    CHECK(probe.received.size() == 1000);
    CHECK(probe.conn.RcvNxt() == irs + 1001);

    // The next in-order segment is rejected: the app buffer is full.
    probe.Segment(irs + 1001, 0, 1000);
    CHECK(probe.received.size() == 1000);
    CHECK(probe.conn.RcvNxt() == irs + 1001);
    CHECK(probe.conn.AdvertisedWindow() == 0);

    // The peer re-sends while the app is still backpressured: still zero.
    probe.Segment(irs + 1001, 0, 1000);
    CHECK(probe.received.size() == 1000);
    CHECK(probe.conn.RcvNxt() == irs + 1001);
    CHECK(probe.conn.AdvertisedWindow() == 0);

    // The app accepts: the re-sent data lands and the window reopens.
    probe.allow_tail = true;
    probe.Segment(irs + 1001, 0, 1000);
    CHECK(probe.received.size() == 2000);
    CHECK(probe.conn.RcvNxt() == irs + 2001);
    CHECK(probe.conn.AdvertisedWindow() == kWindow);
}

}  // namespace

int main() {
    xtcp::buf::InitPools();
    for (UInt32 irs : {200U, 0xfffffff0U}) {
        RunCase(TcpState::kEstablished, irs);
        RunCase(TcpState::kFinWait2, irs);
        RunRejectTwiceCase(TcpState::kEstablished, irs);
    }
    xtcp::buf::ShutdownPools();
    std::printf("OOO backpressure probe (zero-window contract): 6 cases, %d failures\n", failures);
    return failures ? 1 : 0;
}