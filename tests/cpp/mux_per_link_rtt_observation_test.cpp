// mux_per_link_rtt_observation_test.cpp —— per-carrier RTT「只观测」的三层断言
//
// 背景：上游把 per-link RTT 写了一半 —— 测量做了（每帧记住首发它的载波，
// ACK 时按 Karn 规则取样），判定没做（current_pto(linklayer) 没有调用者，
// CollectExpired 只有一个会话级 base_pto，min_rtt 只写不读）。
// fork 这一版只做「只观测」：给每条载波测 RTT，把离散度发布到 --stats-json，
// 任何判定路径都不许读它。
//
// 三层断言：
//   1) 缓冲层：帧记住首发它的载波，ACK 把样本连同载波 id 一起交出来
//      （只有从未重传的帧才出样本 —— Karn 规则，所以归因是精确的）。
//   2) 登记层：离散度是一个快照，Set 覆盖、Reset 清零。
//   3) 契约层（源码断言）：载波 id 必须真的接进重传缓冲，样本必须真的
//      归因到载波；反过来，会话自己的 SRTT / PTO 路径里不许出现 per-carrier
//      的任何字段 —— 这条是「只观测」的全部意义所在。

#include <ppp/stdafx.h>

#include <ppp/app/mux/MuxRetransmitBuffer.h>
#include <ppp/app/mux/MuxRuntimeCounters.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace mux = ppp::app::mux;

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::string ReadSource(const std::string& relative_path) {
    const std::string path = std::string(OPENPPP2_SOURCE_ROOT) + "/" + relative_path;
    std::ifstream file(path);
    Require(file.good(), "cannot open source file for contract check");
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

std::shared_ptr<std::uint8_t> MakeBuffer(int length, std::uint32_t seed) {
    auto buf = std::shared_ptr<std::uint8_t>(
        new std::uint8_t[static_cast<std::size_t>(length)],
        std::default_delete<std::uint8_t[]>());
    for (int i = 0; i < length; ++i) {
        buf.get()[i] = static_cast<std::uint8_t>((seed * 31 + i * 7 + 0x5A) & 0xFF);
    }
    return buf;
}

const std::vector<mux::MuxAckRange> g_ranges_1 = { { 1, 1 } };
const std::vector<mux::MuxAckRange> g_ranges_2 = { { 2, 2 } };

}  // namespace

// ---------------------------------------------------------------------------
// 1. 缓冲层：帧记住首发它的载波，ACK 把它交出来
// ---------------------------------------------------------------------------

static void TestTrackRemembersTheCarrierAndAckReturnsIt() {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    Require(rtx.Track(1, 1, MakeBuffer(100, 0xA01), 100, 1000, cap, 7),
        "the frame must be retained");

    std::uint16_t carrier = 0xFFFF;
    const std::uint64_t sample = rtx.Ack(1, 1, g_ranges_1, 1100, &carrier);

    Require(sample == 100u, "the sample must be the round-trip time");
    Require(carrier == 7u, "the sample must be attributed to the carrier that sent the frame");
}

static void TestWithoutACarrierTheAttributionIsZero() {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    Require(rtx.Track(1, 1, MakeBuffer(100, 0xA02), 100, 1000, cap),
        "the frame must be retained");

    std::uint16_t carrier = 0xFFFF;
    const std::uint64_t sample = rtx.Ack(1, 1, g_ranges_1, 1100, &carrier);

    Require(sample == 100u, "the sample must still be produced");
    Require(carrier == 0u, "a frame sent without a carrier must report no carrier");
}

static void TestARetransmittedFrameProducesNoSample() {
    // Karn 的规则：被重传过的帧不能用来测 RTT（重传间隔混在里面）。
    // 归因必须跟着样本一起消失，否则离散度里会出现一个假的载波。
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    Require(rtx.Track(1, 1, MakeBuffer(100, 0xA03), 100, 1000, cap, 5),
        "the frame must be retained");
    rtx.MarkRetransmitted(mux::MuxRetransmitBuffer::Key(1, 1), 1500);

    std::uint16_t carrier = 0xFFFF;
    const std::uint64_t sample = rtx.Ack(1, 1, g_ranges_1, 1600, &carrier);

    Require(sample == 0u, "a retransmitted frame must produce no sample");
    Require(carrier == 0u, "a retransmitted frame must produce no attribution");
}

static void TestTheAttributionPointerIsOptional() {
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    Require(rtx.Track(1, 1, MakeBuffer(100, 0xA04), 100, 1000, cap, 9),
        "the frame must be retained");

    const std::uint64_t sample = rtx.Ack(1, 1, g_ranges_1, 1100, nullptr);
    Require(sample == 100u, "the sample must be produced without an attribution slot");
}

static void TestEachFrameCarriesItsOwnCarrier() {
    // 两条载波各发一帧：样本必须各自回到自己的载波上。
    mux::MuxRetransmitBuffer rtx;
    const std::size_t cap = 1 << 20;

    Require(rtx.Track(1, 1, MakeBuffer(100, 0xA05), 100, 1000, cap, 2),
        "the first frame must be retained");
    Require(rtx.Track(1, 2, MakeBuffer(100, 0xA06), 100, 1000, cap, 3),
        "the second frame must be retained");

    std::uint16_t carrier_1 = 0;
    std::uint16_t carrier_2 = 0;
    const std::uint64_t sample_1 = rtx.Ack(1, 1, g_ranges_1, 1020, &carrier_1);
    const std::uint64_t sample_2 = rtx.Ack(1, 2, g_ranges_2, 1300, &carrier_2);

    Require(sample_1 == 20u, "the first frame must carry its own round-trip time");
    Require(carrier_1 == 2u, "the first frame must be attributed to the first carrier");
    Require(sample_2 == 300u, "the second frame must carry its own round-trip time");
    Require(carrier_2 == 3u, "the second frame must be attributed to the second carrier");
}

// ---------------------------------------------------------------------------
// 2. 登记层：离散度是快照
// ---------------------------------------------------------------------------

static void TestTheSpreadIsASnapshot() {
    mux::MuxRuntimeCounterRegistry::Reset();

    mux::MuxRuntimeCounterRegistry::SetLinkRttSpread(3, 20, 240, 220, 1);
    mux::MuxRuntimeCounters snap = mux::MuxRuntimeCounterRegistry::GetSnapshot();
    Require(snap.rtt_link_count == 3u, "the carrier count must be published");
    Require(snap.rtt_link_min_srtt_ms == 20u, "the fastest carrier must be published");
    Require(snap.rtt_link_max_srtt_ms == 240u, "the slowest carrier must be published");
    Require(snap.rtt_link_spread_ms == 220u, "the spread must be published");
    Require(snap.rtt_link_heterogeneous == 1u, "the heterogeneity flag must be published");

    // 它是快照，不是累加器：再发布一次就是新值。
    mux::MuxRuntimeCounterRegistry::SetLinkRttSpread(2, 30, 40, 10, 0);
    snap = mux::MuxRuntimeCounterRegistry::GetSnapshot();
    Require(snap.rtt_link_count == 2u, "the carrier count must be replaced, not accumulated");
    Require(snap.rtt_link_spread_ms == 10u, "the spread must be replaced, not accumulated");
    Require(snap.rtt_link_heterogeneous == 0u, "the heterogeneity flag must be replaced");

    mux::MuxRuntimeCounterRegistry::Reset();
    snap = mux::MuxRuntimeCounterRegistry::GetSnapshot();
    Require(snap.rtt_link_count == 0u, "the reset must clear the carrier count");
    Require(snap.rtt_link_spread_ms == 0u, "the reset must clear the spread");
    Require(snap.rtt_link_heterogeneous == 0u, "the reset must clear the heterogeneity flag");
}

// ---------------------------------------------------------------------------
// 3. 契约层：观测接得对，且判定路径不碰它
// ---------------------------------------------------------------------------

static void TestTheCarrierIdReachesTheRetransmitBuffer() {
    const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");

    // 发送时必须把载波 id 交给重传缓冲，否则样本无从归因。
    Require(net.find("track_sent_frame(packet, packet_length, sent_now, linklayer->id_)") != std::string::npos,
        "the carrier id must be handed to the retransmit buffer when the frame is sent");
    Require(net.find("rtx_.Track(key_cid, seq, packet, packet_length, now, rtx_cap_bytes_, link_id)") != std::string::npos,
        "the retransmit buffer must remember the carrier");

    // ACK 时必须把样本连同载波 id 一起取出来。
    Require(net.find("rtx_.Ack(key_cid, block.largest, block.ranges, now, &sample_link_id)") != std::string::npos,
        "the acknowledgement must ask for the carrier that produced the sample");
    Require(net.find("note_link_rtt_sample(sample_link_id, sample)") != std::string::npos,
        "the sample must be attributed to its carrier");
}

static void TestTheSessionDecisionNeverReadsThePerCarrierEstimate() {
    const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");

    // 会话的判定仍然只看会话自己的 SRTT 和 PTO。
    Require(net.find("rtx_.CollectExpired(now, current_pto(),") != std::string::npos,
        "the retransmission timeout must stay session-level");
    Require(net.find("const uint64_t min_gap = current_pto() / 4;") != std::string::npos,
        "the gap timeout must stay session-level");
    // 上游那个没接线的 per-link PTO 钩子不许被接上：它没有调用者，
    // 接上就是「判定读观测」，而那不是这一版要做的事。
    Require(net.find("current_pto(linklayer") == std::string::npos,
        "the per-link probe timeout hook must stay unwired");

    // per-carrier 的字段只许出现在两个观测函数里。
    const size_t region_begin = net.find("void vmux_net::note_link_rtt_sample(");
    Require(region_begin != std::string::npos, "the observation function must exist");
    const size_t publish = net.find("void vmux_net::publish_link_rtt_spread(", region_begin);
    Require(publish != std::string::npos, "the publisher must exist");
    const size_t region_end = net.find("void vmux_net::", publish + 1);
    Require(region_end != std::string::npos, "the publisher must be followed by another definition");

    static const char* kPerCarrierFields[] = {
        "rtt_srtt_ms_", "rtt_rttvar_ms_", "rtt_min_ms_", "rtt_samples_",
    };
    for (const char* field : kPerCarrierFields) {
        size_t pos = net.find(field);
        while (pos != std::string::npos) {
            Require(pos >= region_begin && pos < region_end,
                "a per-carrier field is used outside the observation functions");
            pos = net.find(field, pos + 1);
        }
    }
}

static void TestTheHeaderMarksTheEstimateAsObservationOnly() {
    const std::string header = ReadSource("ppp/app/mux/vmux_net.h");
    Require(header.find("observation only") != std::string::npos,
        "the per-carrier estimate must be marked as observation only");
}

int main() {
    try {
        TestTrackRemembersTheCarrierAndAckReturnsIt();
        TestWithoutACarrierTheAttributionIsZero();
        TestARetransmittedFrameProducesNoSample();
        TestTheAttributionPointerIsOptional();
        TestEachFrameCarriesItsOwnCarrier();
        TestTheSpreadIsASnapshot();
        TestTheCarrierIdReachesTheRetransmitBuffer();
        TestTheSessionDecisionNeverReadsThePerCarrierEstimate();
        TestTheHeaderMarksTheEstimateAsObservationOnly();
        std::cout << "mux_per_link_rtt_observation_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_per_link_rtt_observation_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
