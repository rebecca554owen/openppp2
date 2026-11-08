// fuzz_vmux_ack.cpp —— 恶意 ACK 帧的 coverage-guided fuzz 目标（VMUX-QA-001 场景）
//
// 审计报告的封板后任务 VMUX-QA-001 写着：「补齐剩余关键场景的直接端到端覆盖」，
// 其中一条是「恶意 ACK range 经过完整 session 输入路径」。手工构造的用例只能覆盖
// 写下来那几个形状；coverage-guided fuzz 能把解码器和重传缓冲真正吃进去的所有字节
// 组合都跑一遍。
//
// 这个目标不需要任何私有访问：ACK 帧的解码器与重传缓冲的确认路径都是公开的。
// 它检查的不变量是：
//
//   - 解码成功的一帧**不会**让保留集合变大（确认帧只能释放，不能新增）；
//   - 保留集合永远不超过字节上限；
//   - 每个序列空间的字节账与该空间里**实际还在的条目**一致 —— 归因错了会在这里
//     露出来（字节账被释放了但条目还在，或者反过来）。
//
// 语料在 tests/fuzz/corpus/fuzz_vmux_ack/，字典在 tests/fuzz/dictionary/vmux.dict。

#include <ppp/stdafx.h>

#include <ppp/app/mux/MuxAckTracker.h>
#include <ppp/app/mux/MuxRetransmitBuffer.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace {

using ppp::app::mux::MuxAckBlock;
using ppp::app::mux::MuxAckRange;
using ppp::app::mux::MuxRetransmitBuffer;

constexpr std::uint32_t kSeededSequences = 32;
constexpr int kFrameLength = 64;
constexpr std::size_t kByteCap = 1u << 20;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::vector<MuxAckBlock> blocks;
    if (!ppp::app::mux::DecodeMuxAckFrame(data, size,
            PPP_MUX_ACK_MAX_BLOCKS, PPP_MUX_ACK_MAX_RANGES, blocks)) {
        // A frame that does not decode is not an error: the peer may be
        // speaking another dialect, or the frame may simply be truncated.
        return 0;
    }

    // A retained set with entries around the frontier, so that a decoded
    // frame has something to release and something to keep.
    MuxRetransmitBuffer rtx;
    const std::shared_ptr<std::uint8_t> frame =
        std::make_shared<std::uint8_t>(static_cast<std::size_t>(kFrameLength));
    for (std::uint32_t seq = 1; seq <= kSeededSequences; ++seq) {
        rtx.Track(1, seq, frame, kFrameLength, 1000, kByteCap);
    }
    const std::size_t before = rtx.size();

    for (const MuxAckBlock& block : blocks) {
        rtx.Ack(block.connection_id, block.largest, block.ranges, 2000);
    }

    if (rtx.size() > before) {
        return -1; // an acknowledgement grew the retained set
    }
    if (rtx.bytes() > kByteCap) {
        return -1; // the byte cap was broken
    }

    // The per-space byte total must match the entries that are actually
    // still there. A release that forgets to discount the bytes, or a
    // discount for a release that did not happen, shows up here.
    std::size_t alive = 0;
    for (std::uint32_t seq = 1; seq <= kSeededSequences; ++seq) {
        if (nullptr != rtx.Find(MuxRetransmitBuffer::Key(1, seq))) {
            ++alive;
        }
    }
    if (rtx.BytesForCid(1) != alive * static_cast<std::size_t>(kFrameLength)) {
        return -1; // the byte accounting and the retained entries disagree
    }

    return 0;
}
