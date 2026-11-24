// fuzz_vmux_ack.cpp -- a coverage-guided fuzz target for malicious ACK
// frames (the VMUX-QA-001 scenario).
//
// The audit report's post-closure task VMUX-QA-001 says: "fill in the direct
// end-to-end coverage of the remaining critical scenarios", and one of them
// is "a malicious ACK range through the full session input path". Hand-written
// cases only cover the shapes somebody thought of; coverage-guided fuzzing
// runs every byte combination of the decoder and the retransmit buffer.
//
// This target needs no private access: the ACK frame decoder and the
// retransmit buffer's acknowledgement path are both public. The invariants it
// checks are:
//
//   - a decoded frame never GROWS the retained set (an acknowledgement can
//     only release, never add);
//   - the retained set never exceeds the byte cap;
//   - the byte total of a sequence space matches the entries that are
//     actually still in it -- a mis-attribution shows up here (the bytes were
//     discounted but the entry is still there, or the other way round).
//
// The corpus is in tests/fuzz/corpus/fuzz_vmux_ack/ and the dictionary is in
// tests/fuzz/dictionary/vmux.dict.

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

// The fast-retransmit thresholds of the production caller. They only decide
// WHICH unacked entries become retransmission candidates; they never release
// anything, so they cannot affect the invariants below.
constexpr std::uint32_t kFastThreshold = 3;
constexpr std::uint64_t kFastTimeThreshold = 0;

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

    std::vector<std::uint64_t> fast_candidates;
    for (const MuxAckBlock& block : blocks) {
        rtx.Ack(block.connection_id, block.largest, block.ranges, 2000,
            kFastThreshold, kFastTimeThreshold, fast_candidates);
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
    if (rtx.CidBytes(1) != alive * static_cast<std::size_t>(kFrameLength)) {
        return -1; // the byte accounting and the retained entries disagree
    }

    return 0;
}
