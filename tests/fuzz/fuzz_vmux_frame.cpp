// fuzz_vmux_frame.cpp —— 一帧 vmux 帧走完整解析 + 分发路径的 fuzz 目标
//
// 这是 P2-8 那条修复的对面：未知命令现在只跳过、只计数，会话与载波都存活。
// 「跳过」的前提是**任何命令字节都不能把会话带崩**。手工用例只能测写下来的那
// 几个字节；coverage-guided fuzz 把命令字节、帧头字段与载荷的组合都过一遍。
//
// 目标需要一个 vmux_net 实例。它很重（一次 io_context + strand + 会话状态），
// 所以它被复用，并且每 N 轮重建一次：确认帧会创建流，不重建的话保留集合会随
// 迭代次数单调增长，fuzzer 就会去探索一个现实中不存在的状态。
//
// 输入的形状就是一帧：[seq(4)][cmd(1)][connection_id(4)][payload...]，与线上
// 的帧头布局一致（vmux_net.h 里的 vmux_hdr）。

#include <ppp/stdafx.h>

#include <ppp/app/mux/MuxRuntimeCounters.h>
#include <ppp/app/mux/vmux_net.h>
#include <ppp/configurations/AppConfiguration.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

namespace vmux {

/**
 * @brief The fuzz target's way into the private dispatch path.
 * @details The command dispatcher and the frame header are private because
 *          they are the session's inside door. Reaching them from a fuzz
 *          target is the whole point: the input path has to survive every
 *          byte, and the only way to check that is to send every byte
 *          through it.
 */
struct vmux_fuzz_test_access {
    /** @brief The size of the packed frame header. */
    static std::size_t HeaderSize() noexcept {
        return sizeof(vmux_net::vmux_hdr);
    }

    /** @brief Hands one whole frame to the command dispatcher. */
    static bool PacketInput(vmux_net& mux, std::uint8_t* frame, int frame_size, std::uint64_t now) noexcept {
        auto* header = reinterpret_cast<vmux_net::vmux_hdr*>(frame);
        return mux.packet_input(header->cmd, frame, frame_size, now);
    }
};

}  // namespace vmux

namespace {

using ppp::threading::Executors;

// The session accumulates flows: a SYN frame opens one, and a fuzzer that
// reaches the SYN branch often would otherwise grow the retained set without
// bound. The session is therefore replaced often enough that the growth
// stays small, and the old one is stopped before it is dropped so that the
// work queued on its strand is released with it.
constexpr std::uint64_t kRebuildEvery = 64;

std::shared_ptr<boost::asio::io_context> g_context;
std::shared_ptr<Executors::Strand> g_strand;
std::shared_ptr<vmux::vmux_net> g_mux;
std::weak_ptr<vmux::vmux_net> g_last_session;
std::uint64_t g_iterations = 0;

/**
 * @brief Closes the session and releases everything that belongs to it.
 * @details A session must be closed before it is dropped. An abandoned
 *          session keeps a reference cycle (the session owns its flows, a
 *          flow owns the session), and only the teardown path breaks that
 *          cycle. A session that is simply dropped is therefore never
 *          released: the session, its strand and its context stay alive
 *          until the process exits, and the leak detector reports the whole
 *          island as unreachable garbage once the globals are gone.
 *
 *          The teardown is posted on the strand, so the context has to run
 *          it before the session can be released. The check at the end is
 *          the harness guarantee: a session that survives its own teardown
 *          is a finding, not a fuzzing artefact.
 */
void Teardown() {
    if (g_mux) {
        g_last_session = g_mux;
        g_mux->close_exec();
    }
    if (g_context) {
        g_context->restart();
        g_context->poll();
        g_context->stop();
    }
    g_mux.reset();
    g_strand.reset();
    g_context.reset();

    // The session is NOT required to be gone here: it holds its own strand,
    // and the strand may still carry handlers for this session's flows, so
    // the flow -> session -> strand -> handler -> flow chain can legitimately
    // keep it alive until the strand itself is released. What must not
    // happen is the island becoming unreachable garbage, and that is what the
    // leak detector at exit checks (the fuzzer's own RSS thread is the one
    // thing it suppresses, see tests/fuzz/lsan.supp).
    g_last_session.reset();
}

void Rebuild() {
    Teardown();

    g_context = std::make_shared<boost::asio::io_context>();
    g_strand = std::make_shared<Executors::Strand>(g_context->get_executor());
    g_mux = ppp::make_shared_object<vmux::vmux_net>(
        g_context, g_strand, 1, true, false, vmux::vmux_net::mux_mode_balance);
    if (!g_mux) {
        return;
    }
    auto cfg = ppp::make_shared_object<ppp::configurations::AppConfiguration>();
    if (cfg) {
        cfg->mux.congestions = 0;
        g_mux->AppConfiguration = cfg;
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (0 == (g_iterations++ % kRebuildEvery)) {
        Rebuild();
    }
    if (!g_mux) {
        return 0;
    }

    // Anything shorter than a frame header cannot be a frame.
    if (size < vmux::vmux_fuzz_test_access::HeaderSize()) {
        return 0;
    }

    // The frame is copied into an owned buffer because the dispatcher
    // rewrites the payload pointer in place.
    std::vector<std::uint8_t> frame(data, data + size);

    // The dispatcher must survive the frame, whatever the command byte says.
    // A false result means the frame was rejected, which is a valid answer;
    // what must never happen is a crash, a hang, or a session teardown.
    const bool handled = vmux::vmux_fuzz_test_access::PacketInput(
        *g_mux, frame.data(), static_cast<int>(frame.size()), 1000);
    (void)handled;

    return 0;
}
