// mux_flow_refusal_contract_test.cpp —— 已死的流必须被「明确拒绝」，不能静默丢弃
//
// 背景（2026-11-02 生产实测，v2.2.15 现网）：
//   好路径（直连 0.7~1.36 Gbps）上仍有 4~6 次/120s 的「发送端放弃流」，且与路径质量无关。
//   根因在协议层，有两条：
//
//   1) 本地读侧 EOF 会把 mux 流置为「已发 FIN」，但**不关闭 socket** ⇒ app 还能继续写
//      ⇒ 这些帧的 DSN 大于 FIN 的 DSN ⇒ 对端按「已关闭流的越界帧」静默丢弃且**不回 ACK**
//      ⇒ 发送侧一路重传到 30 s 预算烧完 ⇒ rtx exhausted + 对一条**已经死掉的流**做 flow reset。
//
//   2) 接收侧丢弃「自己没有的流」的帧时，既不回 ACK，也不告知对端「这条流没了」
//      ⇒ 对端只能烧满预算才发现，每死一条流就是 30 s × 12 载体的重传流量。
//
// 行为级用例在 tests/cpp/vmux_receive_semantics_test.cpp（链接 openppp2_lib，
// 随完整构建的 ctest 运行）。本文件是**源码契约断言**（与 mux_carrier_clean_close_test
// 同一套路），把三条不变量钉在 CI 里，防止后续重构把守卫改没了。

#include <ppp/stdafx.h>

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

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

// anchor 之后 window 字节内是否出现了 needle。
bool AppearsWithin(const std::string& text,
                    const std::string& needle,
                    const std::string& anchor,
                    std::size_t window) {
    const size_t anchor_pos = text.find(anchor);
    if (anchor_pos == std::string::npos) {
        return false;
    }
    const size_t needle_pos = text.find(needle, anchor_pos);
    return needle_pos != std::string::npos && (needle_pos - anchor_pos) <= window;
}

} // namespace

int main() {
    try {
        const std::string skt = ReadSource("ppp/app/mux/vmux_skt.cpp");
        const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");
        const std::string def = ReadSource("ppp/diagnostics/ErrorCodes.def");

        // 1) FIN 之后不得再为该流发数据帧。
        Require(AppearsWithin(skt, "VmuxSocketSendAfterFin", "if (status_.fin_)", 600),
                "send_to_peer must refuse a write that follows the flow's FIN");
        Require(def.find("X(VmuxSocketSendAfterFin") != std::string::npos,
                "the refusal must report a dedicated error code");

        // 2) 接收侧必须能显式拒绝「自己没有的流」。
        Require(net.find("void vmux_net::refuse_flow") != std::string::npos,
                "the receiver must be able to refuse a flow it does not have");
        Require(net.find("mux.rx.flow.refused") != std::string::npos,
                "the refusal must be observable in telemetry");
        Require(net.find("cmd_syn_ok, &err, 1, connection_id)") != std::string::npos,
                "the refusal must ride the existing syn-ok error channel (no new command needed)");

        // 3) 两条丢弃路径都要拒绝：未知 cid，以及已关闭流的越界帧。
        Require(AppearsWithin(net, "refuse_flow(cid)", "try_get_or_create_flow(cid)", 400),
                "a frame of an unknown flow must be refused, not dropped in silence");
        Require(AppearsWithin(net, "refuse_flow(cid)", "mux.rx.closed_flow.drop", 400),
                "a post-FIN frame of a closed flow must be refused, not dropped in silence");

        // 4) 被拒方收到拒绝后必须释放该流的重传条目，否则照样烧满 30 s 预算。
        Require(AppearsWithin(net, "release_flow_reliability_state(connection_id)",
                              "elif(cmd == cmd_syn_ok)", 1500),
                "a refused flow must release its retained frames on the sender side");

        std::cout << "mux_flow_refusal_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_flow_refusal_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
