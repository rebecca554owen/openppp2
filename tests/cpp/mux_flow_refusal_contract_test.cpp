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
#include <vector>

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

// 取命令分发器里某一个 `elif(cmd == ...) { ... }` 分支的源码。
std::string BranchText(const std::string& text, const std::string& anchor) {
    const size_t start = text.find(anchor);
    if (start == std::string::npos) {
        return std::string();
    }
    const size_t next = text.find("elif(cmd == ", start + anchor.size());
    if (next == std::string::npos) {
        return text.substr(start);
    }
    return text.substr(start, next - start);
}

// 去掉 // 行注释，避免注释里的花括号干扰后面的结构分析。
std::string StripLineComments(const std::string& text) {
    std::string out;
    out.reserve(text.size());
    size_t i = 0;
    while (i < text.size()) {
        const size_t eol = text.find('\n', i);
        const size_t end = (eol == std::string::npos) ? text.size() : eol;
        const std::string line = text.substr(i, end - i);
        const size_t comment = line.find("//");
        out.append(comment == std::string::npos ? line : line.substr(0, comment));
        out.push_back('\n');
        if (eol == std::string::npos) {
            break;
        }
        i = eol + 1;
    }
    return out;
}

// 取出块头部条件文本（第一对括号里的内容）。
std::string ExtractCondition(const std::string& header) {
    const size_t open = header.find('(');
    if (open == std::string::npos) {
        return std::string();
    }
    int depth = 0;
    for (size_t i = open; i < header.size(); ++i) {
        if (header[i] == '(') {
            ++depth;
        }
        else if (header[i] == ')') {
            --depth;
            if (depth == 0) {
                return header.substr(open + 1, i - open - 1);
            }
        }
    }
    return std::string();
}

// 按顶层 || 切分条件。
std::vector<std::string> TopLevelDisjuncts(const std::string& condition) {
    std::vector<std::string> parts;
    int depth = 0;
    std::string current;
    for (size_t i = 0; i < condition.size(); ++i) {
        const char c = condition[i];
        if (c == '(') {
            ++depth;
        }
        else if (c == ')') {
            --depth;
        }

        if (c == '|' && depth == 0 && i + 1 < condition.size() && condition[i + 1] == '|') {
            parts.push_back(current);
            current.clear();
            ++i;
            continue;
        }
        current.push_back(c);
    }
    parts.push_back(current);
    return parts;
}

// 这个块的条件是否**要求**本地 socket 存在。
//
// 只要有一个顶层析取项跟 socket 无关，条件就可能在 socket 缺席时成立，
// 块里的代码就不是被 socket 守卫关住的。
bool RequiresLocalSocket(const std::string& header) {
    const std::string condition = ExtractCondition(header);
    if (condition.empty()) {
        return false;
    }
    const std::vector<std::string> parts = TopLevelDisjuncts(condition);
    for (const std::string& part : parts) {
        if (part.find("NULLPTR != skt") == std::string::npos &&
            part.find("skt != NULLPTR") == std::string::npos) {
            return false;
        }
    }
    return true;
}

// call 是否没有被任何「要求本地 socket 存在」的块关住。
//
// 遍历分支的花括号，保留每个包围 call 的块的头部文本；只要其中有一个要求
// socket 存在，就说明 call 被关在里面了。
bool CallOutsideSocketGuard(const std::string& branch, const std::string& call) {
    const std::string code = StripLineComments(branch);
    const size_t call_pos = code.find(call);
    if (call_pos == std::string::npos) {
        return false;
    }

    std::vector<std::string> headers;
    std::string header;
    for (size_t i = 0; i < call_pos; ++i) {
        const char c = code[i];
        if (c == '{') {
            headers.push_back(header);
            header.clear();
        }
        else if (c == '}') {
            if (!headers.empty()) {
                headers.pop_back();
            }
            header.clear();
        }
        else if (c == ';') {
            header.clear();
        }
        else {
            header.push_back(c);
        }
    }

    for (const std::string& enclosing : headers) {
        if (RequiresLocalSocket(enclosing)) {
            return false;
        }
    }
    return true;
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
        const std::string syn_ok_branch = BranchText(net, "elif(cmd == cmd_syn_ok)");
        Require(!syn_ok_branch.empty(), "the syn-ok branch must exist");
        Require(syn_ok_branch.find("release_flow_reliability_state(connection_id)") != std::string::npos,
                "a refused flow must release its retained frames on the sender side");

        // 5) 这个释放必须发生在 socket 查找之外。
        //
        //    现网形态：本地 socket 已经没了，对端的拒绝帧是发送端唯一能收到的
        //    「这条流死了」的信号。把释放关在 socket 守卫里，等于把这条信号
        //    丢掉，于是发送端把一条已经死掉的流重传满 30 s 预算。
        Require(CallOutsideSocketGuard(syn_ok_branch, "release_flow_reliability_state(connection_id)"),
                "the release must not be guarded by the local socket lookup");

        std::cout << "mux_flow_refusal_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_flow_refusal_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
