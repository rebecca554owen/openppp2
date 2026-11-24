// mux_flow_refusal_contract_test.cpp -- a dead flow must never be swallowed
// in silence.
//
// Background (measured in production on 2026-11-02, v2.2.15):
//   Even on the good path (a direct 0.7~1.36 Gbps link) there were still 4~6
//   "the sender gave up on a flow" events per 120 s, unrelated to the quality
//   of the path. The root cause was in the protocol layer, and it had two
//   halves:
//
//   1) A local read-side EOF put the mux flow into "FIN already sent" without
//      closing the socket, so the application could keep writing. Those frames
//      carry a DSN beyond the FIN's, and the peer silently DROPS every frame of
//      a closed flow WITHOUT acknowledging it, so the sender keeps
//      retransmitting until the 30 s budget is gone and then resets a flow
//      that is already dead.
//
//   2) When the receiver dropped a frame of a flow it does not have, it
//      neither acknowledged it nor told the peer "that flow is gone". The peer
//      could only find out by burning its whole budget: every dead flow costs
//      30 s of retransmission traffic across 12 carriers.
//
// The behavioural cases live in tests/cpp/vmux_receive_semantics_test.cpp
// (linked against openppp2_lib and run by the full ctest pass). This file is
// the SOURCE CONTRACT assertion (same approach as mux_carrier_clean_close_test)
// and pins the invariants in CI so a later refactor cannot quietly remove the
// guards.
//
// ---------------------------------------------------------------------------
// What upstream provides, and what this file therefore pins
// ---------------------------------------------------------------------------
// Upstream has no explicit "refuse this flow" frame: there is no refuse_flow()
// and no closed-flow memory (no remember_closed_flow_from_context()). The
// three dev-era invariants that relied on those are therefore NOT pinned here:
// upstream has no corresponding capability, and a contract test for a
// capability that does not exist would be theatre.
//
// What upstream DOES provide is the same outcome in a different shape:
//
//   (1) A write that arrives after the flow's FIN is REFUSED locally with a
//       dedicated error code, so the frame never leaves the host at all.
//   (2) A frame of an unknown flow is COUNTED (never swallowed silently) and
//       the receive context of that flow is never created, so an unknown flow
//       cannot grow the session's flow table without bound.
//   (3) The peer's refusal (a syn-ok whose payload is not 'A') is observable
//       EVEN WHEN this side no longer has the flow: the refusal signal must
//       not be guarded by the local socket lookup, because the local socket is
//       gone exactly in the case that matters.
//   (4) A command this build does not know is skipped and counted, never
//       fatal: the session and the carriers survive it.
//   (5) The retained frames of a flow are released on BOTH teardown paths, so
//       a dead flow cannot keep burning the retransmit budget.

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

// Whether needle appears within window bytes after anchor.
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

// The source of one `elif(cmd == ...)` branch of the command dispatcher.
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

// Strip the // line comments so that a brace inside a comment cannot confuse
// the structural analysis.
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

// The body of a function: from the first '{' after the signature, balanced.
std::string FunctionBody(const std::string& text, const std::string& signature) {
    const size_t start = text.find(signature);
    if (start == std::string::npos) {
        return std::string();
    }
    const size_t open = text.find('{', start);
    if (open == std::string::npos) {
        return std::string();
    }
    int depth = 0;
    for (size_t i = open; i < text.size(); ++i) {
        if (text[i] == '{') {
            ++depth;
        }
        else if (text[i] == '}') {
            --depth;
            if (depth == 0) {
                return text.substr(open, i - open + 1);
            }
        }
    }
    return std::string();
}

} // namespace

int main() {
    try {
        const std::string skt = ReadSource("ppp/app/mux/vmux_skt.cpp");
        const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");
        const std::string def = ReadSource("ppp/diagnostics/ErrorCodes.def");

        // 1) No data frame may go out for a flow whose FIN already went out.
        Require(AppearsWithin(skt, "VmuxSocketSendAfterFin", "if (status_.fin_)", 600),
                "send_to_peer must refuse a write that follows the flow's FIN");
        Require(def.find("X(VmuxSocketSendAfterFin") != std::string::npos,
                "the refusal must report a dedicated error code");

        // 2) A frame of an unknown flow must be counted, not swallowed in
        //    silence, and it must not create a receive context.
        Require(AppearsWithin(net, "AddRxFlowUnknownCid()", "try_get_or_create_flow(uint32_t", 2000),
                "a frame of an unknown flow must be counted, not dropped in silence");
        Require(net.find("mux.rx.flow.unknown_cid") != std::string::npos,
                "the unknown flow must be observable in telemetry");
        const std::string admission = FunctionBody(net, "vmux_net::try_get_or_create_flow(");
        Require(!admission.empty(), "try_get_or_create_flow must exist");
        Require(admission.find("RejectUnknown") != std::string::npos,
                "an unknown flow must be rejected by the flow context admission");

        // 3) The peer's refusal must be observable even when this side no
        //    longer has the flow.
        //
        //    Shape seen in production: the local socket is already gone, and
        //    the peer's refusal frame is the only signal the sender gets that
        //    the flow is dead. A refusal that is guarded by the local socket
        //    lookup drops that signal, so the sender retransmits a dead flow
        //    until its whole budget is gone.
        const std::string syn_ok_branch = BranchText(net, "elif(cmd == cmd_syn_ok)");
        Require(!syn_ok_branch.empty(), "the syn-ok branch must exist");
        Require(syn_ok_branch.find("AddRxSynOkRefused()") != std::string::npos,
                "the refusal must be counted");
        Require(syn_ok_branch.find("AddRxSynOkRefusedNoSocket()") != std::string::npos,
                "the refusal of a flow this side no longer has must be counted separately");
        Require(syn_ok_branch.find("AddRxSynOkRefused()") < syn_ok_branch.find("if (NULLPTR != skt)"),
                "the refusal must be counted outside the local socket lookup");

        // 4) A command this build does not know must be skipped and counted:
        //    the session and the carriers have to survive it.
        const std::string dispatch = FunctionBody(net, "bool vmux_net::packet_input(");
        Require(!dispatch.empty(), "the command dispatcher must exist");
        const size_t unknown_at = dispatch.find("AddRxUnknownCmd()");
        Require(unknown_at != std::string::npos,
                "an unknown command must be counted");
        const std::string unknown_tail = dispatch.substr(unknown_at, 400);
        Require(unknown_tail.find("return false;") != std::string::npos,
                "an unknown command must be rejected, not treated as a fatal error");
        Require(unknown_tail.find("close_exec") == std::string::npos,
                "an unknown command must not tear the session down");

        // 5) The retained frames of a flow must be released on both teardown
        //    paths, so a dead flow cannot keep burning the retransmit budget.
        const std::string release_body = FunctionBody(net, "vmux_net::release_connection(");
        Require(!release_body.empty(), "release_connection must exist");
        Require(release_body.find("release_flow_reliability_state(connection_id") != std::string::npos,
                "release_connection must release the reliability state of the flow");

        // The queued frames of the flow are NOT dropped: their sequence numbers
        // were spent when they were queued, so dropping them leaves a hole in
        // the peer's sequence space and the peer's gap timeout resets the flow.
        Require(release_body.find("keep_frames") != std::string::npos,
                "release_connection must keep the queued frames of the flow");
        Require(release_body.find("tx_flows_.erase") == std::string::npos,
                "release_connection must not drop the queued frames of the flow");

        const std::string fail_body = FunctionBody(net, "vmux_net::fail_flow(");
        Require(!fail_body.empty(), "fail_flow must exist");
        Require(fail_body.find("release_flow_reliability_state(connection_id)") != std::string::npos,
                "fail_flow must release the retained frames of the flow");

        // 6) The counters that carry these signals must exist in the registry,
        //    so a rename on either side fails this file.
        const std::string counters = ReadSource("ppp/app/mux/MuxRuntimeCounters.h");
        Require(counters.find("AddRxFlowUnknownCid") != std::string::npos,
                "the registry must expose the unknown flow counter");
        Require(counters.find("AddRxSynOkRefused") != std::string::npos,
                "the registry must expose the syn-ok refusal counter");
        Require(counters.find("AddRxUnknownCmd") != std::string::npos,
                "the registry must expose the unknown command counter");

        std::cout << "mux_flow_refusal_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_flow_refusal_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
