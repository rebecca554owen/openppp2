// mux_fin_dsn_contract_test.cpp -- the end-of-stream frame must continue the
// DSN space of its flow.
//
// Background:
//   vmux_skt::finalize() released the connection first and posted the FIN
//   afterwards. The release erases the per-flow send DSN counter, so the FIN
//   restarted the flow's DSN space at 1.
//
//   Under the flow v2 ordering the receiver delivers the frames of a flow
//   strictly in DSN order and silently drops a stale DSN as a duplicate (the
//   "Stale/duplicate" branch of vmux_net::packet_input_flow). A FIN that
//   carries DSN 1 after the data frames 1..N were delivered is therefore
//   discarded, and the peer never observes the end of the stream: the flow
//   hangs on the peer side until its gap clock fires and resets it.
//
//   The close path now releases the flow and posts the FIN in one step, so the
//   FIN carries the next DSN of the flow.
//
// The behavioural case lives in tests/cpp/vmux_fin_dsn_test.cpp (linked
// against openppp2_lib and run by the sanitizer job). This file is the SOURCE
// CONTRACT assertion (same approach as mux_flow_refusal_contract_test) and
// pins the invariant in the main ctest pass so a later refactor cannot
// quietly reintroduce a FIN that restarts the DSN space.

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

        // 1) The close path must not post the FIN on its own any more: the FIN
        //    has to go through the path that keeps the per-flow send DSN alive
        //    across the release of the flow.
        Require(skt.find("mux_->post(vmux_net::cmd_fin") == std::string::npos,
                "the FIN must not be posted directly after the flow was released");
        Require(skt.find("release_connection_and_post_fin") != std::string::npos,
                "the close path must release the flow and post the FIN in one step");

        // 2) That path must carry the per-flow send DSN counter across the
        //    release and drop it once the FIN has been queued.
        const std::string body = FunctionBody(net, "vmux_net::release_connection_and_post_fin(");
        Require(!body.empty(), "the combined release-and-FIN path must exist");
        const size_t read_at = body.find("tx_flow_seq_");
        const size_t post_at = body.find("post(cmd_fin");
        const size_t erase_at = body.find("tx_flow_seq_.erase");
        Require(read_at != std::string::npos,
                "the combined path must read the per-flow send DSN counter");
        Require(post_at != std::string::npos,
                "the combined path must post the end-of-stream frame");
        Require(erase_at != std::string::npos,
                "the combined path must drop the per-flow send DSN counter");
        Require(read_at < post_at && post_at < erase_at,
                "the DSN counter must be read before the FIN is posted and dropped after it");

        // 3) The counter the FIN draws its DSN from is the per-flow one, not
        //    the global sequence space of the compat mode.
        Require(net.find("is_per_flow_data(cmd)") != std::string::npos,
                "the per-flow DSN space must stay the source of a data frame's DSN");

        std::cout << "mux_fin_dsn_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_fin_dsn_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
