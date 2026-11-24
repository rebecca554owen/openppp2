// mux_connect_yield_lifetime_contract_test.cpp -- the posted lambda of
// connect_yield must not capture a bare this (P0-1: a deterministic async
// use-after-free).
//
// Background: the audit report's P0-1 records that the posted lambda of
// connect_yield() captured a bare `this`, which is a deterministic
// use-after-free. finalize() only sets the disposed_ flag and moves/clears the
// internal containers; it does not drain the strand and does not wait for it.
// The strand and the io_context are owned by the exchanger, so they outlive
// the vmux_net. After the last shared_ptr<vmux_net> is released, a posted but
// not yet executed lambda is still scheduled on the strand and touches an
// object that is already destroyed.
//
// The fix is to capture shared_from_this() and call self->connect(...) inside
// the lambda. `self` keeps the object alive until the lambda has run, so
// capturing a bare `this` is unnecessary and dangerous.
//
// A behavioural test can hardly reproduce this use-after-free (it needs the
// last reference to be released at exactly the right moment), but the SHAPE
// can be pinned. This file is a source contract assertion, the same approach
// as mux_flow_refusal_contract_test: the invariant goes into CI so a later
// refactor cannot quietly remove it again.

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

// The body of connect_yield: from its definition to the next definition at
// the same indentation.
std::string ConnectYieldBody(const std::string& text) {
    const std::string anchor = "bool vmux_net::connect_yield(";
    const size_t start = text.find(anchor);
    Require(start != std::string::npos, "connect_yield definition not found");
    const size_t end = text.find("\n    bool vmux_net::", start + anchor.size());
    if (end == std::string::npos) {
        return text.substr(start);
    }
    return text.substr(start, end - start);
}

// The capture list of the posted lambda: the first '[' ... ']' after
// vmux_post_exec.
std::string CaptureListOfPostedLambda(const std::string& body) {
    const size_t post = body.find("vmux_post_exec(");
    Require(post != std::string::npos, "connect_yield must post its lambda through vmux_post_exec");
    const size_t open = body.find('[', post);
    Require(open != std::string::npos, "the posted lambda must have a capture list");
    const size_t close = body.find(']', open);
    Require(close != std::string::npos, "the posted lambda's capture list is not terminated");
    return body.substr(open + 1, close - open - 1);
}

// Split a capture list on its top-level commas (a lambda capture list has no
// nested brackets, so this is enough).
std::vector<std::string> SplitCaptures(const std::string& capture_list) {
    std::vector<std::string> captures;
    std::string current;
    for (const char c : capture_list) {
        if (c == ',') {
            captures.push_back(current);
            current.clear();
            continue;
        }
        current.push_back(c);
    }
    captures.push_back(current);
    for (std::string& capture : captures) {
        const size_t begin = capture.find_first_not_of(" \t\n");
        const size_t end = capture.find_last_not_of(" \t\n");
        capture = (begin == std::string::npos) ? std::string() : capture.substr(begin, end - begin + 1);
    }
    return captures;
}

} // namespace

int main() {
    try {
        const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");
        const std::string body = ConnectYieldBody(net);
        const std::string captures = CaptureListOfPostedLambda(body);

        // 1) It must capture shared_from_this(): the object must not die before
        //    the lambda runs.
        Require(body.find("std::shared_ptr<vmux_net> self = shared_from_this();") != std::string::npos,
            "connect_yield must keep a strong reference to itself before posting the lambda");
        Require(captures.find("self") != std::string::npos,
            "the posted lambda must capture the strong reference");

        // 2) The capture list must not contain a bare this: finalize() does not
        //    drain strand_, so a bare this dangles.
        for (const std::string& capture : SplitCaptures(captures)) {
            Require(capture != "this",
                "the posted lambda must not capture a bare this (P0-1)");
        }

        // 3) The lambda must reach the member function through the strong
        //    reference, not through a bare this.
        Require(body.find("self->connect(") != std::string::npos,
            "the posted lambda must reach the member function through the strong reference");

        // 4) The explanatory comment must stay: this shape is the only clue the
        //    next person editing the code has about why it is safe.
        Require(body.find("keep *this alive") != std::string::npos,
            "the strong-reference form must keep the comment that explains why it is safe");

        std::cout << "mux_connect_yield_lifetime_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_connect_yield_lifetime_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
