// mux_invariants_contract_test.cpp -- turn three vmux invariants from comments
// into executable assertions.
//
// The audit findings that could only be "downgraded to advisory" were the ones
// whose invariant lived in a comment: nothing failed when it was broken, and
// the breakage showed up months later as data corruption nobody could trace.
//
// This file pins three invariants:
//
//   (a) connection_id lifetime: an id is never reused inside one session. The
//       number space is refused once it is exhausted instead of recycling an
//       old id, and a new session starts from its own counter.
//   (b) the three lock domains never nest: syncobj_ / tx_completion_mutex_ /
//       runtime_state_mutex_ are independent, and no function holds two of
//       them at once.
//   (c) strand affinity of the state that has no lock of its own.
//
// (c) is pinned the way upstream pins it. Upstream has no runtime strand
// assertion (there is no assert_on_strand() in vmux_net.h), so the invariant
// is expressed by two things upstream does have:
//
//   - the strand-affine entries are DOCUMENTED as strand-affine in the header,
//     so a future edit that moves one of them off the strand is visible in a
//     review; and
//   - post_internal() -- the one entry point that is allowed to be called from
//     outside the strand -- REPORTS the failure by returning false instead of
//     asserting. Turning it into an assertion would crash a supported call.
//
// These invariants have no cheap runtime observation point: they are shapes
// that must not happen, so they are pinned against the source shape.

#include <cctype>
#include <fstream>
#include <iostream>
#include <set>
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

std::vector<std::string> SplitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::string current;
    for (const char c : text) {
        if ('\n' == c) {
            lines.push_back(current);
            current.clear();
            continue;
        }
        if ('\r' != c) {
            current.push_back(c);
        }
    }
    lines.push_back(current);
    return lines;
}

/**
 * @brief The span of one out-of-line member definition, from its definition
 *        line to the line before the next definition.
 * @details Every out-of-line definition in vmux_net.cpp sits at four spaces
 *          of indentation and names its function as vmux_net::name(...). The
 *          other uses of that prefix are type names, and a type name is
 *          followed by something other than an opening parenthesis.
 */
struct FunctionSpan {
    std::string name;
    std::size_t first = 0;
    std::size_t last = 0;
};

std::vector<FunctionSpan> SplitFunctions(const std::vector<std::string>& lines) {
    std::vector<std::pair<std::string, std::size_t>> starts;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        if (line.size() < 8 || line.compare(0, 4, "    ") != 0) {
            continue;
        }
        if (line.compare(0, 8, "        ") == 0) {
            continue; // deeper indentation: not a definition
        }
        // A definition line can name the class twice: once in the return
        // type (vmux_net::mux_mode vmux_net::parse_mode(...)) and once in the
        // function name. Look at every occurrence and accept the line if any
        // of them is followed by a name and an opening parenthesis.
        std::string name;
        std::size_t at = 0;
        while ((at = line.find("vmux_net::", at)) != std::string::npos) {
            std::size_t name_at = at + 10; // strlen("vmux_net::")
            while (name_at < line.size() &&
                (std::isalnum(static_cast<unsigned char>(line[name_at])) || '_' == line[name_at])) {
                ++name_at;
            }
            if (name_at < line.size() && '(' == line[name_at] && name_at != at + 10) {
                name = line.substr(at + 10, name_at - at - 10);
                break;
            }
            at += 10;
        }
        if (name.empty()) {
            continue;
        }
        starts.emplace_back(name, i);
    }

    std::vector<FunctionSpan> spans;
    for (std::size_t i = 0; i < starts.size(); ++i) {
        FunctionSpan span;
        span.name = starts[i].first;
        span.first = starts[i].second;
        span.last = (i + 1 < starts.size()) ? starts[i + 1].second : lines.size();
        spans.push_back(span);
    }
    return spans;
}

}  // namespace

// ---------------------------------------------------------------------------
// (a) The connection id lifetime
// ---------------------------------------------------------------------------

static void TestConnectionIdsAreNeverReusedWithinASession() {
    const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");

    // The allocator seeds itself once with a random non-zero value and then
    // only ever counts up. A reset -- to zero or to a value it had already
    // handed out -- would let a late frame from a closed flow land on a
    // recycled id.
    Require(net.find("next_connection_id_ = ftt_random_aid(") != std::string::npos,
        "the connection id allocator must seed itself from a random start");
    Require(net.find("next_connection_id_ = 0;") == std::string::npos,
        "the connection id counter must never be reset to zero: that would reuse ids");

    // Every use has to be the seed, the zero-guard, the increment, or the
    // test for the zero-guard. Anything else is a new way to reuse an id.
    std::size_t at = 0;
    std::size_t seen = 0;
    while ((at = net.find("next_connection_id_", at)) != std::string::npos) {
        const std::string rest = net.substr(at, 64);
        if (rest.rfind("next_connection_id_ = ftt_random_aid(", 0) == 0 ||
            rest.rfind("next_connection_id_ = 1;", 0) == 0 ||
            rest.rfind("next_connection_id_++", 0) == 0 ||
            rest.rfind("next_connection_id_ == 0", 0) == 0) {
            ++seen;
        }
        else {
            throw std::runtime_error("the connection id counter is used in an unexpected way");
        }
        at += 19;
    }
    Require(seen >= 4u, "the connection id counter should still be used as expected");

    // When the space is exhausted the allocator refuses instead of recycling.
    Require(net.find("connection_id_wrap_") != std::string::npos,
        "the allocator must record that the id space is exhausted");
    Require(net.find("if (connection_id_wrap_)") != std::string::npos,
        "the allocator must refuse new ids once the space is exhausted");

    // A new session starts from a fresh counter, so the seed is drawn per
    // session and two sessions never share an id space.
    const std::string header = ReadSource("ppp/app/mux/vmux_net.h");
    Require(header.find("next_connection_id_ = 0;") != std::string::npos,
        "a new session must start its id counter at zero, so the seed is drawn per session");
}

// ---------------------------------------------------------------------------
// (b) The three lock domains are independent
// ---------------------------------------------------------------------------

static void TestTheThreeLockDomainsAreNeverNested() {
    const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");
    const std::vector<std::string> lines = SplitLines(net);
    const std::vector<FunctionSpan> spans = SplitFunctions(lines);
    Require(spans.size() > 40u, "the source split found suspiciously few definitions");

    // The idioms that take a lock. The names are matched with their
    // acquisition syntax, not on their own, so that a comment mentioning a
    // lock does not count as taking it.
    struct LockUse {
        const char* name;
        const char* idiom;
    };
    const LockUse kLocks[] = {
        { "syncobj_", "__SCOPE__(syncobj_)" },
        { "syncobj_", "lock(syncobj_" },
        { "tx_completion_mutex_", "scope(tx_completion_mutex_)" },
        { "runtime_state_mutex_", "scope(runtime_state_mutex_)" },
    };

    std::set<std::string> taken_anywhere;
    for (const FunctionSpan& span : spans) {
        std::string body;
        for (std::size_t i = span.first; i < span.last && i < lines.size(); ++i) {
            body += lines[i];
            body.push_back('\n');
        }
        std::set<std::string> taken;
        for (const LockUse& use : kLocks) {
            if (body.find(use.idiom) != std::string::npos) {
                taken.insert(use.name);
            }
        }
        if (taken.size() > 1) {
            std::string message = "two lock domains are held at once in ";
            message += span.name;
            throw std::runtime_error(message.c_str());
        }
        for (const std::string& name : taken) {
            taken_anywhere.insert(name);
        }
    }

    // The check must not be vacuous: every domain has to be taken somewhere,
    // otherwise a rename would make this file pass for the wrong reason.
    Require(taken_anywhere.count("syncobj_") == 1u,
        "the carrier handshake lock must still be taken somewhere");
    Require(taken_anywhere.count("tx_completion_mutex_") == 1u,
        "the transmit completion lock must still be taken somewhere");
    Require(taken_anywhere.count("runtime_state_mutex_") == 1u,
        "the published runtime state lock must still be taken somewhere");
}

// ---------------------------------------------------------------------------
// (c) The strand affinity of the state that has no lock of its own
// ---------------------------------------------------------------------------

static void TestStrandAffineEntriesAreDocumentedAsSuch() {
    const std::string header = ReadSource("ppp/app/mux/vmux_net.h");

    // Upstream has no runtime strand assertion, so the invariant is pinned by
    // the documentation that tells the next editor which entries must stay on
    // the strand. Every one of these entries owns state that no other lock
    // protects.
    const char* kStrandEntries[] = {
        "enqueue_flow_tx",
        "note_ack_pending",
        "maybe_send_ack",
        "count_live_carriers",
    };
    for (const char* entry : kStrandEntries) {
        // The declaration, not a mention in a comment: "count_live_carriers"
        // also appears in the prose of another member's doc comment.
        const std::string declaration = std::string(entry) + "(";
        const std::size_t at = header.find(declaration);
        Require(at != std::string::npos,
            "the strand-affine entry point must exist in the header");
        // The strand-affine marker sits on the doc comment of the declaration.
        const std::size_t doc_end = header.rfind("*/", at);
        const std::size_t doc_start = (doc_end == std::string::npos)
            ? std::string::npos
            : header.rfind("/**", doc_end);
        Require(doc_start != std::string::npos && doc_start < at,
            "the strand-affine entry point must carry a doc comment");
        const std::string doc = header.substr(doc_start, doc_end - doc_start);
        Require(doc.find("strand-affine") != std::string::npos,
            "a strand-affine entry point must be documented as strand-affine");
    }

    // The strand-affine STATE is documented the same way: the members that
    // no lock protects say so, so nobody moves them off the strand.
    const char* kStrandState[] = {
        "queued_bytes_ = 0;",
        "total_sent_bytes_ = 0;",
        "drain_;",
    };
    for (const char* member : kStrandState) {
        const std::size_t at = header.find(member);
        Require(at != std::string::npos,
            "the strand-affine member must exist in the header");
        const std::size_t line_end = header.find('\n', at);
        const std::string line = header.substr(at, line_end - at);
        Require(line.find("Strand-affine") != std::string::npos,
            "a strand-affine member must be documented as strand-affine");
    }
}

static void TestPostInternalReportsAnOffStrandCallInsteadOfAsserting() {
    const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");

    // post_internal is the one entry point that is allowed to be called from
    // outside the strand: it reports that by returning false. Asserting there
    // would turn a supported call into a crash.
    const std::vector<std::string> lines = SplitLines(net);
    const std::vector<FunctionSpan> spans = SplitFunctions(lines);
    std::size_t post_internal_count = 0;
    for (const FunctionSpan& span : spans) {
        if (span.name != "post_internal") {
            continue;
        }
        ++post_internal_count;
        std::string body;
        for (std::size_t i = span.first; i < span.last && i < lines.size(); ++i) {
            body += lines[i];
            body.push_back('\n');
        }
        Require(body.find("assert") == std::string::npos,
            "post_internal must not assert the strand: it is callable from outside it");
        Require(body.find("is_strand_thread()") != std::string::npos,
            "post_internal must test the strand it runs on");
        Require(body.find("return false;") != std::string::npos,
            "post_internal must report an off-strand call by returning false");
    }
    Require(post_internal_count >= 1u,
        "post_internal must be present in the source");
}

int main() {
    try {
        TestConnectionIdsAreNeverReusedWithinASession();
        TestTheThreeLockDomainsAreNeverNested();
        TestStrandAffineEntriesAreDocumentedAsSuch();
        TestPostInternalReportsAnOffStrandCallInsteadOfAsserting();
        std::cout << "mux_invariants_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_invariants_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
