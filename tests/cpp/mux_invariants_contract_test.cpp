// mux_invariants_contract_test.cpp —— 把 vmux 的三条不变量从注释变成可执行断言
//
// 审计报告的 P3-12 / P3-13 之所以只能「降级保留」，是因为
// 「strand 亲和性」与「锁域」这两个不变量只存在于注释里：没有任何东西会在它们
// 被破坏时失败，破坏的后果是几个月后一次查不到原因的数据损坏。
//
// 这个文件把三条不变量钉成断言：
//
//   (a) connection_id 的生命周期：一个 session 内不复用，号段用尽就拒绝新连接，
//       而不是回收旧号；新 session 有自己的号段。
//   (b) 三个锁域互不嵌套：syncobj_ / tx_completion_mutex_ / runtime_state_mutex_
//       各自独立，任何一个函数都不会同时持有其中两个。
//   (c) strand 亲和性：只有 strand 才碰的入口在调试构建里断言自己在 strand 上；
//       而唯一允许从 strand 外调用的入口（post_internal）必须**不**断言，
//       它用返回值报告失败。
//
// 与 mux_connect_yield_lifetime_contract_test 同一套路：源码契约断言。
// 这些不变量没有便宜的运行时观测点 —— 它们是「不该发生」的形状，只能从源码
// 形状上钉住。

#include <ppp/stdafx.h>

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

static void TestStrandAffineEntriesAssertTheyAreOnTheStrand() {
    const std::string header = ReadSource("ppp/app/mux/vmux_net.h");
    const std::string net = ReadSource("ppp/app/mux/vmux_net.cpp");

    // The assertion exists, it asks the right question, and it costs nothing
    // in a release build.
    Require(header.find("assert_on_strand(const char* where)") != std::string::npos,
        "the strand assertion helper must exist");
    Require(header.find("#ifndef NDEBUG") != std::string::npos,
        "the strand assertion must be compiled out of a release build");
    Require(header.find("assert(is_strand_thread() && where)") != std::string::npos,
        "the strand assertion must check the strand");

    // The entries that touch strand-owned state assert it.
    const char* kStrandEntries[] = {
        "enqueue_flow_tx",
        "note_ack_pending",
        "maybe_send_ack",
        "process_tx_all_packets",
    };
    for (const char* entry : kStrandEntries) {
        const std::string call = std::string("assert_on_strand(\"") + entry + "\")";
        Require(net.find(call) != std::string::npos,
            "a strand-affine entry point must assert that it runs on the strand");
    }

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
        for (std::size_t i = span.first; i < span.last && i < lines.size(); ++i) {
            Require(lines[i].find("assert_on_strand(") == std::string::npos,
                "post_internal must not assert the strand: it is callable from outside it");
        }
    }
    Require(post_internal_count == 2u,
        "both post_internal overloads must be present in the source");
}

int main() {
    try {
        TestConnectionIdsAreNeverReusedWithinASession();
        TestTheThreeLockDomainsAreNeverNested();
        TestStrandAffineEntriesAssertTheyAreOnTheStrand();
        std::cout << "mux_invariants_contract_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_invariants_contract_test failed: " << ex.what() << std::endl;
        return 1;
    }
}

