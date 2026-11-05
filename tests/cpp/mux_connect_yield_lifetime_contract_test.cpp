// mux_connect_yield_lifetime_contract_test.cpp —— connect_yield 的 posted lambda
// 不得捕获裸 this（P0-1：确定性异步 UAF）
//
// 背景：审计报告 P0-1 记录了 connect_yield() 的 posted lambda 捕获裸 `this`
// 造成的确定性 UAF。`finalize()` 只设置 disposed_ 标志并 move/clear 内部容器，
// 不清空 strand 队列也不等待 drain；strand 和 io_context 由 exchanger 持有，
// 生命周期长于 vmux_net。于是最后一个 shared_ptr<vmux_net> 释放后，已 post
// 但未执行的 lambda 仍会被 strand 调度执行，访问已析构的对象。
//
// 修复形态：捕获 `shared_from_this()`，lambda 里用 `self->connect(...)`。
// `self` 本身就把对象钉到 lambda 跑完，裸 `this` 捕获是不必要的、也是危险的。
//
// fork 的 `57f0ffa5`（vmux_net.cpp 整文件重写）把这个形态改了回去
// （`[self, this, ...]` + 裸 `connect(...)`），并删掉了上游那段解释注释。
// 实质上仍然安全（`self` 已被捕获，shared_ptr 会把对象钉住），但报告里
// 「lambda 中不再捕获裸 this」那条清单不再成立，形态随时可能被再次改没。
//
// 行为级用例很难稳定复现这个 UAF（要精确卡在 lambda 被调度前释放最后一个
// 引用），但**形态**是可以钉死的。本文件是源码契约断言，与
// mux_flow_refusal_contract_test 同一套路：把不变量放进 CI，防止重构改没。

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

// 取 connect_yield 的函数体：从定义处到下一个同缩进的函数定义之前。
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

// 取 posted lambda 的捕获列表文本：vmux_post_exec 之后的第一个 '[' ... ']'。
std::string CaptureListOfPostedLambda(const std::string& body) {
    const size_t post = body.find("vmux_post_exec(");
    Require(post != std::string::npos, "connect_yield must post its lambda through vmux_post_exec");
    const size_t open = body.find('[', post);
    Require(open != std::string::npos, "the posted lambda must have a capture list");
    const size_t close = body.find(']', open);
    Require(close != std::string::npos, "the posted lambda's capture list is not terminated");
    return body.substr(open + 1, close - open - 1);
}

// 捕获列表按顶层逗号切分（lambda 捕获里没有嵌套的 []，够用）。
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

        // 1) 必须捕获 shared_from_this()：lambda 跑完之前对象不能析构。
        Require(body.find("std::shared_ptr<vmux_net> self = shared_from_this();") != std::string::npos,
            "connect_yield must keep a strong reference to itself before posting the lambda");
        Require(captures.find("self") != std::string::npos,
            "the posted lambda must capture the strong reference");

        // 2) 捕获列表里不得有裸 this：finalize() 不 drain strand_，裸 this 会悬空。
        for (const std::string& capture : SplitCaptures(captures)) {
            Require(capture != "this",
                "the posted lambda must not capture a bare this (P0-1)");
        }

        // 3) lambda 内必须经由 self 调用成员函数，不能靠裸 this。
        Require(body.find("self->connect(") != std::string::npos,
            "the posted lambda must reach the member function through the strong reference");

        // 4) 解释注释要留着：这个形态为什么安全，是下一位改代码的人唯一的依据。
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
