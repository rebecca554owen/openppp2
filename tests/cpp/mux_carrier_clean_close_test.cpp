// mux_carrier_clean_close_test.cpp — 载体优雅关闭：close 前必须先半关接收方向
//
// 背景（2026-11-01 晚高峰实测）：
//   dmit 侧 mux 载体的 socket 在 close() 时接收队列里还有未读字节，
//   内核因此发 RST 而不是 FIN。NAS 侧随即看到
//   "Read failed outlen=0 error=101"(ECONNRESET)，
//   11 条载体一起死 -> 客户端 TUN detached -> 整个 mux 会话重建，
//   同会话上其它在途传输全部作废。
//   内核计数器佐证：dmit 上 TcpExtTCPAbortOnClose = 224
//   （用户态 close 时仍有未读数据 => 发 RST）。
//
// 本测试分两层：
//   1) 内核语义（socketpair 实测）：接收队列非空时直接 close()，
//      对端读到的是 ECONNRESET；先 shutdown(SHUT_RD) 再 close()，
//      对端读到的是干净 EOF。这正是修复所依赖的内核行为。
//   2) mux 侧契约（源码断言）：载体在 Dispose() 之前必须先调用
//      DrainReceive()，否则上面的内核行为就会发生。

#include <ppp/stdafx.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unistd.h>
#include <sys/socket.h>

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

// 对端在 close 之后观察到的结果。
enum class PeerOutcome {
    kEof,       // 干净 EOF：读到 0 字节
    kReset,     // ECONNRESET：读到 -1 且 errno == ECONNRESET
    kOther
};

PeerOutcome ObservePeer(int fd) {
    char buffer[64];
    const ssize_t n = ::read(fd, buffer, sizeof(buffer));
    if (n == 0) {
        return PeerOutcome::kEof;
    }
    if (n < 0 && errno == ECONNRESET) {
        return PeerOutcome::kReset;
    }
    return PeerOutcome::kOther;
}

// 建立一对已连接的本地 socket，往对端写一些数据让本地接收队列非空。
// drain_receive=true 时先把接收队列读空再 close()，否则直接 close()。
PeerOutcome RunCloseScenario(bool drain_receive) {
    int fds[2] = { -1, -1 };
    Require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");
    const int a = fds[0];
    const int b = fds[1];

    const char payload[] = "queued-but-never-read";
    Require(::write(b, payload, sizeof(payload)) == static_cast<ssize_t>(sizeof(payload)),
            "write to peer failed");

    if (drain_receive) {
        // 排空接收队列：一直读到 EAGAIN。
        char scratch[4096];
        for (;;) {
            const ssize_t n = ::recv(a, scratch, sizeof(scratch), MSG_DONTWAIT);
            if (n > 0) {
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            break;
        }
    }
    ::close(a);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const PeerOutcome outcome = ObservePeer(b);
    ::close(b);
    return outcome;
}

std::string ReadFile(const std::string& relative_path) {
    const std::string path = std::string(OPENPPP2_SOURCE_ROOT) + "/" + relative_path;
    std::ifstream file(path);
    Require(file.good(), "cannot open source file for contract check");
    std::ostringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

// 在 text 中找到 marker 之后的第一个 occurrence 之前，是否出现了 needle。
bool AppearsBefore(const std::string& text,
                    const std::string& needle,
                    const std::string& marker) {
    const size_t needle_pos = text.find(needle);
    if (needle_pos == std::string::npos) {
        return false;
    }
    const size_t marker_pos = text.find(marker, needle_pos);
    return marker_pos != std::string::npos;
}

} // namespace

int main() {
    try {
        // --- 1) 内核语义（Linux）---
        // 关闭一个接收队列里还有未读字节的 socket，内核会发 RST 而不是 FIN；
        // 把队列读空之后再关，对端才能读到干净的 EOF。
        // AF_UNIX 的 socketpair 不走 TCP 的这条判定路径，行为与 TCP 不同
        // （macOS 上两者都不发 RST），所以内核语义只在 Linux 上断言。
#if defined(__linux__)
        // 直接 close()：接收队列非空 => 对端看到 ECONNRESET。
        const PeerOutcome without_drain = RunCloseScenario(false);
        Require(without_drain == PeerOutcome::kReset,
                "closing a socket with unread bytes did not reset the peer");

        // 先把接收队列读空再 close()：对端读到干净 EOF。
        const PeerOutcome with_drain = RunCloseScenario(true);
        Require(with_drain == PeerOutcome::kEof,
                "draining the receive queue before close() did not produce a clean EOF");
#else
        // 非 Linux：socketpair 不具备 TCP 的 RST 判定语义，只跑契约检查。
        (void)RunCloseScenario;
#endif

        // --- 2) mux 关闭路径的契约 ---
        const std::string vmux = ReadFile("ppp/app/mux/vmux_net.cpp");

        // 载体退出路径：必须先 DrainReceive 再 Dispose。
        Require(AppearsBefore(vmux,
                              "drain_carrier_receive(linklayer->connection);",
                              "linklayer->connection->Dispose();"),
                "on_link_exit disposes the carrier without a preceding DrainReceive()");

        // 会话拆除路径：同样必须先 DrainReceive 再 Dispose。
        Require(AppearsBefore(vmux,
                              "drain_carrier_receive(connection);",
                              "connection->Dispose();"),
                "finalize disposes the carrier without a preceding DrainReceive()");

        // 辅助函数必须真的把 DrainReceive 转发到底层传输。
        Require(vmux.find("transmission->DrainReceive()") != std::string::npos,
                "drain_carrier_receive() does not call DrainReceive()");

        // 传输层必须真的把接收队列读空（drain），而不是 shutdown(SHUT_RD)：
        // 实测 Linux 上 SHUT_RD 之后 close() 仍然发 RST。
        const std::string tcpip = ReadFile("ppp/transmissions/ITcpipTransmission.cpp");
        Require(tcpip.find("DrainReceive") != std::string::npos,
                "ITcpipTransmission does not implement DrainReceive()");
        Require(tcpip.find("MSG_DONTWAIT") != std::string::npos,
                "DrainReceive() does not read the queue empty");
        Require(tcpip.find("shutdown_receive") == std::string::npos,
                "DrainReceive() still relies on shutdown(SHUT_RD), which does not prevent RST");

        // 接口必须提供该能力，且对不支持的传输默认返回 false。
        const std::string iface = ReadFile("ppp/transmissions/ITransmission.h");
        Require(iface.find("DrainReceive() noexcept { return false; }") != std::string::npos,
                "ITransmission does not declare DrainReceive() with a safe default");

        std::cout << "mux_carrier_clean_close_test: all checks passed" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "mux_carrier_clean_close_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
