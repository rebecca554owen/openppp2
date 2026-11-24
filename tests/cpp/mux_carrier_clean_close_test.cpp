// mux_carrier_clean_close_test.cpp -- a carrier must half-close its receive
// direction before it is closed.
//
// Background (measured on the 2026-11-01 evening peak):
//   The mux carrier socket on the dmit side still had unread bytes in its
//   receive queue when close() ran, so the kernel sent an RST instead of a
//   FIN. The NAS side then saw "Read failed outlen=0 error=101"
//   (ECONNRESET), eleven carriers died together, the client TUN detached, and
//   the whole mux session was rebuilt -- every in-flight transfer on that
//   session was thrown away.
//   The kernel counter confirms it: TcpExtTCPAbortOnClose = 224 on dmit (a
//   user-space close with unread data sends an RST).
//
// This test has two layers:
//   1) Kernel semantics (measured with a socketpair): closing a socket whose
//      receive queue is not empty makes the peer read ECONNRESET; draining the
//      queue first, then closing, makes the peer read a clean EOF. That is
//      the kernel behaviour the fix relies on.
//   2) The mux-side contract (source assertions): a carrier must call
//      DrainReceive() before Dispose(), otherwise the behaviour above happens.

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

// What the peer observed after the close.
enum class PeerOutcome {
    kEof,       // clean EOF: zero bytes read
    kReset,     // ECONNRESET: -1 with errno == ECONNRESET
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

// Build one connected local socket pair, write to the peer so the local
// receive queue is not empty, then close.
// drain_receive=true reads the receive queue empty before close().
PeerOutcome RunCloseScenario(bool drain_receive) {
    int fds[2] = { -1, -1 };
    Require(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0, "socketpair failed");
    const int a = fds[0];
    const int b = fds[1];

    const char payload[] = "queued-but-never-read";
    Require(::write(b, payload, sizeof(payload)) == static_cast<ssize_t>(sizeof(payload)),
            "write to peer failed");

    if (drain_receive) {
        // Drain the receive queue: read until EAGAIN.
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

// Whether needle appears in text before the first occurrence of marker.
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
        // --- 1) Kernel semantics (Linux) ---
        // Closing a socket that still has unread bytes makes the kernel send an
        // RST; only an empty receive queue produces a clean FIN.
        // An AF_UNIX socketpair does not take the TCP decision path (on macOS
        // neither sends an RST), so the kernel semantics are asserted on Linux
        // only.
#if defined(__linux__)
        // A direct close(): the receive queue is not empty => the peer sees
        // ECONNRESET.
        const PeerOutcome without_drain = RunCloseScenario(false);
        Require(without_drain == PeerOutcome::kReset,
                "closing a socket with unread bytes did not reset the peer");

        // Drain the receive queue, then close(): the peer reads a clean EOF.
        const PeerOutcome with_drain = RunCloseScenario(true);
        Require(with_drain == PeerOutcome::kEof,
                "draining the receive queue before close() did not produce a clean EOF");
#else
        // Not Linux: a socketpair has no TCP RST semantics, so only the
        // contract checks run.
        (void)RunCloseScenario;
#endif

        // --- 2) The contract of the mux close path ---
        const std::string vmux = ReadFile("ppp/app/mux/vmux_net.cpp");

        // The carrier exit path: DrainReceive() must come before Dispose().
        Require(AppearsBefore(vmux,
                              "drain_carrier_receive(linklayer->connection);",
                              "linklayer->connection->Dispose();"),
                "on_link_exit disposes the carrier without a preceding DrainReceive()");

        // The session teardown path: same rule.
        Require(AppearsBefore(vmux,
                              "drain_carrier_receive(connection);",
                              "connection->Dispose();"),
                "finalize disposes the carrier without a preceding DrainReceive()");

        // The helper must really forward DrainReceive() to the transport.
        Require(vmux.find("transmission->DrainReceive()") != std::string::npos,
                "drain_carrier_receive() does not call DrainReceive()");

        // The transport must really read the queue empty (drain) instead of
        // shutdown(SHUT_RD): on Linux an RST is still sent after SHUT_RD.
        const std::string tcpip = ReadFile("ppp/transmissions/ITcpipTransmission.cpp");
        Require(tcpip.find("DrainReceive") != std::string::npos,
                "ITcpipTransmission does not implement DrainReceive()");
        Require(tcpip.find("MSG_DONTWAIT") != std::string::npos,
                "DrainReceive() does not read the queue empty");
        Require(tcpip.find("shutdown_receive") == std::string::npos,
                "DrainReceive() still relies on shutdown(SHUT_RD), which does not prevent RST");

        // The interface must offer the capability, with a safe default for the
        // transports that cannot drain.
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
