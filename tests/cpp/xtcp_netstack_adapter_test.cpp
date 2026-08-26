/**
 * @file xtcp_netstack_adapter_test.cpp
 * @brief M2 integration test for the XTCP MIMT flow pump.
 *
 * Two XtcpStacks are connected over ManualBackends (the ManualBackend pair
 * plays the role of the TUN wire):
 *
 *   Stack A (TUN client): Connect() to 127.0.0.1:38080, Send()s a payload.
 *   Stack B (adapter side): Listen()s on 127.0.0.1:38080. The MIMT hook
 *   mirrors what XtcpNetstackAdapter::BindFlow does at the flow level:
 *   AsyncRead from the flow, then AsyncWrite the payload back (an echo).
 *
 *   A.Send -> A stack -> wire -> B stack -> MimtFlow -> AsyncRead
 *          -> AsyncWrite -> B stack -> wire -> A stack -> recv handler
 *
 * The adapter's socket pump (flow->socket / socket->flow) is compiled into
 * the library and exercised end-to-end by the client-layer functional matrix
 * (M3); this test keeps the flow-level contract hermetic without a TAP
 * device or exchanger.
 */

#include <xtcp/core/stack.h>
#include <xtcp/ndi/manual.h>
#include <xtcp/mimt/mimt.h>

#include <ppp/stdafx.h>
#include <xtcp/XtcpNetstackAdapter.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

static int g_failures = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        if (!(cond)) {                                                    \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                 \
        }                                                                \
    } while (0)

namespace {

using ppp::ethernet::XtcpNetstackAdapter;

constexpr UInt16 kTunPort = 38080;

/** @brief Relays packets between two stacks' ManualBackends. */
class Wire {
public:
    Wire(xtcp::ndi::ManualBackend& a, xtcp::ndi::ManualBackend& b,
         xtcp::XtcpStack& sa, xtcp::XtcpStack& sb)
        : a_(a), b_(b), sa_(sa), sb_(sb) {}

    void Pump() {
        Byte out[65536];
        while (0 != a_.TxPending()) {
            const UInt32 n = a_.PollTx(out);
            if (0 < n) {
                b_.Inject(out, n, 0x0800);
            }
        }
        while (0 != b_.TxPending()) {
            const UInt32 n = b_.PollTx(out);
            if (0 < n) {
                a_.Inject(out, n, 0x0800);
            }
        }
        sa_.DispatchMimt();
        sb_.DispatchMimt();
        sa_.PollAckTimers();
        sb_.PollAckTimers();
    }

private:
    xtcp::ndi::ManualBackend& a_;
    xtcp::ndi::ManualBackend& b_;
    xtcp::XtcpStack& sa_;
    xtcp::XtcpStack& sb_;
};

} // namespace

int main() {
    xtcp::buf::InitPools();

    // Wire: stack A (TUN client) <-> stack B (adapter side).
    xtcp::ndi::ManualBackend backend_a;
    xtcp::ndi::ManualBackend backend_b;
    xtcp::XtcpStack stack_a(&backend_a);
    xtcp::XtcpStack stack_b(&backend_b);
    Wire wire(backend_a, backend_b, stack_a, stack_b);

    // Adapter side: listen on 127.0.0.1:38080.
    xtcp::core::Endpoint listen_ep;
    listen_ep.family = 4;
    listen_ep.addr[0] = 0x7f000001;
    listen_ep.port = kTunPort;
    CHECK(stack_b.Listen(listen_ep));

    // MIMT hook (adapter BindFlow semantics at the flow level): echo every
    // read back through the flow. RemoteEndpoint must carry the SYN's
    // destination (the fork patch stamps it at accept time) - the adapter
    // relies on it to dial the outbound socket.
    std::atomic<int> flows_seen{0};
    std::atomic<bool> echo_ok{false};
    std::vector<Byte> echoed;
    xtcp::core::Endpoint accepted_remote{};

    auto on_flow = [&](const std::shared_ptr<xtcp::mimt::MimtFlow>& flow) {
        flows_seen.fetch_add(1);
        accepted_remote = flow->RemoteEndpoint();
        auto buf = std::make_shared<std::vector<Byte>>(256);
        flow->AsyncRead(buf->data(), (UInt32)buf->size(),
            [flow, buf, &echoed, &echo_ok](xtcp::mimt::Result ec, UInt32 n) {
                if (ec != xtcp::mimt::Result::kOk || n == 0) {
                    return;
                }
                echoed.insert(echoed.end(), buf->begin(), buf->begin() + n);
                flow->AsyncWrite(buf->data(), n,
                    [flow, buf, &echo_ok](xtcp::mimt::Result wec, UInt32) {
                        if (wec == xtcp::mimt::Result::kOk) {
                            echo_ok.store(true);
                        }
                    });
            });
    };
    stack_b.StartMimt(on_flow);

    // TUN client side: connect and send.
    xtcp::core::Endpoint local_ep;
    local_ep.family = 4;
    local_ep.addr[0] = 0x7f000001;
    local_ep.port = 40000;
    xtcp::core::Endpoint remote_ep;
    remote_ep.family = 4;
    remote_ep.addr[0] = 0x7f000001;
    remote_ep.port = kTunPort;

    UInt64 conn = stack_a.Connect(local_ep, remote_ep);
    CHECK(conn != 0);

    // Pump until the flow is delivered.
    for (int round = 0; round < 2000 && flows_seen.load() == 0; ++round) {
        wire.Pump();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    CHECK(flows_seen.load() >= 1);
    CHECK(accepted_remote.port == kTunPort);
    CHECK(accepted_remote.family == 4);
    CHECK(accepted_remote.addr[0] == 0x7f000001);

    // Send a payload from A; expect it to echo back through the flow hook.
    const char payload[] = "hello-xtcp-m2-pump";
    std::vector<Byte> sent(payload, payload + sizeof(payload) - 1);
    bool send_ok = false;
    for (int round = 0; round < 2000; ++round) {
        wire.Pump();
        if (!send_ok) {
            send_ok = stack_a.Send(conn, (const Byte*)sent.data(), (UInt32)sent.size());
        }
        if (echo_ok.load() && echoed.size() >= sent.size()) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    CHECK(send_ok);
    CHECK(echo_ok.load());
    CHECK(echoed.size() == sent.size());
    if (echoed.size() == sent.size()) {
        CHECK(0 == std::memcmp(echoed.data(), sent.data(), sent.size()));
    }

    // Tear down.
    stack_b.StartMimt(nullptr);
    stack_a.Abort(conn);
    wire.Pump();

    if (g_failures == 0) {
        std::printf("xtcp_netstack_adapter_test: OK\n");
        return 0;
    }
    std::fprintf(stderr, "xtcp_netstack_adapter_test: %d failure(s)\n", g_failures);
    return 1;
}
