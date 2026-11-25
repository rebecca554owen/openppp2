// vmux_fin_dsn_test.cpp -- the end-of-stream frame must continue the DSN
// space of its flow.
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
// The test drives the real send path (post_internal), the real close path
// (release_connection_and_post_fin) and the real peer receive path
// (packet_input_flow): the exact frame the sender produced is fed into the
// peer, so the end-to-end contract ("the peer observes a clean end of
// stream") is asserted, not just the header field.
//
// The wire header and the command codes are private to vmux_net, so every
// access to them lives inside vmux_net_test_access (a friend of vmux_net).

#include <ppp/stdafx.h>
#include <ppp/app/mux/vmux_net.h>
#include <ppp/app/mux/vmux_skt.h>
#include <ppp/configurations/AppConfiguration.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vmux {

// The friend of vmux_net declared in vmux_net.h: the test drives the private
// send and receive paths of one session.
struct vmux_net_test_access {
    template <typename Handler>
    static auto RunOnStrand(vmux_net& mux, Handler&& handler) -> decltype(handler()) {
        using Result = decltype(handler());
        if (mux.is_strand_thread()) {
            return handler();
        }
        if (!mux.context_ || !mux.strand_) {
            throw std::runtime_error("mux executor unavailable");
        }

        std::optional<Result> result;
        std::exception_ptr error;
        boost::asio::post(*mux.strand_, [&]() {
            try {
                result.emplace(handler());
            }
            catch (...) {
                error = std::current_exception();
            }
        });
        mux.context_->restart();
        while (!result && !error) {
            if (mux.context_->run_one() == 0) {
                throw std::runtime_error("mux strand handler did not run");
            }
        }
        if (error) {
            std::rethrow_exception(error);
        }
        return std::move(*result);
    }

    template <typename Handler>
    static void RunOnStrandVoid(vmux_net& mux, Handler&& handler) {
        RunOnStrand(mux, [&]() {
            handler();
            return true;
        });
    }

    /** Put the session into the flow v2 ordering with an established session. */
    static void ConfigureFlowV2(vmux_net& mux) {
        RunOnStrandVoid(mux, [&]() {
            mux.ordering_mode_ = vmux_net::ordering_flow_v2;
            mux.base_.established_ = true;
            mux.base_.disposed_.store(false, std::memory_order_release);
        });
    }

    /** Install one logical socket so the flow context of its cid is admitted. */
    static std::shared_ptr<vmux_skt> InstallSkt(const std::shared_ptr<vmux_net>& mux, std::uint32_t connection_id) {
        return RunOnStrand(*mux, [&]() {
            auto skt = ppp::make_shared_object<vmux_skt>(mux, connection_id);
            if (!skt) {
                throw std::runtime_error("skt alloc failed");
            }
            skt->status_.connected_ = true;
            skt->status_.disposed_ = false;
            skt->status_.fin_ = false;
            skt->status_.sending_.store(1, std::memory_order_relaxed); // queue-only input path
            mux->skts_[connection_id] = skt;
            return skt;
        });
    }

    /** Post one push frame through the real send path so the DSN advances. */
    static bool PostPush(vmux_net& mux, std::uint32_t connection_id, int payload_len) {
        return RunOnStrand(mux, [&]() {
            std::vector<std::uint8_t> payload(static_cast<std::size_t>(payload_len), 'p');
            vmux_net::PostInternalAsynchronousCallback none;
            return mux.post_internal(vmux_net::cmd_push, payload.data(), payload_len, connection_id, false, none);
        });
    }

    /**
     * @brief Close the flow the way the application does, then let the close run.
     * @details vmux_skt::close() is the production close path: it posts the
     *          finalization to the mux strand, where the flow is released and
     *          its end-of-stream frame is queued. The test drives that path
     *          instead of the helper it calls, so the assertion covers what the
     *          application really does.
     */
    static void CloseFlow(vmux_net& mux, const std::shared_ptr<vmux_skt>& skt) {
        const auto& context = mux.get_context();
        if (!context) {
            return;
        }
        // vmux_skt::close() posts the finalization to the mux strand, and the
        // post is refused when the context is stopped -- which is the state
        // an exhausted io_context leaves behind. Restart it first, then pump
        // it so the posted close handler actually runs.
        context->restart();
        skt->close();
        for (int i = 0; i < 16; ++i) {
            if (context->poll() == 0) {
                break;
            }
            context->restart();
        }
    }

    /** Copy the frame that is queued for the flow, header included. */
    static std::vector<std::uint8_t> TakeQueuedFrame(vmux_net& mux, std::uint32_t connection_id) {
        return RunOnStrand(mux, [&]() {
            std::vector<std::uint8_t> out;
            auto it = mux.tx_flows_.find(connection_id);
            if (it == mux.tx_flows_.end() || it->second.queue.empty()) {
                return out;
            }
            const vmux_net::tx_packet& frame = it->second.queue.front();
            out.assign(frame.buffer.get(), frame.buffer.get() + frame.length);
            return out;
        });
    }

    /** Every frame that is queued for the flow, in queue order. */
    static std::vector<std::vector<std::uint8_t>> QueuedFrames(vmux_net& mux, std::uint32_t connection_id) {
        return RunOnStrand(mux, [&]() {
            std::vector<std::vector<std::uint8_t>> out;
            auto it = mux.tx_flows_.find(connection_id);
            if (it == mux.tx_flows_.end()) {
                return out;
            }
            for (const auto& frame : it->second.queue) {
                out.emplace_back(frame.buffer.get(), frame.buffer.get() + frame.length);
            }
            return out;
        });
    }

    /** The end-of-stream frame of the flow, if it is queued. */
    static std::vector<std::uint8_t> FindQueuedFin(vmux_net& mux, std::uint32_t connection_id) {
        for (const auto& frame : QueuedFrames(mux, connection_id)) {
            if (FrameIsFin(frame)) {
                return frame;
            }
        }
        return std::vector<std::uint8_t>();
    }

    /** Build a push frame the way the sender would put it on the wire. */
    static std::vector<std::uint8_t> MakePushFrame(std::uint32_t connection_id, std::uint32_t dsn, int payload_len) {
        std::vector<std::uint8_t> frame(sizeof(vmux_net::vmux_hdr) + static_cast<std::size_t>(payload_len));
        std::memset(frame.data(), 'p', frame.size());
        auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(frame.data());
        h->cmd = static_cast<std::uint8_t>(vmux_net::cmd_push);
        h->connection_id = htonl(connection_id);
        h->seq = htonl(dsn);
        return frame;
    }

    /** The command byte of a frame. */
    static std::uint8_t FrameCmd(const std::vector<std::uint8_t>& frame) {
        if (frame.size() < sizeof(vmux_net::vmux_hdr)) {
            return 0;
        }
        const auto* h = reinterpret_cast<const vmux_net::vmux_hdr*>(frame.data());
        return h->cmd;
    }

    /** True when the frame is the end-of-stream frame. */
    static bool FrameIsFin(const std::vector<std::uint8_t>& frame) {
        return FrameCmd(frame) == static_cast<std::uint8_t>(vmux_net::cmd_fin);
    }

    /** The DSN a frame carries. */
    static std::uint32_t FrameDsn(const std::vector<std::uint8_t>& frame) {
        if (frame.size() < sizeof(vmux_net::vmux_hdr)) {
            return 0;
        }
        const auto* h = reinterpret_cast<const vmux_net::vmux_hdr*>(frame.data());
        return ntohl(h->seq);
    }

    /** Deliver a frame to the peer side of a flow v2 session. */
    static bool InjectFrame(vmux_net& mux, const std::vector<std::uint8_t>& frame, std::uint64_t now) {
        return RunOnStrand(mux, [&]() {
            std::vector<std::uint8_t> copy(frame);
            auto* h = reinterpret_cast<vmux_net::vmux_hdr*>(copy.data());
            return mux.packet_input_flow(vmux_net::vmux_linklayer_ptr{}, h, static_cast<int>(copy.size()), now);
        });
    }

    /** Close the session and drain its executor. */
    static void CloseAndDrain(const std::shared_ptr<vmux_net>& mux) noexcept {
        if (!mux) {
            return;
        }
        const auto& context = mux->get_context();
        if (!context) {
            return;
        }
        context->restart();
        mux->close_exec();
        for (int i = 0; i < 64; ++i) {
            const std::size_t n = context->poll();
            context->restart();
            if (n == 0) {
                break;
            }
        }
    }

    /** True when the peer still holds a receive context for the flow. */
    static bool PeerHasFlow(vmux_net& mux, std::uint32_t connection_id) {
        return RunOnStrand(mux, [&]() {
            return mux.flows_.find(connection_id) != mux.flows_.end();
        });
    }

    /** The DSN the peer expects next for the flow. */
    static std::uint32_t PeerNextDsn(vmux_net& mux, std::uint32_t connection_id) {
        return RunOnStrand(mux, [&]() {
            auto it = mux.flows_.find(connection_id);
            return it == mux.flows_.end() ? 0 : it->second.flow_rx_next_;
        });
    }
};

} // namespace vmux

namespace {

using ppp::threading::Executors;

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

struct ScopedMux {
    explicit ScopedMux(std::shared_ptr<vmux::vmux_net> mux) : mux_(std::move(mux)) {}
    ~ScopedMux() {
        if (mux_) {
            vmux::vmux_net_test_access::CloseAndDrain(mux_);
        }
    }
    vmux::vmux_net& operator*() const noexcept { return *mux_; }
    operator const std::shared_ptr<vmux::vmux_net>&() const noexcept { return mux_; }

private:
    std::shared_ptr<vmux::vmux_net> mux_;
};

ScopedMux MakeMux() {
    auto context = std::make_shared<boost::asio::io_context>();
    auto strand = std::make_shared<Executors::Strand>(context->get_executor());
    auto mux = ppp::make_shared_object<vmux::vmux_net>(
        context, strand, 1, true, false, vmux::vmux_net::mux_mode_balance);
    Require(static_cast<bool>(mux), "vmux allocation failed");
    auto cfg = ppp::make_shared_object<ppp::configurations::AppConfiguration>();
    Require(static_cast<bool>(cfg), "cfg allocation failed");
    cfg->mux.congestions = 0; // disable congestion accounting path in tests
    mux->AppConfiguration = cfg;
    return ScopedMux(std::move(mux));
}

// The FIN of a flow that carried data must continue the flow's DSN space.
void TestFinContinuesTheFlowDsn() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux);
    constexpr std::uint32_t cid = 21;

    auto skt = vmux::vmux_net_test_access::InstallSkt(mux, cid);
    Require(vmux::vmux_net_test_access::PostPush(*mux, cid, 16), "first push");
    Require(vmux::vmux_net_test_access::PostPush(*mux, cid, 16), "second push");
    Require(vmux::vmux_net_test_access::PostPush(*mux, cid, 16), "third push");

    vmux::vmux_net_test_access::CloseFlow(*mux, skt);

    // The close does not drop the frames that were still queued: their DSNs
    // were spent when they were queued and the peer waits for exactly those
    // numbers.  The end-of-stream frame follows them.
    const auto queued = vmux::vmux_net_test_access::QueuedFrames(*mux, cid);
    Require(queued.size() == 4,
            "the close must keep the three queued data frames and add the end-of-stream frame");

    const std::vector<std::uint8_t> fin = vmux::vmux_net_test_access::FindQueuedFin(*mux, cid);
    Require(!fin.empty(), "the close must queue the end-of-stream frame");
    Require(vmux::vmux_net_test_access::FrameDsn(fin) == 4,
            "the FIN must carry the next DSN of the flow (4), not restart at 1");
}

// The close of a flow must not drop the frames that are still queued for it.
//
// The frames spent their sequence numbers when they were queued, and the peer
// waits for exactly those numbers.  Dropping them leaves a hole in the peer's
// sequence space: the peer delivers in order, stops at the hole and resets
// the flow when its gap timeout expires, so a bulk transfer ends early even
// though the sender still had the data.
void TestCloseKeepsTheQueuedFrames() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux);
    constexpr std::uint32_t cid = 24;

    auto skt = vmux::vmux_net_test_access::InstallSkt(mux, cid);
    Require(vmux::vmux_net_test_access::PostPush(*mux, cid, 16), "first push");
    Require(vmux::vmux_net_test_access::PostPush(*mux, cid, 16), "second push");

    vmux::vmux_net_test_access::CloseFlow(*mux, skt);

    const auto queued = vmux::vmux_net_test_access::QueuedFrames(*mux, cid);
    Require(queued.size() == 3,
            "the close must keep the two queued data frames and add the end-of-stream frame");

    // The DSN space of the flow stays contiguous: the data frames carry 1 and
    // 2 and the end-of-stream frame carries 3, so the peer sees no hole.
    Require(vmux::vmux_net_test_access::FrameDsn(queued[0]) == 1,
            "the first queued data frame keeps DSN 1");
    Require(vmux::vmux_net_test_access::FrameDsn(queued[1]) == 2,
            "the second queued data frame keeps DSN 2");
    Require(vmux::vmux_net_test_access::FrameIsFin(queued[2]),
            "the end-of-stream frame must follow the queued data frames");
    Require(vmux::vmux_net_test_access::FrameDsn(queued[2]) == 3,
            "the end-of-stream frame must continue the DSN space of the flow");
}

// The FIN of a flow that never carried data is the first frame of its space.
void TestFinOfAnEmptyFlowIsDsnOne() {
    auto mux = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*mux);
    constexpr std::uint32_t cid = 22;

    auto skt = vmux::vmux_net_test_access::InstallSkt(mux, cid);
    vmux::vmux_net_test_access::CloseFlow(*mux, skt);

    const std::vector<std::uint8_t> fin = vmux::vmux_net_test_access::TakeQueuedFrame(*mux, cid);
    Require(!fin.empty(), "the close must queue the end-of-stream frame");
    Require(vmux::vmux_net_test_access::FrameDsn(fin) == 1,
            "the FIN of a flow without data must be the first frame of its DSN space");
}

// End to end: the frame the sender produced must be a clean end of stream for
// the peer. A FIN that restarts the DSN space is dropped as a stale DSN, so
// the peer keeps its flow context and never observes the end of the stream.
void TestPeerObservesTheEndOfStream() {
    auto sender = MakeMux();
    auto peer = MakeMux();
    vmux::vmux_net_test_access::ConfigureFlowV2(*sender);
    vmux::vmux_net_test_access::ConfigureFlowV2(*peer);
    constexpr std::uint32_t cid = 23;

    auto sender_skt = vmux::vmux_net_test_access::InstallSkt(sender, cid);
    vmux::vmux_net_test_access::InstallSkt(peer, cid);

    Require(vmux::vmux_net_test_access::PostPush(*sender, cid, 16), "first push");
    Require(vmux::vmux_net_test_access::PostPush(*sender, cid, 16), "second push");

    // The sender closes.  The frames that were still queued are kept, so the
    // peer receives the whole flow without a hole in its DSN space.
    vmux::vmux_net_test_access::CloseFlow(*sender, sender_skt);
    const auto queued = vmux::vmux_net_test_access::QueuedFrames(*sender, cid);
    Require(queued.size() == 3,
            "the close must keep the queued data frames and add the end-of-stream frame");

    Require(vmux::vmux_net_test_access::InjectFrame(*peer, queued[0], 1),
            "peer takes DSN 1");
    Require(vmux::vmux_net_test_access::InjectFrame(*peer, queued[1], 2),
            "peer takes DSN 2");
    Require(vmux::vmux_net_test_access::PeerNextDsn(*peer, cid) == 3,
            "the peer must expect the next DSN of the flow");

    // The FIN must land on the DSN the peer waits for.
    Require(vmux::vmux_net_test_access::FrameIsFin(queued[2]),
            "the last queued frame must be the end-of-stream frame");
    Require(vmux::vmux_net_test_access::FrameDsn(queued[2]) == 3,
            "the FIN must carry the DSN the peer waits for");

    Require(vmux::vmux_net_test_access::InjectFrame(*peer, queued[2], 3),
            "the peer must accept the end-of-stream frame");
    Require(!vmux::vmux_net_test_access::PeerHasFlow(*peer, cid),
            "the peer must release the flow: the end of the stream was observed");
}

} // namespace

int main() {
    try {
        TestFinContinuesTheFlowDsn();
        TestFinOfAnEmptyFlowIsDsnOne();
        TestCloseKeepsTheQueuedFrames();
        TestPeerObservesTheEndOfStream();
        std::cout << "vmux_fin_dsn_test: ok" << std::endl;
        return 0;
    }
    catch (const std::exception& ex) {
        std::cerr << "vmux_fin_dsn_test failed: " << ex.what() << std::endl;
        return 1;
    }
}
