#define BOOST_TEST_MODULE p2p_channel_lifecycle_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/p2p/P2PChannel.h>

#include <chrono>

using namespace ppp;
using namespace ppp::p2p;

namespace ppp {

uint64_t GetTickCount() noexcept {
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

} // namespace ppp

namespace {

class TestProtector final : public ISocketProtector {
public:
    explicit TestProtector(bool result) noexcept : result_(result) {}

    bool IsReady() const noexcept override { return true; }
    bool Protect(int) noexcept override {
        ++calls;
        return result_;
    }

    int calls = 0;

private:
    bool result_;
};

std::shared_ptr<P2PChannel> MakeChannel(
        boost::asio::io_context& context,
        const std::shared_ptr<ISocketProtector>& protector) {
    uint8_t session_key[SESSION_KEY_SIZE] = {};
    uint8_t token_key[SESSION_KEY_SIZE] = {};
    session_key[0] = 1;
    token_key[0] = 2;
    P2PConfig config;
    config.probe_timeout_ms = 1;
    return std::make_shared<P2PChannel>(
        context, protector, Int128(1), session_key, token_key, config,
        P2PCipher::ChaCha20Poly1305);
}

ppp::vector<P2PCandidate> LoopbackCandidates() {
    return {{boost::asio::ip::udp::endpoint(
        boost::asio::ip::address_v4::loopback(), 9), "test"}};
}

} // namespace

BOOST_AUTO_TEST_CASE(close_is_idempotent_and_cancelled_handlers_stay_on_relay) {
    boost::asio::io_context context;
    auto protector = std::make_shared<TestProtector>(true);
    auto channel = MakeChannel(context, protector);

    channel->StartProbing(LoopbackCandidates(), Int128(2), "offer-token");
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Probing));
    BOOST_TEST(protector->calls == 1);

    channel->Close();
    channel->Close();
    context.run();

    BOOST_TEST(channel->IsClosed());
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(channel->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::None));
}

BOOST_AUTO_TEST_CASE(first_fallback_reason_survives_repeated_stop) {
    boost::asio::io_context context;
    auto channel = MakeChannel(context, std::make_shared<TestProtector>(true));

    channel->StartProbing(LoopbackCandidates(), Int128(2), "");
    channel->StartProbing(LoopbackCandidates(), Int128(2), "offer-token");
    channel->Close();

    BOOST_TEST(channel->IsClosed());
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(channel->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::AuthenticationFailure));
}

BOOST_AUTO_TEST_CASE(socket_protection_failure_falls_back_and_cleans_up) {
    boost::asio::io_context context;
    auto protector = std::make_shared<TestProtector>(false);
    auto channel = MakeChannel(context, protector);

    channel->StartProbing(LoopbackCandidates(), Int128(2), "offer-token");
    context.run();

    BOOST_TEST(protector->calls == 1);
    BOOST_TEST(channel->IsClosed());
    BOOST_TEST(static_cast<int>(channel->GetState()) ==
        static_cast<int>(P2PChannelState::Relay));
    BOOST_TEST(static_cast<int>(channel->GetFallbackReason()) ==
        static_cast<int>(P2PFallbackReason::SocketError));
}
