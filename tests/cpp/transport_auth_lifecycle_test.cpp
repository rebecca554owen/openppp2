#define BOOST_TEST_MODULE transport_auth_lifecycle_test
#include <boost/test/included/unit_test.hpp>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/cryptography/noise/NoisePsk.h>
#include <ppp/p2p/P2PRelayOffer.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>
#include <ppp/transmissions/NoisePskAuthenticatedCarrierBinding.h>

#include <boost/asio/post.hpp>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace noise = ppp::cryptography::noise;
namespace protocol = ppp::app::protocol;
namespace transmissions = ppp::transmissions;
using tcp = asio::ip::tcp;

namespace ppp::transmissions {
std::ostream& operator<<(std::ostream& stream, AuthenticatedCarrierKind value) {
    return stream << static_cast<unsigned>(value);
}
std::ostream& operator<<(std::ostream& stream, AuthenticatedCarrierMethod value) {
    return stream << static_cast<unsigned>(value);
}
}

namespace {

template <std::size_t N>
std::array<std::uint8_t, N> Filled(std::uint8_t start) {
    std::array<std::uint8_t, N> value{};
    for (std::size_t i = 0; i < N; ++i) {
        value[i] = static_cast<std::uint8_t>(start + i);
    }
    return value;
}

noise::Secret32 Secret(std::uint8_t start) {
    return noise::Secret32(Filled<32>(start));
}

noise::NoisePskHandshakeResult CompleteNoiseResult(
    noise::Carrier carrier = noise::Carrier::Tcp) {
    std::vector<std::uint8_t> prologue;
    const auto session_id = Filled<noise::NoiseSessionIdSize>(0x10);
    const std::string key_id = "transport-auth-test";
    BOOST_REQUIRE(noise::BuildCanonicalPrologue(carrier, session_id,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size(),
        prologue));

    noise::NoisePskHandshake client(
        noise::HandshakeRole::NetworkClientInitiator, Secret(0x00), prologue);
    noise::NoisePskHandshake server(
        noise::HandshakeRole::NetworkServerResponder, Secret(0x00), prologue);
    BOOST_REQUIRE(client.SetDeterministicEphemeralPrivateKeyForTesting(
        Secret(0x20)));
    BOOST_REQUIRE(server.SetDeterministicEphemeralPrivateKeyForTesting(
        Secret(0x40)));

    std::vector<std::uint8_t> message1;
    std::vector<std::uint8_t> message2;
    BOOST_REQUIRE(client.WriteMessage1(message1));
    BOOST_REQUIRE(server.ReadMessage1(message1.data(), message1.size()));
    BOOST_REQUIRE(server.WriteMessage2(message2));
    BOOST_REQUIRE(client.ReadMessage2(message2.data(), message2.size()));

    noise::NoisePskHandshakeResult result;
    BOOST_REQUIRE(client.TakeResult(result,
        reinterpret_cast<const std::uint8_t*>(key_id.data()), key_id.size()));
    return result;
}

class FakeTransmission final : public transmissions::ITransmission {
public:
    FakeTransmission(const ContextPtr& context, const StrandPtr& strand,
        transmissions::AuthenticatedCarrierKind kind)
        : ITransmission(context, strand,
            std::make_shared<ppp::configurations::AppConfiguration>())
        , kind_(kind) {
    }

    transmissions::AuthenticatedCarrierKind GetAuthenticatedCarrierKind() const noexcept override {
        return kind_;
    }

    bool IsHandshakeComplete() const noexcept override {
        return handshake_complete_;
    }

    void SetHandshakeComplete(bool value) noexcept {
        handshake_complete_ = value;
    }

    bool ShiftToScheduler() noexcept override {
        InvalidateAuthenticatedCarrierBinding();
        return true;
    }

    tcp::endpoint GetRemoteEndPoint() noexcept override {
        return {};
    }

protected:
    std::shared_ptr<ppp::Byte> DoReadBytes(YieldContext&, int) noexcept override {
        return nullptr;
    }

    bool DoWriteBytes(std::shared_ptr<ppp::Byte>, int, int,
        const AsynchronousWriteBytesCallback&) noexcept override {
        return false;
    }

private:
    transmissions::AuthenticatedCarrierKind kind_;
    bool handshake_complete_ = false;
};

template <typename Callback>
void OnStrand(const std::shared_ptr<asio::io_context>& context,
    const FakeTransmission::StrandPtr& strand, Callback&& callback) {
    context->restart();
    asio::post(*strand, std::forward<Callback>(callback));
    context->run();
}

std::shared_ptr<tcp::socket> ConnectedSocket(
    const std::shared_ptr<asio::io_context>& context,
    std::vector<std::shared_ptr<tcp::socket>>& peers) {
    tcp::acceptor acceptor(*context,
        tcp::endpoint(asio::ip::address_v4::loopback(), 0));
    auto client = std::make_shared<tcp::socket>(*context);
    auto server = std::make_shared<tcp::socket>(*context);
    client->connect(acceptor.local_endpoint());
    acceptor.accept(*server);
    peers.push_back(server);
    return client;
}

}

BOOST_AUTO_TEST_CASE(noise_binding_is_one_shot_typed_and_lifecycle_bound) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));
    auto transmission = std::make_shared<FakeTransmission>(context, strand,
        transmissions::AuthenticatedCarrierKind::Tcp);
    const auto exporter_context = Filled<16>(0x70);
    auto changed_exporter_context = exporter_context;
    changed_exporter_context.back() ^= 1;
    const auto p2p_exporter_context = Filled<ppp::p2p::P2PExporterContext{}.size()>(0x20);
    std::array<std::uint8_t, 32> root{};
    std::array<std::uint8_t, 32> changed_root{};
    std::array<std::uint8_t, 32> candidate{};
    std::array<std::uint8_t, 32> p2p{};

    BOOST_TEST(transmission->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::Tcp);
    BOOST_TEST(!transmission->IsServerLoopbackIngress());
    BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
        transmissions::AuthenticatedCarrierMethod::None);
    BOOST_TEST(!transmission->HasAuthenticatedSessionExporter());

    OnStrand(context, strand, [&]() {
        auto premature = CompleteNoiseResult();
        BOOST_TEST(!transmission->InstallNoiseAuthenticatedCarrierBinding(
            std::move(premature)));
        transmission->SetHandshakeComplete(true);
        auto result = CompleteNoiseResult();
        BOOST_REQUIRE(transmission->InstallNoiseAuthenticatedCarrierBinding(
            std::move(result)));

        BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
            transmissions::AuthenticatedCarrierMethod::NoisePskV1);
        BOOST_TEST(transmission->IsAuthenticatedCarrierBindingActive());
        BOOST_TEST(transmission->HasAuthenticatedSessionExporter());
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            exporter_context.data(), exporter_context.size(),
            root.data(), root.size()));
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            changed_exporter_context.data(), changed_exporter_context.size(),
            changed_root.data(), changed_root.size()));
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeCandidateExporterLabel,
            exporter_context.data(), exporter_context.size(),
            candidate.data(), candidate.size()));
        BOOST_REQUIRE(transmission->ExportAuthenticatedSessionKey(
            ppp::p2p::P2PWrapExporterLabel,
            p2p_exporter_context.data(), p2p_exporter_context.size(),
            p2p.data(), p2p.size()));
        BOOST_TEST(root != changed_root);
        BOOST_TEST(root != candidate);
        BOOST_TEST(root != p2p);
        BOOST_TEST(candidate != p2p);
        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            ppp::p2p::P2PWrapExporterLabel,
            exporter_context.data(), exporter_context.size(),
            p2p.data(), p2p.size()));

        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            "EXPORTER-OPENPPP2-UNKNOWN-v1",
            exporter_context.data(), exporter_context.size(),
            root.data(), root.size()));
        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            exporter_context.data(), exporter_context.size() - 1,
            root.data(), root.size()));
        BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
            protocol::SessionResumeRootExporterLabel,
            exporter_context.data(), exporter_context.size(),
            root.data(), root.size() - 1));

        auto duplicate = CompleteNoiseResult();
        BOOST_TEST(!transmission->InstallNoiseAuthenticatedCarrierBinding(
            std::move(duplicate)));
    });

    BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
        transmissions::AuthenticatedCarrierMethod::NoisePskV1);
    BOOST_TEST(!transmission->IsAuthenticatedCarrierBindingActive());
    BOOST_TEST(!transmission->ExportAuthenticatedSessionKey(
        protocol::SessionResumeRootExporterLabel,
        exporter_context.data(), exporter_context.size(),
        root.data(), root.size()));

    OnStrand(context, strand, [&]() {
        transmission->Dispose();
        BOOST_TEST(!transmission->HasAuthenticatedSessionExporter());
        BOOST_TEST(transmission->GetAuthenticatedCarrierMethod() ==
            transmissions::AuthenticatedCarrierMethod::None);
    });
}

BOOST_AUTO_TEST_CASE(noise_rejects_non_carriers_accepts_loopback_and_migration_invalidates) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));

    for (const auto kind : {
            transmissions::AuthenticatedCarrierKind::None,
            transmissions::AuthenticatedCarrierKind::TlsWebSocket}) {
        auto transmission = std::make_shared<FakeTransmission>(context, strand, kind);
        transmission->SetHandshakeComplete(true);
        OnStrand(context, strand, [&]() {
            auto result = CompleteNoiseResult();
            BOOST_TEST(!transmission->InstallNoiseAuthenticatedCarrierBinding(
                std::move(result)));
        });
    }

    // v2.2.0: loopback ingress is authenticated exactly like LAN, so the
    // noise binding installs and the exporter is available on loopback too.
    auto loopback = std::make_shared<FakeTransmission>(context, strand,
        transmissions::AuthenticatedCarrierKind::Tcp);
    loopback->SetHandshakeComplete(true);
    loopback->MarkServerLoopbackIngress();
    BOOST_TEST(loopback->IsServerLoopbackIngress());
    OnStrand(context, strand, [&]() {
        auto result = CompleteNoiseResult();
        BOOST_REQUIRE(loopback->InstallNoiseAuthenticatedCarrierBinding(
            std::move(result)));
        BOOST_TEST(loopback->IsAuthenticatedCarrierBindingActive());
        BOOST_TEST(loopback->HasAuthenticatedSessionExporter());
    });

    auto websocket = std::make_shared<FakeTransmission>(context, strand,
        transmissions::AuthenticatedCarrierKind::WebSocket);
    websocket->SetHandshakeComplete(true);
    OnStrand(context, strand, [&]() {
        auto result = CompleteNoiseResult(noise::Carrier::WebSocket);
        BOOST_REQUIRE(websocket->InstallNoiseAuthenticatedCarrierBinding(
            std::move(result)));
        BOOST_REQUIRE(websocket->HasAuthenticatedSessionExporter());
        BOOST_REQUIRE(websocket->ShiftToScheduler());
        BOOST_TEST(!websocket->HasAuthenticatedSessionExporter());
        BOOST_TEST(websocket->GetAuthenticatedCarrierMethod() ==
            transmissions::AuthenticatedCarrierMethod::None);
    });
}

BOOST_AUTO_TEST_CASE(noise_binding_key_id_copy_survives_concurrent_invalidate) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<transmissions::NoisePskAuthenticatedCarrierBinding::StrandPtr::element_type>(
        asio::make_strand(*context));

    // Same canonical key id CompleteNoiseResult() installs.
    const std::string canonical = "transport-auth-test";

    // Regression: the binding used to hand out a raw pointer into the
    // handshake result's key id and let the caller read it *after* the lock
    // was released, while InvalidateAuthenticatedCarrierBinding() on the
    // teardown path cleanses those very bytes under that lock.  A torn key id
    // would build a binding context different from the peer's and silently
    // break AEAD record derivation, so a copy must either return the exact
    // canonical bytes or fail cleanly with a zero length.
    //
    // Each round gets a fresh binding on purpose: Invalidate() is one-shot
    // per binding (it clears valid_ before it ever takes the lock), so one
    // shared binding would close the window after its first teardown and hide
    // the very race this test exists to catch.
    std::atomic_bool torn{false};
    std::size_t copies = 0;
    std::size_t failures = 0;

    for (int round = 0; round < 200 && !torn.load(std::memory_order_acquire); ++round) {
        auto binding = std::make_shared<transmissions::NoisePskAuthenticatedCarrierBinding>(
            context, strand, CompleteNoiseResult());
        BOOST_REQUIRE(binding->IsValid());

        std::atomic_bool start{false};
        std::atomic_bool stop{false};
        std::atomic<std::size_t> round_copies{0};
        std::atomic<std::size_t> round_failures{0};

        std::vector<std::thread> readers;
        for (int i = 0; i < 3; ++i) {
            readers.emplace_back([&]() {
                while (!start.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                while (!stop.load(std::memory_order_acquire)) {
                    std::array<std::uint8_t, noise::NoiseKeyIdMaxSize> buffer{};
                    std::size_t length = 0;
                    if (binding->CopyTransportAuthKeyId(
                            buffer.data(), buffer.size(), length)) {
                        round_copies.fetch_add(1, std::memory_order_relaxed);
                        if (length != canonical.size() ||
                            std::memcmp(buffer.data(), canonical.data(), length) != 0) {
                            torn.store(true, std::memory_order_release);
                        }
                    } else {
                        round_failures.fetch_add(1, std::memory_order_relaxed);
                        if (length != 0) {
                            torn.store(true, std::memory_order_release);
                        }
                    }
                }
            });
        }

        start.store(true, std::memory_order_release);
        // Let the readers actually get spinning, then tear the binding down
        // exactly once, then give any in-flight reader time to land.  Both
        // spins are bounded: after Invalidate() the readers can only fail,
        // so waiting on a copy counter here would never terminate.
        for (int spin = 0; spin < 2000; ++spin) {
            std::this_thread::yield();
        }
        binding->Invalidate();
        for (int spin = 0; spin < 2000; ++spin) {
            std::this_thread::yield();
        }
        stop.store(true, std::memory_order_release);
        for (auto& reader : readers) {
            reader.join();
        }

        copies += round_copies.load(std::memory_order_relaxed);
        failures += round_failures.load(std::memory_order_relaxed);
        BOOST_TEST(!binding->IsValid());
    }

    BOOST_TEST(!torn.load(std::memory_order_acquire));
    BOOST_TEST(copies > 0);

    // A null or undersized destination buffer is rejected without touching it.
    auto sink = std::make_shared<transmissions::NoisePskAuthenticatedCarrierBinding>(
        context, strand, CompleteNoiseResult());
    BOOST_REQUIRE(sink->IsValid());
    std::size_t length = 12345;
    BOOST_TEST(!sink->CopyTransportAuthKeyId(NULLPTR,
        noise::NoiseKeyIdMaxSize, length));
    BOOST_TEST(length == 0);
    length = 12345;
    std::array<std::uint8_t, 4> too_small{};
    BOOST_TEST(!sink->CopyTransportAuthKeyId(too_small.data(),
        too_small.size(), length));
    BOOST_TEST(length == 0);
    BOOST_TEST(too_small[0] == 0);
}

BOOST_AUTO_TEST_CASE(production_transport_descriptors_are_explicit) {
    auto context = std::make_shared<asio::io_context>();
    auto strand = std::make_shared<FakeTransmission::StrandPtr::element_type>(
        asio::make_strand(*context));
    auto configuration = std::make_shared<ppp::configurations::AppConfiguration>();
    std::vector<std::shared_ptr<tcp::socket>> peers;

    auto child = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Child);
    auto main = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Main);
    auto server = std::make_shared<transmissions::ITcpipTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration,
        transmissions::TcpTransmissionRole::Server);
    auto websocket = std::make_shared<transmissions::IWebsocketTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration);
    auto wss = std::make_shared<transmissions::ISslWebsocketTransmission>(
        context, strand, ConnectedSocket(context, peers), configuration);

    BOOST_TEST(child->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::Tcp);
    BOOST_TEST(main->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::Tcp);
    BOOST_TEST(server->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::Tcp);
    BOOST_TEST(websocket->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::WebSocket);
    BOOST_TEST(wss->GetAuthenticatedCarrierKind() ==
        transmissions::AuthenticatedCarrierKind::TlsWebSocket);
    BOOST_TEST(wss->GetAuthenticatedCarrierMethod() ==
        transmissions::AuthenticatedCarrierMethod::TlsExporterV1);
    BOOST_TEST(!wss->IsAuthenticatedCarrierBindingActive());

    child->Dispose();
    main->Dispose();
    server->Dispose();
    websocket->Dispose();
    wss->Dispose();
    context->restart();
    context->poll();
}
