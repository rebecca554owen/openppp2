#pragma once

#include <ppp/cryptography/noise/NoisePsk.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace ppp::transmissions {

/** Owns Noise exporter state for one authenticated carrier and owner executor. */
class NoisePskAuthenticatedCarrierBinding final {
public:
    using ContextPtr = std::shared_ptr<boost::asio::io_context>;
    using Strand = boost::asio::strand<boost::asio::io_context::executor_type>;
    using StrandPtr = std::shared_ptr<Strand>;

    NoisePskAuthenticatedCarrierBinding(
        const ContextPtr& context,
        const StrandPtr& strand,
        ppp::cryptography::noise::NoisePskHandshakeResult&& result) noexcept;
    ~NoisePskAuthenticatedCarrierBinding() noexcept;

    NoisePskAuthenticatedCarrierBinding(
        const NoisePskAuthenticatedCarrierBinding&) = delete;
    NoisePskAuthenticatedCarrierBinding& operator=(
        const NoisePskAuthenticatedCarrierBinding&) = delete;

    bool IsValid() const noexcept;
    bool IsAvailable(
        const ContextPtr& context,
        const StrandPtr& strand) const noexcept;
    /**
     * @brief Copies the negotiated canonical transport-auth key id out.
     *
     * The key id is *copied* rather than handed out as a pointer into the
     * binding: Invalidate() may cleanse it from another thread at any time,
     * so a borrowed pointer would be read outside the lock that guards it.
     * This mirrors what Export() already does for the derived secret.
     *
     * @param output          Caller-owned buffer, at least NoiseKeyIdMaxSize bytes.
     * @param output_capacity Size of @p output in bytes.
     * @param key_id_length   Receives the key id length (1..63 when set).
     * @return True when a canonical key id was negotiated and copied into
     *         @p output; false otherwise (@p key_id_length is set to 0 and
     *         @p output is left untouched).
     */
    bool CopyTransportAuthKeyId(std::uint8_t* output,
                                std::size_t output_capacity,
                                std::size_t& key_id_length) const noexcept;
    bool Export(
        const ContextPtr& context,
        const StrandPtr& strand,
        const char* label,
        const std::uint8_t* exporter_context,
        std::size_t context_length,
        std::uint8_t* output,
        std::size_t output_length) noexcept;
    void Invalidate() noexcept;

private:
    bool IsOwnerExecutor(
        const ContextPtr& context,
        const StrandPtr& strand) const noexcept;

    ContextPtr context_;
    StrandPtr strand_;
    mutable std::mutex mutex_;
    ppp::cryptography::noise::NoisePskHandshakeResult result_;
    std::atomic_bool valid_{false};
};

}
