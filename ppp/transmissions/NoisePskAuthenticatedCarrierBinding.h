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
     * @brief Returns the negotiated canonical transport-auth key id.
     * @param key_id         Receives the key id bytes owned by the binding.
     * @param key_id_length  Receives the key id length (1..63 when set).
     * @return True when a canonical key id was negotiated; false otherwise
     *         (key_id is set to null and key_id_length to 0).
     */
    bool GetTransportAuthKeyId(const std::uint8_t*& key_id,
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
