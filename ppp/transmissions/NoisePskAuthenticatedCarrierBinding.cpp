#include <ppp/transmissions/NoisePskAuthenticatedCarrierBinding.h>

#include <ppp/app/protocol/SessionResumeAuthenticator.h>
#include <ppp/p2p/P2PRelayOffer.h>

#include <cstring>

namespace ppp::transmissions {
namespace {

using ppp::cryptography::noise::BindingPurpose;
using ppp::cryptography::noise::Secret32;

bool ResolvePurpose(const char* label, BindingPurpose& purpose,
    std::size_t& required_context_length) noexcept {
    if (label == nullptr) {
        return false;
    }
    if (std::strcmp(label,
            ppp::app::protocol::SessionResumeRootExporterLabel) == 0) {
        purpose = BindingPurpose::SessionResumeRetainedRootV1;
        required_context_length = 16;
        return true;
    }
    if (std::strcmp(label,
            ppp::app::protocol::SessionResumeCandidateExporterLabel) == 0) {
        purpose = BindingPurpose::SessionResumeCandidateV1;
        required_context_length = 16;
        return true;
    }
    if (std::strcmp(label, ppp::p2p::P2PWrapExporterLabel) == 0) {
        purpose = BindingPurpose::P2PWrapV1;
        required_context_length = ppp::p2p::P2PExporterContext{}.size();
        return true;
    }
    if (std::strcmp(label,
            ppp::cryptography::noise::RecordProtectorExporterLabel) == 0) {
        purpose = BindingPurpose::RecordProtector;
        // Variable-length context: version(1)||ivv(16)||carrier(1)||
        // key_id_len(1)||key_id; validated structurally in Export().
        required_context_length = 0;
        return true;
    }
    return false;
}

}

NoisePskAuthenticatedCarrierBinding::NoisePskAuthenticatedCarrierBinding(
    const ContextPtr& context,
    const StrandPtr& strand,
    ppp::cryptography::noise::NoisePskHandshakeResult&& result) noexcept
    : context_(context), strand_(strand), result_(std::move(result)) {
    valid_.store(context_ && strand_ && result_.IsValid(),
        std::memory_order_release);
}

NoisePskAuthenticatedCarrierBinding::~NoisePskAuthenticatedCarrierBinding() noexcept {
    Invalidate();
}

bool NoisePskAuthenticatedCarrierBinding::IsOwnerExecutor(
    const ContextPtr& context,
    const StrandPtr& strand) const noexcept {
    return context && strand && context == context_ && strand == strand_ &&
        !context->stopped() && strand->running_in_this_thread();
}

bool NoisePskAuthenticatedCarrierBinding::IsValid() const noexcept {
    return valid_.load(std::memory_order_acquire);
}

bool NoisePskAuthenticatedCarrierBinding::IsAvailable(
    const ContextPtr& context,
    const StrandPtr& strand) const noexcept {
    if (!IsValid()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return IsValid() && IsOwnerExecutor(context, strand);
}

bool NoisePskAuthenticatedCarrierBinding::GetTransportAuthKeyId(
    const std::uint8_t*& key_id, std::size_t& key_id_length) const noexcept {
    key_id = nullptr;
    key_id_length = 0;
    std::lock_guard<std::mutex> lock(mutex_);
    if (!valid_.load(std::memory_order_acquire)) {
        return false;
    }
    return result_.GetTransportAuthKeyId(key_id, key_id_length);
}

bool NoisePskAuthenticatedCarrierBinding::Export(
    const ContextPtr& context,
    const StrandPtr& strand,
    const char* label,
    const std::uint8_t* exporter_context,
    std::size_t context_length,
    std::uint8_t* output,
    std::size_t output_length) noexcept {
    BindingPurpose purpose{};
    std::size_t required_context_length = 0;
    const bool purpose_resolved = ResolvePurpose(label, purpose, required_context_length);
    bool context_valid = false;
    if (purpose_resolved && exporter_context != nullptr) {
        if (purpose == BindingPurpose::RecordProtector) {
            // Variable-length explicit layout; both ends must parse it strictly.
            context_valid =
                ppp::cryptography::noise::IsValidRecordProtectorBindingContext(
                    exporter_context, context_length);
        } else {
            context_valid = context_length == required_context_length;
        }
    }
    if (!IsValid() ||
        context == nullptr || strand == nullptr ||
        context != context_ || strand != strand_ ||
        context->stopped() ||
        !purpose_resolved || !context_valid ||
        output == nullptr || output_length != 32) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!valid_.load(std::memory_order_acquire)) {
        return false;
    }

    Secret32 derived;
    if (!result_.DeriveBinding(purpose, exporter_context, context_length, derived) ||
        !derived.IsSet() || derived.size() != output_length) {
        return false;
    }
    std::memcpy(output, derived.data(), output_length);
    derived.Clear();
    return true;
}

void NoisePskAuthenticatedCarrierBinding::Invalidate() noexcept {
    valid_.store(false, std::memory_order_release);
    std::lock_guard<std::mutex> lock(mutex_);
    result_.Clear();
    strand_.reset();
    context_.reset();
}

}
