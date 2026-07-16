#include <ppp/p2p/P2PClientOfferSession.h>

#include <openssl/crypto.h>

#include <limits>

namespace ppp::p2p {
namespace {

template <typename T>
void Cleanse(T& value) noexcept {
    OPENSSL_cleanse(&value, sizeof(value));
}

}

P2PClientOfferSession::~P2PClientOfferSession() noexcept {
    Reset();
}

bool P2PClientOfferSession::Accept(
    const std::string& encoded,
    const P2PRelayOfferRecipientContext& context,
    const P2PRelayOfferExporter& exporter,
    std::uint64_t received_at_ms,
    std::uint64_t generation) noexcept {
    P2PRelayOfferRecipientResult opened;
    if (!OpenP2PRelayOfferRecipient(encoded, context, exporter, opened)) {
        return false;
    }

    P2POfferHash offer_hash{};
    P2PV1KeyMaterial key_material{};
    const bool derived = HashP2PRelayOffer(opened.offer, offer_hash) &&
        DeriveP2PV1KeyMaterial(opened.pair_seed, offer_hash, key_material);
    OPENSSL_cleanse(opened.pair_seed.data(), opened.pair_seed.size());
    OPENSSL_cleanse(offer_hash.data(), offer_hash.size());
    if (!derived) {
        Cleanse(key_material);
        return false;
    }

    const std::uint64_t ttl_ms =
        static_cast<std::uint64_t>(opened.ttl_seconds) * 1000;
    if (received_at_ms > std::numeric_limits<std::uint64_t>::max() - ttl_ms) {
        Cleanse(key_material);
        return false;
    }
    const std::uint64_t deadline_ms = received_at_ms + ttl_ms;

    bool accepted = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation < generation_floor_) {
            Cleanse(key_material);
            return false;
        }
        if (generation > generation_floor_) {
            ClearActiveLocked();
            ClearReplayLocked();
            generation_floor_ = generation;
        }
        if (!SeenLocked(opened.offer.offer_id)) {
            ClearActiveLocked();
            active_ = true;
            state_ = P2PState::Eligible;
            offer_ = opened.offer;
            key_material_ = key_material;
            local_role_ = opened.local_role;
            peer_session_id_ = opened.peer_session_id;
            peer_id_ = opened.peer_id;
            received_at_ms_ = received_at_ms;
            deadline_ms_ = deadline_ms;
            generation_ = generation;
            RememberLocked(opened.offer.offer_id);
            accepted = true;
        }
    }
    Cleanse(key_material);
    return accepted;
}

bool P2PClientOfferSession::Expire(
    std::uint64_t now_ms,
    std::uint64_t* expired_generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || now_ms < deadline_ms_) {
        return false;
    }
    const std::uint64_t generation = generation_;
    ClearActiveLocked();
    if (expired_generation) {
        *expired_generation = generation;
    }
    return true;
}

void P2PClientOfferSession::AdvanceGeneration(
    std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (generation <= generation_floor_) {
        return;
    }
    ClearActiveLocked();
    ClearReplayLocked();
    generation_floor_ = generation;
}

bool P2PClientOfferSession::IsActiveGeneration(
    std::uint64_t generation) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_ && generation_ == generation;
}

bool P2PClientOfferSession::ResetGeneration(std::uint64_t generation) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_ || generation_ != generation) {
        return false;
    }
    ClearActiveLocked();
    return true;
}

void P2PClientOfferSession::Reset() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    ClearActiveLocked();
    ClearReplayLocked();
    generation_floor_ = 0;
}

void P2PClientOfferSession::ClearReplayLocked() noexcept {
    for (auto& offer_id : seen_offer_ids_) {
        Cleanse(offer_id);
    }
    seen_count_ = 0;
    seen_next_ = 0;
}

P2PClientOfferSnapshot P2PClientOfferSession::Snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    P2PClientOfferSnapshot snapshot;
    snapshot.active = active_;
    snapshot.state = state_;
    if (active_) {
        snapshot.offer_id = offer_.offer_id;
        snapshot.connection_epoch = offer_.connection_epoch;
        snapshot.peer_session_id = peer_session_id_;
        snapshot.peer_id = peer_id_;
        snapshot.local_role = local_role_;
        snapshot.received_at_ms = received_at_ms_;
        snapshot.deadline_ms = deadline_ms_;
        snapshot.generation = generation_;
    }
    return snapshot;
}

bool P2PClientOfferSession::SeenLocked(const P2PId& offer_id) const noexcept {
    for (std::size_t i = 0; i < seen_count_; ++i) {
        if (seen_offer_ids_[i] == offer_id) {
            return true;
        }
    }
    return false;
}

void P2PClientOfferSession::RememberLocked(const P2PId& offer_id) noexcept {
    seen_offer_ids_[seen_next_] = offer_id;
    seen_next_ = (seen_next_ + 1) % ReplayCapacity;
    if (seen_count_ < ReplayCapacity) {
        ++seen_count_;
    }
}

void P2PClientOfferSession::ClearActiveLocked() noexcept {
    Cleanse(key_material_);
    active_ = false;
    state_ = P2PState::Relay;
    offer_ = {};
    peer_session_id_ = {};
    peer_id_ = {};
    local_role_ = P2PPeerRole::Initiator;
    received_at_ms_ = 0;
    deadline_ms_ = 0;
    generation_ = 0;
}

}
