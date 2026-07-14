#include <ppp/app/client/dns/DnsController.h>

#include <utility>

namespace ppp::app::client::dns {

DnsController::DnsController(
    std::shared_ptr<IDnsPolicy> policy,
    std::shared_ptr<IDnsTimerScheduler> timers) noexcept
    : policy_(std::move(policy)),
      timers_(std::move(timers)) {
}

std::shared_ptr<const DnsSessionContext> DnsController::OpenSession(
    const std::shared_ptr<IDnsTunnelTransport>& transport) noexcept {
    if (nullptr == transport || closed_.load(std::memory_order_acquire)) {
        return nullptr;
    }

    std::lock_guard<std::mutex> scope(syncobj_);
    if (closed_.load(std::memory_order_relaxed)) {
        return nullptr;
    }
    if (active_session_) {
        active_session_->Close();
    }
    active_session_ = std::make_shared<DnsSessionContext>(
        transport,
        generation_.fetch_add(1, std::memory_order_acq_rel) + 1);
    return active_session_;
}

void DnsController::Close() noexcept {
    bool expected = false;
    if (!closed_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return;
    }

    std::shared_ptr<DnsSessionContext> session;
    {
        std::lock_guard<std::mutex> scope(syncobj_);
        session = std::move(active_session_);
    }
    if (session) {
        session->Close();
    }
    if (timers_) {
        timers_->CancelAll();
    }
    if (policy_) {
        policy_->Close();
    }
}

bool DnsController::IsClosed() const noexcept {
    return closed_.load(std::memory_order_acquire);
}

}
