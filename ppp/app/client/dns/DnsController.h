#pragma once

#include <atomic>
#include <memory>
#include <mutex>

#include <ppp/app/client/dns/DnsSessionContext.h>
#include <ppp/app/client/dns/IDnsPolicy.h>
#include <ppp/app/client/dns/IDnsTimerScheduler.h>

namespace ppp::app::client::dns {

class DnsController final {
public:
    DnsController(
        std::shared_ptr<IDnsPolicy> policy,
        std::shared_ptr<IDnsTimerScheduler> timers) noexcept;

    std::shared_ptr<const DnsSessionContext> OpenSession(
        const std::shared_ptr<IDnsTunnelTransport>& transport) noexcept;
    void Close() noexcept;
    bool IsClosed() const noexcept;

private:
    std::shared_ptr<IDnsPolicy> policy_;
    std::shared_ptr<IDnsTimerScheduler> timers_;
    std::shared_ptr<DnsSessionContext> active_session_;
    std::atomic_uint64_t generation_{0};
    std::atomic_bool closed_{false};
    mutable std::mutex syncobj_;
};

}
