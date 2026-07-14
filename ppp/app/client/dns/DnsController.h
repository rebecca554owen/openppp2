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
    bool Configure(DnsQueryContext context) noexcept;
    bool HandleQuery(
        const std::shared_ptr<const DnsSessionContext>& session,
        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept;
    void HandleResolverResponse(
        const std::shared_ptr<const DnsSessionContext>& session,
        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
        const boost::asio::ip::udp::endpoint& source,
        const boost::asio::ip::udp::endpoint& destination,
        ppp::vector<Byte> response) noexcept;
    void Close() noexcept;
    bool IsClosed() const noexcept;

private:
    std::shared_ptr<IDnsPolicy> policy_;
    std::shared_ptr<IDnsTimerScheduler> timers_;
    std::shared_ptr<DnsSessionContext> active_session_;
    DnsQueryContext context_;
    std::atomic_uint64_t generation_{0};
    std::atomic_bool closed_{false};
    mutable std::mutex syncobj_;
};

}
