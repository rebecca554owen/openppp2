#include <ppp/app/client/dns/DnsController.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/configurations/AppConfiguration.h>

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

bool DnsController::Configure(DnsQueryContext context) noexcept {
    if (closed_.load(std::memory_order_acquire) || !context.IsValid()) {
        return false;
    }
    std::lock_guard<std::mutex> scope(syncobj_);
    context_ = std::move(context);
    return true;
}

bool DnsController::HandleQuery(
    const std::shared_ptr<const DnsSessionContext>& session,
    const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
    const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept {
    if (closed_.load(std::memory_order_acquire) || !policy_ || !session || !session->IsActive()) {
        return false;
    }
    DnsQueryContext context;
    {
        std::lock_guard<std::mutex> scope(syncobj_);
        context = context_;
    }
    context.handle_resolver_response =
        [this, session](const auto& pending, const auto& source, const auto& destination, auto response) noexcept {
            HandleResolverResponse(session, pending, source, destination, std::move(response));
        };
    return context.IsValid() && policy_->HandleQuery(context, session, packet, frame, messages);
}

void DnsController::HandleResolverResponse(
    const std::shared_ptr<const DnsSessionContext>& session,
    const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
    const boost::asio::ip::udp::endpoint& source,
    const boost::asio::ip::udp::endpoint& destination,
    ppp::vector<Byte> response) noexcept {
    DnsQueryContext context;
    {
        std::lock_guard<std::mutex> scope(syncobj_);
        context = context_;
    }
    DnsResponseHandlerPorts ports;
    if (context.configuration && context.configuration->udp.dns.cache) {
        ports.enable_dns_cache = true;
        ports.write_cache = context.write_cache;
    }
    ports.datagram_output = context.datagram_output;
    if (session) {
        ports.tunnel_send = [session](const auto& source_ep, const auto& destination_ep, const void* packet, int size) noexcept {
            return session->Send(source_ep, destination_ep, packet, size);
        };
    }
    DnsResponseHandler::HandleWithPorts(
        ports, messages, source, destination, std::move(response));
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
