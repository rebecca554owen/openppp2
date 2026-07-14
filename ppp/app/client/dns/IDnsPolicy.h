#pragma once

#include <memory>

#include <ppp/app/client/dns/DnsQueryContext.h>

namespace ppp::net::packet { class IPFrame; class UdpFrame; class BufferSegment; }

namespace ppp::app::client::dns {

class DnsSessionContext;

class IDnsPolicy {
public:
    virtual ~IDnsPolicy() noexcept = default;
    virtual bool HandleQuery(
        const DnsQueryContext& context,
        const std::shared_ptr<const DnsSessionContext>& session,
        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept = 0;
    virtual void Close() noexcept = 0;
};

}
