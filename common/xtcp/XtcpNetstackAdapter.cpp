/**
 * @file XtcpNetstackAdapter.cpp
 * @brief XTCP (MIMT mode) network stack adapter — M2 byte pump.
 */

#include "XtcpNetstackAdapter.h"

#include <ppp/threading/Executors.h>

#include <boost/asio/ip/tcp.hpp>

namespace ppp {
    namespace ethernet {
        namespace {
            /** @brief Read buffer size for the flow -> socket pump. */
            constexpr std::size_t kFlowReadBufferSize = 64 * 1024;
            /** @brief Write buffer size for the socket -> flow pump. */
            constexpr std::size_t kSocketReadBufferSize = 64 * 1024;
        }

        XtcpNetstackAdapter::XtcpNetstackAdapter(
            const std::shared_ptr<boost::asio::io_context>& context,
            const ppp::threading::Executors::StrandPtr&    strand) noexcept
            : context_(context)
            , strand_(strand) {}

        XtcpNetstackAdapter::~XtcpNetstackAdapter() noexcept {
            Close();
        }

        boost::asio::ip::tcp::endpoint XtcpNetstackAdapter::ToAsioEndpoint(const xtcp::core::Endpoint& ep) noexcept {
            boost::asio::ip::tcp::endpoint endpoint;
            try {
                if (ep.family == 4) {
                    boost::asio::ip::address_v4::bytes_type bytes = {
                        (Byte)ep.addr[0], (Byte)ep.addr[1],
                        (Byte)ep.addr[2], (Byte)ep.addr[3],
                    };
                    endpoint = boost::asio::ip::tcp::endpoint(
                        boost::asio::ip::address_v4(bytes), ep.port);
                }
                else if (ep.family == 6) {
                    boost::asio::ip::address_v6::bytes_type bytes{};
                    for (int i = 0; i < 4; ++i) {
                        bytes[i * 4 + 0] = (Byte)(ep.addr[i] >> 24);
                        bytes[i * 4 + 1] = (Byte)(ep.addr[i] >> 16);
                        bytes[i * 4 + 2] = (Byte)(ep.addr[i] >> 8);
                        bytes[i * 4 + 3] = (Byte)(ep.addr[i]);
                    }
                    endpoint = boost::asio::ip::tcp::endpoint(
                        boost::asio::ip::address_v6(bytes), ep.port);
                }
            }
            catch (const std::exception&) {}
            return endpoint;
        }

        bool XtcpNetstackAdapter::Open(const std::shared_ptr<xtcp::ndi::Backend>& ndi_backend) noexcept {
            bool expected = false;
            if (!opened_.compare_exchange_strong(expected, true,
                    std::memory_order_acq_rel, std::memory_order_acquire)) {
                return true; // already open
            }
            if (NULLPTR == ndi_backend || NULLPTR == context_) {
                opened_.store(false, std::memory_order_release);
                return false;
            }
            ndi_ = ndi_backend;
            stack_ = std::make_shared<xtcp::XtcpStack>(ndi_.get());
            if (NULLPTR == stack_) {
                opened_.store(false, std::memory_order_release);
                return false;
            }

            auto self = shared_from_this();
            stack_->StartMimt([self](const MimtFlowPtr& flow) noexcept {
                // xtcp dispatch thread -> strand.
                boost::asio::post(*(self->strand_), [self, flow]() noexcept {
                    self->OnNewFlow(flow);
                });
            });

            return true;
        }

        void XtcpNetstackAdapter::Close() noexcept {
            if (!opened_.exchange(false, std::memory_order_acq_rel)) {
                return; // was not open
            }
            std::lock_guard<std::mutex> scope(flows_mutex_);
            clients_.clear();
            {
                std::lock_guard<std::mutex> stack_scope(stack_mutex_);
                if (NULLPTR != stack_) {
                    stack_->StartMimt(NULLPTR);
                }
                stack_.reset();
            }
            ndi_.reset();
        }

        void XtcpNetstackAdapter::OnPacket(xtcp::buf::BufRef&& packet) noexcept {
            // Strand affinity: every XTCP entry point runs on the owner strand so
            // a single thread drives the stack (its callbacks hold shard locks and
            // its contract is only safe under a single-driver relay).
            std::shared_ptr<XtcpNetstackAdapter> self = shared_from_this();
            if (NULLPTR != self && NULLPTR != strand_ && !strand_->running_in_this_thread()) {
                boost::asio::post(*strand_, [self, packet = std::move(packet)]() mutable noexcept {
                    self->OnPacket(std::move(packet));
                });
                return;
            }

            std::shared_ptr<xtcp::XtcpStack> stack;
            {
                std::lock_guard<std::mutex> scope(stack_mutex_);
                if (!opened_.load(std::memory_order_acquire)) {
                    return;
                }
                stack = stack_;
            }
            if (NULLPTR != stack) {
                stack->OnPacket(std::move(packet));
            }
        }

        void XtcpNetstackAdapter::Pump() noexcept {
            std::shared_ptr<XtcpNetstackAdapter> self = shared_from_this();
            if (NULLPTR != self && NULLPTR != strand_ && !strand_->running_in_this_thread()) {
                boost::asio::post(*strand_, [self]() noexcept { self->Pump(); });
                return;
            }

            std::shared_ptr<xtcp::XtcpStack> stack;
            {
                std::lock_guard<std::mutex> scope(stack_mutex_);
                if (!opened_.load(std::memory_order_acquire)) {
                    return;
                }
                stack = stack_;
            }
            if (NULLPTR != stack) {
                stack->DispatchMimt();
                stack->PollAckTimers();
            }
        }

        void XtcpNetstackAdapter::OnNewFlow(const MimtFlowPtr& flow) noexcept {
            BindFlow(flow);
        }

        void XtcpNetstackAdapter::BindFlow(const MimtFlowPtr& flow) noexcept {
            std::shared_ptr<XtcpNetstackAdapter> owner = shared_from_this();
            if (NULLPTR != owner && NULLPTR != strand_ && !strand_->running_in_this_thread()) {
                boost::asio::post(*strand_, [owner, flow]() noexcept { owner->BindFlow(flow); });
                return;
            }
            if (NULLPTR == flow || flow->IsClosed()) {
                return;
            }
            if (!opened_.load(std::memory_order_acquire)) {
                return;
            }

            // Recover the SYN's destination so we can dial the outbound
            // connection; the fork patch stamps this at accept time.
            boost::asio::ip::tcp::endpoint remoteEP = ToAsioEndpoint(flow->Local());
            if (remoteEP.port() == 0) {
                // No stamped remote endpoint: nothing to dial, drop the flow.
                ShutdownFlow(flow);
                return;
            }

            ClientFactory factory = client_factory_;
            if (!factory) {
                ShutdownFlow(flow);
                return;
            }

            boost::asio::ip::tcp::endpoint localEP(
                boost::asio::ip::address_v4::any(), 0);
            TapTcpClientPtr client = factory(localEP, remoteEP);
            if (NULLPTR == client) {
                ShutdownFlow(flow);
                return;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = client->GetSocket();
            if (NULLPTR == socket) {
                ShutdownFlow(flow);
                return;
            }

            // Capacity check and publication share one critical section so two
            // concurrent BindFlow calls cannot both slip past the cap.
            bool reserved = false;
            {
                std::lock_guard<std::mutex> scope(flows_mutex_);
                const std::size_t cap = max_flows_.load(std::memory_order_relaxed);
                reserved = (cap == 0 || clients_.size() < cap);
                if (reserved) {
                    clients_[flow] = client;
                }
            }
            if (!reserved) {
                ShutdownFlow(flow);
                return;
            }

            auto self = shared_from_this();
            socket->async_connect(remoteEP,
                [self, flow, client](const boost::system::error_code& ec) noexcept {
                    if (ec) {
                        self->ShutdownFlow(flow);
                        return;
                    }
                    // Both directions now live: drain the flow into the
                    // socket and relay socket reads back into the flow.
                    self->PumpRead(flow);
                    self->PumpWrite(flow);
                });
        }

        void XtcpNetstackAdapter::PumpRead(const MimtFlowPtr& flow) noexcept {
            std::shared_ptr<XtcpNetstackAdapter> owner = shared_from_this();
            if (NULLPTR != owner && NULLPTR != strand_ && !strand_->running_in_this_thread()) {
                boost::asio::post(*strand_, [owner, flow]() noexcept { owner->PumpRead(flow); });
                return;
            }
            if (NULLPTR == flow || flow->IsClosed()) {
                return;
            }

            TapTcpClientPtr client;
            {
                std::lock_guard<std::mutex> scope(flows_mutex_);
                auto it = clients_.find(flow);
                if (it != clients_.end()) {
                    client = it->second;
                }
            }
            if (NULLPTR == client) {
                return;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = client->GetSocket();
            if (NULLPTR == socket || !socket->is_open()) {
                ShutdownFlow(flow);
                return;
            }

            auto buffer = std::make_shared<std::vector<Byte>>(kFlowReadBufferSize);
            auto self = shared_from_this();
            // Capture |socket| (not |client|) so the lambda holds an independent
            // shared_ptr to the socket for the full async_write lifetime.  The
            // |client| map entry may be erased by ShutdownFlow() from another
            // thread before this callback runs; capturing the socket directly
            // prevents a dangling shared_ptr dereference.
            flow->AsyncRead(buffer->data(), (UInt32)buffer->size(),
                [self, flow, socket, buffer](xtcp::mimt::Result ec, UInt32 bytes) noexcept {
                    if (ec != xtcp::mimt::Result::kOk || bytes == 0) {
                        self->ShutdownFlow(flow);
                        return;
                    }
                    boost::asio::async_write(*socket,
                        boost::asio::buffer(buffer->data(), bytes),
                        [self, flow, socket, buffer](const boost::system::error_code& ec, std::size_t) noexcept {
                            if (ec) {
                                self->ShutdownFlow(flow);
                                return;
                            }
                            self->PumpRead(flow);
                        });
                });
        }

        void XtcpNetstackAdapter::PumpWrite(const MimtFlowPtr& flow) noexcept {
            std::shared_ptr<XtcpNetstackAdapter> owner = shared_from_this();
            if (NULLPTR != owner && NULLPTR != strand_ && !strand_->running_in_this_thread()) {
                boost::asio::post(*strand_, [owner, flow]() noexcept { owner->PumpWrite(flow); });
                return;
            }
            if (NULLPTR == flow || flow->IsClosed()) {
                return;
            }

            TapTcpClientPtr client;
            {
                std::lock_guard<std::mutex> scope(flows_mutex_);
                auto it = clients_.find(flow);
                if (it != clients_.end()) {
                    client = it->second;
                }
            }
            if (NULLPTR == client) {
                return;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = client->GetSocket();
            if (NULLPTR == socket || !socket->is_open()) {
                ShutdownFlow(flow);
                return;
            }

            auto buffer = std::make_shared<std::vector<Byte>>(kSocketReadBufferSize);
            auto self = shared_from_this();
            // Capture |socket| (not |client|) so the lambda holds an independent
            // shared_ptr to the socket for the full async_read_some lifetime.
            // The |client| map entry may be erased by ShutdownFlow() from another
            // thread before this callback runs; capturing the socket directly
            // prevents a dangling shared_ptr dereference.
            socket->async_read_some(boost::asio::buffer(buffer->data(), buffer->size()),
                [self, flow, socket, buffer](const boost::system::error_code& ec, std::size_t bytes) noexcept {
                    if (ec) {
                        self->ShutdownFlow(flow);
                        return;
                    }
                    // The socket may complete off-strand; hop back before
                    // touching the strand-affine MIMT flow.
                    self->OnSocketReadComplete(flow, socket, buffer, bytes);
                });
        }

        void XtcpNetstackAdapter::OnSocketReadComplete(
            const MimtFlowPtr& flow,
            const std::shared_ptr<boost::asio::ip::tcp::socket>& socket,
            const std::shared_ptr<std::vector<Byte>>& buffer,
            std::size_t bytes) noexcept {
            std::shared_ptr<XtcpNetstackAdapter> self = shared_from_this();
            if (NULLPTR != self && NULLPTR != strand_ && !strand_->running_in_this_thread()) {
                boost::asio::post(*strand_, [self, flow, socket, buffer, bytes]() noexcept {
                    self->OnSocketReadComplete(flow, socket, buffer, bytes);
                });
                return;
            }

            xtcp::mimt::Result wr = flow->AsyncWrite(buffer->data(), (UInt32)bytes,
                [self, flow, socket, buffer](xtcp::mimt::Result wec, UInt32) noexcept {
                    if (wec != xtcp::mimt::Result::kOk) {
                        self->ShutdownFlow(flow);
                        return;
                    }
                    self->PumpWrite(flow);
                });
            if (wr != xtcp::mimt::Result::kOk) {
                ShutdownFlow(flow);
            }
        }

        void XtcpNetstackAdapter::ShutdownFlow(const MimtFlowPtr& flow) noexcept {
            std::shared_ptr<XtcpNetstackAdapter> self = shared_from_this();
            if (NULLPTR != self && NULLPTR != strand_ && !strand_->running_in_this_thread()) {
                boost::asio::post(*strand_, [self, flow]() noexcept { self->ShutdownFlow(flow); });
                return;
            }
            if (NULLPTR == flow) {
                return;
            }

            TapTcpClientPtr client;
            {
                std::lock_guard<std::mutex> scope(flows_mutex_);
                auto it = clients_.find(flow);
                if (it != clients_.end()) {
                    client = it->second;
                    clients_.erase(it);
                }
            }

            if (NULLPTR != client) {
                std::shared_ptr<boost::asio::ip::tcp::socket> socket = client->GetSocket();
                if (NULLPTR != socket) {
                    boost::system::error_code ignored;
                    socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
                    socket->close(ignored);
                }
                client->Dispose();
            }

            // Propagate close into XTCP so the peer sees FIN: the MIMT
            // layer alone never signals a close to the TCP connection, so
            // issue a stack Close on the owning connection handle (stamped
            // by upstream SetOrigin at accept time).
            // Snapshot the stack under stack_mutex_ exactly like
            // OnPacket()/Pump(): Close() may reset stack_ from another
            // thread, and holding a shared_ptr keeps the stack alive for
            // the duration of the Close call.
            std::shared_ptr<xtcp::XtcpStack> stack;
            {
                std::lock_guard<std::mutex> scope(stack_mutex_);
                if (opened_.load(std::memory_order_acquire)) {
                    stack = stack_;
                }
            }
            if (NULLPTR != stack && !flow->IsClosed()) {
                const UInt64 conn_id = flow->ConnId();
                if (conn_id != 0) {
                    stack->Close(conn_id);
                }
                flow->AsyncClose(nullptr);
                flow->Close();
            }
        }
    }
}
