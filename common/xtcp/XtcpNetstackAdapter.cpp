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
            if (opened_) {
                return true;
            }
            if (NULLPTR == ndi_backend || NULLPTR == context_) {
                return false;
            }
            ndi_ = ndi_backend;
            stack_ = std::make_shared<xtcp::XtcpStack>(ndi_.get());
            if (NULLPTR == stack_) {
                return false;
            }

            auto self = shared_from_this();
            stack_->StartMimt([self](const MimtFlowPtr& flow) noexcept {
                // xtcp dispatch thread -> strand.
                boost::asio::post(*(self->strand_), [self, flow]() noexcept {
                    self->OnNewFlow(flow);
                });
            });

            opened_ = true;
            return true;
        }

        void XtcpNetstackAdapter::Close() noexcept {
            if (!opened_) {
                return;
            }
            opened_ = false;
            std::lock_guard<std::mutex> scope(flows_mutex_);
            clients_.clear();
            if (NULLPTR != stack_) {
                stack_->StartMimt(NULLPTR);
            }
            stack_.reset();
            ndi_.reset();
        }

        void XtcpNetstackAdapter::OnPacket(xtcp::buf::BufRef&& packet) noexcept {
            if (opened_ && NULLPTR != stack_) {
                stack_->OnPacket(std::move(packet));
            }
        }

        void XtcpNetstackAdapter::Pump() noexcept {
            if (opened_ && NULLPTR != stack_) {
                stack_->DispatchMimt();
                stack_->PollAckTimers();
            }
        }

        void XtcpNetstackAdapter::OnNewFlow(const MimtFlowPtr& flow) noexcept {
            BindFlow(flow);
        }

        void XtcpNetstackAdapter::BindFlow(const MimtFlowPtr& flow) noexcept {
            if (NULLPTR == flow || flow->IsClosed()) {
                return;
            }

            // Recover the SYN's destination so we can dial the outbound
            // connection; the fork patch stamps this at accept time.
            boost::asio::ip::tcp::endpoint remoteEP = ToAsioEndpoint(flow->RemoteEndpoint());
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

            {
                std::lock_guard<std::mutex> scope(flows_mutex_);
                clients_[flow] = client;
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
            flow->AsyncRead(buffer->data(), (UInt32)buffer->size(),
                [self, flow, client, buffer](xtcp::mimt::Result ec, UInt32 bytes) noexcept {
                    if (ec != xtcp::mimt::Result::kOk || bytes == 0) {
                        // Flow closed by the peer (or errored): tear down.
                        self->ShutdownFlow(flow);
                        return;
                    }
                    std::shared_ptr<boost::asio::ip::tcp::socket> socket = client->GetSocket();
                    if (NULLPTR == socket || !socket->is_open()) {
                        self->ShutdownFlow(flow);
                        return;
                    }
                    boost::asio::async_write(*socket,
                        boost::asio::buffer(buffer->data(), bytes),
                        [self, flow, client, buffer](const boost::system::error_code& ec, std::size_t) noexcept {
                            if (ec) {
                                self->ShutdownFlow(flow);
                                return;
                            }
                            // Continue draining the flow.
                            self->PumpRead(flow);
                        });
                });
        }

        void XtcpNetstackAdapter::PumpWrite(const MimtFlowPtr& flow) noexcept {
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
            socket->async_read_some(boost::asio::buffer(buffer->data(), buffer->size()),
                [self, flow, client, buffer](const boost::system::error_code& ec, std::size_t bytes) noexcept {
                    if (ec) {
                        // Remote closed: propagate FIN to the XTCP peer and
                        // tear down the flow mapping.
                        self->ShutdownFlow(flow);
                        return;
                    }
                    xtcp::mimt::Result wr = flow->AsyncWrite(buffer->data(), (UInt32)bytes,
                        [self, flow, client, buffer](xtcp::mimt::Result wec, UInt32) noexcept {
                            if (wec != xtcp::mimt::Result::kOk) {
                                self->ShutdownFlow(flow);
                                return;
                            }
                            // Continue relaying socket reads.
                            self->PumpWrite(flow);
                        });
                    if (wr != xtcp::mimt::Result::kOk) {
                        // Write queue full/closed: stop this direction.
                        self->ShutdownFlow(flow);
                    }
                });
        }

        void XtcpNetstackAdapter::ShutdownFlow(const MimtFlowPtr& flow) noexcept {
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
            // by the fork patch at accept time).
            if (opened_ && NULLPTR != stack_ && !flow->IsClosed()) {
                const UInt64 conn_id = flow->ConnId();
                if (conn_id != 0) {
                    stack_->Close(conn_id);
                }
                flow->AsyncClose(nullptr);
                flow->Close();
            }
        }
    }
}
