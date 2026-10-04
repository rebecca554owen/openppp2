/**
 * @file XtcpNetstackAdapter.h
 * @brief XTCP (MIMT mode) network stack adapter for the openppp2 client.
 *
 * Route B (MIMT flow level) integration: replaces the lwIP TCP termination
 * path inside VEthernet with the XTCP user-space stack. Every TCP flow is
 * delivered as an xtcp::mimt::MimtFlow; the adapter maps it onto
 * ppp::ethernet::VNetstack::TapTcpClient lifecycle, skipping the
 * seq/NAT translation layer entirely.
 *
 * M2: BindFlow creates a TapTcpClient through the injected ClientFactory and
 * runs a symmetric byte pump between the MimtFlow and the client's outbound
 * socket (flow->AsyncRead => socket write; socket read => flow->AsyncWrite).
 * Peer FIN is propagated as flow->AsyncClose() plus a stack Close(conn_id)
 * so the remote side sees the TCP close (MimtFlow alone never propagates FIN).
 */

#pragma once

#include <xtcp/core/stack.h>
#include <xtcp/mimt/mimt.h>
#include <xtcp/ndi.h>

#include <ppp/ethernet/VNetstack.h>
#include <ppp/tap/ITap.h>

#include <functional>
#include <map>
#include <memory>
#include <mutex>

namespace ppp {
    namespace ethernet {
        /**
         * @brief NDI backend that writes XTCP output into the TAP device.
         *
         * The XTCP stack calls Tx() for every IP packet it produces
         * (SYN-ACKs, data segments, FIN/RST). This backend forwards them to
         * ppp::tap::ITap::Output, which queues the write on the device's
         * async write path. The backend holds only a weak reference to the
         * TAP device: the owning VEthernet keeps it alive for the adapter's
         * lifetime, and the backend never outlives it.
         */
        class TapNdiBackend final : public xtcp::ndi::Backend {
        public:
            explicit TapNdiBackend(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept
                : tap_(tap) {}

            bool Tx(xtcp::ndi::Packet&& packet) noexcept override {
                std::shared_ptr<ppp::tap::ITap> tap = tap_.lock();
                if (NULLPTR == tap || NULLPTR == packet.data || packet.len == 0) {
                    return false;
                }
                return tap->Output(packet.data, (int)packet.len);
            }

            void SetRxHandler(xtcp::ndi::RxHandler handler) noexcept override {
                rx_handler_ = std::move(handler);
            }

            xtcp::ndi::BackendCaps Caps() const noexcept override {
                return xtcp::ndi::kCapNone;
            }

        public:
            /** @brief Forwards one TAP-read IP packet into the XTCP stack. */
            void OnTapPacket(const void* data, int len) noexcept {
                xtcp::ndi::RxHandler handler = rx_handler_;
                if (!handler || NULLPTR == data || len <= 0) {
                    return;
                }
                xtcp::ndi::Packet packet;
                packet.data = (Byte*)data;
                packet.len = (UInt32)len;
                packet.eth_type = 0x0800;
                handler(std::move(packet));
            }

        private:
            std::weak_ptr<ppp::tap::ITap>  tap_;
            xtcp::ndi::RxHandler         rx_handler_;
        };

        /**
         * @brief Bridges XTCP MIMT flows onto TapTcpClient.
         *
         * Threading model: xtcp callbacks (StartMimt hook, NDI rx) fire on
         * the stack's dispatch thread; openppp2 expects boost::asio strand
         * affinity. Every xtcp->ppp transition posts onto the given strand;
         * ppp->xtcp calls (OnPacket, Close) are issued from the pump thread.
         */
        class XtcpNetstackAdapter final : public std::enable_shared_from_this<XtcpNetstackAdapter> {
        public:
            using MimtFlowPtr = std::shared_ptr<xtcp::mimt::MimtFlow>;
            using TapTcpClient = VNetstack::TapTcpClient;
            using TapTcpClientPtr = std::shared_ptr<TapTcpClient>;
            /**
             * @brief Creates the outbound TapTcpClient for one accepted flow.
             * @param localEP  LAN-side endpoint seen on the TAP flow.
             * @param remoteEP WAN-side destination endpoint (SYN destination).
             * @return A client whose socket is ready to connect; null on error.
             */
            using ClientFactory = std::function<TapTcpClientPtr(
                const boost::asio::ip::tcp::endpoint& localEP,
                const boost::asio::ip::tcp::endpoint& remoteEP)>;

            XtcpNetstackAdapter(
                const std::shared_ptr<boost::asio::io_context>& context,
                const ppp::threading::Executors::StrandPtr&    strand) noexcept;
            virtual ~XtcpNetstackAdapter() noexcept;

            XtcpNetstackAdapter(const XtcpNetstackAdapter&) = delete;
            XtcpNetstackAdapter& operator=(const XtcpNetstackAdapter&) = delete;

        public:
            /**
             * @brief Starts the stack and arms the MIMT hook.
             * @param ndi_backend  Packet backend (TUN device on the client).
             * @return True when the stack is ready to accept packets.
             */
            bool Open(const std::shared_ptr<xtcp::ndi::Backend>& ndi_backend) noexcept;
            /** @brief Closes every flow and the stack. */
            void Close() noexcept;
        /**
         * @brief Installs the client factory used to create outbound flows.
         * @note Called once before Open(); the factory is read on the
         *       strand while binding flows, so install before arming.
         */
        void SetClientFactory(ClientFactory factory) noexcept { client_factory_ = std::move(factory); }

        /**
         * @brief Sets the maximum number of concurrent MIMT flows.
         * @param max 0 (default) means unlimited; positive values cap the
         *             number of simultaneously active flows to protect against
         *             SYN-flood-style resource exhaustion.
         */
        void SetMaxFlows(std::size_t max) noexcept { max_flows_ = max; }
        /** @brief Current flow limit (0 = unlimited). */
        std::size_t MaxFlows() const noexcept { return max_flows_; }

        public:
            /** @brief Feeds one raw IP packet into XTCP (call from the pump thread). */
            void OnPacket(xtcp::buf::BufRef&& packet) noexcept;
            /** @brief Drives the stack event loop (MIMT completions, ACK timers). */
            void Pump() noexcept;

        private:
            /** @brief StartMimt hook: one new TCP flow from the tun side. */
            void OnNewFlow(const MimtFlowPtr& flow) noexcept;
            /** @brief Maps a MimtFlow onto a TapTcpClient and starts relay. */
            void BindFlow(const MimtFlowPtr& flow) noexcept;
            /** @brief AsyncRead pump: drain flow -> client socket. */
            void PumpRead(const MimtFlowPtr& flow) noexcept;
            /** @brief AsyncWrite pump: client socket -> flow. */
            void PumpWrite(const MimtFlowPtr& flow) noexcept;
            /** @brief Shuts down one flow and its client socket (idempotent). */
            void ShutdownFlow(const MimtFlowPtr& flow) noexcept;
            /** @brief Converts an xtcp endpoint to a boost asio tcp endpoint. */
            static boost::asio::ip::tcp::endpoint ToAsioEndpoint(const xtcp::core::Endpoint& ep) noexcept;

        private:
            std::shared_ptr<boost::asio::io_context>          context_;
            ppp::threading::Executors::StrandPtr              strand_;
            std::shared_ptr<xtcp::XtcpStack>                  stack_;
            std::shared_ptr<xtcp::ndi::Backend>               ndi_;
            ClientFactory                                     client_factory_;
            std::mutex                                        flows_mutex_;
            std::map<MimtFlowPtr, TapTcpClientPtr>            clients_; ///< flow -> outbound client
            std::atomic<bool>                                 opened_{false};
            std::size_t                                       max_flows_{0}; ///< 0 = unlimited
        };
    }
}
