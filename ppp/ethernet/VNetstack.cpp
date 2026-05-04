#include <ppp/ethernet/VNetstack.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/LinkTelemetry.h>
#include <ppp/diagnostics/Telemetry.h>
/**
 * @file VNetstack.cpp
 * @brief Implements virtual TCP NAT mapping, accept bridge, and flow lifecycle.
 */
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/native/udp.h>
#include <ppp/net/native/icmp.h>
#include <ppp/net/packet/IPFrame.h>

#include <ppp/IDisposable.h>
#include <ppp/threading/Executors.h>
#include <ppp/io/File.h>

#include <ppp/collections/Dictionary.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/coroutines/asio/asio.h>

#include <chrono>

#include <libtcpip/netstack.h>

#ifdef SYSNAT
#include <linux/ppp/tap/TapLinux.h>
#endif

typedef ppp::net::AddressFamily                                 AddressFamily;
typedef ppp::net::Socket                                        Socket;
typedef ppp::tap::ITap                                          ITap;
typedef ppp::threading::Executors                               Executors;
typedef ppp::net::IPEndPoint                                    IPEndPoint;
typedef ppp::net::native::ip_hdr                                ip_hdr;
typedef ppp::net::native::tcp_hdr                               tcp_hdr;
typedef tcp_hdr::tcp_flags                                      TcpFlags;
typedef tcp_hdr::tcp_state                                      TcpState;
typedef ppp::collections::Dictionary                            Dictionary;

namespace ppp {
    using ppp::telemetry::Level;
    /**
     * @brief SYN/ACK handshake state values used by TapTcpClient.
     */
    static constexpr Byte VNETSTACK_SYNC_ACK_STATE_CLOSED    = 0;
    static constexpr Byte VNETSTACK_SYNC_ACK_STATE_SYN_SENT  = 1;
    static constexpr Byte VNETSTACK_SYNC_ACK_STATE_SYN_RECVD = 2;

    namespace ethernet {
#ifdef SYSNAT
        /**
         * @brief Returns process-wide lock for SYSNAT driver API calls.
         */
        static VNetstack::SynchronizedObject& openppp2_sysnat_syncobj() noexcept {
            static VNetstack::SynchronizedObject lock_obj;
            return lock_obj;
        }
#endif

        /**
         * @brief Builds LAN-to-WAN flow key from endpoint tuple.
         */
        static Int128 LAN2WAN_KEY(uint32_t src_ip, uint16_t src_port, uint32_t dst_ip, uint16_t dst_port) noexcept {
            uint64_t src_ep = MAKE_QWORD(src_ip, src_port);
            uint64_t dst_ep = MAKE_QWORD(dst_ip, dst_port);

            return MAKE_OWORD(dst_ep, src_ep);
        }

        /**
         * @brief Initializes a fresh TCP link record.
         */
        VNetstack::TapTcpLink::TapTcpLink() noexcept {
            this->dstAddr = 0;
            this->dstPort = 0;
            this->srcAddr = 0;
            this->srcPort = 0;
            this->natPort = 0;
            this->lwip = false;
            this->accepting.store(false, std::memory_order_relaxed);
            this->closed.store(false, std::memory_order_relaxed);
            this->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
            this->socket = NULLPTR;
            this->lastTime.store(Executors::GetTickCount(), std::memory_order_relaxed);
        }

        /**
         * @brief Releases link resources and resets to closed state.
         */
        void VNetstack::TapTcpLink::Release() noexcept {
            if (this->closed.load(std::memory_order_acquire)) {
                return;
            }

            this->Closing();

            this->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
            this->Update();
        }

        /**
         * @brief Closes and disposes the associated TAP TCP client.
         */
        void VNetstack::TapTcpLink::Closing() noexcept {
            if (this->closed.exchange(true, std::memory_order_acq_rel)) {
                return;
            }

            this->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);

            std::shared_ptr<TapTcpClient> c = std::atomic_exchange(&this->socket, std::shared_ptr<TapTcpClient>());

            if (NULLPTR != c) {
                c->Dispose();
            }
        }

        /**
         * @brief Finds link by NAT-side lookup key.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::FindTcpLink(int key) noexcept {
            SynchronizedObjectScope scope(syncobj_);

            auto& map = this->wan2lan_;
            auto tail = map.find(key);
            auto endl = map.end();
            if (tail == endl) {
                return NULLPTR;
            }
            else {
                return tail->second;
            }
        }

        /**
         * @brief Finds link by LAN-to-WAN 4-tuple key.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::FindTcpLink(const Int128& key) noexcept {
            SynchronizedObjectScope scope(syncobj_);

            auto& map = this->lan2wan_;
            auto tail = map.find(key);
            auto endl = map.end();
            if (tail == endl) {
                return NULLPTR;
            }
            else {
                return tail->second;
            }
        }

        /**
         * @brief Allocates or returns NAT mapping for a new LAN-originated flow.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::AllocTcpLink(UInt32 src_ip, int src_port, UInt32 dst_ip, int dst_port) noexcept {
            auto key = LAN2WAN_KEY(src_ip, src_port, dst_ip, dst_port);
            std::shared_ptr<TapTcpLink> link = this->FindTcpLink(key);
            if (NULLPTR != link) {
                return link;
            }
            else {
                int newPort = 0;
                SynchronizedObjectScope scope(syncobj_);

                /**
                 * @brief TOCTOU guard: re-check for an existing entry inside the lock.
                 *
                 * A concurrent thread may have inserted the same key between the unlocked
                 * FindTcpLink() call above and this lock acquisition.  Without this check,
                 * two threads could both pass the unlocked read (both see no entry), then
                 * both insert — producing duplicate NAT mappings and state corruption for
                 * the same source flow.
                 */
                {
                    auto existing_tail = lan2wan_.find(key);
                    if (existing_tail != lan2wan_.end()) {
                        link = existing_tail->second;
                    }
                }

                /**
                 * @brief Port scan: find one free NAT port and allocate the link.
                 *        The outer for-loop that previously wrapped this block always broke
                 *        on its first iteration; it has been removed (L4-5) to eliminate the
                 *        dead O(N²) shell.  The inner scan is preserved as-is.
                 */
                if (NULLPTR == link) {
                    for (int c = 0; c <= IPEndPoint::MaxPort; c++) {
                        int localPort = ++this->ap_;
                        if (localPort <= IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                            this->ap_ = IPEndPoint::MinPort + 1;
                            localPort = this->ap_;
                        }

                        if (localPort == this->listenEP_.Port) {
                            continue;
                        }

                        auto tail = this->wan2lan_.find(localPort);
                        auto endl = this->wan2lan_.end();
                        if (tail == endl) {
                            newPort = localPort;
                            break;
                        }
                    }

                    if (0 != newPort) {
                        link = make_shared_object<TapTcpLink>();
                        if (NULLPTR != link) {
                            link->dstAddr = dst_ip;
                            link->dstPort = dst_port;
                            link->srcAddr = src_ip;
                            link->srcPort = src_port;
                            link->natPort = newPort;
                            link->state.store((Byte)TcpState::TCP_STATE_SYN_RECEIVED, std::memory_order_relaxed);

                            this->lan2wan_[key]     = link;
                            this->wan2lan_[newPort] = link;
                        }
                    }
                }
            }

            if (NULLPTR != link) {
                link->Update();
            }

            return link;
        }

        /**
         * @brief Constructs stack with randomized NAT port cursor.
         */
        VNetstack::VNetstack() noexcept
            : ap_(RandomNext(IPEndPoint::MinPort, IPEndPoint::MaxPort))
            , lwip_(false) {

        }

        /**
         * @brief Destroys stack and releases all runtime resources.
         */
        VNetstack::~VNetstack() noexcept {
            ReleaseAllResources();
        }

#ifdef SYSNAT
        /**
         * @brief Mounts SYSNAT and attaches it to current TAP interface.
         */
        static bool SysnatAttachDriver(const std::shared_ptr<ITap>& tap, ppp::string& interface_name) noexcept {
            ppp::telemetry::SpanScope span("vnetstack.sysnat.attach");
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            VNetstack::SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj()); 
            auto started_at = std::chrono::steady_clock::now();
            if (0 != openppp2_sysnat_mount()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("vnetstack.sysnat.attach.us", elapsed);
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
            }

            ppp::tap::TapLinux* linux_tap = dynamic_cast<ppp::tap::TapLinux*>(tap.get());
            if (NULLPTR == linux_tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceUnsupported);
            }

            int64_t h = reinterpret_cast<int64_t>(linux_tap->GetHandle());
            if (!linux_tap->GetInterfaceName(static_cast<int>(h), interface_name)) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
            }

            int attach_status = openppp2_sysnat_attach(interface_name.data());
            if (0 != attach_status) {
                auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                ppp::telemetry::Histogram("vnetstack.sysnat.attach.us", elapsed);
                openppp2_sysnat_publish_error(attach_status);
                return false;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
            ppp::telemetry::Histogram("vnetstack.sysnat.attach.us", elapsed);
            return true;
        }
#endif

        /**
         * @brief Opens listener, initializes accept callback, and sets runtime mode.
         */
        bool VNetstack::Open(bool lwip, const int& localPort) noexcept {
            struct ScopedConnectHistogram final {
                std::chrono::steady_clock::time_point started_at = std::chrono::steady_clock::now();

                ~ScopedConnectHistogram() noexcept {
                    auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started_at).count();
                    ppp::telemetry::Histogram("vnetstack.connect.us", elapsed);
                }
            } connect_histogram;

            if (localPort < IPEndPoint::MinPort || localPort > IPEndPoint::MaxPort) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            std::shared_ptr<SocketAcceptor> acceptor = SocketAcceptor::New();
            if (NULLPTR == acceptor) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }
            else {
                ppp::string bindIP = ppp::net::Ipep::ToAddressString<ppp::string>(boost::asio::ip::address_v4::any());
                if (!acceptor->Open(bindIP.data(), localPort, PPP_LISTEN_BACKLOG)) {
                    acceptor->Dispose();
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::SocketListenFailed);
                }
                else {
                    int handle = acceptor->GetHandle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, false);
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    
                    listenEP_ = IPEndPoint::ToEndPoint(Socket::GetLocalEndPoint(acceptor->GetHandle()));
                    constantof(localPort) = listenEP_.Port;
                    listenPort_.store(listenEP_.Port, std::memory_order_release);
                }
            }

            std::shared_ptr<VNetstack> self = shared_from_this();
            acceptor->AcceptSocket = 
                [self](SocketAcceptor*, SocketAcceptor::AcceptSocketEventArgs& e) noexcept {
                    self->ProcessAcceptSocket(e.Socket);
                };

            lwip_ = lwip;
            acceptor_ = acceptor;

            lwip::netstack::Localhost = localPort;
#ifdef SYSNAT
            sysnat_ = SysnatAttachDriver(tap, sysnat_interface_name_);
#endif
            return true;
        }

        /**
         * @brief Public release entry that frees all resources.
         */
        void VNetstack::Release() noexcept {
            ReleaseAllResources();
        }

        /**
         * @brief Releases acceptor, flow tables, and SYSNAT binding state.
         */
        void VNetstack::ReleaseAllResources() noexcept {
            std::shared_ptr<SocketAcceptor> acceptor;
            WAN2LANTABLE wan2lan;
            LAN2WANTABLE lan2wan; 
            
            for (;;) {
                SynchronizedObjectScope scope(syncobj_);
                acceptor = std::move(acceptor_);

                wan2lan = std::move(wan2lan_);
                wan2lan_.clear();

                lan2wan = std::move(lan2wan_);
                lan2wan_.clear();

                // Reset these fields INSIDE the lock so that concurrent SSMT Input() threads
                // that read listenPort_ (lock-free) observe the cleared value only after the
                // tables are already empty — preventing a window where a packet arrives after
                // the tables are cleared but before listenPort_ reads return MinPort.
                listenPort_.store(IPEndPoint::MinPort, std::memory_order_release);
                listenEP_ = IPEndPoint();
                lwip_     = false;
                ap_       = RandomNext(IPEndPoint::MinPort, IPEndPoint::MaxPort);
                break;
            }

            if (NULLPTR != acceptor) {
                acceptor->Dispose();
            }

            Dictionary::ReleaseAllObjects(wan2lan);
            Dictionary::ReleaseAllObjects(lan2wan);

#ifdef SYSNAT
            if (!sysnat_interface_name_.empty()) {
                VNetstack::SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj()); 

                int detach_status = openppp2_sysnat_detach(sysnat_interface_name_.data());
                if (0 != detach_status && ERR_NOT_ATTACHED != detach_status) {
                    openppp2_sysnat_publish_error(detach_status);
                }
                sysnat_interface_name_.clear();
            }
#endif
        }

        /**
         * @brief Processes one TCP packet through NAT mapping and state machine.
         */
        bool VNetstack::Input(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept {
            if (NULLPTR == ip || NULLPTR == tcp || tcp_len < 1) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "null packet input");
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VNetstackNullPacketInput);
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            ppp::telemetry::Count("vnetstack.input", 1);
            TcpFlags flags = (TcpFlags)tcp_hdr::TCPH_FLAGS(tcp);
            bool lan2wan = true;
            bool rst = true;
            std::shared_ptr<TapTcpLink> link;
            std::shared_ptr<TapTcpClient> c;

            /**
             * @brief Packet direction handling.
             * - Gateway destination packets are NAT return traffic (V->Local).
             * - Non-SYN packets from LAN reuse existing mapping (Local->V).
             * - SYN packets allocate mapping and start accept path.
             */
            if (ip->dest == tap->GatewayServer) { // V->Local 
                if ((link = this->FindTcpLink(tcp->dest))) {
                    link->Update();
                    lan2wan = false;
                    rst = false;
                    
                    ip->src = link->dstAddr;
                    tcp->src = link->dstPort;
                    ip->dest = link->srcAddr;
                    tcp->dest = link->srcPort;
                }
            }
            elif(flags != TcpFlags::TCP_SYN) { // Local->V
                if ((link = this->FindTcpLink(LAN2WAN_KEY(ip->src, tcp->src, ip->dest, tcp->dest)))) {
                    link->Update();
                    rst = false;

                    ip->src = tap->GatewayServer;
                    tcp->src = link->natPort;
                    ip->dest = tap->IPAddress;
                    tcp->dest = ntohs((UInt16)this->listenPort_.load(std::memory_order_acquire));
                }
            }
            elif((link = this->AllocTcpLink(ip->src, tcp->src, ip->dest, tcp->dest))) { // SYN
                for (;;) {
                    TcpState ls = (TcpState)link->state.load(std::memory_order_relaxed);
                    if (ls == TcpState::TCP_STATE_CLOSED) {
                        break;
                    }
                    else {
                        c = std::atomic_load(&link->socket);
                        if (NULLPTR != c) {
                            if (c->IsDisposed()) {
                                if (ls == TcpState::TCP_STATE_SYN_RECEIVED || ls == TcpState::TCP_STATE_SYN_SENT) {
                                    link->Update();
                                    return true;
                                }

                                rst = true;
                            }
                            break;
                        }
                    }

                    if (ls != TcpState::TCP_STATE_SYN_RECEIVED && ls != TcpState::TCP_STATE_SYN_SENT) {
                        /**
                         * @brief Keep handshake links pending to allow retransmission retry.
                         */
                        link->Update();
                        return true;
                    }

                    /**
                     * @brief CAS guard: only the SSMT thread that wins this exchange may call
                     *        BeginAcceptClient().  Concurrent SYN retransmissions on other threads
                     *        lose the CAS and defer, preventing duplicate clients for the same flow.
                     */
                    bool expected_accepting = false;
                    if (!link->accepting.compare_exchange_strong(expected_accepting, true, std::memory_order_acq_rel)) {
                        link->Update();
                        return true;
                    }

                    boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->src, ntohs(tcp->src));
                    boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(ip->dest, ntohs(tcp->dest));

                    c = this->BeginAcceptClient(localEP, remoteEP);
                    if (NULLPTR == c) {
                        /**
                         * @brief Defer failure; reset accepting so the next retransmission may retry.
                         */
                        link->accepting.store(false, std::memory_order_release);
                        link->Update();
                        return true;
                    }

                    c->sync_ack_state_ = VNETSTACK_SYNC_ACK_STATE_SYN_SENT;
#ifdef SYSNAT
                    for (SynchronizedObjectScope _(c->sysnat_synbobj_);;) {
                        c->listenPort_ = this->listenPort_.load(std::memory_order_acquire);
                        c->sysnat_status_ = this->sysnat_ ? 0 : -1;
                        break;
                    }
#endif

                    if (!c->BeginAccept()) {
                        /**
                         * @brief Preserve pending SYN while outbound connect is transiently unavailable.
                         *        Reset accepting so that the next retransmission may retry.
                         */
                        link->accepting.store(false, std::memory_order_release);
                        link->Update();
                        return true;
                    }

                    ppp::telemetry::Count("vnetstack.connect", 1);
                    ppp::telemetry::Log(Level::kDebug, "vnetstack", "TCP connect begin");
                    rst = false;
                    c->link_ = link;
                    std::atomic_store(&link->socket, c);

                    ip->src = tap->GatewayServer;
                    tcp->src = link->natPort;
                    ip->dest = tap->IPAddress;
                    tcp->dest = ntohs((UInt16)this->listenPort_.load(std::memory_order_acquire));
                    break;
                }
            }

            /**
             * @brief If mapping is unresolved, send RST and abort processing.
             */
            if (rst) {
                ppp::telemetry::Log(Level::kInfo, "vnetstack", "link input error: unresolved mapping");
                this->RST(ip, tcp, tcp_len);
                return false;
            }

            /**
             * @brief Advance simplified TCP state for timeout management.
             */
            if (flags & TcpFlags::TCP_RST) {
                TcpState prev_state = (TcpState)link->state.load(std::memory_order_relaxed);
                link->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);

                /**
                 * @brief Link telemetry: unexpected RST received on an established connection.
                 *
                 * An RST on an ESTABLISHED connection is an unexpected interruption.
                 * RST on other states (SYN_RECEIVED, etc.) is a normal connection rejection
                 * and does not count as a link fault.
                 *
                 * Also: RST received through the underlying link (when the EC triggers it)
                 * should be recorded as a fault. Other RSTs (e.g., destination unreachable)
                 * are not link faults.
                 */
                if (prev_state == TcpState::TCP_STATE_ESTABLISHED) {
                    ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().RecordFault();
                    ppp::telemetry::Count("vnetstack.unexpected_rst", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "unexpected RST on established connection");
                }
            }
            elif((flags & TcpFlags::TCP_SYN) && (flags & TcpFlags::TCP_ACK)) {
                if ((TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_SYN_RECEIVED) {
                    link->state.store((Byte)TcpState::TCP_STATE_ESTABLISHED, std::memory_order_relaxed);
                }
            }
            elif((flags & TcpFlags::TCP_FIN) && (flags & TcpFlags::TCP_ACK)) {
                TcpState ls2 = (TcpState)link->state.load(std::memory_order_relaxed);
                if (ls2 == TcpState::TCP_STATE_ESTABLISHED) {
                    link->state.store((Byte)TcpState::TCP_STATE_CLOSE_WAIT, std::memory_order_relaxed);

                    /**
                     * @brief Link telemetry: clean FIN received on an established connection.
                     *
                     * A FIN+ACK on an ESTABLISHED connection with no error is a graceful close.
                     * Per specification, FIN with 0 bytes is NOT an error.
                     * Record as success (clean close).
                     */
                    ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().RecordSuccess();
                    ppp::telemetry::Count("vnetstack.clean_fin", 1);
                }
                elif(ls2 == TcpState::TCP_STATE_LAST_ACK) {
                    link->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
                }
            }
            elif(flags & TcpFlags::TCP_ACK) {
                if ((TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_CLOSE_WAIT) {
                    link->state.store((Byte)TcpState::TCP_STATE_LAST_ACK, std::memory_order_relaxed);
                }
            }

            return this->Output(lan2wan, ip, tcp, tcp_len, c.get());
        }

        /**
         * @brief Returns connect-phase timeout in milliseconds.
         */
        uint64_t VNetstack::GetMaxConnectTimeout() noexcept {
            return 10000;
        }

        /**
         * @brief Returns finalize-phase timeout in milliseconds.
         */
        uint64_t VNetstack::GetMaxFinalizeTimeout() noexcept {
            return 20000;
        }

        /**
         * @brief Returns established idle timeout in milliseconds.
         */
        uint64_t VNetstack::GetMaxEstablishedTimeout() noexcept {
            return 72000;
        }

        /**
         * @brief Performs periodic flow timeout scan and cleanup.
         *
         * Snapshot-and-release pattern (L4-10): the wan2lan_ table is copied under a
         * brief syncobj_ lock, then the lock is dropped before the O(N) per-entry
         * evaluation.  CloseTcpLink() re-acquires syncobj_ internally per entry, so
         * there is no lock held across the full traversal.
         */
        bool VNetstack::Update(uint64_t now) noexcept {
            const uint64_t MaxEstablishedTimeout = GetMaxEstablishedTimeout();
            const uint64_t MaxFinalizeTimeout    = GetMaxFinalizeTimeout();
            const uint64_t MaxConnectTimeout     = GetMaxConnectTimeout();

            // Step 1: Snapshot the table under a brief lock.
            WAN2LANTABLE snapshot;
            {
                SynchronizedObjectScope scope(syncobj_);
                if (wan2lan_.empty()) {
                    return true;
                }

                snapshot = wan2lan_;   // O(N) copy; shared_ptr ref-count increments only.
            }
            // syncobj_ is released here; the snapshot keeps all links alive.

            // Step 2: Iterate the snapshot without holding syncobj_.
            std::shared_ptr<TapTcpClient> socket;
            ppp::vector<TapTcpLink::Ptr> releases;

            for (auto& kv : snapshot) {
                std::shared_ptr<TapTcpLink> link = kv.second;
                if (NULLPTR == link) {
                    continue;
                }

                UInt64 deltaTime = now - link->lastTime.load(std::memory_order_relaxed);
                if (link->lwip) {
                    socket = std::atomic_load(&link->socket);
                    if (NULLPTR == socket) {
                        TcpState ls0 = (TcpState)link->state.load(std::memory_order_relaxed);
                        bool syn = ls0 == TcpState::TCP_STATE_SYN_SENT || ls0 == TcpState::TCP_STATE_SYN_RECEIVED;
                        if (!syn) {
                            releases.emplace_back(link);
                        }
                    }
                    elif(socket->IsDisposed()) {
                        releases.emplace_back(link);
                    }
                    else {
                        uint64_t maxTimeout = (TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_ESTABLISHED ? MaxEstablishedTimeout : MaxFinalizeTimeout;
                        if (deltaTime >= maxTimeout) {
                            releases.emplace_back(link);
                        }
                    }

                    continue;
                }
#ifdef SYSNAT
                else {
                    socket = std::atomic_load(&link->socket);
                    if (NULL != socket) {
                        /**
                         * @brief sysnat_status_ is std::atomic<int>; a lock-free
                         *        acquire-load is sufficient here.  Acquiring
                         *        sysnat_synbobj_ while syncobj_ is already held
                         *        would create an inconsistent lock-ordering with
                         *        other code paths that hold sysnat_synbobj_ alone,
                         *        introducing a potential stall (and, if a third
                         *        lock were ever added, a deadlock cycle).  The
                         *        atomic read is the correct, safe alternative.
                         */
                        if (socket->sysnat_status_.load(std::memory_order_acquire) > 0) {
                            continue;
                        }
                    }
                }
#endif
                /**
                 * @brief Snapshot state atomically once; reuse across all comparisons in
                 *        this scan iteration to avoid repeated atomic reads and to ensure
                 *        consistent state across the if/elif/goto chain.
                 */
                TcpState lsn = (TcpState)link->state.load(std::memory_order_relaxed);
                if (lsn == TcpState::TCP_STATE_ESTABLISHED) {
                    goto TCP_STATE_INACTIVE;
                }
                elif(lsn == TcpState::TCP_STATE_CLOSED) {
                    releases.emplace_back(link);
                }
                elif(lsn > TcpState::TCP_STATE_ESTABLISHED) {
                TCP_STATE_FINALIZE:
                    if (deltaTime >= MaxFinalizeTimeout) {
                        releases.emplace_back(link);
                    }
                }
                elif(lsn == TcpState::TCP_STATE_SYN_SENT || lsn == TcpState::TCP_STATE_SYN_RECEIVED) {
                    if (deltaTime >= MaxConnectTimeout) {
                        releases.emplace_back(link);
                    }
                }
                else {
                TCP_STATE_INACTIVE:
                    socket = std::atomic_load(&link->socket);
                    if (NULLPTR == socket || socket->IsDisposed()) {
                        goto TCP_STATE_FINALIZE;
                    }

                    if (deltaTime >= MaxEstablishedTimeout) {
                        releases.emplace_back(link);
                    }
                }
            }

            // Step 3: Close identified links (CloseTcpLink acquires syncobj_ internally).
            for (const TapTcpLink::Ptr& i : releases) {
                if (NULLPTR != i) {
                    this->CloseTcpLink(i);
                }
            }

            return true;
        }

        /**
         * @brief Rewrites packet as TCP RST response and outputs it.
         */
        bool VNetstack::RST(ip_hdr* iphdr, tcp_hdr* tcp, int tcp_len) noexcept {
            uint32_t dstAddr = iphdr->dest;
            uint16_t dstPort = tcp->dest;
            uint32_t srcAddr = iphdr->src;
            uint16_t srcPort = tcp->src;
            uint32_t seqNo   = tcp->seqno;
            uint32_t ackNo   = tcp->ackno;

            uint32_t hdrlen_bytes = tcp_hdr::TCPH_HDRLEN_BYTES(tcp);
            uint32_t tcplen = tcp_len - hdrlen_bytes;
            uint8_t tcp_flags = tcp_hdr::TCPH_FLAGS(tcp);
            if (tcp_flags & (TcpFlags::TCP_FIN | TcpFlags::TCP_SYN)) {
                tcplen++;
            }

            tcp_len                 = tcp_hdr::TCP_HLEN;
            iphdr->src              = dstAddr;
            tcp->src                = dstPort;
            iphdr->dest             = srcAddr;
            tcp->dest               = srcPort;
            tcp->ackno              = seqNo + tcplen;
            tcp->seqno              = ackNo;
            tcp->urgp               = 0;
            tcp->wnd                = 0;
            tcp->hdrlen_rsvd_flags  = 0;

            tcp_hdr::TCPH_HDRLEN_BYTES_SET(tcp, tcp_len);
            tcp_hdr::TCPH_FLAGS_SET(tcp, TcpFlags::TCP_RST);

            return this->Output(false, iphdr, tcp, tcp_len, NULLPTR);
        }

        /**
         * @brief Recomputes checksums and sends packet to TAP or SYN/ACK cache.
         */
        bool VNetstack::Output(bool lan2wan, ip_hdr* ip, tcp_hdr* tcp, int tcp_len, TapTcpClient* c) noexcept {
            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }

            ppp::telemetry::Count("vnetstack.output", 1);
            if (ppp::net::Socket::IsDefaultFlashTypeOfService()) {
                ip->tos = std::max<Byte>(ip->tos, ppp::net::packet::IPFrame::DefaultFlashTypeOfService());
            }

            tcp->chksum = 0;
            tcp->chksum = ppp::net::native::inet_chksum_pseudo((unsigned char*)tcp,
                (unsigned int)ip_hdr::IP_PROTO_TCP,
                (unsigned int)tcp_len,
                ip->src,
                ip->dest);
            if (tcp->chksum == 0) {
                tcp->chksum = 0xffff;
            }

            int iphdr_len = (char*)tcp - (char*)ip;
            ip->chksum = 0;
            ip->chksum = ppp::net::native::inet_chksum(ip, iphdr_len);
            if (ip->chksum == 0) {
                ip->chksum = 0xffff;
            }

            int ippkg_len = ((char*)tcp + tcp_len) - (char*)ip;
            if (NULLPTR == c) {
                return tap->Output(ip, ippkg_len);
            }

            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = GetBufferAllocator();
            std::shared_ptr<Byte> packet = ppp::threading::BufferswapAllocator::MakeByteArray(allocator, ippkg_len);
            if (NULLPTR == packet) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            }
            else {
                memcpy(packet.get(), ip, ippkg_len);
            }

            /** @brief Atomic stores prevent a data race with the SYN-ACK retry timer callback running on context_. */
            std::atomic_store(&c->sync_ack_tap_driver_, tap);
            std::atomic_store(&c->sync_ack_byte_array_, packet);
            c->sync_ack_bytes_size_.store(ippkg_len, std::memory_order_release);
            return true;
        }

        /**
         * @brief Removes flow tables entry and closes linked client.
         */
        bool VNetstack::CloseTcpLink(const std::shared_ptr<TapTcpLink>& link) noexcept {
            if (NULLPTR == link) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VNetstackNullLinkInput);
            }

            std::shared_ptr<ITap> tap = this->Tap;
            if (NULLPTR == tap) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
            }
            else {
                SynchronizedObjectScope scope(syncobj_);

                // Use the full Int128 key for lwIP-path links; the lower-16-bit natPort for standard NAT.
                Int128 wan_key = (Int128(0) != link->lwipKey) ? link->lwipKey : Int128(link->natPort);
                auto tail_wan2lan = this->wan2lan_.find(wan_key);
                auto endl_wan2lan = this->wan2lan_.end();
                if (tail_wan2lan != endl_wan2lan) {
                    this->wan2lan_.erase(tail_wan2lan);
                }

                auto key = LAN2WAN_KEY(link->srcAddr, link->srcPort, link->dstAddr, link->dstPort);
                auto tail_lan2wan = this->lan2wan_.find(key);
                auto endl_lan2wan = this->lan2wan_.end();
                if (tail_lan2wan != endl_lan2wan) {
                    this->lan2wan_.erase(tail_lan2wan);
                }
            }

            link->Release();
            return true;
        }

        /**
         * @brief Resolves accepted socket to pending flow and finalizes accept.
         */
        bool VNetstack::ProcessAcceptSocket(int sockfd) noexcept {
            std::shared_ptr<boost::asio::ip::tcp::socket> socket;
            std::shared_ptr<TapTcpLink> link;
            std::shared_ptr<TapTcpClient> pcb;
            std::shared_ptr<ITap> tap;

            do {
                tap = this->Tap;
                if (NULLPTR == tap) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                    ppp::telemetry::Count("vnetstack.accept.fail.tap", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: tap missing");
                    break;
                }

                boost::asio::ip::tcp::endpoint natEP = Socket::GetRemoteEndPoint(sockfd);
                IPEndPoint remoteEP = IPEndPoint::V6ToV4(IPEndPoint::ToEndPoint(natEP));
                if (lwip_) {
                    if (remoteEP.GetAddress() != htonl(IPEndPoint::LoopbackAddress)) {
                        ppp::telemetry::Count("vnetstack.accept.fail.endpoint", 1);
                        ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: lwip endpoint mismatch");
                        break;
                    }
                }
                elif(remoteEP.GetAddress() != tap->GatewayServer) {
                    ppp::telemetry::Count("vnetstack.accept.fail.endpoint", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: endpoint mismatch");
                    break;
                }

                if (remoteEP.Port <= IPEndPoint::MinPort || remoteEP.Port > IPEndPoint::MaxPort) {
                    ppp::telemetry::Count("vnetstack.accept.fail.port", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: invalid port");
                    break;
                }

                if (lwip_) {
                    uint32_t srcAddr; 
                    uint32_t dstAddr;
                    int srcPort;
                    int dstPort;
                    if (!lwip::netstack::link(remoteEP.Port, srcAddr, srcPort, dstAddr, dstPort)) {
                        ppp::telemetry::Count("vnetstack.accept.fail.lwip_link", 1);
                        ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: lwip link missing");
                        break;
                    }

                    link = this->LwIpAcceptLink(srcAddr, dstAddr, srcPort, dstPort);
                }
                else {
                    link = this->FindTcpLink(htons(remoteEP.Port));
                }

                if (NULLPTR == link) {
                    ppp::telemetry::Count("vnetstack.accept.fail.link", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: link missing");
                    break;
                }

                pcb = std::atomic_load(&link->socket);
                if (NULLPTR == pcb) {
                    if ((TcpState)link->state.load(std::memory_order_relaxed) != TcpState::TCP_STATE_CLOSED) {
                        link->state.store((Byte)TcpState::TCP_STATE_CLOSED, std::memory_order_relaxed);
                    }

                    ppp::telemetry::Count("vnetstack.accept.fail.pcb", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: pcb missing");
                    break;
                }

                socket = pcb->NewAsynchronousSocket(sockfd, natEP);
                if (NULLPTR == socket) {
                    ppp::telemetry::Count("vnetstack.accept.fail.socket", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: socket wrap failed");
                    break;
                }

                bool ok = pcb->EndAccept(socket, natEP);
                if (ok) {
                    ppp::telemetry::Count("vnetstack.accept", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "socket accepted");
                    link->Update();
                }
                else {
                    ppp::telemetry::Count("vnetstack.accept.fail.end_accept", 1);
                    ppp::telemetry::Log(Level::kInfo, "vnetstack", "accept failed: end accept failed");
                    link->Release();
                }
                
                return ok;
            } while (false);

            if (NULLPTR == socket) {
                Socket::Closesocket(sockfd);
            }

            return false;
        }

        /**
         * @brief Handles lwIP accept callback and prepares SYN/ACK packet state.
         */
        int VNetstack::LwIpBeginAccept(boost::asio::ip::tcp::endpoint& dest, boost::asio::ip::tcp::endpoint& src, uint32_t seq, uint32_t ack, uint16_t wnd) noexcept {
            // Guard against non-IPv4 endpoints: lwIP is inherently IPv4-only and
            // to_v4() would throw (or cause std::terminate in a noexcept function)
            // if called on an IPv6 address, e.g. from a dual-stack listener.
            if (!dest.address().is_v4() || !src.address().is_v4()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6AddressInvalid);
                return -1;
            }

            const uint32_t dest_ip = *(uint32_t*)dest.address().to_v4().to_bytes().data();
            const uint32_t src_ip = *(uint32_t*)src.address().to_v4().to_bytes().data();
           
            const int dest_port = dest.port();
            const int src_port = src.port();

            std::shared_ptr<TapTcpLink> link = this->LwIpAcceptLink(src_ip, dest_ip, src_port, dest_port);
            if (NULLPTR == link) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
                return -1;
            }

            std::shared_ptr<TapTcpClient> pcb = std::atomic_load(&link->socket);
            if (NULLPTR == pcb) {
                if ((TcpState)link->state.load(std::memory_order_relaxed) == TcpState::TCP_STATE_SYN_SENT) {
                    boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(src_ip, src_port);
                    boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(dest_ip, dest_port);

                    pcb = this->BeginAcceptClient(localEP, remoteEP);
                    if (NULLPTR != pcb) {
                        pcb->lwip_ = link->lwipKey;   // Non-zero key marks this TapTcpClient as lwIP-path.
                        pcb->link_ = link;
                        std::atomic_store(&link->socket, pcb);
                    }
                }

                if (NULLPTR == pcb) {
                    link->Update();
                    return 0;
                }
            }
            
            Byte sync_ack_state = VNETSTACK_SYNC_ACK_STATE_CLOSED;
            if (pcb->sync_ack_state_.compare_exchange_strong(sync_ack_state, VNETSTACK_SYNC_ACK_STATE_SYN_SENT)) {
                int sync_packet_size = 0;
                link->Update();
                ppp::telemetry::Log(Level::kDebug, "vnetstack", "lwip sync-ack begin");

                pcb->sync_ack_bytes_size_.store(0, std::memory_order_relaxed);
                std::atomic_store(&pcb->sync_ack_byte_array_, lwip::netstack_wrap_ipv4_tcp_syn_packet(dest, src, wnd, ack, seq, sync_packet_size));

                if (NULLPTR != std::atomic_load(&pcb->sync_ack_byte_array_)) {
                    pcb->sync_ack_bytes_size_.store(sync_packet_size, std::memory_order_release);
                    return 1;
                }
                else {
                    this->CloseTcpLink(link);
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return -1;
                }
            }

            return pcb->sync_ack_state_.load() >= VNETSTACK_SYNC_ACK_STATE_SYN_RECVD ? 0 : 1;
        }

        /**
         * @brief Finds or creates lwIP flow link and starts accept workflow.
         */
        std::shared_ptr<VNetstack::TapTcpLink> VNetstack::LwIpAcceptLink(uint32_t srcAddr, uint32_t dstAddr, int srcPort, int dstPort) noexcept {
            ppp::telemetry::SpanScope span("vnetstack.connect");
            Int128 key = LAN2WAN_KEY(srcAddr, srcPort, dstAddr, dstPort);
            std::shared_ptr<TapTcpLink> link;

            for (SynchronizedObjectScope scope(syncobj_);;) {
                WAN2LANTABLE::iterator tail = this->wan2lan_.find(key);
                WAN2LANTABLE::iterator endl = this->wan2lan_.end();
                if (tail != endl) {
                    return tail->second;
                }

                link = make_shared_object<TapTcpLink>();
                if (NULLPTR == link) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return NULLPTR;
                }
                
                link->dstAddr = dstAddr;
                link->dstPort = ntohs(dstPort);
                link->srcAddr = srcAddr;
                link->srcPort = ntohs(srcPort);
                link->natPort = 0;       // Not used as a real NAT port in the lwIP path.
                link->lwipKey = key;     // Store full Int128 key for wan2lan_ lookup on close.
                link->lwip = true;
                link->closed.store(false, std::memory_order_relaxed);
                link->state.store((Byte)TcpState::TCP_STATE_SYN_SENT, std::memory_order_relaxed);

                this->wan2lan_[key] = link;
                break;
            }

            boost::asio::ip::tcp::endpoint localEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(srcAddr, srcPort);
            boost::asio::ip::tcp::endpoint remoteEP = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(dstAddr, dstPort);

            std::shared_ptr<TapTcpClient> socket = this->BeginAcceptClient(localEP, remoteEP);
            if (NULLPTR == socket) {
                /**
                 * @brief Keep pending SYN link alive for retransmission-driven retry.
                 */
                link->Update();
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
                return NULLPTR;
            }

            socket->lwip_ = key;
            socket->link_ = link;

#ifdef SYSNAT
            for (SynchronizedObjectScope _(socket->sysnat_synbobj_);;) {
                socket->listenPort_ = this->listenPort_.load(std::memory_order_acquire);
                socket->sysnat_status_ = this->sysnat_ ? 0 : -1;
                break;
            }
#endif

            bool bok = socket->BeginAccept();
            if (!bok) {
                /** @brief Preserve pending SYN until next retransmission window. */
                link->Update();
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceOpenFailed);
                return NULLPTR;
            }

            ppp::telemetry::Count("vnetstack.connect", 1);
            ppp::telemetry::Log(Level::kDebug, "vnetstack", "TCP connect begin");
            std::atomic_store(&link->socket, socket);
            return link;
        }

        /**
         * @brief Creates a TCP client wrapper for one accepted flow.
         */
        VNetstack::TapTcpClient::TapTcpClient(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept
            : lwip_(IPEndPoint::MinPort)
            , disposed_(FALSE)
            , context_(context)
            , strand_(strand)
            , sync_ack_state_(VNETSTACK_SYNC_ACK_STATE_CLOSED)
            , sync_ack_bytes_size_(0) {
            ppp::telemetry::Log(Level::kInfo, "vnetstack", "socket created");
            socket_ = strand ? 
                make_shared_object<boost::asio::ip::tcp::socket>(*strand) : make_shared_object<boost::asio::ip::tcp::socket>(*context);
        }

        /**
         * @brief Finalizes and releases TCP client state.
         */
        VNetstack::TapTcpClient::~TapTcpClient() noexcept {
            Finalize();
        }

        /**
         * @brief Stores endpoint metadata for this client.
         */
        void VNetstack::TapTcpClient::Open(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            this->localEP_ = localEP;
            this->remoteEP_ = remoteEP;
        }

        /**
         * @brief Wraps accepted native socket handle into client socket.
         */
        std::shared_ptr<boost::asio::ip::tcp::socket> VNetstack::TapTcpClient::NewAsynchronousSocket(int sockfd, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept {
            if (disposed_) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                return NULLPTR;
            }

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_;
            if (NULLPTR == socket) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return NULLPTR;
            }

            if (socket->is_open()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return NULLPTR;
            }

            boost::system::error_code ec = boost::asio::error::operation_aborted;
            try {
                socket->assign(remoteEP.protocol(), sockfd, ec);
            }
            catch (const std::exception&) {}

            if (ec) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SocketOpenFailed);
                return NULLPTR;
            }
            else {
                return socket;
            }
        }

        /**
         * @brief Schedules asynchronous finalization on socket executor.
         */
        void VNetstack::TapTcpClient::Dispose() noexcept {
            if (disposed_.exchange(TRUE, std::memory_order_acq_rel) != FALSE) {
                return;
            }

            ppp::telemetry::Log(Level::kInfo, "vnetstack", "socket disposed");
            std::shared_ptr<TapTcpClient> self = shared_from_this();
            ppp::threading::Executors::ContextPtr context = context_;
            ppp::threading::Executors::StrandPtr strand = strand_;

            auto finalize = 
                [self, this, context, strand]() noexcept {
                    Finalize();
                };

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = socket_; 
            if (NULLPTR != socket) {
                boost::asio::post(socket->get_executor(), finalize);
            }
            else {
                ppp::threading::Executors::Post(context, strand, finalize);
            }
        }

        /**
         * @brief Resets handshake state, closes socket, and releases link.
         */
        void VNetstack::TapTcpClient::Finalize() noexcept {
            disposed_.store(TRUE, std::memory_order_release);

            this->CancelSyncAckRetry();

            std::atomic_store(&this->sync_ack_byte_array_, std::shared_ptr<Byte>());
            this->sync_ack_bytes_size_.store(0, std::memory_order_release);
            std::atomic_store(&this->sync_ack_tap_driver_, std::shared_ptr<ITap>());
            this->sync_ack_retry_count_ = 0;
            this->sync_ack_state_ = VNETSTACK_SYNC_ACK_STATE_CLOSED;

            std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::move(socket_);
            std::shared_ptr<TapTcpLink> link = std::move(link_);

            if (NULLPTR != socket) {
                Socket::Closesocket(socket);
            }

            if (NULLPTR != link) {
                if (lwip_) {
                    link->Release();
                }
                else {
                    link->Closing();
                }
            }

#ifdef SYSNAT
            {
                SynchronizedObjectScope scope(sysnat_synbobj_);
                int _ = 1;
                if (sysnat_status_.compare_exchange_strong(_, -1)) {
                    SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj());
                    openppp2_sysnat_del_rule(&forward_key_);
                    openppp2_sysnat_del_rule(&backward_key_);
                }
            }

            /**
             * @brief Virtual Update() calls run outside sysnat_synbobj_ to prevent
             *        lock-order inversion: a subclass override of Update() may acquire
             *        its own mutex, and acquiring that mutex while holding sysnat_synbobj_
             *        would create a deadlock if another thread acquires them in reverse order.
             */
            Update();
            if (NULL != link) {
                link->Update();
            }
#endif
        }

        /**
         * @brief Refreshes linked flow activity timestamp.
         */
        bool VNetstack::TapTcpClient::Update() noexcept {
            if (disposed_) {
                return false;
            }

            std::shared_ptr<TapTcpLink> link = link_;
            if (NULLPTR != link) {
                link->Update();
                return true;
            }
            else {
                return false;
            }
        }

        /**
         * @brief Binds accepted NAT endpoint and transitions into established flow.
         */
        bool VNetstack::TapTcpClient::EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept {
            if (NULLPTR == socket) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::VNetstackNullSocketInput);
            }

            std::shared_ptr<boost::asio::io_context> context = this->context_;
            if (NULLPTR == context) {
                return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::RuntimeIoContextMissing);
            }

            this->natEP_ = natEP;
            this->socket_ = socket;

            this->CancelSyncAckRetry();

            std::atomic_store(&this->sync_ack_byte_array_, std::shared_ptr<Byte>());
            this->sync_ack_bytes_size_.store(0, std::memory_order_release);
            std::atomic_store(&this->sync_ack_tap_driver_, std::shared_ptr<ITap>());
            this->sync_ack_retry_count_ = 0;
            this->sync_ack_state_ = VNETSTACK_SYNC_ACK_STATE_CLOSED;

            if (lwip_) {
                std::shared_ptr<TapTcpLink> link = this->link_;
                if (NULLPTR == link) {
                    return ppp::diagnostics::SetLastError(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
                }

                link->state.store((Byte)TcpState::TCP_STATE_ESTABLISHED, std::memory_order_relaxed);
            }

            return this->Establish();
        }

        /**
         * @brief Sends SYN/ACK once and schedules retransmission when needed.
         */
        bool VNetstack::TapTcpClient::AckAccept() noexcept {
            if (disposed_) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                return false;
            }

            std::shared_ptr<Byte> packet = std::atomic_load(&this->sync_ack_byte_array_);
            std::shared_ptr<ITap> tap    = std::atomic_load(&this->sync_ack_tap_driver_);

            int packet_length = this->sync_ack_bytes_size_.load(std::memory_order_acquire);
            if (packet_length < 1) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VNetstackSyncAckInvalidState);
                return false;
            }

            Byte sync_ack_state = VNETSTACK_SYNC_ACK_STATE_SYN_SENT;
            if (!this->sync_ack_state_.compare_exchange_strong(sync_ack_state, VNETSTACK_SYNC_ACK_STATE_SYN_RECVD)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VNetstackSyncAckInvalidState);
                return false;
            }

            ppp::telemetry::Log(Level::kDebug, "vnetstack", "sync-ack accepted");
            if (NULLPTR == tap) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelDeviceMissing);
                return false;
            }

            if (lwip_) {
                std::shared_ptr<TapTcpLink> link = this->link_;
                if (NULLPTR == link) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::InternalLogicNullPointer);
                    return false;
                }

                link->state.store((Byte)TcpState::TCP_STATE_SYN_RECEIVED, std::memory_order_relaxed);
                (void)tap->Output(packet, packet_length);

                std::atomic_store(&this->sync_ack_byte_array_, packet);
                this->sync_ack_bytes_size_.store(packet_length, std::memory_order_release);
                this->sync_ack_retry_count_ = 0;
                this->ScheduleSyncAckRetry(200);
                
                (void)lwip::netstack::input(packet.get(), packet_length);
                return true;
            }

            if (NULLPTR == packet) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryBufferNull);
                return false;
            }

#ifdef SYSNAT
            for (int _ = 0;;) {
                std::shared_ptr<TapTcpLink> link = this->link_;
                if (NULLPTR == link) {
                    break;
                }

                SynchronizedObjectScope scope(sysnat_synbobj_);
                if (!sysnat_status_.compare_exchange_strong(_, 1)) {
                    break;
                }

                uint32_t inner_src   = link->srcAddr;   
                uint16_t inner_sport = link->srcPort;   
                uint32_t outer_dst   = link->dstAddr;   
                uint16_t outer_dport = link->dstPort;   

                uint32_t nat_ip      = tap->GatewayServer;   
                uint16_t nat_port    = link->natPort;       
                uint32_t local_ip    = tap->IPAddress;       
                uint16_t listen_port = htons(listenPort_);       

                forward_key_.src_ip   = inner_src;
                forward_key_.src_port = (inner_sport);
                forward_key_.dst_ip   = outer_dst;
                forward_key_.dst_port = (outer_dport);
                forward_key_.proto    = IPPROTO_TCP;

                struct openppp2_sysnat_value forward_val;
                forward_val.new_src_addr     = nat_ip;
                forward_val.new_src_port     = nat_port;
                forward_val.new_dst_addr     = local_ip;
                forward_val.new_dst_port     = listen_port;
                forward_val.redirect_ifindex = 0;
  
                backward_key_.src_ip   = local_ip;
                backward_key_.src_port = listen_port;
                backward_key_.dst_ip   = nat_ip;
                backward_key_.dst_port = nat_port;
                backward_key_.proto    = IPPROTO_TCP;

                struct openppp2_sysnat_value backward_val;
                backward_val.new_src_addr     = outer_dst;
                backward_val.new_src_port     = outer_dport;
                backward_val.new_dst_addr     = inner_src;
                backward_val.new_dst_port     = inner_sport;
                backward_val.redirect_ifindex = 0;

                SynchronizedObjectScope __SCOPE__(openppp2_sysnat_syncobj()); 
                int forward_add_status = openppp2_sysnat_add_rule(&forward_key_, &forward_val);
                if (0 == forward_add_status) {
                    int backward_add_status = openppp2_sysnat_add_rule(&backward_key_, &backward_val);
                    if (0 != backward_add_status) {
                        /**
                         * @brief Roll back forward SYSNAT rule when backward install fails.
                         */
                        openppp2_sysnat_del_rule(&forward_key_);

                        _ = 1;
                        sysnat_status_.compare_exchange_strong(_, -1);
                        openppp2_sysnat_publish_error(backward_add_status);
                    }
                }
                else {
                    _ = 1;
                    sysnat_status_.compare_exchange_strong(_, -1);
                    openppp2_sysnat_publish_error(forward_add_status);
                }

                break;
            }
#endif

            std::atomic_store(&this->sync_ack_byte_array_, packet);
            this->sync_ack_bytes_size_.store(packet_length, std::memory_order_release);            this->sync_ack_retry_count_ = 0;
            this->ScheduleSyncAckRetry(200);

            (void)tap->Output(packet, packet_length);
            return true;
        }

        /**
         * @brief Cancels pending SYN/ACK retry timer if present.
         */
        void VNetstack::TapTcpClient::CancelSyncAckRetry() noexcept {
            std::shared_ptr<boost::asio::steady_timer> timer = std::move(this->sync_ack_retry_timer_);
            if (NULLPTR != timer) {
                timer->cancel();
            }
        }

        /**
         * @brief Arms SYN/ACK retransmission timer with exponential-like schedule.
         */
        void VNetstack::TapTcpClient::ScheduleSyncAckRetry(uint64_t delay_ms) noexcept {
            if (disposed_ || delay_ms == 0) {
                return;
            }

            std::shared_ptr<boost::asio::io_context> context = this->context_;
            if (NULLPTR == context) {
                return;
            }

            std::shared_ptr<TapTcpClient> self = shared_from_this();
            std::shared_ptr<boost::asio::steady_timer> timer = this->sync_ack_retry_timer_;
            if (NULLPTR == timer) {
                timer = make_shared_object<boost::asio::steady_timer>(*context);
                this->sync_ack_retry_timer_ = timer;
            }

            if (NULLPTR == timer) {
                return;
            }

            timer->expires_after(std::chrono::milliseconds(delay_ms));
            timer->async_wait([self](const boost::system::error_code& ec) noexcept {
                if (ec || self->disposed_) {
                    return;
                }

                std::shared_ptr<Byte> packet = std::atomic_load(&self->sync_ack_byte_array_);
                std::shared_ptr<ITap> tap    = std::atomic_load(&self->sync_ack_tap_driver_);
                int packet_length            = self->sync_ack_bytes_size_.load(std::memory_order_acquire);
                if (NULLPTR == packet || NULLPTR == tap || packet_length < 1) {
                    return;
                }

                if (self->sync_ack_state_.load() != VNETSTACK_SYNC_ACK_STATE_SYN_RECVD) {
                    return;
                }

                /**
                 * @brief Retry delays in milliseconds for SYN/ACK retransmission.
                 */
                static constexpr uint64_t retry_delays[] = {200, 400, 800, 1200, 1600};

                int retry_index = self->sync_ack_retry_count_;
                if (retry_index < 0 || retry_index >= static_cast<int>(arraysizeof(retry_delays))) {
                    return;
                }

                bool ok = tap->Output(packet, packet_length);
                self->sync_ack_retry_count_ = retry_index + 1;

                if (self->sync_ack_retry_count_ < static_cast<int>(arraysizeof(retry_delays))) {
                    self->ScheduleSyncAckRetry(retry_delays[self->sync_ack_retry_count_]);
                }

            });
        }
    }
}
