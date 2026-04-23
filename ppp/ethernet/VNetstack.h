#pragma once

/**
 * @file VNetstack.h
 * @brief Declares the virtual TCP NAT/forwarding stack used by VEthernet.
 */

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/ip.h>
#include <ppp/net/native/tcp.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/SocketAcceptor.h>
#include <ppp/net/asio/IAsynchronousWriteIoQueue.h>

#include <boost/asio/steady_timer.hpp>

#ifdef SYSNAT
#include <linux/ppp/tap/openppp2_sysnat.h>
#endif

namespace ppp {
    namespace ethernet {
        /**
         * @brief Virtual TCP stack that maps TAP-side flows to outbound sockets.
         */
        class VNetstack : public std::enable_shared_from_this<VNetstack> {
            friend class                                                    VEthernet;
            friend class                                                    TapTcpClient;

        public:
            class                                                           TapTcpClient;

        private:
            /**
             * @brief Stores one TCP flow translation entry.
             */
            struct TapTcpLink {
            public:
                /** @brief Destination (WAN-side) IPv4 address. */
                UInt32                                                      dstAddr = 0;
                /** @brief Destination (WAN-side) TCP port. */
                UInt16                                                      dstPort = 0;
                /** @brief Source (LAN-side) IPv4 address. */
                UInt32                                                      srcAddr = 0;
                /** @brief Source (LAN-side) TCP port. */
                UInt16                                                      srcPort = 0;
                /** @brief Locally allocated NAT port used on the loopback listener side. */
                UInt16                                                      natPort = 0;
                /**
                 * @brief Full Int128 LAN2WAN key stored by the lwIP accept path.
                 *        Standard NAT path flows leave this zero and use natPort for
                 *        wan2lan_ lookup.  lwIP-path flows store the full key here so
                 *        that CloseTcpLink() can locate and remove the correct wan2lan_
                 *        entry without the Int128→UInt16 truncation that previously caused
                 *        map entries to leak.  Zero for non-lwIP flows.
                 */
                Int128                                                      lwipKey = 0;
                /**
                 * @brief Set once at link creation from the lwIP accept path; never mutated
                 *        afterwards.  Plain bool is safe — no cross-thread write after init.
                 */
                bool                                                        lwip      = false;
                /**
                 * @brief TCP state machine value.  Read and written from multiple SSMT threads
                 *        without a lock; must be atomic to avoid a data race.
                 */
                std::atomic<Byte>                                           state     = { 0 };
                /**
                 * @brief CAS guard that prevents two concurrent SSMT threads from both calling
                 *        BeginAcceptClient() for the same SYN flow during retransmission.
                 *        Atomically exchanged false→true by the winning thread; reset to false
                 *        only on failure so the next retransmission may retry.
                 */
                std::atomic_bool                                            accepting = { false };
                /**
                 * @brief Set-once closing guard.  exchange(true) returns the previous value;
                 *        only the first caller that sees false performs the close.
                 */
                std::atomic_bool                                            closed    = { false };
                /**
                 * @brief Last activity timestamp in milliseconds.  Updated lock-free by SSMT
                 *        threads via Update(); must be atomic to avoid a data race.
                 */
                std::atomic<UInt64>                                         lastTime  = { 0 };
                /**
                 * @brief Bound outbound socket for this flow.
                 * @note  These fields MUST be accessed exclusively via `std::atomic_load` /
                 *        `std::atomic_store` / `std::atomic_exchange` free functions
                 *        (C++17 valid pattern).
                 *        Do NOT use `std::atomic<std::shared_ptr<T>>` — that is a C++20
                 *        feature and this project targets C++17.
                 */
                std::shared_ptr<TapTcpClient>                               socket;

            public:
                /** @brief Initializes a closed link entry. */
                TapTcpLink() noexcept;
                /** @brief Releases this link entry and associated resources. */
                virtual ~TapTcpLink() noexcept { this->Release(); }

            public:
                /** @brief Refreshes last activity timestamp. */
                void                                                        Update() noexcept { this->lastTime.store(ppp::threading::Executors::GetTickCount(), std::memory_order_relaxed); }
                /** @brief Closes the link and resets state. */
                void                                                        Release() noexcept;
                /** @brief Marks link closed and disposes bound socket client. */
                void                                                        Closing() noexcept;
                /** @brief Alias of Release for IDisposable-like usage. */
                void                                                        Dispose() noexcept { this->Release(); };

            public:
                typedef std::shared_ptr<TapTcpLink>                         Ptr;
            };
            typedef ppp::unordered_map<Int128, TapTcpLink::Ptr>             LAN2WANTABLE;
            typedef LAN2WANTABLE                                            WAN2LANTABLE;

        public:
            typedef ppp::tap::ITap                                          ITap;
            typedef ppp::threading::Executors                               Executors;
            typedef ppp::net::IPEndPoint                                    IPEndPoint;
            typedef ppp::net::native::ip_hdr                                ip_hdr;
            typedef ppp::net::native::tcp_hdr                               tcp_hdr;
            typedef ppp::net::SocketAcceptor                                SocketAcceptor;
            typedef ppp::coroutines::YieldContext                           YieldContext;
            typedef std::mutex                                              SynchronizedObject;
            typedef std::lock_guard<SynchronizedObject>                     SynchronizedObjectScope;
            
        public:
            /**
             * @brief Represents one accepted TCP transport bound to a TapTcpLink.
             */
            class TapTcpClient : public std::enable_shared_from_this<TapTcpClient>
            {
                friend class                                                VNetstack;

            public:
                /**
                 * @brief Creates a TAP TCP client object.
                 * @param context Asio context used by timers and fallback posting.
                 * @param strand Optional strand used for serialized socket execution.
                 */
                TapTcpClient(const std::shared_ptr<boost::asio::io_context>& context, const ppp::threading::Executors::StrandPtr& strand) noexcept;
                /** @brief Releases socket and link resources. */
                virtual ~TapTcpClient() noexcept;

            public:
                /** @brief Sets local and remote endpoint metadata. */
                virtual void                                                Open(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                /** @brief Refreshes underlying link timestamp if available. */
                virtual bool                                                Update() noexcept;
                /** @brief Schedules asynchronous finalization. */
                virtual void                                                Dispose() noexcept;
                /** @brief Returns whether this client uses lwIP accept path. */
                bool                                                        IsLwip() const noexcept { return lwip_ != 0; }
                /** @brief Returns whether this client is disposed. */
                bool                                                        IsDisposed() noexcept { return disposed_.load() != FALSE; }

            public:
                /** @brief Gets the LAN-side endpoint seen by TAP flow. */
                const boost::asio::ip::tcp::endpoint&                       GetLocalEndPoint() const noexcept  { return this->localEP_; }
                /** @brief Gets the NAT-side endpoint accepted by local listener. */
                const boost::asio::ip::tcp::endpoint&                       GetNatEndPoint() const noexcept    { return this->natEP_; }
                /** @brief Gets the remote destination endpoint. */
                const boost::asio::ip::tcp::endpoint&                       GetRemoteEndPoint() const noexcept { return this->remoteEP_; }

            public:
                /** @brief Gets the underlying asynchronous socket. */
                std::shared_ptr<boost::asio::ip::tcp::socket>               GetSocket() noexcept  { return socket_; }
                /** @brief Gets the owning io_context. */
                std::shared_ptr<boost::asio::io_context>&                   GetContext() noexcept { return context_; }
                /** @brief Gets the optional execution strand. */
                ppp::threading::Executors::StrandPtr&                       GetStrand() noexcept  { return strand_; }

            protected:
                /** @brief Starts outbound connection preparation. */
                virtual bool                                                BeginAccept() noexcept = 0;
                /** @brief Emits SYN/ACK packet after outbound path is ready. */
                virtual bool                                                AckAccept() noexcept;
                /** @brief Called after accept is finalized and socket is active. */
                virtual bool                                                Establish() noexcept = 0;
                /** @brief Binds accepted NAT socket and transitions state. */
                virtual bool                                                EndAccept(const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, const boost::asio::ip::tcp::endpoint& natEP) noexcept;
                /** @brief Cancels pending SYN/ACK retry timer. */
                void                                                        CancelSyncAckRetry() noexcept;
                /** @brief Schedules SYN/ACK retransmission timer. */
                void                                                        ScheduleSyncAckRetry(uint64_t delay_ms) noexcept;

            private:
                /** @brief Internal finalizer that releases all owned state. */
                void                                                        Finalize() noexcept;
                /** @brief Wraps accepted native socket handle into asio socket. */
                std::shared_ptr<boost::asio::ip::tcp::socket>               NewAsynchronousSocket(int sockfd, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;

            private:
                /** @brief Non-zero when this client was created through the lwIP accept path. */
                Int128                                                      lwip_                = 0;
                /** @brief Disposal guard; exchange FALSE→non-zero to perform one-time finalization. */
                std::atomic<int>                                            disposed_            = FALSE;

                /** @brief io_context used for posting timers and fallback async operations. */
                std::shared_ptr<boost::asio::io_context>                    context_;
                /** @brief Optional strand serializing socket callbacks. */
                ppp::threading::Executors::StrandPtr                        strand_;
                /** @brief Outbound TCP socket connecting to the upstream destination. */
                std::shared_ptr<boost::asio::ip::tcp::socket>               socket_;
                /** @brief Owning NAT flow link entry. */
                std::shared_ptr<TapTcpLink>                                 link_;

                /**
                 * @note  These fields MUST be accessed exclusively via `std::atomic_load` /
                 *        `std::atomic_store` / `std::atomic_exchange` free functions
                 *        (C++17 valid pattern).
                 *        Do NOT use `std::atomic<std::shared_ptr<T>>` — that is a C++20
                 *        feature and this project targets C++17.
                 */
                std::shared_ptr<ITap>                                       sync_ack_tap_driver_;   ///< Atomically-accessed TAP driver reference for SYN/ACK retry path.
                std::shared_ptr<Byte>                                       sync_ack_byte_array_;   ///< Atomically-accessed SYN/ACK packet buffer for retry path.
                std::atomic<Byte>                                           sync_ack_state_       = 0;
                std::atomic<int>                                            sync_ack_bytes_size_  = 0; ///< Atomic: written by Output() thread, read by retry timer thread.
                int                                                         sync_ack_retry_count_ = 0; ///< Single-threaded (context_ strand only); no atomic needed.
                std::shared_ptr<boost::asio::steady_timer>                  sync_ack_retry_timer_;

                /** @brief NAT-side local endpoint accepted by the loopback listener. */
                boost::asio::ip::tcp::endpoint                              natEP_;
                /** @brief LAN-side source endpoint seen in the TAP packet flow. */
                boost::asio::ip::tcp::endpoint                              localEP_;
                /** @brief WAN-side remote destination endpoint. */
                boost::asio::ip::tcp::endpoint                              remoteEP_;

#ifdef SYSNAT
                SynchronizedObject                                          sysnat_synbobj_;
                int                                                         listenPort_          = 0;
                std::atomic<int>                                            sysnat_status_       = 0;

                struct openppp2_sysnat_key                                  forward_key_;
                struct openppp2_sysnat_key                                  backward_key_;
#endif
            };

        public:
            const std::shared_ptr<ITap>                                     Tap;

        public:
            /** @brief Constructs an empty virtual stack. */
            VNetstack() noexcept;
            /** @brief Releases listeners, links, and client resources. */
            virtual ~VNetstack() noexcept;

        public:
            /** @brief Returns allocator inherited from TAP device. */
            std::shared_ptr<ppp::threading::BufferswapAllocator>            GetBufferAllocator() noexcept
            {
                std::shared_ptr<ITap> tap = this->Tap;
                return NULLPTR != tap ? tap->BufferAllocator : NULLPTR;
            }
            /** @brief Returns a shared reference to this object. */
            std::shared_ptr<VNetstack>                                      GetReference() noexcept { return shared_from_this(); }
            /** @brief Returns synchronization object protecting flow tables. */
            SynchronizedObject&                                             GetSynchronizedObject() noexcept { return syncobj_; }
            /** @brief Opens local acceptor and initializes runtime mode. */
            virtual bool                                                    Open(bool lwip, const int& localPort) noexcept;
            /** @brief Releases all runtime resources. */
            virtual void                                                    Release() noexcept;
            /** @brief Processes one TCP packet from VEthernet input path. */
            virtual bool                                                    Input(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept;
            /** @brief Performs periodic timeout and cleanup maintenance. */
            virtual bool                                                    Update(uint64_t now) noexcept;

        protected:
            /** @brief Creates a transport client for a new TCP flow. */
            virtual std::shared_ptr<TapTcpClient>                           BeginAcceptClient(const boost::asio::ip::tcp::endpoint& localEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept = 0;
            /** @brief Returns timeout used for SYN/connect phase. */
            virtual uint64_t                                                GetMaxConnectTimeout() noexcept;
            /** @brief Returns timeout used for teardown/finalization phase. */
            virtual uint64_t                                                GetMaxFinalizeTimeout() noexcept;
            /** @brief Returns timeout used for established but inactive flows. */
            virtual uint64_t                                                GetMaxEstablishedTimeout() noexcept;

        private:
            /** @brief Sends a TCP RST reply for rejected flows. */
            bool                                                            RST(ip_hdr* ip, tcp_hdr* tcp, int tcp_len) noexcept;
            /** @brief Rewrites checksums and emits packet to TAP/SYN-ACK cache. */
            bool                                                            Output(bool lan2wan, ip_hdr* ip, tcp_hdr* tcp, int tcp_len, TapTcpClient* c) noexcept;
            /** @brief Releases acceptor and all flow tables. */
            void                                                            ReleaseAllResources() noexcept;
            /** @brief Handles one socket accepted by local listener. */
            bool                                                            ProcessAcceptSocket(int sockfd) noexcept;

        private:
            /** @brief Handles lwIP callback for starting accept path. */
            int                                                             LwIpBeginAccept(
                boost::asio::ip::tcp::endpoint&                             dest, 
                boost::asio::ip::tcp::endpoint&                             src,
                uint32_t                                                    seq,
                uint32_t                                                    ack,    
                uint16_t                                                    wnd) noexcept;
            /** @brief Finds or creates a lwIP flow link entry. */
            std::shared_ptr<TapTcpLink>                                     LwIpAcceptLink(uint32_t srcAddr, uint32_t dstAddr, int srcPort, int dstPort) noexcept;

        private:
            /** @brief Removes a flow entry and closes its client. */
            bool                                                            CloseTcpLink(const std::shared_ptr<TapTcpLink>& link) noexcept;
            /** @brief Finds link by NAT-side port key. */
            std::shared_ptr<TapTcpLink>                                     FindTcpLink(int key) noexcept;
            /** @brief Finds link by LAN-to-WAN composite key. */
            std::shared_ptr<TapTcpLink>                                     FindTcpLink(const Int128& key) noexcept;
            /** @brief Allocates a new NAT translation link for SYN flows. */
            std::shared_ptr<TapTcpLink>                                     AllocTcpLink(UInt32 src_ip, int src_port, UInt32 dst_ip, int dst_port) noexcept;

        private:
            /** @brief Guards wan2lan_, lan2wan_, and acceptor_ from concurrent access. */
            SynchronizedObject                                              syncobj_;
            /** @brief Next NAT port allocation counter. */
            int                                                             ap_     = 0;
            /** @brief Indicates whether lwIP accept path is active. */
            bool                                                            lwip_   = false;
#ifdef SYSNAT
            /** @brief Indicates whether SYSNAT kernel-bypass mode is enabled. */
            bool                                                            sysnat_ = false;
            /** @brief Network interface name used by SYSNAT kernel module. */
            ppp::string                                                     sysnat_interface_name_;
#endif
            /** @brief Local loopback endpoint that the acceptor listens on. */
            IPEndPoint                                                      listenEP_;
            /**
             * @brief Atomic mirror of listenEP_.Port.
             * @note  Written under syncobj_ in Open() and ReleaseAllResources().
             *        Read lock-free on SSMT Input() threads to avoid holding syncobj_
             *        during per-packet NAT rewrites.
             */
            std::atomic<int>                                                listenPort_ = { 0 };
            /** @brief WAN-to-LAN NAT translation table keyed by composite flow ID. */
            WAN2LANTABLE                                                    wan2lan_;
            /** @brief LAN-to-WAN NAT translation table keyed by composite flow ID. */
            LAN2WANTABLE                                                    lan2wan_;
            /** @brief Loopback socket acceptor used to receive locally originated connections. */
            std::shared_ptr<SocketAcceptor>                                 acceptor_;
        };
    }
}
