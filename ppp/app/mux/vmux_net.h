#pragma once

#include "vmux.h"

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetNetworkTcpipConnection;
        }

        namespace client {
            class VEthernetNetworkTcpipConnection;
        }
    }
}

namespace vmux {
    class vmux_skt;

    class vmux_net final : public std::enable_shared_from_this<vmux_net> {
    public:
        typedef ppp::function<void(vmux_skt*, bool)>                                ConnectAsynchronousCallback;
        typedef ppp::app::protocol::VirtualEthernetTcpipConnection                  VirtualEthernetTcpipConnection;
        typedef std::shared_ptr<VirtualEthernetTcpipConnection>                     VirtualEthernetTcpipConnectionPtr;
        typedef std::shared_ptr<ppp::transmissions::ITransmission>                  ITransmissionPtr;

        std::shared_ptr<ppp::threading::BufferswapAllocator>                        BufferAllocator;
        std::shared_ptr<ppp::configurations::AppConfiguration>                      AppConfiguration;
        std::shared_ptr<ppp::app::protocol::VirtualEthernetLogger>                  Logger;
        uint16_t                                                                    Vlan;
        std::shared_ptr<ppp::net::Firewall>                                         Firewall;

        typedef std::shared_ptr<vmux_skt>                                           vmux_skt_ptr;
        typedef struct {
            VirtualEthernetTcpipConnectionPtr                                       connection;
            std::shared_ptr<
                ppp::app::server::VirtualEthernetNetworkTcpipConnection>            server;
        }                                                                           vmux_linklayer;

        typedef std::shared_ptr<vmux_linklayer>                                     vmux_linklayer_ptr;
        typedef ppp::function<bool()>                                               vmux_native_add_linklayer_after_success_before_callback;
        
#if defined(_LINUX)
    public:
        typedef std::shared_ptr<ppp::net::ProtectorNetwork>                         ProtectorNetworkPtr;

    public:
        ProtectorNetworkPtr                                                         ProtectorNetwork;
#endif

    private:
        friend class                                                                vmux_skt;
        struct                                                                      vmux_frame;

        template <typename _Tp>
        struct packet_less {
            static constexpr bool                                                   before(uint32_t seq1, uint32_t seq2) noexcept {
                return (int32_t)(seq1 - seq2) < 0;
            }

            static constexpr bool                                                   after(uint32_t seq2, uint32_t seq1) noexcept {
                return before(seq1, seq2);
            }

            constexpr bool                                                          operator()(const _Tp& __x, const _Tp& __y) const noexcept {
                return before(__x, __y);
            }
        };

#pragma pack(push, 1)
        typedef struct {
            uint32_t                                                                seq;
            uint8_t                                                                 cmd;
            uint32_t                                                                connection_id;
        }                                                                           vmux_hdr;
#pragma pack(pop)

        enum {
            cmd_none = ('E' - 1),
            cmd_syn,
            cmd_syn_ok,
            cmd_push,
            cmd_fin,
            cmd_keep_alived,
            cmd_fast,
            cmd_max,

            max_buffers_size = UINT16_MAX - sizeof(vmux_hdr),
        };

        typedef ppp::function<void(bool)>                                           PostInternalAsynchronousCallback;
        struct rx_packet {
            std::shared_ptr<Byte>                                                   buffer;
            int                                                                     length = 0;
        };

        struct tx_packet : rx_packet {
            PostInternalAsynchronousCallback                                        ac;
        };

        typedef vmux::list<vmux_linklayer_ptr>                                      vmux_linklayer_list;
        typedef vmux::vector<vmux_linklayer_ptr>                                    vmux_linklayer_vector;

        typedef vmux::list<tx_packet>                                               tx_packet_ssqueue;
        typedef vmux::map_pr<uint32_t, rx_packet, packet_less<uint32_t>>            rx_packet_ssqueue;

        typedef vmux::unordered_map<uint32_t, vmux_skt_ptr>                         vmux_skt_map;

    public:
        enum vmux_fast_mode {
            vmux_fast_mode_none = 0,
            vmux_fast_mode_auto = 1,
            vmux_fast_mode_must = 2,
        };
        vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, vmux_fast_mode fast, bool server_mode) noexcept;
        ~vmux_net() noexcept;

    public:
        const StrandPtr&                                                            get_strand()          noexcept { return strand_; }
        const ContextPtr&                                                           get_context()         noexcept { return context_; }
        uint16_t                                                                    get_max_connections() noexcept { return status_.max_connections; }
        uint64_t                                                                    get_last()            noexcept { return status_.last_; }
        const std::atomic<uint32_t>&                                                get_tx_seq()          noexcept { return status_.tx_seq_; }
        const std::atomic<uint32_t>&                                                get_rx_ack()          noexcept { return status_.rx_ack_; }
        bool                                                                        is_disposed()         noexcept { return base_.disposed_; }
        bool                                                                        is_established()      noexcept { return !base_.disposed_ && base_.established_; }

        bool                                                                        ftt(uint32_t seq, uint32_t ack) noexcept;
        static uint32_t                                                             ftt_random_aid(int min, int max) noexcept;

        bool                                                                        init(const std::shared_ptr<boost::asio::ip::tcp::resolver>& resolver) noexcept;

        void                                                                        close_exec() noexcept;
        bool                                                                        update() noexcept;
        bool                                                                        add_linklayer(
            const VirtualEthernetTcpipConnectionPtr&                                connection, 
            vmux_linklayer_ptr&                                                     linklayer,
            const vmux_native_add_linklayer_after_success_before_callback&          cb) noexcept;

        bool                                                                        connect(const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept;
        bool                                                                        connect_safe(
            ppp::coroutines::YieldContext&                                          y,
            const std::shared_ptr<boost::asio::ip::tcp::socket>&                    sk, 
            const template_string&                                                  host, 
            int                                                                     port,
        vmux_skt_ptr&                                                               return_connection) noexcept;

    public:
        template <typename YieldHandler>
        bool                                                                        do_yield(ppp::coroutines::YieldContext& y, YieldHandler&& h) noexcept {
            bool ok = false;
            std::atomic<int> initiate = -1;

            initiate = vmux_post_exec(context_, strand_, 
                [h, &y, &ok, &initiate]() noexcept {
                    ok = h();
                    await_initiate_after_yield_coroutine(y, initiate);
                }) ? 1 : 0;

            int status = initiate.load();
            if (status > 0) {
                bool suspend = y.Suspend();
                if (suspend) {
                    return ok;
                }
            }

            initiate.exchange(0);
            return false;
        }

        static void                                                                 await_initiate_after_yield_coroutine(ppp::coroutines::YieldContext& y, std::atomic<int>& initiate) noexcept;

    public:
        static void                                                                 close(const std::shared_ptr<boost::asio::ip::tcp::socket>& sk) noexcept { ppp::net::Socket::Closesocket(sk); }
        static void                                                                 close(const boost::asio::ip::tcp::socket& sk) noexcept { ppp::net::Socket::Closesocket(sk); }

    public:
        std::shared_ptr<Byte>                                                       make_byte_array(int array_size) noexcept {
            return ppp::threading::BufferswapAllocator::MakeByteArray(BufferAllocator, array_size);
        }
        
        static uint32_t                                                             generate_id() noexcept;

        static uint64_t                                                             now_tick() noexcept { return ppp::threading::Executors::GetTickCount(); }

    private:
        bool                                                                        underlyin_sent(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& packet, int packet_length, const PostInternalAsynchronousCallback& posted_ac) noexcept;

    private:
        vmux_skt_ptr                                                                get_connection(uint32_t connection_id) noexcept;
        vmux_skt_ptr                                                                release_connection(uint32_t connection_id, vmux_skt* refer_pointer) noexcept;

        bool                                                                        packet_input_unorder(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept;
        bool                                                                        packet_input_single(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept;
        bool                                                                        packet_input(Byte cmd, Byte* buffer, int buffer_size, uint64_t now) noexcept;

        bool                                                                        process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept;

        void                                                                        active(uint64_t now) noexcept { 
            using Thread = ppp::threading::Thread;

            if (!base_.disposed_) {
                Thread::MemoryBarrier();
                for (;;) {
                    status_.last_ = now; 
                    break;
                }
                Thread::MemoryBarrier();
            }
        }

        void                                                                        active() noexcept { 
            uint64_t now = now_tick();
            active(now);
        }

        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id) noexcept {
            PostInternalAsynchronousCallback ac;
            return post(cmd, packet, packet_length, connection_id, ac);
        }
        bool                                                                        post(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, const PostInternalAsynchronousCallback& posted_ac) noexcept {
            bool successing = post_internal(cmd, packet, packet_length, connection_id, posted_ac);
            if (!successing) {
                close_exec();
            }

            return successing;
        }
        bool                                                                        post_internal(Byte cmd, const void* packet, int packet_length, uint32_t connection_id, const PostInternalAsynchronousCallback& posted_ac) noexcept;
        bool                                                                        post_internal(const std::shared_ptr<Byte>& packet, int packet_length, const PostInternalAsynchronousCallback& posted_ac) noexcept;
        
        bool                                                                        process_tx_all_packets() noexcept;
        void                                                                        finalize() noexcept;

        VirtualEthernetTcpipConnectionPtr                                           get_linklayer() noexcept;

        bool                                                                        connect_require(
            const std::shared_ptr<boost::asio::ip::tcp::socket>&                    sk, 
            const template_string&                                                  host, 
            int                                                                     port) noexcept;

        bool                                                                        handshake(const vmux_linklayer_ptr& linklayer, uint16_t connection_id, ppp::coroutines::YieldContext& y) noexcept;
        bool                                                                        forwarding(const vmux_linklayer_ptr& linklayer, ppp::coroutines::YieldContext& y) noexcept;

        bool                                                                        packet_input_acked(const vmux_linklayer_ptr& linklayer, vmux_frame* frames, int frame_count, uint64_t now) noexcept;
        bool                                                                        packet_input_acking(vmux_frame* frames, int& frame_count) noexcept;

        void                                                                        linklayer_established() noexcept;

        void                                                                        linklayer_update(const vmux_linklayer_ptr& linklayer) noexcept;

    private:
        struct {
            bool                                                                    disposed_          : 1;
            bool                                                                    ftt_               : 1;
            bool                                                                    server_or_client_  : 1;
            bool                                                                    established_       : 5;
            vmux_fast_mode                                                          fast_              = vmux_fast_mode_none;
        }                                                                           base_;

        struct {
            uint16_t                                                                max_connections    = 0;
            uint16_t                                                                opened_connections = 0;

            std::atomic<uint32_t>                                                   rx_ack_            = 0;
            std::atomic<uint32_t>                                                   tx_seq_            = 0;
                       
            volatile uint64_t                                                       last_              = 0;
            uint64_t                                                                last_heartbeat_    = 0;
        }                                                                           status_;

        SynchronizationObject                                                       syncobj_;
        vmux_skt_map                                                                skts_;
        StrandPtr                                                                   strand_;
        ContextPtr                                                                  context_;

        tx_packet_ssqueue                                                           tx_queue_;
        rx_packet_ssqueue                                                           rx_queue_;

        vmux_linklayer_vector                                                       rx_links_;
        vmux_linklayer_list                                                         tx_links_;

        std::shared_ptr<boost::asio::ip::tcp::resolver>                             tx_resolver_;
    };
}