#include "vmux.h"
#include "vmux_net.h"
#include "vmux_skt.h"

#include "ppp/app/client/VEthernetNetworkTcpipConnection.h"
#include "ppp/app/server/VirtualEthernetNetworkTcpipConnection.h"
#include "ppp/collections/Dictionary.h"

namespace vmux {
    vmux_net::vmux_net(const ContextPtr& context, const StrandPtr strand, uint16_t max_connections, vmux_fast_mode fast, bool server_mode) noexcept {
        Vlan = 0;

        base_.server_or_client_ = server_mode;
        base_.disposed_ = false;
        base_.ftt_ = false;
        base_.fast_ = fast;
        base_.established_ = false;
        
        status_.max_connections = max_connections;
        status_.opened_connections = 0;

        status_.rx_ack_ = 0;
        status_.tx_seq_ = 0;

        uint64_t now = now_tick();
        status_.last_ = now;
        status_.last_heartbeat_ = now;

        strand_ = strand;
        context_ = context;

        assert(max_connections > 0 && "The value of max_connections must be greater than 0.");
    }

    vmux_net::~vmux_net() noexcept {
        finalize();
    }

    void vmux_net::finalize() noexcept {
        using Thread = ppp::threading::Thread;

        vmux_linklayer_vector rx_links;
        tx_packet_ssqueue tx_queue;
        rx_packet_ssqueue rx_queue;
        vmux_skt_map skts;
        std::shared_ptr<boost::asio::ip::tcp::resolver> tx_resolver;

        bool disposing = false;
        for (;;) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (!base_.disposed_) {
                disposing = true;
                base_.disposed_ = true;
            }

            rx_links = std::move(rx_links_);
            tx_queue = std::move(tx_queue_);
            rx_queue = std::move(rx_queue_);

            tx_resolver = std::move(tx_resolver_);
            tx_resolver_.reset();

            skts = std::move(skts_);
            skts_.clear();

            tx_queue_.clear();
            rx_queue_.clear();
            rx_links_.clear();
            tx_links_.clear();
            break;
        }

        for (const std::pair<uint32_t, vmux_skt_ptr>& kv : skts) {
            const vmux_skt_ptr& skt = kv.second;
            skt->close(); // There is no need to send any data because the underlying link will be interrupted.
        }

        for (vmux_linklayer_ptr& linklayer : rx_links) {
            VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
            connection->Dispose();

            if (auto server = linklayer->server; NULL != server) {
                server->Dispose();
                linklayer->server.reset();
            }
        }

        if (disposing) {
            Thread::MemoryBarrier();
            for (;;) {
                status_.last_ = now_tick(); 
                break;
            }
            Thread::MemoryBarrier();
        }

        if (NULL != tx_resolver) {
            boost::asio::dispatch(tx_resolver->get_executor(),
                [tx_resolver]() noexcept {
                    try {
                        tx_resolver->cancel();
                    }
                    catch (const std::exception&) {}
                });
        }
    }

    bool vmux_net::init(const std::shared_ptr<boost::asio::ip::tcp::resolver>& resolver) noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_) {
            return false;
        }

        if (NULL != resolver) {
            tx_resolver_ = resolver;
        }
        else if (NULL != strand_) {
            tx_resolver_ = ppp::make_shared_object<boost::asio::ip::tcp::resolver>(*strand_);
        }
        else {
            tx_resolver_ = ppp::make_shared_object<boost::asio::ip::tcp::resolver>(*context_);
        }

        return NULL != tx_resolver_;
    }

    vmux_net::VirtualEthernetTcpipConnectionPtr vmux_net::get_linklayer() noexcept {
        vmux_linklayer_vector::iterator tail = rx_links_.begin();
        vmux_linklayer_vector::iterator endl = rx_links_.end();
        return tail != endl ? (*tail)->connection : NULL;
    }

    bool vmux_net::ftt(uint32_t seq, uint32_t ack) noexcept {
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_) {
            return false;
        }
        elif(!base_.ftt_) {
            ppp::threading::Thread::MemoryBarrier();
            for (;;) {
                base_.ftt_ = true;
                status_.tx_seq_ = seq;
                status_.rx_ack_ = ack;
                break;
            }
            ppp::threading::Thread::MemoryBarrier();
        }

        return (status_.tx_seq_ == seq) && (status_.rx_ack_ == ack);
    }

    uint32_t vmux_net::ftt_random_aid(int min, int max) noexcept {
        int a = ppp::RandomNext();
        int b = a & 1;
        if (b != 0) {
            return (uint32_t)-ppp::RandomNext(min, max);
        }
        else {
            return (uint32_t)ppp::RandomNext(min, max);
        }
    }

    void vmux_net::close_exec() noexcept {
        std::shared_ptr<vmux_net> self = shared_from_this();
        vmux_post_exec(context_, strand_,
            [self, this]() noexcept {
                finalize();
            });
    }

    static bool transmission_write(
        std::shared_ptr<vmux_net>                                           self,
        const vmux_net::ITransmissionPtr&                                   transmission, 
        const std::shared_ptr<Byte>&                                        packet, 
        int                                                                 packet_length,
        const ppp::transmissions::ITransmission::AsynchronousWriteCallback& ac) noexcept {
        
        using vmux_atomic_boolean = std::atomic<bool>;

        std::shared_ptr<vmux_atomic_boolean> initiate = ppp::make_shared_object<vmux_atomic_boolean>(false);
        if (NULL == initiate) {
            return false;
        }

        const ppp::function<void(bool)> on_completely = 
            [self, ac, initiate](bool successed) noexcept {
                if (initiate->exchange(true)) {
                    return false;
                }

                bool forwarding = 
                    vmux_post_exec(self->get_context(), self->get_strand(), 
                        [self, successed, ac]() noexcept {
                            ac(successed);
                        });

                if (forwarding) {
                    return true;
                }
                else {
                    ac(false);
                    self->close_exec();
                    return false;
                }
            };

        return vmux_post_exec(transmission->GetContext(), transmission->GetStrand(),
            [self, transmission, packet, packet_length, on_completely]() noexcept {
                bool forwarding = 
                    transmission->Write(packet.get(), packet_length,
                        [self, on_completely](bool ok) noexcept {
                            on_completely(ok);
                        });

                if (!forwarding) {
                    on_completely(false);
                }
            });
    }

    bool vmux_net::underlyin_sent(const vmux_linklayer_ptr& linklayer, const std::shared_ptr<Byte>& packet, int packet_length, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULL == packet || packet_length < sizeof(vmux_hdr)) {
            return false;
        }
        
        if (base_.disposed_) {
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
        if (!connection->IsLinked()) {
            return false;
        }

        ITransmissionPtr transmission = connection->GetTransmission();
        if (NULL == transmission) {
            return false;
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        return transmission_write(self, transmission, packet, packet_length, 
            [self, this, linklayer, posted_ac](bool ok) noexcept {
                if (NULL != posted_ac) {
                    posted_ac(ok);
                }

                if (ok) {
                    active();
                    linklayer_update(linklayer);
                    
                    vmux_net::tx_packet packet{ NULL, -1 };
                    for (;;) {
                        SynchronizationObjectScope __SCOPE__(syncobj_);
                        auto packet_tail = tx_queue_.begin();
                        auto packet_endl = tx_queue_.end();
                        if (packet_tail == packet_endl) {
                            tx_links_.emplace_back(linklayer);
                        }
                        else {
                            packet = *packet_tail;
                            tx_queue_.erase(packet_tail);
                        }

                        break;
                    }

                    if (packet.length > -1) {
                        ok = underlyin_sent(linklayer, packet.buffer, packet.length, packet.ac);
                    }
                }

                if (!ok) {
                    close_exec();
                }
            });
    }

    bool vmux_net::update() noexcept {
        if (base_.disposed_) {
            return false;
        }

        std::shared_ptr<vmux_net> self = shared_from_this();
        return vmux_post_exec(context_, strand_,
            [self, this]() noexcept {
                uint64_t max_inactive_timeout_zw = ((uint64_t)AppConfiguration->tcp.inactive.timeout) * 1000ULL;
                uint64_t max_connect_timeout = ((uint64_t)AppConfiguration->tcp.connect.timeout) * 1000ULL;
                uint64_t max_inactive_timeout = std::min<uint64_t>(max_connect_timeout << 1, max_inactive_timeout_zw);

                uint64_t now = now_tick();
                if (base_.established_) {
                    list<vmux_skt_ptr> release_skts;
                    for (;;) {
                        SynchronizationObjectScope __SCOPE__(syncobj_);
                        for (const std::pair<uint32_t, vmux_skt_ptr>& kv : skts_) {
                            bool is_port_aging = false;
                            const vmux_skt_ptr& skt = kv.second;

                            uint64_t delta_time = now - skt->last_;
                            if (skt->status_.connected_) {
                                is_port_aging = delta_time >= max_inactive_timeout_zw;
                            }
                            else {
                                is_port_aging = delta_time >= max_connect_timeout;
                            }

                            if (is_port_aging) {
                                release_skts.emplace_back(skt);
                            }
                        }

                        break;
                    }

                    for (vmux_skt_ptr& skt : release_skts) {
                        skt->close();
                    }
                }

                uint64_t delta_time = now - status_.last_;
                if (delta_time >= (base_.established_ ? max_inactive_timeout : max_connect_timeout)) {
                    close_exec();
                    return false;
                }
                else if (base_.established_) {
                    if ((now - status_.last_heartbeat_) >= max_connect_timeout) {
                        if (post(cmd_keep_alived, NULL, 0, ftt_random_aid(1, INT32_MAX))) {
                            status_.last_heartbeat_ = now;
                        }
                    }
                }

                return true;
            });
    }

    struct vmux_net::vmux_frame {
        rx_packet   packet;
        vmux_hdr*   h;
    };

    static constexpr int VMUX_MAX_FRAME_COUNT = 64;

    bool vmux_net::packet_input_acked(const vmux_linklayer_ptr& linklayer, vmux_frame* frames, int frame_count, uint64_t now) noexcept {
        for (int i = 0; i < frame_count; i++) {
            vmux_frame& frame = frames[i];
            vmux_hdr* h = frame.h;
            if (!packet_input(h->cmd, (Byte*)h, frame.packet.length, now)) {
                close_exec();
                return false;
            }
        }

        return true;
    }

    bool vmux_net::packet_input_acking(vmux_frame* frames, int& frame_count) noexcept {
        for (;;) {
            if (frame_count >= VMUX_MAX_FRAME_COUNT) {
                return true;
            }

            rx_packet_ssqueue::iterator packet_tail = rx_queue_.begin();
            rx_packet_ssqueue::iterator packet_endl = rx_queue_.end();
            if (packet_tail != packet_endl && status_.rx_ack_ == packet_tail->first) {
                rx_packet& packet = packet_tail->second;
                frames[frame_count++] = 
                    vmux_frame{ packet, (vmux_hdr*)packet.buffer.get() };

                status_.rx_ack_++;
                rx_queue_.erase(packet_tail);
            }
            else {
                return false;
            }
        }
    }

    bool vmux_net::packet_input_unorder(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept {
        // Prepare the ack frames.
        vmux_frame frames[VMUX_MAX_FRAME_COUNT];
        int frame_count = 0;
        bool frame_nexting = false;

        for (uint32_t seq = ntohl(h->seq);;) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (base_.disposed_) {
                return false;
            }

            if (status_.rx_ack_ == seq) {
                status_.rx_ack_++;
                frames[frame_count++] = vmux_frame{ rx_packet{ NULL, length }, h };
                frame_nexting = packet_input_acking(frames, frame_count);
                break;
            }
            else if (packet_less<uint32_t>::after(seq, status_.rx_ack_)) {
                std::shared_ptr<Byte> buf = make_byte_array(length);
                if (NULL == buf) {
                    return false;
                }

                rx_packet packet = { buf, length };
                memcpy(buf.get(), h, length);

                return rx_queue_.emplace(std::make_pair(seq, packet)).second;
            }
            else {
                return false;
            }
        }

        // Process the acked frames.
        for (;;) {
            if (packet_input_acked(linklayer, frames, frame_count, now) && frame_nexting) {
                SynchronizationObjectScope __SCOPE__(syncobj_);
                if (!base_.disposed_) {
                    frame_count = 0;
                    if (packet_input_acking(frames, frame_count)) {
                        continue;
                    }
                }
                else {
                    return false;
                }
            }

            return true;
        }
    }

    bool vmux_net::packet_input(Byte cmd, Byte* buffer, int buffer_size, uint64_t now) noexcept {
        buffer_size -= sizeof(vmux_hdr);
        if (buffer_size < 0) {
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)buffer;
        buffer = (Byte*)(h + 1);

        uint32_t connection_id = ntohl(h->connection_id);
        if (cmd == cmd_push) {
        LABEL_READ:
            vmux_skt_ptr skt = get_connection(connection_id);
            if (NULL != skt) {
                if (skt->input(buffer, buffer_size)) {
                    skt->active(now);
                }
                else {
                    skt->close();
                }
            }
        }
        else if (cmd == cmd_fin) {
            cmd = cmd_push;
            buffer_size = 0;
            goto LABEL_READ;
        }
        else if (cmd == cmd_syn) {
            std::shared_ptr<vmux_skt> sk;
            bool successed = process_rx_connecting(sk, connection_id, (char*)buffer, buffer_size);

            if (NULL != sk) {
                if (successed) {
                    sk->active(now);
                }
                else {
                    sk->close();
                }
            }
        }
        else if (cmd == cmd_syn_ok) {
            vmux_skt_ptr skt = get_connection(connection_id);
            if (NULL != skt) {
                bool successed = false;
                if (buffer_size > 0) {
                    const Byte err = *buffer;
                    if (err == 'A') {
                        successed = skt->connect_ok();
                    }
                    else {
                        skt->status_.fin_ = true;
                    }
                }

                if (successed) {
                    skt->active(now);
                }
                else {
                    skt->close();
                }
            }
        }
        else if (cmd == cmd_keep_alived) {
            active(now);
        }
        else if (cmd == cmd_fast) {
            if (buffer_size > 0) {
                if (base_.fast_ == vmux_fast_mode_auto) {
                    base_.fast_ = (vmux_fast_mode)*buffer;
                }

                active(now);
            }
        }
        else {
            return false;
        }

        return true;
    }
    
    bool vmux_net::process_rx_connecting(std::shared_ptr<vmux_skt>& skt, uint32_t connection_id, const char* host, int host_size) noexcept {
        for (;;) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (base_.disposed_) {
                return false;;
            }

            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
                if (NULL != skt) {
                    return false;
                }
            }

            std::shared_ptr<vmux_net> self = shared_from_this();
            skt = ppp::make_shared_object<vmux_skt>(self, connection_id);

            if (NULL == skt) {
                return false;
            }

            skts_[connection_id] = skt;
            break;
        }

        if (skt->accept(template_string(host, host_size))) {
            return true;
        }
        else {
            return false;
        }
    }

    uint32_t vmux_net::generate_id() noexcept {
        static std::atomic<uint32_t> aid = ftt_random_aid(1, INT32_MAX);

        for (;;) {
            uint32_t n = ++aid;
            if (n != 0) {
                return n;
            }
        }
    }

    vmux_net::vmux_skt_ptr vmux_net::get_connection(uint32_t connection_id) noexcept {
        vmux_skt_ptr skt;
        if (connection_id != 0) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
            }
        }

        return skt;
    }

    vmux_net::vmux_skt_ptr vmux_net::release_connection(uint32_t connection_id, vmux_skt* refer_pointer) noexcept {
        vmux_skt_ptr skt;
        if (connection_id != 0) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            vmux_skt_map::iterator tail = skts_.find(connection_id);
            vmux_skt_map::iterator endl = skts_.end();
            if (tail != endl) {
                skt = tail->second;
                if (skt.get() == refer_pointer) {
                    skts_.erase(tail);
                }
            }
        }

        return skt;
    }

    bool vmux_net::post_internal(const std::shared_ptr<Byte>& packet, int packet_length, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULL == packet || packet_length < sizeof(vmux_hdr)) {
            return false;
        }
        
        SynchronizationObjectScope __SCOPE__(syncobj_);
        if (base_.disposed_ || !base_.established_) {
            return false;
        }

        vmux_hdr* h = (vmux_hdr*)packet.get();
        h->seq = htonl(status_.tx_seq_++);

        vmux_linklayer_list::iterator linklayer_tail = tx_links_.begin();
        vmux_linklayer_list::iterator linklayer_endl = tx_links_.end();
        if (linklayer_tail != linklayer_endl) {
            if (base_.server_or_client_) {
                tx_queue_.emplace_back(tx_packet{ packet, packet_length }); 
                if (NULL != posted_ac) {
                    bool posted = ppp::threading::Executors::Post(context_, strand_, 
                        [posted_ac]() noexcept {
                            posted_ac(true);
                        });
                    if (!posted) {
                        return false;
                    }
                }
            }
            else {
                tx_queue_.emplace_back(tx_packet{ packet, packet_length, posted_ac });
            }

            return process_tx_all_packets();
        }
        else {
            tx_queue_.emplace_back(tx_packet{ packet, packet_length, posted_ac });
            return true;
        }
    }

    bool vmux_net::process_tx_all_packets() noexcept {
        vmux_linklayer_list::iterator linklayer_tail = tx_links_.begin();
        vmux_linklayer_list::iterator linklayer_endl = tx_links_.end();
        while (linklayer_tail != linklayer_endl) {
            tx_packet_ssqueue::iterator packet_tail = tx_queue_.begin();
            tx_packet_ssqueue::iterator packet_endl = tx_queue_.end();
            if (packet_tail == packet_endl) {
                break;
            }

            vmux_linklayer_ptr linklayer = *linklayer_tail;
            tx_links_.erase(linklayer_tail);

            tx_packet nexting_packet = *packet_tail;
            tx_queue_.erase(packet_tail);

            bool forwarding = underlyin_sent(linklayer, nexting_packet.buffer, nexting_packet.length, nexting_packet.ac);
            if (!forwarding) {
                return false;
            }
        }

        return true;
    }

    bool vmux_net::post_internal(Byte cmd, const void* buffer, int buffer_size, uint32_t connection_id, const PostInternalAsynchronousCallback& posted_ac) noexcept {
        if (NULL != buffer && buffer_size < 0) {
            return false;
        }

        if (base_.disposed_ || !base_.established_) {
            return false;
        }

        int packet_length = sizeof(vmux_hdr) + buffer_size;
        std::shared_ptr<Byte> packet_managed = make_byte_array(packet_length);

        if (NULL == packet_managed) {
            return false;
        }

        Byte* packet_memory = packet_managed.get();
        if (NULL != buffer) {
            memcpy(packet_memory + sizeof(vmux_hdr), buffer, buffer_size);
        }

        vmux_hdr* h = (vmux_hdr*)packet_memory;
        h->cmd = cmd;
        h->connection_id = htonl(connection_id);
        
        return post_internal(packet_managed, packet_length, posted_ac);
    }

    bool vmux_net::add_linklayer(const VirtualEthernetTcpipConnectionPtr& connection, vmux_linklayer_ptr& linklayer, const vmux_native_add_linklayer_after_success_before_callback& cb) noexcept {
        if (base_.disposed_ || NULL == connection) {
            return false;
        }
        else {
            bool unlimited = false;
            if (!connection->IsLinked()) {
                return false;
            }
            else {
                SynchronizationObjectScope __SCOPE__(syncobj_);
                if (rx_links_.size() >= status_.max_connections) {
                    return false;
                }

                linklayer = ppp::make_shared_object<vmux_linklayer>();
                if (NULL == linklayer) {
                    return false;
                }

                std::shared_ptr<Byte> buffer = make_byte_array(max_buffers_size);
                if (NULL == buffer) {
                    return false;
                }

                linklayer->connection = connection;
                tx_links_.emplace_back(linklayer);
                rx_links_.emplace_back(linklayer);

                unlimited = rx_links_.size() < status_.max_connections;
            }

            if (unlimited) {
                if (NULL != cb && !cb()) {
                    return false;
                }

                return true;
            }
            elif(NULL != cb && !cb()) {
                return false;
            }
        }

        uint64_t now = now_tick();
        active(now);

        std::shared_ptr<vmux_net> self = shared_from_this();
        for (vmux_linklayer_ptr& linklayer : rx_links_) {
            uint16_t connection_id = 0;
            if (base_.server_or_client_) {
                SynchronizationObjectScope __SCOPE__(syncobj_);
                connection_id = ++status_.opened_connections;
            }

            auto process =
                [self, this, linklayer, connection_id](ppp::coroutines::YieldContext& y) noexcept {
                    if (handshake(linklayer, connection_id, y)) {
                        forwarding(linklayer, y);
                    }

                    close_exec();
                };

            ContextPtr connection_context = linklayer->connection->GetContext();
            StrandPtr connection_strand = linklayer->connection->GetStrand();
            if (!ppp::coroutines::YieldContext::Spawn(BufferAllocator.get(), *connection_context, connection_strand.get(), process)) {
                return false;
            }

            linklayer_update(linklayer);
        }

        return true;
    }

    bool vmux_net::handshake(const vmux_linklayer_ptr& linklayer, uint16_t connection_id, ppp::coroutines::YieldContext& y) noexcept {
        if (base_.disposed_) {
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULL == linklayer_transmission) {
            return false;
        }

#pragma pack(push, 1)
        typedef struct {
            uint16_t receive_id;
        } vmux_linlayer_add_ack_packet;
#pragma pack(pop)

        if (base_.server_or_client_) {
            vmux_linlayer_add_ack_packet packet;
            packet.receive_id = htons(connection_id);

            if (!linklayer_transmission->Write(y, &packet, sizeof(vmux_linlayer_add_ack_packet))) {
                return false;
            }
        }
        else {
            int buffer_size = 0;
            std::shared_ptr<Byte> packet_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULL == packet_memory || buffer_size < sizeof(vmux_linlayer_add_ack_packet)) {
                return false;
            }

            vmux_linlayer_add_ack_packet* packet = (vmux_linlayer_add_ack_packet*)packet_memory.get();
            uint32_t receive_id = ntohs(packet->receive_id);

            if (receive_id == 0 && receive_id <= rx_links_.size()) {
                return false;
            }
            else {
                SynchronizationObjectScope __SCOPE__(syncobj_);
                status_.opened_connections++;
            }
        }

        linklayer_established();
        return true;
    }

    void vmux_net::linklayer_established() noexcept {
        using Thread = ppp::threading::Thread;

        bool established = false;
        do {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            Thread::MemoryBarrier();
            if (!base_.established_) {
                established = status_.opened_connections >= status_.max_connections;
                base_.established_ = established;
            }

            Thread::MemoryBarrier();
        } while (false);

        while (established) {
            if (!base_.server_or_client_ && base_.fast_ != vmux_fast_mode_none) {
                Byte fast_mode = (Byte)vmux_fast_mode_must;
                if (post(cmd_fast, &fast_mode, sizeof(fast_mode), ftt_random_aid(1, INT32_MAX))) {
                    base_.fast_ = vmux_fast_mode_must;
                }
                else {
                    close_exec();
                    break;
                }
            }

            uint64_t now = now_tick();
            active(now);
            status_.last_heartbeat_ = now;
            break;
        }
    }

    bool vmux_net::forwarding(const vmux_linklayer_ptr& linklayer, ppp::coroutines::YieldContext& y) noexcept {
        if (base_.disposed_) {
            return false;
        }

        VirtualEthernetTcpipConnectionPtr& linklayer_socket = linklayer->connection;
        if (!linklayer_socket->IsLinked()) {
            return false;
        }

        ITransmissionPtr linklayer_transmission = linklayer_socket->GetTransmission();
        if (NULL == linklayer_transmission) {
            return false;
        }

        int buffer_size = 0;
        boost::system::error_code ec;

        bool any = false;
        std::shared_ptr<vmux_net> self = shared_from_this();

        linklayer_update(linklayer);
        for (;;) {
            if (base_.disposed_) {
                break;
            }

            if (!linklayer_socket->IsLinked()) {
                break;
            }

            std::shared_ptr<Byte> buffer_memory = linklayer_transmission->Read(y, buffer_size);
            if (NULL == buffer_memory || buffer_size < sizeof(vmux_hdr)) {
                break;
            }

            vmux_hdr* h = (vmux_hdr*)buffer_memory.get();
            Byte cmd = h->cmd;
            if (cmd <= cmd_none || cmd >= cmd_max) {
                break;
            }

            any |= vmux_post_exec(context_, strand_,
                [self, this, linklayer, buffer_memory, h, buffer_size]() noexcept {
                    if (base_.disposed_) {
                        return false;
                    }

                    uint64_t now = now_tick();
                    if (status_.max_connections == 1) {
                        if (packet_input_single(linklayer, h, buffer_size, now)) {
                            active(now);
                            linklayer_update(linklayer);
                            return true;
                        }
                    }
                    else if (packet_input_unorder(linklayer, h, buffer_size, now)) {
                        active(now);
                        linklayer_update(linklayer);
                        return true;
                    }
                    
                    close_exec();
                    return false;
                });
        }
        
        return any;
    }

    bool vmux_net::packet_input_single(const vmux_linklayer_ptr& linklayer, vmux_hdr* h, int length, uint64_t now) noexcept {
        for (;;) {
            SynchronizationObjectScope __SCOPE__(syncobj_);
            if (base_.disposed_) {
                return false;
            }

            status_.rx_ack_++;
            break;
        }

        return packet_input(h->cmd, (Byte*)h, length, now);
    }

    void vmux_net::linklayer_update(const vmux_linklayer_ptr& linklayer) noexcept {
        VirtualEthernetTcpipConnectionPtr& connection = linklayer->connection;
        if (connection->IsLinked()) {
            connection->Update();
        }
    }

    bool vmux_net::connect_require(
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string& host,
        int port) noexcept {

        if (base_.disposed_ || !base_.established_) {
            return false;
        }

        if (host.empty() || port <= 0 || port > UINT16_MAX) {
            return false;
        }

        if (NULL == sk) {
            return false;
        }

        return true;
    }

    bool vmux_net::connect_safe(
        ppp::coroutines::YieldContext& y,
        const std::shared_ptr<boost::asio::ip::tcp::socket>& sk,
        const template_string& host,
        int port,
        vmux_skt_ptr& return_connection) noexcept {

        if (!connect_require(sk, host, port) || !y) {
            return false;
        }

        bool ok = false;
        bool posted = vmux_post_exec(context_, strand_,
            [this, &sk, &host, &port, &ok, &y, &return_connection]() noexcept {
                ok = connect(sk, host, port,
                    [&](vmux_skt* sender, bool success) noexcept {
                        ok = success;
                        if (ok) {
                            return_connection = sender->shared_from_this();
                        }

                        y.R();
                    });

                if (!ok) {
                    y.R();
                }
            });

        if (posted) {
            bool suspend = y.Suspend();
            if (suspend) {
                return ok;
            }
        }

        return false;
    }

    bool vmux_net::connect(const std::shared_ptr<boost::asio::ip::tcp::socket>& sk, const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept {
        if (!connect_require(sk, host, port)) {
            return false;
        }

        vmux_skt_ptr skt;
        std::shared_ptr<vmux_net> self = shared_from_this();

        for (;;) {
            uint32_t connection_id = generate_id();
            if (connection_id == 0) {
                continue;
            }

            SynchronizationObjectScope __SCOPE__(syncobj_);
            vmux_skt_map::iterator skt_tail = skts_.find(connection_id);
            vmux_skt_map::iterator skt_endl = skts_.end();
            if (skt_tail != skt_endl) {
                continue;
            }

            skt = ppp::make_shared_object<vmux_skt>(self, connection_id);
            if (NULL == skt) {
                return false;
            }

            skt->tx_socket_ = sk;
            skts_[connection_id] = skt;
            break;
        }

        if (skt->connect(host, port, ac)) {
            return true;
        }

        skt->close();
        return false;
    }

    void vmux_net::await_initiate_after_yield_coroutine(ppp::coroutines::YieldContext& y, std::atomic<int>& initiate) noexcept {
        int status = initiate.load();
        if (status > -1) {
            y.R();
        }
        else {
            boost::asio::io_context& context = y.GetContext();
            ppp::threading::Executors::Post(&context, y.GetStrand(),
                [&y, &initiate]() noexcept -> void {
                    await_initiate_after_yield_coroutine(y, initiate);
                });
        }
    }
}