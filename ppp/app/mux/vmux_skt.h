#pragma once

#include "vmux.h"
#include "vmux_net.h"

namespace vmux {
    class vmux_skt final : public std::enable_shared_from_this<vmux_skt> {
        friend class                                    vmux_net;

        typedef std::shared_ptr<Byte>                   buffer_array_ptr;
        typedef vmux::list<buffer_array_ptr>            buffer_array_list;

        struct packet {
            std::shared_ptr<Byte>                       buffer;
            int                                         buffer_size = 0;
        };
        typedef vmux::list<packet>                      packet_queue;

    public:
        typedef ppp::function<void(vmux_skt*, bool)>    ConnectAsynchronousCallback;
        typedef ConnectAsynchronousCallback             ActiveEventHandler;
        typedef ConnectAsynchronousCallback             SendAsynchronousCallback;

    public:
        ActiveEventHandler                              active_event;

    public:
        vmux_skt(const std::shared_ptr<vmux_net>& mux, uint32_t connection_id) noexcept;
        ~vmux_skt() noexcept;

    public:
        void                                            close() noexcept;
        bool                                            is_disposed() noexcept { return status_.disposed_; }
        bool                                            is_connected() noexcept { return !status_.disposed_ && status_.connected_; }
        bool                                            run() noexcept;
        bool                                            send_to_peer(const void* packet, int packet_length, ppp::coroutines::YieldContext& y) noexcept;

    private:
        void                                            finalize() noexcept;

        bool                                            accept(const template_string& host, int port) noexcept;
        bool                                            accept(const template_string& host_and_port) noexcept;
        bool                                            connect(const template_string& host, int port, const ConnectAsynchronousCallback& ac) noexcept;
        bool                                            connect_ok() noexcept;

        bool                                            input(Byte* payload, int payload_size) noexcept;
        bool                                            send_to_peer(const void* packet, int packet_length, const SendAsynchronousCallback& ac) noexcept;
        
        void                                            active(uint64_t now) noexcept;
        void                                            active() noexcept {
            uint64_t now = mux_->now_tick();
            active(now);
        }

        void                                            on_connected(bool ok) noexcept;

        bool                                            forward_to_tx_socket(const std::shared_ptr<Byte>& payload, int payload_size) noexcept;
        bool                                            forward_to_rx_socket() noexcept;

    private:
        struct vmux_status {
            bool                                        disposed_  : 1;
            bool                                        connected_ : 1;
            bool                                        fin_       : 1;
            bool                                        forwarding : 1;
            bool                                        sending_   : 4;
        }                                               status_;

#if defined(_WIN32)
        std::shared_ptr<ppp::net::QoSS>                 qoss_;
#endif

        std::shared_ptr<vmux_net>                       mux_;
        volatile uint64_t                               last_          = 0;
        uint32_t                                        connection_id_ = 0;

        packet_queue                                    rx_queue_;
        std::shared_ptr<boost::asio::ip::tcp::socket>   tx_socket_;
        std::shared_ptr<Byte>                           tx_buffer_;

        ConnectAsynchronousCallback                     connect_ac_;
    };
}