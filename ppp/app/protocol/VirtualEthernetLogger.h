#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace app {
        namespace protocol {
            class VirtualEthernetLogger : public std::enable_shared_from_this<VirtualEthernetLogger> {
            public:
                enum class PacketDirection : Byte {
                    ClientToServer,
                    ServerToClient,
                    ServerToUplink,
                    UplinkToServer,
                };

            public:
                VirtualEthernetLogger(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& log_path) noexcept;
                virtual ~VirtualEthernetLogger() noexcept;

            public:
                std::shared_ptr<ppp::threading::BufferswapAllocator>            BufferAllocator;

            public:
                std::shared_ptr<boost::asio::io_context>                        GetContext()   noexcept { return log_context_; }
                ppp::string                                                     GetPath()      noexcept { return log_path_; }
                std::shared_ptr<VirtualEthernetLogger>                          GetReference() noexcept { return shared_from_this(); }
                bool                                                            Valid()        noexcept;
                virtual void                                                    Dispose()      noexcept;

            public:
                bool                                                            Vpn(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept;
                bool                                                            Dns(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const ppp::string& hostDomain) noexcept;
                bool                                                            Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, uint32_t ip, uint32_t mask) noexcept;
                bool                                                            Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept;
                bool                                                            Port(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::udp::endpoint& inEP, const boost::asio::ip::udp::endpoint& natEP) noexcept;
                bool                                                            Connect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& natEP, const boost::asio::ip::tcp::endpoint& dstEP, const ppp::string& hostDomain) noexcept;

            public:
                bool                                                            MPEntry(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, bool protocol_tcp_or_udp) noexcept;
                bool                                                            MPConnect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                bool                                                            Packet(Int128 guid, const void* packet, int packet_length, PacketDirection direction) noexcept;
                
            public:
                bool                                                            Write(const void* s, int length, const ppp::function<void(bool)>& cb) noexcept;
                virtual bool                                                    Write(const std::shared_ptr<Byte>& s, int length, const ppp::function<void(bool)>& cb) noexcept;

            private:
                bool                                                            OpenLogFile() noexcept;
                bool                                                            EnsureLogFile(std::size_t incoming_bytes) noexcept;
                bool                                                            EnqueueLine(ppp::string line) noexcept;
                void                                                            FlushPending() noexcept;
                void                                                            RotateLogFile(int day_key) noexcept;
                void                                                            CleanupArchives() noexcept;
                void                                                            Finalize() noexcept;

            private:
                FILE*                                                           log_file_ = NULLPTR;
                ppp::string                                                     log_path_;
                ppp::string                                                     log_directory_;
                ppp::string                                                     log_file_name_;
                std::shared_ptr<boost::asio::io_context>                        log_context_;
                std::shared_ptr<boost::asio::strand<boost::asio::io_context::executor_type>> log_strand_;
                std::size_t                                                     log_file_size_ = 0;
                int                                                             log_file_day_key_ = -1;
                bool                                                            flush_scheduled_ = false;
                std::list<ppp::string>                                          pending_lines_;
            };
        }
    }
}
