// SPDX-License-Identifier: GPL-3.0-only

/**
 * @file VirtualEthernetLogger.h
 * @brief Structured JSON event logger for virtual Ethernet sessions.
 */

#pragma once

#include <ppp/stdafx.h>
#include <ppp/Int128.h>
#include <ppp/transmissions/ITransmission.h>
#include <ppp/threading/BufferswapAllocator.h>

namespace ppp {
    namespace app {
        namespace protocol {
            /**
             * @brief Writes protocol/session/network events into rotating log files.
             */
            class VirtualEthernetLogger : public std::enable_shared_from_this<VirtualEthernetLogger> {
            public:
                /** @brief Packet flow direction used by packet telemetry records. */
                enum class PacketDirection : Byte {
                    ClientToServer,
                    ServerToClient,
                    ServerToUplink,
                    UplinkToServer,
                };

            public:
                /**
                 * @brief Constructs a logger bound to an IO context and log path.
                 * @param context IO context used for serialized write scheduling.
                 * @param log_path Target log file path.
                 */
                VirtualEthernetLogger(const std::shared_ptr<boost::asio::io_context>& context, const ppp::string& log_path) noexcept;
                /** @brief Destroys the logger and flushes pending lines. */
                virtual ~VirtualEthernetLogger() noexcept;

            public:
                /** @brief Optional allocator used when copying caller-owned buffers. */
                std::shared_ptr<ppp::threading::BufferswapAllocator>            BufferAllocator;

            public:
                /** @brief Returns logger IO context. */
                std::shared_ptr<boost::asio::io_context>                        GetContext()   noexcept { return log_context_; }
                /** @brief Returns absolute path of active log file. */
                ppp::string                                                     GetPath()      noexcept { return log_path_; }
                /** @brief Returns `shared_from_this()` for this logger. */
                std::shared_ptr<VirtualEthernetLogger>                          GetReference() noexcept { return shared_from_this(); }
                /** @brief Returns true when logger is ready to accept writes. */
                bool                                                            Valid()        noexcept;
                /** @brief Asynchronously finalizes logger resources. */
                virtual void                                                    Dispose()      noexcept;

            public:
                /** @brief Logs a VPN session-open event. */
                bool                                                            Vpn(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission) noexcept;
                /** @brief Logs a DNS routing/lookup event. */
                bool                                                            Dns(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const ppp::string& hostDomain) noexcept;
                /** @brief Logs ARP-style network assignment event with raw v4 values. */
                bool                                                            Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, uint32_t ip, uint32_t mask) noexcept;
                /** @brief Logs ARP-style network assignment event with address objects. */
                bool                                                            Arp(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::address& ip, const boost::asio::ip::address& mask) noexcept;
                /** @brief Logs UDP mapping tuple (in/nat). */
                bool                                                            Port(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::udp::endpoint& inEP, const boost::asio::ip::udp::endpoint& natEP) noexcept;
                /** @brief Logs TCP connect metadata for mapped flow. */
                bool                                                            Connect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& natEP, const boost::asio::ip::tcp::endpoint& dstEP, const ppp::string& hostDomain) noexcept;

            public:
                /** @brief Logs mapping entry registration event. */
                bool                                                            MPEntry(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, bool protocol_tcp_or_udp) noexcept;
                /** @brief Logs mapping-side TCP connect event. */
                bool                                                            MPConnect(Int128 guid, const std::shared_ptr<ppp::transmissions::ITransmission>& transmission, const boost::asio::ip::tcp::endpoint& publicEP, const boost::asio::ip::tcp::endpoint& remoteEP) noexcept;
                /** @brief Logs packet telemetry with lightweight decode metadata. */
                bool                                                            Packet(Int128 guid, const void* packet, int packet_length, PacketDirection direction) noexcept;
                
            public:
                /** @brief Queues raw bytes as one log line. */
                bool                                                            Write(const void* s, int length, const ppp::function<void(bool)>& cb) noexcept;
                /** @brief Queues owned bytes as one log line. */
                virtual bool                                                    Write(const std::shared_ptr<Byte>& s, int length, const ppp::function<void(bool)>& cb) noexcept;

            private:
                /** @brief Opens or reopens the active log file handle. */
                bool                                                            OpenLogFile() noexcept;
                /** @brief Rotates or opens file before writing incoming bytes. */
                bool                                                            EnsureLogFile(std::size_t incoming_bytes) noexcept;
                /** @brief Pushes one line into bounded pending queue. */
                bool                                                            EnqueueLine(ppp::string line) noexcept;
                /** @brief Flushes all pending lines to disk. */
                void                                                            FlushPending() noexcept;
                /** @brief Rotates current log file into dated archive name. */
                void                                                            RotateLogFile(int day_key) noexcept;
                /** @brief Deletes old archive files outside retention window. */
                void                                                            CleanupArchives() noexcept;
                /** @brief Final synchronous cleanup routine. */
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
