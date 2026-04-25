#include <ppp/app/server/VirtualEthernetDatagramPortStatic.h>
#include <ppp/app/server/VirtualEthernetDatagramPort.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/app/protocol/VirtualEthernetPacket.h>
#include <ppp/net/native/checksum.h>
#include <ppp/net/Socket.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/coroutines/asio/asio.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/diagnostics/Error.h>

/**
 * @file VirtualEthernetDatagramPort.cpp
 * @brief Implements dynamic UDP relay port behavior for virtual ethernet traffic.
 */

typedef ppp::coroutines::YieldContext                   YieldContext;
typedef ppp::net::IPEndPoint                            IPEndPoint;
typedef ppp::net::Socket                                Socket;
typedef ppp::net::Ipep                                  Ipep;
typedef ppp::app::protocol::VirtualEthernetPacket       VirtualEthernetPacket;

namespace ppp {
    namespace app {
        namespace server {
            /**
             * @brief Initializes relay state and acquires a reusable receive buffer.
             */
            VirtualEthernetDatagramPort::VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept
                : disposed_(false)
                , onlydns_(true)
                , sendto_(false)
                , in_(false)
                , finalize_(false)
                , timeout_(0)
                , context_(transmission->GetContext())
                , socket_(*context_)
                , exchanger_(exchanger)
                , transmission_(transmission)
                , configuration_(exchanger->GetConfiguration())
                , sourceEP_(sourceEP) {
                buffer_ = Executors::GetCachedBuffer(context_);
                Update();
            }

            /**
             * @brief Ensures asynchronous resources are finalized.
             */
            VirtualEthernetDatagramPort::~VirtualEthernetDatagramPort() noexcept {
                Finalize();
            }

            /**
             * @brief Closes socket, sends a close signal when needed, and unregisters this port.
             */
            void VirtualEthernetDatagramPort::Finalize() noexcept {
                std::shared_ptr<ITransmission> transmission = std::move(transmission_); 
                if (sendto_ && !finalize_) {
                    if (NULLPTR != transmission) {
                        if (!exchanger_->DoSendTo(transmission, sourceEP_, sourceEP_, NULLPTR, 0, nullof<YieldContext>())) {
                            transmission->Dispose();
                        }
                    }
                }

                disposed_ = true;
                sendto_ = false;
                finalize_ = true;
                Socket::Closesocket(socket_);

                exchanger_->ReleaseDatagramPort(sourceEP_);
            }

            /**
             * @brief Dispatches finalization to the owning io_context thread.
             */
            void VirtualEthernetDatagramPort::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            /**
             * @brief Opens and configures the UDP socket, then starts async receive loop.
             * @return True if opening and initialization succeed.
             */
            bool VirtualEthernetDatagramPort::Open() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket_.is_open();
                if (opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::VEthernetDatagramPortOpenSocketAlreadyOpen);
                    return false;
                }

                std::shared_ptr<VirtualEthernetSwitcher> switcher = exchanger_->GetSwitcher();
                boost::asio::ip::address address = switcher->GetInterfaceIP();

                bool success = VirtualEthernetPacket::OpenDatagramSocket(socket_, address, IPEndPoint::MinPort, sourceEP_) && Loopback();
                if (success) {
                    boost::system::error_code ec;
                    localEP_ = socket_.local_endpoint(ec);
                    if (ec) {
                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                        return false;
                    }

                    boost::asio::ip::address localIP = localEP_.address();
                    in_ = localIP.is_v4();

                    int handle = socket_.native_handle();
                    ppp::net::Socket::AdjustDefaultSocketOptional(handle, in_);
                    ppp::net::Socket::SetTypeOfService(handle);
                    ppp::net::Socket::SetSignalPipeline(handle, false);
                    ppp::net::Socket::ReuseSocketAddress(handle, true);
                    ppp::net::Socket::SetWindowSizeIfNotZero(handle, configuration_->udp.cwnd, configuration_->udp.rwnd);
                }

                return success;
            }

            /**
             * @brief Starts one asynchronous receive cycle for relay traffic.
             * @return True if receive operation is scheduled.
             */
            bool VirtualEthernetDatagramPort::Loopback() noexcept {
                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }

                auto self = shared_from_this();
                socket_.async_receive_from(boost::asio::buffer(buffer_.get(), PPP_BUFFER_SIZE), remoteEP_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        bool disposing = true;
                        /**
                         * @brief Handles one datagram and decides whether to continue loopback.
                         */
                        while (ec == boost::system::errc::success) {
                            int bytes_transferred = static_cast<int>(sz);
                            if (bytes_transferred < 1) {
                                disposing = false;
                                break;
                            }

                            if (configuration_->udp.dns.cache) {
                                int remotePort = remoteEP_.port();
                                if (remotePort == PPP_DNS_SYS_PORT) {
                                    NamespaceQuery(exchanger_->GetSwitcher(), buffer_.get(), bytes_transferred);
                                }
                            }

                            std::shared_ptr<ITransmission> transmission = transmission_;
                            if (NULLPTR == transmission) {
                                break;
                            }

                            boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(remoteEP_);
                            if (exchanger_->DoSendTo(transmission, sourceEP_, remoteEP, buffer_.get(), bytes_transferred, nullof<YieldContext>())) {
                                Update();
                                disposing = false;
                            }
                            else {
                                transmission_.reset();
                                transmission->Dispose();
                            }

                            break;
                        }

                        if (disposing) {
                            Dispose();
                        }
                        else {
                            Loopback();
                        }
                    });
                return true;
            }

            /**
             * @brief Parses DNS response and stores it into namespace cache.
             * @return True if DNS payload is accepted and cached.
             */
            bool VirtualEthernetDatagramPort::NamespaceQuery(
                const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                const void*                                         packet,
                int                                                 packet_length) noexcept {

                auto cache = switcher->GetNamespaceCache();
                if (NULLPTR == cache) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsCacheFailed);
                    return false;
                }

                uint16_t queries_type = 0;
                uint16_t queries_clazz = 0;
                ppp::string domain = ppp::net::native::dns::ExtractHostY((Byte*)packet, packet_length,
                    [&queries_type, &queries_clazz](ppp::net::native::dns::dns_hdr* h, ppp::string& domain, uint16_t type, uint16_t clazz) noexcept -> bool {
                        queries_type = type;
                        queries_clazz = clazz;
                        return true;
                    });

                if (domain.empty()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::DnsPacketInvalid);
                    return false;
                }

                std::shared_ptr<Byte> response = make_shared_alloc<Byte>(packet_length);
                if (NULLPTR == response) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
                    return false;
                }

                ppp::string queries_key = VirtualEthernetNamespaceCache::QueriesKey(queries_type, queries_clazz, domain);
                memcpy(response.get(), packet, packet_length);

                return cache->Add(queries_key, response, packet_length);
            }

            /**
             * @brief Tries to answer DNS query from cache via static or dynamic output path.
             * @return 1 if served, 0 if no cache hit, -1 if output path fails.
             */
            int VirtualEthernetDatagramPort::NamespaceQuery(
                const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                VirtualEthernetExchanger*                           exchanger, 
                const boost::asio::ip::udp::endpoint&               sourceEP,
                const boost::asio::ip::udp::endpoint&               destinationEP,
                const ppp::string&                                  domain,
                const void*                                         packet,
                int                                                 packet_length,
                uint16_t                                            queries_type,
                uint16_t                                            queries_clazz,
                bool                                                static_transit) noexcept { 
                
                using dns_hdr = ppp::net::native::dns::dns_hdr;

                if (NULLPTR != packet && packet_length >= sizeof(dns_hdr)) {
                    if (domain.size() > 0) {
                        auto cache = switcher->GetNamespaceCache();
                        if (NULLPTR != cache) {
                            std::shared_ptr<Byte> response;
                            int response_length;

                            ppp::string queries_key = VirtualEthernetNamespaceCache::QueriesKey(queries_type, queries_clazz, domain);
                            if (cache->Get(queries_key, response, response_length, ((dns_hdr*)packet)->usTransID)) {
                                std::shared_ptr<ITransmission> transmission = exchanger->GetTransmission();
                                if (NULLPTR != transmission) {
                                    boost::asio::ip::udp::endpoint remoteEP = Ipep::V6ToV4(destinationEP);
                                    if (static_transit) {
                                        bool outputed = VirtualEthernetDatagramPortStatic::Output(switcher.get(), 
                                            exchanger, response.get(), response_length, sourceEP, remoteEP);
                                        if (outputed) {
                                            return 1;
                                        }
                                        else {
                                            return -1;
                                        }
                                    }
                                    elif(exchanger->DoSendTo(transmission, sourceEP, remoteEP, response.get(), response_length, nullof<YieldContext>())) {
                                        return 1;
                                    }
                                    else {
                                        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpRelayFailed);
                                        transmission->Dispose();
                                        return -1;
                                    }
                                }
                            }
                        }
                    }
                }

                return 0;
            }

            /**
             * @brief Sends outbound UDP payload and refreshes aging timeout.
             * @return True on successful send.
             */
            bool VirtualEthernetDatagramPort::SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept {
                if (NULLPTR == packet || packet_length < 1) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpPacketInvalid);
                    return false;
                }

                if (disposed_) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SessionDisposed);
                    return false;
                }

                bool opened = socket_.is_open();
                if (!opened) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpOpenFailed);
                    return false;
                }

                int destinationPort = destinationEP.port();
                if (destinationPort <= IPEndPoint::MinPort || destinationPort > IPEndPoint::MaxPort) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPortInvalid);
                    return false;
                }

                boost::system::error_code ec;
                if (in_) {
                    socket_.send_to(boost::asio::buffer(packet, packet_length), 
                        Ipep::V6ToV4(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }
                else {
                    socket_.send_to(boost::asio::buffer(packet, packet_length), 
                        Ipep::V4ToV6(destinationEP), boost::asio::socket_base::message_end_of_record, ec);
                }

                if (ec) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::UdpSendFailed);
                    return false; // Failed to sendto the datagram packet. 
                }
                else {
                    // Succeeded in sending the datagram packet to the external network. 
                    sendto_ = true;
                    if (destinationPort != PPP_DNS_SYS_PORT) {
                        onlydns_ = false;
                    }

                    Update();
                    return true;
                }
            }
        }
    }
}
