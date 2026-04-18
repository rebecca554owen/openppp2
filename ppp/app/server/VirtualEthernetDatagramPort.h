#pragma once

/**
 * @file VirtualEthernetDatagramPort.h
 * @brief Datagram port abstraction used by the virtual ethernet exchanger.
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITransmission.h>

namespace ppp {
    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
            class VirtualEthernetExchanger;

            /**
             * @brief Represents a UDP relay port bound to one virtual ethernet source endpoint.
             *
             * This object owns an async UDP socket, forwards packets between the local network and
             * a transmission channel, and tracks DNS-only timeout behavior.
             */
            class VirtualEthernetDatagramPort : public std::enable_shared_from_this<VirtualEthernetDatagramPort> {
                friend class                                            VirtualEthernetExchanger;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::shared_ptr<VirtualEthernetExchanger>       VirtualEthernetExchangerPtr;

            public:
                /**
                 * @brief Creates a datagram relay port for a specific source endpoint.
                 * @param exchanger Owner exchanger that manages this port.
                 * @param transmission Transmission used for tunnel forwarding.
                 * @param sourceEP Source endpoint represented by this port.
                 */
                VirtualEthernetDatagramPort(const VirtualEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /**
                 * @brief Finalizes resources and unregisters the port.
                 */
                virtual ~VirtualEthernetDatagramPort() noexcept;

            public:
                std::shared_ptr<VirtualEthernetDatagramPort>            GetReference() noexcept      { return shared_from_this(); }
                VirtualEthernetExchangerPtr                             GetExchanger() noexcept      { return exchanger_; }
                ContextPtr                                              GetContext() noexcept        { return context_; }
                AppConfigurationPtr                                     GetConfiguration() noexcept  { return configuration_; }
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept  { return localEP_; }
                boost::asio::ip::udp::endpoint&                         GetSourceEndPoint() noexcept { return sourceEP_; }

            public:
                /**
                 * @brief Schedules asynchronous disposal on the owning io_context.
                 */
                virtual void                                            Dispose() noexcept;
                /**
                 * @brief Opens and configures the UDP socket, then starts receive loop.
                 * @return True if socket opening and loop startup succeed.
                 */
                virtual bool                                            Open() noexcept;
                /**
                 * @brief Sends one UDP datagram to the destination endpoint.
                 * @param packet Payload pointer.
                 * @param packet_length Payload size in bytes.
                 * @param destinationEP Target UDP endpoint.
                 * @return True on successful send and timeout refresh.
                 */
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;
                /**
                 * @brief Checks whether the port is disposed or timeout-expired.
                 * @param now Current tick count in milliseconds.
                 * @return True if the port should be considered aging.
                 */
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }

            public:
                /**
                 * @brief Parses and inserts a DNS response packet into namespace cache.
                 * @param switcher Switcher providing namespace cache access.
                 * @param packet DNS packet buffer.
                 * @param packet_length Packet size in bytes.
                 * @return True if the cache entry is added successfully.
                 */
                static bool                                             NamespaceQuery(
                    const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                    const void*                                         packet,
                    int                                                 packet_length) noexcept;
                /**
                 * @brief Tries to answer a DNS query from cache and output the cached response.
                 * @param switcher Switcher providing namespace cache access.
                 * @param exchanger Exchanger used for output path selection.
                 * @param sourceEP Logical source endpoint.
                 * @param destinationEP Logical destination endpoint.
                 * @param domain Domain key parsed from the query.
                 * @param packet Original DNS query packet.
                 * @param packet_length Query packet size in bytes.
                 * @param queries_type DNS query type.
                 * @param queries_clazz DNS query class.
                 * @param static_transit True to use static transit output path.
                 * @return 1 if handled from cache, 0 if not found, -1 on output failure.
                 */
                static int                                              NamespaceQuery(
                    const std::shared_ptr<VirtualEthernetSwitcher>&     switcher,
                    VirtualEthernetExchanger*                           exchanger,
                    const boost::asio::ip::udp::endpoint&               sourceEP,
                    const boost::asio::ip::udp::endpoint&               destinationEP,
                    const ppp::string&                                  domain,
                    const void*                                         packet,
                    int                                                 packet_length,
                    uint16_t                                            queries_type,
                    uint16_t                                            queries_clazz,
                    bool                                                static_transit) noexcept;

            private:
                /**
                 * @brief Releases socket and transmission state.
                 */
                void                                                    Finalize() noexcept;
                /**
                 * @brief Starts one asynchronous receive cycle.
                 * @return True if receive operation is scheduled.
                 */
                bool                                                    Loopback() noexcept;
                /**
                 * @brief Refreshes timeout according to DNS-only or inactive policy.
                 */
                void                                                    Update() noexcept {
                    UInt64 now = Executors::GetTickCount();
                    if (onlydns_) {
                        timeout_ = now + (UInt64)configuration_->udp.dns.timeout * 1000;
                    }
                    else {
                        timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                    }
                }
                /**
                 * @brief Marks this port as externally finalized.
                 */
                void                                                    MarkFinalize() noexcept { finalize_ = true; }

            private:
                struct {
                    bool                                                disposed_ : 1;
                    bool                                                onlydns_  : 1;
                    bool                                                sendto_   : 1;
                    bool                                                in_       : 1;
                    bool                                                finalize_ : 4;
                    UInt64                                              timeout_  = 0;
                };
                std::shared_ptr<boost::asio::io_context>                context_;
                boost::asio::ip::udp::socket                            socket_;
                VirtualEthernetExchangerPtr                             exchanger_;
                ITransmissionPtr                                        transmission_;
                AppConfigurationPtr                                     configuration_;
                std::shared_ptr<Byte>                                   buffer_;
                boost::asio::ip::udp::endpoint                          localEP_;
                boost::asio::ip::udp::endpoint                          remoteEP_;
                boost::asio::ip::udp::endpoint                          sourceEP_;
            };
        }
    }
}
