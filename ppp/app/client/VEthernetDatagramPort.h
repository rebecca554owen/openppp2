#pragma once

/**
 * @file VEthernetDatagramPort.h
 * @brief Datagram relay port for client-side virtual Ethernet exchange.
 * @details
 * This file is part of the project and is distributed under the terms of
 * the GNU General Public License v3.0 (GPL-3.0).
 */

#include <ppp/configurations/AppConfiguration.h>
#include <ppp/threading/Executors.h>
#include <ppp/coroutines/YieldContext.h>
#include <ppp/transmissions/ITransmission.h>

#if defined(_ANDROID)
#include <linux/ppp/net/ProtectorNetwork.h>
#endif

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetExchanger;
            class VEthernetNetworkSwitcher;

            /**
             * @brief Represents a UDP datagram relay endpoint bound to a local source endpoint.
             * @details
             * The port tracks activity timeout, forwards outbound datagrams through
             * the active transmission, and routes inbound datagrams back to the
             * network switcher path.
             */
            class VEthernetDatagramPort : public std::enable_shared_from_this<VEthernetDatagramPort> {
                friend class                                            VEthernetExchanger;
                friend class                                            VEthernetNetworkSwitcher;

            public:
                typedef ppp::configurations::AppConfiguration           AppConfiguration;
                typedef std::shared_ptr<AppConfiguration>               AppConfigurationPtr;
                typedef ppp::threading::Executors                       Executors;
                typedef std::shared_ptr<boost::asio::io_context>        ContextPtr;
                typedef ppp::transmissions::ITransmission               ITransmission;
                typedef std::shared_ptr<ITransmission>                  ITransmissionPtr;
                typedef std::mutex                                      SynchronizedObject;
                typedef std::lock_guard<SynchronizedObject>             SynchronizedObjectScope;
                typedef std::shared_ptr<VEthernetExchanger>             VEthernetExchangerPtr;
                typedef std::shared_ptr<VEthernetNetworkSwitcher>       VEthernetNetworkSwitcherPtr;

#if defined(_ANDROID)
            public:
                typedef std::shared_ptr<ppp::net::ProtectorNetwork>     ProtectorNetworkPtr;
                /** @brief Buffered UDP datagram pending local send on Android. */
                typedef struct {
                    std::shared_ptr<Byte>                               packet;
                    int                                                 packet_length = 0;
                    boost::asio::ip::udp::endpoint                      destinationEP;
                }                                                       Message;
                typedef ppp::list<Message>                              Messages;

            public:
                ProtectorNetworkPtr                                     ProtectorNetwork;
#endif

            public:
                /** @brief Initializes a datagram relay port instance. */
                VEthernetDatagramPort(const VEthernetExchangerPtr& exchanger, const ITransmissionPtr& transmission, const boost::asio::ip::udp::endpoint& sourceEP) noexcept;
                /** @brief Releases resources owned by the port. */
                virtual ~VEthernetDatagramPort() noexcept;

            public:
                /** @brief Returns a shared self reference. */
                std::shared_ptr<VEthernetDatagramPort>                  GetReference()     noexcept { return shared_from_this(); }
                /** @brief Returns the owning exchanger. */
                VEthernetExchangerPtr                                   GetExchanger()     noexcept { return exchanger_; }
                /** @brief Returns the scheduler context used by this port. */
                ContextPtr                                              GetContext()       noexcept { return context_; }
                /** @brief Returns immutable runtime configuration. */
                AppConfigurationPtr                                     GetConfiguration() noexcept { return configuration_; }
                /** @brief Returns the local source endpoint represented by this port. */
                boost::asio::ip::udp::endpoint&                         GetLocalEndPoint() noexcept { return sourceEP_; }

            public:
                /** @brief Checks whether the port is disposed or timeout-expired. */
                bool                                                    IsPortAging(UInt64 now) noexcept { return disposed_ || now >= timeout_; }
                /** @brief Disposes the relay port and releases owned resources. */
                virtual void                                            Dispose() noexcept;
                /** @brief Sends a UDP payload to destination through the remote exchanger. */
                virtual bool                                            SendTo(const void* packet, int packet_length, const boost::asio::ip::udp::endpoint& destinationEP) noexcept;

#if defined(_ANDROID)
            public:  
                /** @brief Opens Android UDP socket and starts loopback receive flow. */
                bool                                                    Open(ppp::coroutines::YieldContext& y) noexcept;

            private: 
                /** @brief Receives datagrams from socket and forwards to remote exchanger. */
                bool                                                    Loopback() noexcept;
#endif

            protected:
                /** @brief Handles datagram received from remote side for this source endpoint. */
                virtual void                                            OnMessage(void*, int, const boost::asio::ip::udp::endpoint&) noexcept;

            private:
                /** @brief Finalizes and unhooks this port from owner tables. */
                void                                                    Finalize() noexcept;
                /** @brief Refreshes inactivity timeout according to current mode. */
                void                                                    Update() noexcept {
                    UInt64 now = Executors::GetTickCount();
                    if (onlydns_) {
                        timeout_ = now + (UInt64)configuration_->udp.dns.timeout * 1000;
                    }
                    else {
                        timeout_ = now + (UInt64)configuration_->udp.inactive.timeout * 1000;
                    }
                }
                /** @brief Marks this port for finalization on next disposal path. */
                void                                                    MarkFinalize() noexcept { finalize_ = true; }

            private:
                struct {
                    bool                                                disposed_ : 1;
                    bool                                                onlydns_  : 1;
                    bool                                                sendto_   : 1;
                    bool                                                finalize_ : 5;
                    UInt64                                              timeout_  = 0;
                };
                SynchronizedObject                                      syncobj_;
                ContextPtr                                              context_;
                VEthernetNetworkSwitcherPtr                             switcher_;
                VEthernetExchangerPtr                                   exchanger_;
                ITransmissionPtr                                        transmission_;
                AppConfigurationPtr                                     configuration_;
                boost::asio::ip::udp::endpoint                          sourceEP_;
#if defined(_ANDROID)
                Messages                                                messages_;
                int                                                     opened_   = 0;
                boost::asio::ip::udp::socket                            socket_;
                std::shared_ptr<Byte>                                   buffer_;
                boost::asio::ip::udp::endpoint                          remoteEP_;
#endif
            };
        }
    }
}
