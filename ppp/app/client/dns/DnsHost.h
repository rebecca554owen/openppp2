#pragma once

/**
 * @file DnsHost.h
 * @brief Narrow host surface for DNS intercept/relay without VEthernetNetworkSwitcher.h.
 */

#include <ppp/stdafx.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }
    namespace tap {
        class ITap;
    }
    namespace threading {
        class BufferswapAllocator;
        class Timer;
    }
    namespace net {
        namespace packet {
            class IPFrame;
            class UdpFrame;
            class BufferSegment;
        }
#if defined(_LINUX)
        class ProtectorNetwork;
#endif
    }
}

namespace ppp {
    namespace app {
        namespace client {
            class VEthernetNetworkSwitcher;
            class VEthernetExchanger;

            namespace dns {

                /** @brief Injectable switcher capabilities for DNS pipeline (no switcher header). */
                struct DnsHostPorts final {
                    ppp::function<bool(
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destinationEP,
                        void* packet,
                        int packet_size,
                        bool caching)> datagram_output;

                    ppp::function<std::shared_ptr<ppp::tap::ITap>()> get_tap;

                    ppp::function<std::shared_ptr<ppp::configurations::AppConfiguration>()> get_configuration;

                    ppp::function<std::shared_ptr<ppp::threading::BufferswapAllocator>()> get_buffer_allocator;

                    ppp::function<bool(
                        void* key,
                        const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& timeout)> emplace_timeout;

                    ppp::function<bool(void* key)> delete_timeout;

#if defined(_LINUX)
                    ppp::function<std::shared_ptr<ppp::net::ProtectorNetwork>()> get_protector_network;
#endif

                    ppp::function<void(
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                        const boost::asio::ip::udp::endpoint& sourceEP,
                        const boost::asio::ip::udp::endpoint& destEP,
                        ppp::vector<Byte> response)> handle_resolver_response;

                    bool IsValid() const noexcept {
                        if (!datagram_output || !get_tap || !get_configuration ||
                            !get_buffer_allocator || !emplace_timeout || !delete_timeout ||
                            !handle_resolver_response) {
                            return false;
                        }
#if defined(_LINUX)
                        if (!get_protector_network) {
                            return false;
                        }
#endif
                        return true;
                    }
                };

                class IDnsHost {
                public:
                    virtual ~IDnsHost() noexcept = default;
                    virtual DnsHostPorts BuildDnsHostPorts(
                        const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept = 0;
                    virtual const DnsHostPorts& DnsHostPortsFor(
                        const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept = 0;
                    virtual void InvalidateDnsHostPorts() noexcept = 0;
                    virtual bool RedirectDnsServer(
                        const std::shared_ptr<VEthernetExchanger>& exchanger,
                        const std::shared_ptr<ppp::net::packet::IPFrame>& packet,
                        const std::shared_ptr<ppp::net::packet::UdpFrame>& frame,
                        const std::shared_ptr<ppp::net::packet::BufferSegment>& messages) noexcept = 0;
                };

                DnsHostPorts MakeDnsHostPorts(
                    const std::shared_ptr<IDnsHost>& host,
                    const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

                DnsHostPorts MakeDnsHostPorts(
                    const std::shared_ptr<VEthernetNetworkSwitcher>& self,
                    const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept;

            }
        }
    }
}
