#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/net/asio/vdns.h>

namespace ppp {
    namespace app {
        namespace client {
            namespace dns {

                namespace {

                    DnsResponseHandlerPorts BuildDnsResponseHandlerPorts(
                        const std::shared_ptr<VEthernetExchanger>& exchanger,
                        const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration,
                        const ppp::function<bool(
                            const boost::asio::ip::udp::endpoint&,
                            const boost::asio::ip::udp::endpoint&,
                            void*,
                            int,
                            bool)>& datagram_output) noexcept {

                        DnsResponseHandlerPorts ports;
                        if (NULLPTR != configuration && configuration->udp.dns.cache) {
                            ports.enable_dns_cache = true;
                            ports.write_cache =
                                [](const Byte* packet, int packet_size) noexcept {
                                    ppp::net::asio::vdns::AddCache(packet, packet_size);
                                };
                        }
                        if (datagram_output) {
                            ports.datagram_output = datagram_output;
                        }
                        if (NULLPTR != exchanger) {
                            ports.tunnel_send =
                                [exchanger](const boost::asio::ip::udp::endpoint& sourceEP,
                                    const boost::asio::ip::udp::endpoint& destinationEP,
                                    const void* packet,
                                    int packet_size) noexcept {
                                    return exchanger->SendTo(
                                        sourceEP, destinationEP, packet, packet_size);
                                };
                        }
                        return ports;
                    }

                }  // namespace

                DnsHostPorts MakeDnsHostPorts(
                    const std::shared_ptr<VEthernetNetworkSwitcher>& self,
                    const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {

                    auto datagram_output =
                        [self](const boost::asio::ip::udp::endpoint& sourceEP,
                            const boost::asio::ip::udp::endpoint& destinationEP,
                            void* packet,
                            int packet_size,
                            bool caching) noexcept {
                            return self->DatagramOutput(
                                sourceEP, destinationEP, packet, packet_size, caching);
                        };

                    DnsHostPorts host;
                    host.datagram_output = datagram_output;
                    host.get_tap = [self]() noexcept { return self->GetTap(); };
                    host.get_configuration = [self]() noexcept { return self->GetConfiguration(); };
                    host.get_buffer_allocator = [self]() noexcept { return self->GetBufferAllocator(); };
                    host.emplace_timeout =
                        [self](void* key,
                            const std::shared_ptr<ppp::function<void(ppp::threading::Timer*)>>& timeout) noexcept {
                            return self->EmplaceTimeout(key, timeout);
                        };
                    host.delete_timeout = [self](void* key) noexcept { return self->DeleteTimeout(key); };
#if defined(_LINUX)
                    host.get_protector_network = [self]() noexcept { return self->GetProtectorNetwork(); };
#endif
                    host.handle_resolver_response =
                        [exchanger, datagram_output, self](
                            const std::shared_ptr<ppp::net::packet::BufferSegment>& messages,
                            const boost::asio::ip::udp::endpoint& sourceEP,
                            const boost::asio::ip::udp::endpoint& destEP,
                            ppp::vector<Byte> response) noexcept {
                            DnsResponseHandlerPorts ports = BuildDnsResponseHandlerPorts(
                                exchanger, self->GetConfiguration(), datagram_output);
                            DnsResponseHandler::HandleWithPorts(
                                ports, messages, sourceEP, destEP, std::move(response));
                        };
                    return host;
                }

            }
        }
    }
}
