#include <ppp/app/client/dns/DnsHost.h>
#include <ppp/app/client/dns/DnsResponseHandler.h>
#include <ppp/app/client/AssignedAddressManager.h>
#include <ppp/app/client/ClientBypassRouteLoader.h>
#include <ppp/app/client/ClientConnectionOpener.h>
#include <ppp/app/client/ClientConnectionTeardown.h>
#include <ppp/app/client/ClientPacketDispatchHandler.h>
#include <ppp/app/client/dns/DnsInterceptor.h>
#include <ppp/app/client/PeerPrefixRouteManager.h>
#include <ppp/app/client/QuicRejectRateLimiter.h>
#include <ppp/app/client/AggregatorLoader.h>
#include <ppp/app/client/RemoteEndpointLoader.h>
#include <ppp/app/client/RouteTableManager.h>
#include <ppp/app/client/SwitcherTimeoutRegistry.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/ethernet/VEthernet.h>
#include <ppp/net/asio/vdns.h>

namespace {

bool g_inject_ok = true;
bool g_datagram_output_called = false;
int g_datagram_output_bytes = 0;
bool g_tunnel_send_called = false;
bool g_tunnel_send_result = false;

}  // namespace

namespace ppp {

int RandomNext() noexcept {
    return 0;
}

}  // namespace ppp

namespace ppp::configurations {

AppConfiguration::AppConfiguration() noexcept = default;

}  // namespace ppp::configurations

namespace ppp::app::client::dns::test {

void ResetDnsHostWiringSpy() noexcept {
    g_datagram_output_called = false;
    g_datagram_output_bytes = 0;
    g_tunnel_send_called = false;
}

void SetDnsHostTunnelSendResult(bool result) noexcept {
    g_tunnel_send_result = result;
}

bool DnsHostTunnelSendCalled() noexcept {
    return g_tunnel_send_called;
}

void SetDnsHostInjectOk(bool inject_ok) noexcept {
    g_inject_ok = inject_ok;
}

bool DnsHostDatagramOutputCalled() noexcept {
    return g_datagram_output_called;
}

int DnsHostDatagramOutputBytes() noexcept {
    return g_datagram_output_bytes;
}

}  // namespace ppp::app::client::dns::test

namespace ppp::ethernet {

VEthernet::VEthernet(
    const std::shared_ptr<boost::asio::io_context>& context,
    bool lwip,
    bool vnet,
    bool mta) noexcept
    : disposed_(false)
    , lwip_(lwip)
    , vnet_(vnet)
    , mta_(mta)
    , context_(context) {}

VEthernet::~VEthernet() noexcept {
    Finalize();
}

void VEthernet::Finalize() noexcept {
    disposed_.store(true, std::memory_order_release);
}

bool VEthernet::IsDisposed() noexcept {
    return disposed_.load(std::memory_order_acquire);
}

bool VEthernet::Open(const std::shared_ptr<ppp::tap::ITap>&) noexcept {
    return true;
}

void VEthernet::Dispose() noexcept {
    Finalize();
}

std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernet::GetBufferAllocator() noexcept {
    return std::shared_ptr<ppp::threading::BufferswapAllocator>();
}

bool VEthernet::OnPacketInput(ppp::net::native::ip_hdr*, int, int, int, bool) noexcept {
    return false;
}

bool VEthernet::OnPacketInput(ppp::Byte*, int, bool) noexcept {
    return false;
}

bool VEthernet::OnPacketInput(const std::shared_ptr<ppp::net::packet::IPFrame>&) noexcept {
    return false;
}

bool VEthernet::OnTick(uint64_t) noexcept {
    return true;
}

bool VEthernet::OnUpdate(uint64_t) noexcept {
    return true;
}

bool VEthernet::Output(const void*, int) noexcept {
    return false;
}

bool VEthernet::Output(const std::shared_ptr<ppp::Byte>&, int) noexcept {
    return false;
}

std::shared_ptr<ppp::net::packet::IPFragment> VEthernet::NewFragment() noexcept {
    return std::shared_ptr<ppp::net::packet::IPFragment>();
}

}  // namespace ppp::ethernet

namespace ppp::app::client {

VEthernetNetworkSwitcher::VEthernetNetworkSwitcher(
    const std::shared_ptr<boost::asio::io_context>& context,
    bool lwip,
    bool vnet,
    bool mta,
    const std::shared_ptr<ppp::configurations::AppConfiguration>& configuration) noexcept
    : VEthernet(context, lwip, vnet, mta)
    , configuration_(configuration)
    , timeout_registry_(std::make_unique<SwitcherTimeoutRegistry>())
    , aggregator_loader_(std::make_unique<AggregatorLoader>()) {

    timeout_registry_->Bind(&GetSynchronizedObject());
    aggregator_loader_->Bind(this);
    static_mode_ = false;
    block_quic_ = false;
    icmppackets_aid_ = RandomNext();
}

VEthernetNetworkSwitcher::~VEthernetNetworkSwitcher() noexcept {
    Finalize();
}

std::shared_ptr<ppp::configurations::AppConfiguration> VEthernetNetworkSwitcher::GetConfiguration() noexcept {
    return configuration_;
}

std::shared_ptr<aggligator::aggligator> VEthernetNetworkSwitcher::GetAggligator() noexcept {
    return aggligator_;
}

void VEthernetNetworkSwitcher::Finalize() noexcept {
    if (timeout_registry_) {
        timeout_registry_->ReleaseAll();
    }
}

bool VEthernetNetworkSwitcher::Open(const std::shared_ptr<ppp::tap::ITap>& tap) noexcept {
    return VEthernet::Open(tap);
}

void VEthernetNetworkSwitcher::Dispose() noexcept {
    VEthernet::Dispose();
}

std::shared_ptr<ppp::threading::BufferswapAllocator> VEthernetNetworkSwitcher::GetBufferAllocator() noexcept {
    if (NULLPTR == configuration_) {
        return std::shared_ptr<ppp::threading::BufferswapAllocator>();
    }
    return configuration_->GetBufferAllocator();
}

bool VEthernetNetworkSwitcher::BlockQUIC(bool) noexcept {
    return false;
}

bool VEthernetNetworkSwitcher::OnPacketInput(ppp::net::native::ip_hdr* packet, int packet_length, int header_length, int proto, bool vnet) noexcept {
    return VEthernet::OnPacketInput(packet, packet_length, header_length, proto, vnet);
}

bool VEthernetNetworkSwitcher::OnPacketInput(ppp::Byte* packet, int packet_length, bool vnet) noexcept {
    return VEthernet::OnPacketInput(packet, packet_length, vnet);
}

bool VEthernetNetworkSwitcher::OnPacketInput(const std::shared_ptr<ppp::net::packet::IPFrame>& packet) noexcept {
    return VEthernet::OnPacketInput(packet);
}

bool VEthernetNetworkSwitcher::OnTick(uint64_t now) noexcept {
    return VEthernet::OnTick(now);
}

bool VEthernetNetworkSwitcher::OnUpdate(uint64_t now) noexcept {
    return VEthernet::OnUpdate(now);
}

bool VEthernetNetworkSwitcher::OnInformation(const std::shared_ptr<VirtualEthernetInformation>&) noexcept {
    return true;
}

bool VEthernetNetworkSwitcher::OnInformation(
    const std::shared_ptr<VirtualEthernetInformation>&,
    const VirtualEthernetInformationExtensions&) noexcept {
    return true;
}

std::shared_ptr<VEthernetExchanger> VEthernetNetworkSwitcher::NewExchanger() noexcept {
    return std::shared_ptr<VEthernetExchanger>();
}

std::shared_ptr<ppp::ethernet::VNetstack> VEthernetNetworkSwitcher::NewNetstack() noexcept {
    return std::shared_ptr<ppp::ethernet::VNetstack>();
}

VEthernetNetworkSwitcher::VEthernetHttpProxySwitcherPtr VEthernetNetworkSwitcher::NewHttpProxy(
    const std::shared_ptr<VEthernetExchanger>&) noexcept {
    return VEthernetHttpProxySwitcherPtr();
}

VEthernetNetworkSwitcher::VEthernetSocksProxySwitcherPtr VEthernetNetworkSwitcher::NewSocksProxy(
    const std::shared_ptr<VEthernetExchanger>&) noexcept {
    return VEthernetSocksProxySwitcherPtr();
}

std::shared_ptr<ppp::transmissions::ITransmissionQoS> VEthernetNetworkSwitcher::NewQoS() noexcept {
    return std::shared_ptr<ppp::transmissions::ITransmissionQoS>();
}

VEthernetNetworkSwitcher::ITransmissionStatisticsPtr VEthernetNetworkSwitcher::NewStatistics() noexcept {
    return ITransmissionStatisticsPtr();
}

#if defined(_LINUX)
VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::NewProtectorNetwork() noexcept {
    return ProtectorNetworkPtr();
}

VEthernetNetworkSwitcher::ProtectorNetworkPtr VEthernetNetworkSwitcher::GetProtectorNetwork() noexcept {
    return ProtectorNetworkPtr();
}
#endif

#if !defined(_ANDROID) && !defined(_IPHONE)
ppp::string VEthernetNetworkSwitcher::GetRemoteUri() noexcept {
    return ppp::string();
}

bool VEthernetNetworkSwitcher::AddLoadIPList(
    const ppp::string&,
#if defined(_LINUX)
    const ppp::string&,
#endif
    const boost::asio::ip::address&,
    const ppp::string&) noexcept {
    return false;
}

void VEthernetNetworkSwitcher::PreferredNic(const ppp::string&) noexcept {}

void VEthernetNetworkSwitcher::PreferredNgw(const boost::asio::ip::address&) noexcept {}
#endif

bool VEthernetNetworkSwitcher::LoadAllDnsRules(const ppp::string&, bool) noexcept {
    return false;
}

const dns::DnsHostPorts& VEthernetNetworkSwitcher::DnsHostPortsFor(
    const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {

    static dns::DnsHostPorts ports;
    ports = BuildDnsHostPorts(exchanger);
    return ports;
}

void VEthernetNetworkSwitcher::InvalidateDnsHostPorts() noexcept {}

bool VEthernetNetworkSwitcher::RedirectDnsServer(
    const std::shared_ptr<VEthernetExchanger>&,
    const std::shared_ptr<ppp::net::packet::IPFrame>&,
    const std::shared_ptr<ppp::net::packet::UdpFrame>&,
    const std::shared_ptr<ppp::net::packet::BufferSegment>&) noexcept {
    return false;
}

dns::DnsHostPorts VEthernetNetworkSwitcher::BuildDnsHostPorts(
    const std::shared_ptr<VEthernetExchanger>& exchanger) noexcept {

    const auto self = std::static_pointer_cast<VEthernetNetworkSwitcher>(shared_from_this());
    auto datagram_output =
        [self](const boost::asio::ip::udp::endpoint& sourceEP,
            const boost::asio::ip::udp::endpoint& destinationEP,
            void* packet,
            int packet_size,
            bool caching) noexcept {
            return self->DatagramOutput(
                sourceEP, destinationEP, packet, packet_size, caching);
        };

    dns::DnsHostPorts host;
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
            ppp::vector<ppp::Byte> response) noexcept {
            dns::DnsResponseHandlerPorts ports;
            const std::shared_ptr<ppp::configurations::AppConfiguration> configuration =
                self->GetConfiguration();
            if (NULLPTR != configuration && configuration->udp.dns.cache) {
                ports.enable_dns_cache = true;
                ports.write_cache =
                    [](const ppp::Byte* packet, int packet_size) noexcept {
                        ppp::net::asio::vdns::AddCache(packet, packet_size);
                    };
            }
            ports.datagram_output = datagram_output;
            if (NULLPTR != exchanger) {
                ports.tunnel_send =
                    [](const boost::asio::ip::udp::endpoint&,
                        const boost::asio::ip::udp::endpoint&,
                        const void*,
                        int) noexcept {
                        g_tunnel_send_called = true;
                        return g_tunnel_send_result;
                    };
            }
            dns::DnsResponseHandler::HandleWithPorts(
                ports, messages, sourceEP, destEP, std::move(response));
        };
    return host;
}

route::RouteHostPorts VEthernetNetworkSwitcher::BuildRouteHostPorts() noexcept {
    route::RouteHostPorts host;
    host.get_tap = []() noexcept { return std::shared_ptr<ppp::tap::ITap>(); };
    host.get_tap_ni = []() noexcept { return std::shared_ptr<ClientNetworkInterface>(); };
    host.get_underlying_ni = []() noexcept { return std::shared_ptr<ClientNetworkInterface>(); };
    host.get_rib = []() noexcept { return route::RouteInformationTablePtr(); };
    host.set_rib = [](route::RouteInformationTablePtr) noexcept {};
    host.get_fib = []() noexcept { return route::ForwardInformationTablePtr(); };
    host.set_fib = [](route::ForwardInformationTablePtr) noexcept {};
    host.get_route_added = []() noexcept { return false; };
    host.set_route_added = [](bool) noexcept {};
    host.get_route_apply_ready = []() noexcept { return false; };
    host.add_dns_server_ip = [](uint32_t, int) noexcept {};
    host.clear_dns_servers = []() noexcept {};
    host.get_dns_server_bucket = [](int bucket) noexcept -> ppp::unordered_set<uint32_t>* {
        static ppp::unordered_set<uint32_t> buckets[3];
        if (bucket < 0 || bucket >= 3) {
            return nullptr;
        }
        return &buckets[bucket];
    };
    host.dedupe_dns_servers = []() noexcept {};
    host.collect_dns_reachability = []() noexcept {};
    host.get_dns_interceptor = []() noexcept { return std::shared_ptr<dns::DnsInterceptor>(); };
    host.get_configuration = []() noexcept { return std::shared_ptr<ppp::configurations::AppConfiguration>(); };
    host.get_default_routes = []() noexcept { return route::RouteInformationTablePtr(); };
    host.set_default_routes = [](route::RouteInformationTablePtr) noexcept {};
    host.get_nics = []() noexcept -> ppp::unordered_map<uint32_t, ppp::string>* {
        static ppp::unordered_map<uint32_t, ppp::string> nics;
        return &nics;
    };
    return host;
}

#if !defined(_ANDROID) && !defined(_IPHONE)
void VEthernetNetworkSwitcher::AddRoute() noexcept {}

void VEthernetNetworkSwitcher::DeleteRoute() noexcept {}
#endif

bool VEthernetNetworkSwitcher::DatagramOutput(
    const boost::asio::ip::udp::endpoint&,
    const boost::asio::ip::udp::endpoint&,
    void*,
    int packet_size,
    bool) noexcept {

    g_datagram_output_called = true;
    g_datagram_output_bytes = packet_size;
    return g_inject_ok;
}

bool VEthernetNetworkSwitcher::PreparedAggregator() noexcept {
    if (NULLPTR == aggregator_loader_) {
        return false;
    }
    return aggregator_loader_->Prepare();
}

bool VEthernetNetworkSwitcher::EmplaceTimeout(
    void* key,
    const std::shared_ptr<ppp::threading::Timer::TimeoutEventHandler>& timeout) noexcept {
    if (NULLPTR == timeout_registry_) {
        return false;
    }
    return timeout_registry_->Emplace(key, timeout);
}

bool VEthernetNetworkSwitcher::DeleteTimeout(void* key) noexcept {
    if (NULLPTR == timeout_registry_) {
        return false;
    }
    return timeout_registry_->Delete(key);
}

}  // namespace ppp::app::client

namespace ppp::net::asio::vdns {

bool AddCache(const ppp::Byte*, int) noexcept {
    return true;
}

}  // namespace ppp::net::asio::vdns
