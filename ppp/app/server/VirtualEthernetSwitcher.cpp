#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetExchanger.h>
#include <ppp/app/server/VirtualEthernetNetworkTcpipConnection.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/server/VirtualEthernetNamespaceCache.h>
#include <ppp/IDisposable.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/cryptography/digest.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/proxies/sniproxy.h>
#include <ppp/io/MemoryStream.h>
#include <ppp/io/File.h>
#include <ppp/app/protocol/VirtualEthernetTcpMss.h>
#include <ppp/net/packet/IPFrame.h>
#include <ppp/net/packet/UdpFrame.h>
#include <ppp/net/packet/IcmpFrame.h>
#include <ppp/app/server/VirtualEthernetIPv6.h>
#include <ppp/ipv6/IPv6Packet.h>
#if defined(_LINUX)
#include <linux/ppp/tap/TapLinux.h>
#endif
#include <ppp/collections/Dictionary.h>
#include <ppp/threading/Executors.h>
#include <ppp/transmissions/ITcpipTransmission.h>
#include <ppp/transmissions/IWebsocketTransmission.h>

using ppp::app::protocol::VirtualEthernetPacket;
using ppp::net::Ipep;
using ppp::net::Socket;
using ppp::net::IPEndPoint;
using ppp::net::AddressFamily;
using ppp::threading::Executors;
using ppp::coroutines::YieldContext;
using ppp::collections::Dictionary;

static void DebugLog(const char* format, ...) noexcept {}

static bool IsGlobalUnicastIPv6Address(const boost::asio::ip::address_v6& address) noexcept {
    boost::asio::ip::address_v6::bytes_type bytes = address.to_bytes();
    return (bytes[0] & 0xe0) == 0x20;
}

static bool TryGetFirstHostIPv6(const boost::asio::ip::address_v6& network, boost::asio::ip::address_v6& host) noexcept {
    boost::asio::ip::address_v6::bytes_type bytes = network.to_bytes();
    for (int i = 15; i >= 0; --i) {
        if (bytes[i] != 0xff) {
            ++bytes[i];
            for (int j = i + 1; j < 16; ++j) {
                bytes[j] = 0;
            }
            host = boost::asio::ip::address_v6(bytes);
            return true;
        }
    }
    return false;
}

#if defined(_LINUX)
static ppp::string ResolvePreferredIPv6UplinkInterface(const ppp::string& preferred_nic) noexcept {
    if (!preferred_nic.empty()) {
        return preferred_nic;
    }

    FILE* pipe = popen("ip -6 route show default", "r");
    if (NULLPTR == pipe) {
        return ppp::string();
    }

    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), pipe) != NULLPTR) {
        ppp::string route = buffer;
        while (!route.empty() && (route.back() == '\n' || route.back() == '\r')) {
            route.pop_back();
        }

        std::size_t pos = route.find(" dev ");
        if (pos == ppp::string::npos) {
            continue;
        }

        pos += 5;
        std::size_t end = route.find(' ', pos);
        ppp::string ifname = end == ppp::string::npos ? route.substr(pos) : route.substr(pos, end - pos);
        if (!ifname.empty()) {
            pclose(pipe);
            return ifname;
        }
    }

    pclose(pipe);
    return ppp::string();
}
#endif

namespace ppp {
    namespace transmissions {
        typedef ITransmission::AppConfigurationPtr      AppConfigurationPtr;

        bool                                            Transmission_Handshake_Nop(
            const AppConfigurationPtr&                  APP,
            ITransmission*                              transmission,
            ITransmission::YieldContext&                y) noexcept;
    }

    namespace app {
        namespace server {
            VirtualEthernetSwitcher::VirtualEthernetSwitcher(const AppConfigurationPtr& configuration, const ppp::string& tun_name, int tun_ssmt, bool tun_ssmt_mq) noexcept
                : disposed_(false)
                , configuration_(configuration)
                , context_(Executors::GetDefault())
                , tun_name_(tun_name)
                , tun_ssmt_(std::max<int>(0, tun_ssmt))
                , tun_ssmt_mq_(tun_ssmt_mq)
                , static_echo_socket_(*context_)
                , static_echo_bind_port_(IPEndPoint::MinPort) {
                
                boost::asio::ip::udp::udp::endpoint dnsserverEP = ParseDNSEndPoint(configuration_->udp.dns.redirect);
                dnsserverEP_ = dnsserverEP;

                interfaceIP_ = Ipep::ToAddress(configuration_->ip.interface_, true);
                statistics_ = make_shared_object<ppp::transmissions::ITransmissionStatistics>();

                static_echo_buffers_ = ppp::threading::Executors::GetCachedBuffer(context_);
            }

            VirtualEthernetSwitcher::~VirtualEthernetSwitcher() noexcept {
                Finalize();
            }

            VirtualEthernetSwitcher::InformationEnvelope VirtualEthernetSwitcher::BuildInformationEnvelope(const Int128& session_id, const VirtualEthernetInformation& info) noexcept {
                InformationEnvelope envelope;
                envelope.Base = info;
                BuildInformationIPv6Extensions(session_id, envelope.Extensions);
                envelope.ExtendedJson = envelope.Extensions.ToJson();
                DebugLog("server info envelope session=%s json=%s",
                    auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                    envelope.ExtendedJson.data());
                return envelope;
            }

            bool VirtualEthernetSwitcher::SupportsIPv6DataPlane() noexcept {
#if defined(_LINUX)
                return true;
#else
                return false;
#endif
            }

            bool VirtualEthernetSwitcher::IsIPv6ServerEnabled() noexcept {
                AppConfiguration::IPv6Mode mode = configuration_->server.ipv6.mode;
                return SupportsIPv6DataPlane() && (mode == AppConfiguration::IPv6Mode_Nat66 || mode == AppConfiguration::IPv6Mode_Gua);
            }

            boost::asio::ip::address VirtualEthernetSwitcher::GetIPv6TransitGateway() noexcept {
                const auto& ipv6 = configuration_->server.ipv6;

                boost::system::error_code ec;
                boost::asio::ip::address configured_gateway = StringToAddress(ipv6.gateway, ec);
                if (!ec && configured_gateway.is_v6()) {
                    return configured_gateway;
                }

                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }

                ec.clear();
                boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
                if (ec || !prefix.is_v6()) {
                    return boost::asio::ip::address();
                }

                boost::asio::ip::address_v6 gateway;
                if (!TryGetFirstHostIPv6(prefix.to_v6(), gateway)) {
                    return boost::asio::ip::address();
                }
                return boost::asio::ip::address(gateway);
            }

            bool VirtualEthernetSwitcher::BuildInformationIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept {
                extensions.Clear();

                const auto& ipv6 = configuration_->server.ipv6;
                if (!IsIPv6ServerEnabled()) {
                    extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                    extensions.IPv6StatusMessage = "server-ipv6-disabled";
                    DebugLog("server ipv6 disabled session=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                    return false;
                }

                IPv6RequestEntry request_entry;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto request_it = ipv6_requests_.find(session_id);
                    if (request_it != ipv6_requests_.end()) {
                        request_entry = request_it->second;
                    }
                }

                extensions.RequestedIPv6Address = request_entry.RequestedAddress;
                extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned;
                extensions.IPv6StatusMessage = "server-auto-assigned";

                auto is_request_usable = [&](const boost::asio::ip::address_v6& requested, const boost::asio::ip::address_v6& prefix, int prefix_length) noexcept -> bool {
                    return request_entry.RequestedAddress.is_v6() &&
                        requested == request_entry.RequestedAddress.to_v6() &&
                        ppp::ipv6::PrefixMatch(requested, prefix, prefix_length);
                };

                auto build_stable_ipv6 = [&](boost::asio::ip::address_v6::bytes_type bytes, int prefix_length) noexcept -> bool {
                    ppp::string seed = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);

                    ppp::string digest = ppp::cryptography::hash_hmac(seed.data(), static_cast<int>(seed.size()), ppp::cryptography::DigestAlgorithmic_sha256, false, false);
                    if (digest.size() < 8) {
                        return false;
                    }

                    prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
                    boost::asio::ip::address_v6::bytes_type digest_bytes = {};
                    memcpy(digest_bytes.data(), digest.data(), std::min<std::size_t>(digest.size(), digest_bytes.size()));

                    boost::asio::ip::address_v6::bytes_type network_bytes = ppp::ipv6::ComputeNetworkAddress(boost::asio::ip::address_v6(bytes), prefix_length).to_bytes();
                    int full_bytes = prefix_length / 8;
                    int remainder_bits = prefix_length % 8;
                    for (int i = full_bytes; i < 16; ++i) {
                        network_bytes[i] = digest_bytes[i];
                    }
                    if (remainder_bits != 0 && full_bytes < 16) {
                        unsigned char host_mask = static_cast<unsigned char>(0xff >> remainder_bits);
                        network_bytes[full_bytes] = static_cast<unsigned char>((network_bytes[full_bytes] & static_cast<unsigned char>(~host_mask)) | (digest_bytes[full_bytes] & host_mask));
                    }

                    boost::asio::ip::address_v6 candidate = boost::asio::ip::address_v6(network_bytes);

                    boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                    if (transit_gateway.is_v6() && candidate == transit_gateway.to_v6()) {
                        boost::asio::ip::address_v6::bytes_type candidate_bytes = candidate.to_bytes();
                        candidate_bytes[15] ^= 0x01;
                        candidate = boost::asio::ip::address_v6(candidate_bytes);
                    }

                    extensions.AssignedIPv6Address = candidate;
                    return true;
                };

                auto try_commit_ipv6_lease = [&](const boost::asio::ip::address_v6& candidate, bool static_binding, Byte status_code, const ppp::string& status_message) noexcept -> bool {
                    boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                    if (transit_gateway.is_v6() && candidate == transit_gateway.to_v6()) {
                        return false;
                    }

                    if (candidate.is_multicast() || candidate.is_unspecified()) {
                        return false;
                    }

                    boost::system::error_code prefix_ec;
                    ppp::string configured_prefix_string;
                    int configured_prefix_length = 0;
                    std::size_t slash = ipv6.cidr.find('/');
                    configured_prefix_string = slash == ppp::string::npos ? ipv6.cidr : ipv6.cidr.substr(0, slash);
                    boost::asio::ip::address configured_prefix = StringToAddress(configured_prefix_string, prefix_ec);
                    int allowed_prefix_length = std::max<int>(0, std::min<int>(128, ipv6.prefix_length));
                    if (!prefix_ec && configured_prefix.is_v6()) {
                        if (!ppp::ipv6::PrefixMatch(candidate, configured_prefix.to_v6(), allowed_prefix_length)) {
                            return false;
                        }
                    }

                    UInt64 now = Executors::GetTickCount();
                    UInt64 expires_at = ipv6.lease_time > 0 ? now + static_cast<UInt64>(ipv6.lease_time) * 1000ULL : UINT64_MAX;

                    SynchronizedObjectScope scope(syncobj_);
                    for (const auto& kv : ipv6_leases_) {
                        if (kv.first == session_id) {
                            continue;
                        }

                        const IPv6LeaseEntry& lease = kv.second;
                        if (!lease.Address.is_v6() || lease.Address.to_v6() != candidate) {
                            continue;
                        }
                        if (lease.StaticBinding || lease.ExpiresAt == UINT64_MAX || lease.ExpiresAt > now) {
                            return false;
                        }
                    }

                    IPv6LeaseEntry& lease = ipv6_leases_[session_id];
                    lease.SessionId = session_id;
                    lease.ExpiresAt = static_binding ? UINT64_MAX : expires_at;
                    lease.Address = boost::asio::ip::address(candidate);
                    lease.AddressPrefixLength = extensions.AssignedIPv6AddressPrefixLength;
                    lease.StaticBinding = static_binding;

                    extensions.AssignedIPv6Address = boost::asio::ip::address(candidate);
                    extensions.IPv6StatusCode = status_code;
                    extensions.IPv6StatusMessage = status_message;
                    return true;
                };

                boost::system::error_code ec;

                AppConfiguration::IPv6Mode mode = ipv6.mode;
                DebugLog("server ipv6 build session=%s mode=%d cidr=%s gateway=%s dns1=%s dns2=%s",
                    auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                    (int)mode,
                    ipv6.cidr.data(),
                    ipv6.gateway.data(),
                    ipv6.dns1.data(),
                    ipv6.dns2.data());
                if (mode == AppConfiguration::IPv6Mode_Nat66) {
                    extensions.AssignedIPv6Mode = VirtualEthernetInformationExtensions::IPv6Mode_Nat66;
                    extensions.AssignedIPv6AddressPrefixLength = 128;

                    if (configuration_->server.subnet && ipv6.prefix_length > 0 && ipv6.prefix_length < 128) {
                        boost::system::error_code route_ec;
                        ppp::string route_prefix_string = ipv6.cidr;
                        std::size_t route_slash = route_prefix_string.find('/');
                        if (route_slash != ppp::string::npos) {
                            route_prefix_string = route_prefix_string.substr(0, route_slash);
                        }

                        boost::asio::ip::address route_prefix = StringToAddress(route_prefix_string, route_ec);
                        if (!route_ec && route_prefix.is_v6()) {
                            extensions.AssignedIPv6RoutePrefix = route_prefix;
                            extensions.AssignedIPv6RoutePrefixLength = static_cast<Byte>(ipv6.prefix_length);
                        }
                    }

                    boost::asio::ip::address_v6::bytes_type ula_bytes = {};
                    ec.clear();
                    ppp::string configured_prefix_string = ipv6.cidr;
                    std::size_t slash = configured_prefix_string.find('/');
                    if (slash != ppp::string::npos) {
                        configured_prefix_string = configured_prefix_string.substr(0, slash);
                    }
                    boost::asio::ip::address configured_prefix = StringToAddress(configured_prefix_string, ec);
                    if (!ec && configured_prefix.is_v6()) {
                        ula_bytes = configured_prefix.to_v6().to_bytes();
                    }
                    else {
                        ula_bytes[0] = 0xfd;
                    }

                    if (!build_stable_ipv6(ula_bytes, ipv6.prefix_length)) {
                        extensions.Clear();
                        DebugLog("server ipv6 build failed session=%s reason=stable-address", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                        return false;
                    }

                    boost::asio::ip::address_v6 stable_candidate = extensions.AssignedIPv6Address.to_v6();
                    extensions.AssignedIPv6Address = boost::asio::ip::address();

                    ppp::string session_guid = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                    auto static_it = ipv6.static_addresses.find(session_guid);
                    if (static_it != ipv6.static_addresses.end()) {
                        ec.clear();
                        boost::asio::ip::address static_address = StringToAddress(static_it->second, ec);
                        if (!ec && static_address.is_v6()) {
                            try_commit_ipv6_lease(static_address.to_v6(), true, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "static-binding");
                        }
                    }

                    boost::asio::ip::address_v6 requested_address = request_entry.RequestedAddress.is_v6() ? request_entry.RequestedAddress.to_v6() : boost::asio::ip::address_v6();
                    bool use_requested_first = is_request_usable(requested_address, boost::asio::ip::address_v6(ula_bytes), ipv6.prefix_length);

                    if (!extensions.AssignedIPv6Address.is_v6()) {
                        boost::asio::ip::address_v6 leased;
                        {
                            SynchronizedObjectScope scope(syncobj_);
                            auto lease_it = ipv6_leases_.find(session_id);
                            if (lease_it != ipv6_leases_.end() && lease_it->second.Address.is_v6()) {
                                leased = lease_it->second.Address.to_v6();
                            }
                        }
                        if (!leased.is_unspecified()) {
                            try_commit_ipv6_lease(leased, false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "lease-reused");
                        }
                    }

                    if (!extensions.AssignedIPv6Address.is_v6() && use_requested_first && request_entry.RequestedAddress.is_v6()) {
                        boost::asio::ip::address_v6 requested = request_entry.RequestedAddress.to_v6();
                        if (ppp::ipv6::PrefixMatch(requested, boost::asio::ip::address_v6(ula_bytes), ipv6.prefix_length)) {
                            try_commit_ipv6_lease(requested, false, VirtualEthernetInformationExtensions::IPv6Status_ClientRequested, "client-request-accepted");
                        }
                    }

                    if (!extensions.AssignedIPv6Address.is_v6()) {
                        if (!try_commit_ipv6_lease(stable_candidate, false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, request_entry.RequestedAddress.is_v6() ? "client-request-replaced" : "server-auto-assigned")) {
                            extensions.Clear();
                            extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                            extensions.IPv6StatusMessage = "ipv6-address-unavailable";
                            return false;
                        }
                    }

                    boost::asio::ip::address gateway = GetIPv6TransitGateway();
                    if (gateway.is_v6()) {
                        extensions.AssignedIPv6Gateway = gateway;
                    }

                    // NAT mode still carries an explicit virtual gateway so clients can prefer
                    // `default via <gateway> dev tun0` over direct-device routing.

                    ec.clear();
                    boost::asio::ip::address dns1 = StringToAddress(ipv6.dns1, ec);
                    if (!ec && dns1.is_v6()) {
                        extensions.AssignedIPv6Dns1 = dns1;
                    }

                    ec.clear();
                    boost::asio::ip::address dns2 = StringToAddress(ipv6.dns2, ec);
                    if (!ec && dns2.is_v6()) {
                        extensions.AssignedIPv6Dns2 = dns2;
                    }

                    DebugLog("server ipv6 build result session=%s address=%s gateway=%s route=%s/%u dns1=%s dns2=%s flags=%u",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        extensions.AssignedIPv6Address.is_v6() ? extensions.AssignedIPv6Address.to_string().c_str() : "",
                        extensions.AssignedIPv6Gateway.is_v6() ? extensions.AssignedIPv6Gateway.to_string().c_str() : "",
                        extensions.AssignedIPv6RoutePrefix.is_v6() ? extensions.AssignedIPv6RoutePrefix.to_string().c_str() : "",
                        (unsigned)extensions.AssignedIPv6RoutePrefixLength,
                        extensions.AssignedIPv6Dns1.is_v6() ? extensions.AssignedIPv6Dns1.to_string().c_str() : "",
                        extensions.AssignedIPv6Dns2.is_v6() ? extensions.AssignedIPv6Dns2.to_string().c_str() : "",
                        (unsigned)extensions.AssignedIPv6Flags);
                    return extensions.HasAny();
                }
                else if (mode == AppConfiguration::IPv6Mode_Gua) {
                    extensions.AssignedIPv6Mode = VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                    extensions.AssignedIPv6AddressPrefixLength = 128;
                    extensions.AssignedIPv6Flags |= VirtualEthernetInformationExtensions::IPv6Flag_NeighborProxy;
                }
                else {
                    DebugLog("server ipv6 build failed session=%s reason=invalid-mode mode=%d", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(), (int)mode);
                    return false;
                }

                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
                if (ec || !prefix.is_v6()) {
                    extensions.Clear();
                    DebugLog("server ipv6 build failed session=%s reason=invalid-cidr cidr=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(), ipv6.cidr.data());
                    return false;
                }

                if (mode == AppConfiguration::IPv6Mode_Gua && !IsGlobalUnicastIPv6Address(prefix.to_v6())) {
                    extensions.Clear();
                    extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                    extensions.IPv6StatusMessage = "server-gua-requires-global-unicast-cidr";
                    DebugLog("server ipv6 build failed session=%s reason=non-global-gua-cidr cidr=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(), ipv6.cidr.data());
                    return false;
                }

                if (configuration_->server.subnet && mode == AppConfiguration::IPv6Mode_Nat66 && ipv6.prefix_length > 0 && ipv6.prefix_length < 128) {
                    extensions.AssignedIPv6RoutePrefix = prefix;
                    extensions.AssignedIPv6RoutePrefixLength = static_cast<Byte>(ipv6.prefix_length);
                }

                boost::asio::ip::address_v6::bytes_type bytes = prefix.to_v6().to_bytes();
                if (!build_stable_ipv6(bytes, ipv6.prefix_length)) {
                    extensions.Clear();
                    DebugLog("server ipv6 build failed session=%s reason=stable-prefix-address", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                    return false;
                }
                boost::asio::ip::address_v6 stable_candidate = extensions.AssignedIPv6Address.to_v6();

                extensions.AssignedIPv6Address = boost::asio::ip::address();

                ppp::string session_guid = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                auto static_it = ipv6.static_addresses.find(session_guid);
                if (static_it != ipv6.static_addresses.end()) {
                    ec.clear();
                    boost::asio::ip::address static_address = StringToAddress(static_it->second, ec);
                    if (!ec && static_address.is_v6()) {
                        try_commit_ipv6_lease(static_address.to_v6(), true, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "static-binding");
                    }
                }

                boost::asio::ip::address_v6 requested_address = request_entry.RequestedAddress.is_v6() ? request_entry.RequestedAddress.to_v6() : boost::asio::ip::address_v6();
                bool use_requested_first = is_request_usable(requested_address, prefix.to_v6(), ipv6.prefix_length);

                if (!extensions.AssignedIPv6Address.is_v6()) {
                    boost::asio::ip::address leased_address;
                    {
                        SynchronizedObjectScope scope(syncobj_);
                        auto lease_it = ipv6_leases_.find(session_id);
                        if (lease_it != ipv6_leases_.end() && lease_it->second.Address.is_v6()) {
                            leased_address = lease_it->second.Address;
                        }
                    }
                    if (leased_address.is_v6()) {
                        try_commit_ipv6_lease(leased_address.to_v6(), false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, "lease-reused");
                    }
                }

                if (!extensions.AssignedIPv6Address.is_v6() && use_requested_first && request_entry.RequestedAddress.is_v6()) {
                    boost::asio::ip::address_v6 requested = request_entry.RequestedAddress.to_v6();
                    if (ppp::ipv6::PrefixMatch(requested, prefix.to_v6(), ipv6.prefix_length)) {
                        try_commit_ipv6_lease(requested, false, VirtualEthernetInformationExtensions::IPv6Status_ClientRequested, "client-request-accepted");
                    }
                }

                if (!extensions.AssignedIPv6Address.is_v6()) {
                    if (!try_commit_ipv6_lease(stable_candidate, false, VirtualEthernetInformationExtensions::IPv6Status_ServerAssigned, request_entry.RequestedAddress.is_v6() ? "client-request-replaced" : "server-auto-assigned")) {
                        extensions.Clear();
                        extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Rejected;
                        extensions.IPv6StatusMessage = "ipv6-address-unavailable";
                        return false;
                    }
                }

                boost::asio::ip::address gateway = GetIPv6TransitGateway();
                if (gateway.is_v6()) {
                    extensions.AssignedIPv6Gateway = gateway;
                }

                ec.clear();
                boost::asio::ip::address dns1 = StringToAddress(ipv6.dns1, ec);
                if (!ec && dns1.is_v6()) {
                    extensions.AssignedIPv6Dns1 = dns1;
                }

                ec.clear();
                boost::asio::ip::address dns2 = StringToAddress(ipv6.dns2, ec);
                if (!ec && dns2.is_v6()) {
                    extensions.AssignedIPv6Dns2 = dns2;
                }

                DebugLog("server ipv6 build result session=%s address=%s gateway=%s route=%s/%u dns1=%s dns2=%s flags=%u",
                    auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                    extensions.AssignedIPv6Address.is_v6() ? extensions.AssignedIPv6Address.to_string().c_str() : "",
                    extensions.AssignedIPv6Gateway.is_v6() ? extensions.AssignedIPv6Gateway.to_string().c_str() : "",
                    extensions.AssignedIPv6RoutePrefix.is_v6() ? extensions.AssignedIPv6RoutePrefix.to_string().c_str() : "",
                    (unsigned)extensions.AssignedIPv6RoutePrefixLength,
                    extensions.AssignedIPv6Dns1.is_v6() ? extensions.AssignedIPv6Dns1.to_string().c_str() : "",
                    extensions.AssignedIPv6Dns2.is_v6() ? extensions.AssignedIPv6Dns2.to_string().c_str() : "",
                    (unsigned)extensions.AssignedIPv6Flags);

                if (mode == AppConfiguration::IPv6Mode_Gua) {
                    DebugLog("server ipv6 gua semantics session=%s provider=%s assigned-prefix-length=%u",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        "kernel",
                        (unsigned)extensions.AssignedIPv6AddressPrefixLength);
                }

                if (extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Nat66 &&
                    extensions.AssignedIPv6Mode != VirtualEthernetInformationExtensions::IPv6Mode_Gua) {
                    DebugLog("server ipv6 build failed session=%s reason=invalid-assigned-mode mode=%u",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        (unsigned)extensions.AssignedIPv6Mode);
                    extensions.Clear();
                    return false;
                }

                return extensions.HasAny();
            }

            bool VirtualEthernetSwitcher::TryGetAssignedIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept {
                extensions.Clear();
                if (!IsIPv6ServerEnabled()) {
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                if (mode != AppConfiguration::IPv6Mode_Nat66 && mode != AppConfiguration::IPv6Mode_Gua) {
                    return false;
                }

                IPv6LeaseEntry lease;
                std::string lease_ip_std;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto lease_it = ipv6_leases_.find(session_id);
                    if (lease_it == ipv6_leases_.end() || !lease_it->second.Address.is_v6()) {
                        return false;
                    }
                    lease = lease_it->second;

                    lease_ip_std = lease.Address.to_string();
                    ppp::string lease_ip_key(lease_ip_std.data(), lease_ip_std.size());
                    auto owner_it = ipv6s_.find(lease_ip_key);
                    if (owner_it == ipv6s_.end() || !owner_it->second || owner_it->second->GetId() != session_id) {
                        return false;
                    }
                }

                boost::system::error_code ec;
                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
                if (ec || !prefix.is_v6()) {
                    return false;
                }

                if (!ppp::ipv6::PrefixMatch(lease.Address.to_v6(), prefix.to_v6(), ipv6.prefix_length)) {
                    return false;
                }

                extensions.AssignedIPv6Mode = mode == AppConfiguration::IPv6Mode_Nat66 ?
                    VirtualEthernetInformationExtensions::IPv6Mode_Nat66 :
                    VirtualEthernetInformationExtensions::IPv6Mode_Gua;
                extensions.AssignedIPv6AddressPrefixLength = 128;
                extensions.AssignedIPv6Address = lease.Address;
                extensions.AssignedIPv6Gateway = GetIPv6TransitGateway();
                if (mode == AppConfiguration::IPv6Mode_Gua) {
                    extensions.AssignedIPv6Flags |= VirtualEthernetInformationExtensions::IPv6Flag_NeighborProxy;
                }
                if (mode == AppConfiguration::IPv6Mode_Nat66 && configuration_->server.subnet && ipv6.prefix_length > 0 && ipv6.prefix_length < 128) {
                    extensions.AssignedIPv6RoutePrefix = prefix;
                    extensions.AssignedIPv6RoutePrefixLength = static_cast<Byte>(ipv6.prefix_length);
                }

                ec.clear();
                boost::asio::ip::address dns1 = StringToAddress(ipv6.dns1, ec);
                if (!ec && dns1.is_v6()) {
                    extensions.AssignedIPv6Dns1 = dns1;
                }

                ec.clear();
                boost::asio::ip::address dns2 = StringToAddress(ipv6.dns2, ec);
                if (!ec && dns2.is_v6()) {
                    extensions.AssignedIPv6Dns2 = dns2;
                }

                return extensions.AssignedIPv6Address.is_v6();
            }

            bool VirtualEthernetSwitcher::AddIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept {
                if (!extensions.AssignedIPv6Address.is_v6()) {
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                const boost::asio::ip::address& ip = extensions.AssignedIPv6Address;
                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                if (NULLPTR == exchanger) {
                    return false;
                }

                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto existing = ipv6s_.find(ip_key);
                    if (existing != ipv6s_.end() && existing->second && existing->second->GetId() != session_id) {
                        DebugLog("server ipv6 exchanger rejected session=%s reason=address-mapped-to-other-session address=%s owner=%s",
                            auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                            ip.to_string().c_str(),
                            auxiliary::StringAuxiliary::Int128ToGuidString(existing->second->GetId()).data());
                        return false;
                    }
                }

                bool route_ok = AddIPv6TransitRoute(ip, 128);
                if (!route_ok) {
                    DebugLog("server ipv6 exchanger rejected session=%s reason=transit-route-install-failed address=%s",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        ip.to_string().c_str());
                    return false;
                }

                bool proxy_required = mode == AppConfiguration::IPv6Mode_Gua;
                bool proxy_ok = !proxy_required || AddIPv6NeighborProxy(ip);
                if (!proxy_ok) {
                    DeleteIPv6TransitRoute(ip, 128);
                    DebugLog("server ipv6 exchanger rejected session=%s reason=neighbor-proxy-install-failed address=%s",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        ip.to_string().c_str());
                    return false;
                }

                {
                    SynchronizedObjectScope scope(syncobj_);
                    for (auto tail = ipv6s_.begin(); tail != ipv6s_.end();) {
                        VirtualEthernetExchangerPtr current = tail->second;
                        if (current && current->GetId() == session_id && tail->first != ip_key) {
                            boost::system::error_code stale_ec;
                            boost::asio::ip::address stale_ip = StringToAddress(tail->first, stale_ec);
                            if (!stale_ec && stale_ip.is_v6()) {
                                DeleteIPv6TransitRoute(stale_ip, 128);
                                DeleteIPv6NeighborProxy(stale_ip);
                            }
                            tail = ipv6s_.erase(tail);
                        }
                        else {
                            ++tail;
                        }
                    }
                    ipv6s_[ip_key] = exchanger;
                }
                return true;
            }

            bool VirtualEthernetSwitcher::DeleteIPv6Exchanger(const Int128& session_id, const VirtualEthernetInformationExtensions& extensions) noexcept {
                if (!extensions.AssignedIPv6Address.is_v6()) {
                    return false;
                }

                const boost::asio::ip::address& ip = extensions.AssignedIPv6Address;
                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = ipv6s_.find(ip_key);
                    if (tail == ipv6s_.end()) {
                        return false;
                    }

                    if (tail->second && tail->second->GetId() != session_id) {
                        return false;
                    }

                    DeleteIPv6TransitRoute(ip, 128);
                    DeleteIPv6NeighborProxy(ip);
                    ipv6s_.erase(tail);
                }
                return true;
            }

            bool VirtualEthernetSwitcher::DeleteIPv6Exchanger(const Int128& session_id) noexcept {
                bool any = false;

                SynchronizedObjectScope scope(syncobj_);
                for (auto tail = ipv6s_.begin(); tail != ipv6s_.end();) {
                    VirtualEthernetExchangerPtr current = tail->second;
                    if (!current || current->GetId() != session_id) {
                        ++tail;
                        continue;
                    }

                    boost::system::error_code ec;
                    boost::asio::ip::address ip = StringToAddress(tail->first, ec);
                    if (!ec && ip.is_v6()) {
                        DeleteIPv6TransitRoute(ip, 128);
                        DeleteIPv6NeighborProxy(ip);
                    }

                    tail = ipv6s_.erase(tail);
                    any = true;
                }

                return any;
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::FindIPv6Exchanger(const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v6()) {
                    return NULLPTR;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                SynchronizedObjectScope scope(syncobj_);
                auto tail = ipv6s_.find(ip_key);
                if (tail != ipv6s_.end()) {
                    return tail->second;
                }
                return NULLPTR;
            }

            bool VirtualEthernetSwitcher::OpenIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                CloseIPv6NeighborProxyIfNeed();
                if (!IsIPv6ServerEnabled() || ipv6.mode != AppConfiguration::IPv6Mode_Gua) {
                    return true;
                }

                DebugLog("server ipv6 neighbor proxy provider=%s", "kernel");

                ppp::string uplink_name = ResolvePreferredIPv6UplinkInterface(preferred_nic_);
                if (uplink_name.empty()) {
                    return false;
                }

                bool proxy_enabled = false;
                bool query_ok = ppp::tap::TapLinux::QueryIPv6NeighborProxy(uplink_name, proxy_enabled);
                if (!ppp::tap::TapLinux::EnableIPv6NeighborProxy(uplink_name)) {
                    return false;
                }

                ipv6_neighbor_proxy_ifname_ = uplink_name;
                ipv6_neighbor_proxy_owned_ = query_ok ? !proxy_enabled : false;
                DebugLog("server ipv6 neighbor proxy enabled if=%s owned=%s", uplink_name.data(), ipv6_neighbor_proxy_owned_ ? "yes" : "no");
#else
                if (IsIPv6ServerEnabled()) {
                    DebugLog("server ipv6 neighbor proxy ignored reason=unsupported-platform");
                }
#endif
                return true;
            }

            bool VirtualEthernetSwitcher::CloseIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                if (ipv6_neighbor_proxy_ifname_.empty()) {
                    return true;
                }

                bool ok = true;
                if (ipv6_neighbor_proxy_owned_) {
                    ok = ppp::tap::TapLinux::DisableIPv6NeighborProxy(ipv6_neighbor_proxy_ifname_);
                }
                DebugLog("server ipv6 neighbor proxy disabled if=%s status=%s owned=%s", ipv6_neighbor_proxy_ifname_.data(), ok ? "ok" : "fail", ipv6_neighbor_proxy_owned_ ? "yes" : "no");
                ipv6_neighbor_proxy_ifname_.clear();
                ipv6_neighbor_proxy_owned_ = false;
#endif
                return true;
            }

            bool VirtualEthernetSwitcher::AddIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6()) {
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                if (!IsIPv6ServerEnabled()) {
                    return false;
                }

                AppConfiguration::IPv6Mode mode = ipv6.mode;
                if (!(mode == AppConfiguration::IPv6Mode_Nat66 || mode == AppConfiguration::IPv6Mode_Gua)) {
                    return false;
                }

                ITapPtr tap = ipv6_transit_tap_;
                if (NULLPTR == tap) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
                bool ok = ppp::tap::TapLinux::AddRoute6(tap->GetId(), ip_str, prefix_length, ppp::string());
                DebugLog("server ipv6 transit route %s name=%s ip=%s/%d", ok ? "add-ok" : "add-fail", tap->GetId().data(), ip_str.data(), prefix_length);
                return ok;
#else
                return false;
#endif
            }

            bool VirtualEthernetSwitcher::DeleteIPv6TransitRoute(const boost::asio::ip::address& ip, int prefix_length) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6()) {
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                if (!IsIPv6ServerEnabled()) {
                    return false;
                }

                AppConfiguration::IPv6Mode mode = ipv6.mode;
                if (!(mode == AppConfiguration::IPv6Mode_Nat66 || mode == AppConfiguration::IPv6Mode_Gua)) {
                    return false;
                }

                ITapPtr tap = ipv6_transit_tap_;
                if (NULLPTR == tap) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                prefix_length = std::max<int>(0, std::min<int>(128, prefix_length));
                bool ok = ppp::tap::TapLinux::DeleteRoute6(tap->GetId(), ip_str, prefix_length, ppp::string());
                DebugLog("server ipv6 transit route %s name=%s ip=%s/%d", ok ? "del-ok" : "del-fail", tap->GetId().data(), ip_str.data(), prefix_length);
                return ok;
#else
                return false;
#endif
            }

            void VirtualEthernetSwitcher::ClearIPv6ExchangersUnsafe() noexcept {
                for (const auto& kv : ipv6s_) {
                    boost::system::error_code ec;
                    boost::asio::ip::address ip = StringToAddress(kv.first, ec);
                    if (ec || !ip.is_v6()) {
                        continue;
                    }

                    DeleteIPv6TransitRoute(ip, 128);
                    DeleteIPv6NeighborProxy(ip);
                }

                ipv6s_.clear();
            }

            bool VirtualEthernetSwitcher::AddIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                if (ipv6.mode != AppConfiguration::IPv6Mode_Gua) {
                    return true;
                }

                if (!ip.is_v6() || ipv6_neighbor_proxy_ifname_.empty()) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::AddIPv6NeighborProxy(ipv6_neighbor_proxy_ifname_, ip_str);
                DebugLog("server ipv6 neighbor proxy %s if=%s ip=%s", ok ? "add-ok" : "add-fail", ipv6_neighbor_proxy_ifname_.data(), ip_str.data());
                return ok;
#else
                return false;
#endif
            }

            bool VirtualEthernetSwitcher::DeleteIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6() || ipv6_neighbor_proxy_ifname_.empty()) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::DeleteIPv6NeighborProxy(ipv6_neighbor_proxy_ifname_, ip_str);
                DebugLog("server ipv6 neighbor proxy %s if=%s ip=%s", ok ? "del-ok" : "del-fail", ipv6_neighbor_proxy_ifname_.data(), ip_str.data());
                return ok;
#else
                return false;
#endif
            }

            bool VirtualEthernetSwitcher::DeleteIPv6NeighborProxy(const ppp::string& ifname, const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6() || ifname.empty()) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::DeleteIPv6NeighborProxy(ifname, ip_str);
                DebugLog("server ipv6 neighbor proxy %s if=%s ip=%s", ok ? "del-ok" : "del-fail", ifname.data(), ip_str.data());
                return ok;
#else
                return false;
#endif
            }

            bool VirtualEthernetSwitcher::Run() noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }

                auto self = shared_from_this();
                bool bany = false;
                for (int categories = NetworkAcceptorCategories_Min; categories < NetworkAcceptorCategories_Max; categories++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[categories];
                    if (NULLPTR == acceptor) {
                        continue;
                    }

                    bool bok = Socket::AcceptLoopbackAsync(acceptor, 
                        [self, this, acceptor, categories](const Socket::AsioContext& context, const Socket::AsioTcpSocket& socket) noexcept {
                            if (!Socket::AdjustDefaultSocketOptional(*socket, configuration_->tcp.turbo)) {
                                return false;
                            }

                            ppp::net::Socket::SetWindowSizeIfNotZero(socket->native_handle(), configuration_->tcp.cwnd, configuration_->tcp.rwnd);
                            return !disposed_ && Accept(context, socket, categories);
                        });

                    if (bok) {
                        bany = true;
                    }
                    else {
                        Socket::Closesocket(acceptor);
                        acceptors_[categories] = NULLPTR;
                    }
                }
                return bany;
            }

            static constexpr int STATUS_ERROR = -1;
            static constexpr int STATUS_RUNING = +1;
            static constexpr int STATUS_RUNNING_SWAP = +0;

            int VirtualEthernetSwitcher::Run(const ContextPtr& context, const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (disposed_) {
                    return STATUS_ERROR;
                }
        
                bool mux = false;
                Int128 session_id = transmission->HandshakeClient(y, mux);
                if (session_id == 0) {
                    return STATUS_ERROR;
                }

                if (!mux) {
                    return Connect(transmission, session_id, y);
                }

                VirtualEthernetManagedServerPtr managed_server = managed_server_;
                if (NULLPTR == managed_server) {
                    return Establish(transmission, session_id, NULLPTR, y) ? STATUS_RUNING : STATUS_ERROR;
                }
                
                VirtualEthernetExchanger* exchanger = GetExchanger(session_id).get(); 
                if (NULLPTR != exchanger) {
                    return Establish(transmission, session_id, NULLPTR, y) ? STATUS_RUNING : STATUS_ERROR;
                }

                auto self = shared_from_this();
                return managed_server->AuthenticationToManagedServer(session_id,
                    [self, this, transmission, session_id, context](bool ok, VirtualEthernetManagedServer::VirtualEthernetInformationPtr& i) noexcept {
                        auto allocator = transmission->BufferAllocator;
                        if (ok) {
                            ok = YieldContext::Spawn(allocator.get(), *context,
                                [self, this, context, transmission, session_id, i](YieldContext& y) noexcept {
                                    if (y) {
                                        Establish(transmission, session_id, i, y);
                                    }

                                    transmission->Dispose();
                                });
                        }

                        if (!ok) {
                            transmission->Dispose();
                        }
                    }) ? STATUS_RUNNING_SWAP : STATUS_ERROR;
            }

            bool VirtualEthernetSwitcher::Accept(const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket, int categories) noexcept {
                if (categories == NetworkAcceptorCategories_CDN1 || categories == NetworkAcceptorCategories_CDN2) {
                    std::shared_ptr<ppp::net::proxies::sniproxy> sniproxy = make_shared_object<ppp::net::proxies::sniproxy>(categories == NetworkAcceptorCategories_CDN1 ? 0 : 1,
                        configuration_,
                        context,
                        socket);
                    if (NULLPTR == sniproxy) {
                        return false;
                    }

                    bool ok = sniproxy->handshake();
                    if (!ok) {
                        sniproxy->close();
                    }

                    return ok;
                }
                else {
                    ITransmissionPtr transmission = Accept(categories, context, socket);
                    if (NULLPTR == transmission) {
                        return false;
                    }

                    auto allocator = transmission->BufferAllocator;
                    auto self = shared_from_this();
                    return YieldContext::Spawn(allocator.get(), *context,
                        [self, this, context, transmission](YieldContext& y) noexcept {
                            int status = Run(context, transmission, y);
                            if (status != STATUS_RUNNING_SWAP) {
                                if (status < STATUS_RUNNING_SWAP) {
                                    FlowerArrangement(
                                        transmission, 
                                        y);
                                }

                                transmission->Dispose();
                            }
                        });
                }
            }

            bool VirtualEthernetSwitcher::FlowerArrangement(const ITransmissionPtr& transmission, YieldContext& y) noexcept {
                if (NULLPTR == transmission) {
                    return false;
                }
                
                return ppp::transmissions::Transmission_Handshake_Nop(configuration_, transmission.get(), y);
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::GetExchanger(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULLPTR;
                }

                return Dictionary::FindObjectByKey(exchangers_, session_id);
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::AddNewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                VirtualEthernetExchangerPtr newExchanger;
                VirtualEthernetExchangerPtr oldExchanger;

                bool ok = false;
                if (NULLPTR != transmission) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return NULLPTR;
                    }

                    newExchanger = NewExchanger(transmission, session_id);
                    if (NULLPTR == newExchanger) {
                        return NULLPTR;
                    }

                    if (newExchanger->Open()) {
                        VirtualEthernetExchangerPtr& tmpExchanger = exchangers_[session_id];
                        ok = true;
                        oldExchanger = tmpExchanger;
                        tmpExchanger = newExchanger;
                    }
                }

                IDisposable::Dispose(oldExchanger);
                if (ok) {
                    return newExchanger;
                }

                IDisposable::Dispose(newExchanger);
                return NULLPTR;
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::NewExchanger(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                auto self = shared_from_this();
                return make_shared_object<VirtualEthernetExchanger>(self, configuration_, transmission, session_id);
            }

            bool VirtualEthernetSwitcher::Establish(const ITransmissionPtr& transmission, const Int128& session_id, const VirtualEthernetInformationPtr& i, YieldContext& y) noexcept {
                if (NULLPTR == transmission) {
                    return false;
                }

                VirtualEthernetExchangerPtr channel = AddNewExchanger(transmission, session_id);
                if (NULLPTR == channel) {
                    return false;
                }

                VirtualEthernetInformation fallback_information;
                const VirtualEthernetInformation* established_information = i.get();
                if (NULLPTR == established_information && IsIPv6ServerEnabled() && configuration_->server.backend.empty()) {
                    fallback_information.Clear();
                    fallback_information.BandwidthQoS = 0;
                    fallback_information.IncomingTraffic = std::numeric_limits<UInt64>::max();
                    fallback_information.OutgoingTraffic = std::numeric_limits<UInt64>::max();
                    fallback_information.ExpiredTime = std::numeric_limits<UInt32>::max();
                    established_information = &fallback_information;
                    const char* reason = "no-managed-backend";
                    DebugLog("server establish using local bootstrap info session=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                    DebugLog("server establish info source=local-bootstrap reason=%s session=%s", reason, auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                }

                if (NULLPTR == established_information && !configuration_->server.backend.empty()) {
                    DebugLog("server establish aborted reason=managed-info-empty session=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                    DeleteExchanger(channel.get());
                    return false;
                }

                bool run = true;
                if (NULLPTR != established_information) {
                    InformationEnvelope envelope = BuildInformationEnvelope(session_id, *established_information);
                    DebugLog("server info send establish session=%s json=%s",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        envelope.ExtendedJson.data());
                    if (envelope.Extensions.AssignedIPv6Address.is_v6() && !AddIPv6Exchanger(session_id, envelope.Extensions)) {
                        RevokeIPv6Lease(session_id);
                        DeleteIPv6Exchanger(session_id);
                        envelope.Extensions.AssignedIPv6Address = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Gateway = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6RoutePrefix = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6RoutePrefixLength = 0;
                        envelope.Extensions.AssignedIPv6Dns1 = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Dns2 = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Flags = 0;
                        envelope.Extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Failed;
                        envelope.Extensions.IPv6StatusMessage = "server-ipv6-dataplane-install-failed";
                    }
                    run = channel->DoInformation(transmission, envelope, y);
                    if (run) {
                        run = VirtualEthernetInformation::Valid(const_cast<VirtualEthernetInformation*>(established_information), (UInt32)(GetTickCount() / 1000));
                    }
                }

                if (run) {
                    VirtualEthernetLoggerPtr logger = GetLogger(); 
                    if (NULLPTR != logger) {
                        logger->Vpn(session_id, transmission);
                    }

                    run = channel->Run(transmission, y);
                }

                DeleteExchanger(channel.get());
                return run;
            }

            VirtualEthernetSwitcher::FirewallPtr VirtualEthernetSwitcher::NewFirewall() noexcept {
                return make_shared_object<Firewall>();
            }

            int VirtualEthernetSwitcher::Connect(const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept {
                // VPN client A link can be created only after a link is established between the local switch and the remote VPN server.
                if (y) {
                    VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                    if (NULLPTR == exchanger) {
                        return STATUS_ERROR;
                    }

                    ITransmissionPtr owner = exchanger->GetTransmission();
                    if (NULLPTR != owner) {
                        std::shared_ptr<ITransmissionStatistics> left = owner->Statistics;
                        std::shared_ptr<ITransmissionStatistics> reft = transmission->Statistics;
                        if (left != reft) {
                            if (NULLPTR != reft) {
                                left->IncomingTraffic += reft->IncomingTraffic;
                                left->OutgoingTraffic += reft->OutgoingTraffic;
                            }

                            transmission->Statistics = left;
                        }
                    }
                }

                auto self = shared_from_this();
                auto run =
                    [self, this](const ITransmissionPtr& transmission, const Int128& session_id, YieldContext& y) noexcept {
                        VirtualEthernetNetworkTcpipConnectionPtr connection = AddNewConnection(transmission, session_id);
                        if (NULLPTR == connection) {
                            return -1;
                        }
                        elif(connection->Run(y)) {
                            if (connection->IsMux()) {
                                SynchronizedObjectScope scope(syncobj_);
                                if (Dictionary::RemoveValueByKey(connections_, (void*)connection.get())) {
                                    return 0;
                                }
                                else {
                                    return -1; // The rear check, which is beyond the expected design, is roughly possible that the switch is being released.
                                }
                            }

                            return 1;
                        }
                        else {
                            return -1;
                        }
                    };

                // Transfer the current link to the scheduler for processing, if the transfer succeeds.
                if (transmission->ShiftToScheduler()) {
                    ppp::threading::Executors::ContextPtr scheduler = transmission->GetContext();
                    ppp::threading::Executors::StrandPtr strand = transmission->GetStrand();
                    std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = transmission->BufferAllocator;

                    return YieldContext::Spawn(allocator.get(), *scheduler, strand.get(),
                        [scheduler, strand, run, transmission, session_id](YieldContext& y) noexcept {
                            int status = run(transmission, session_id, y);
                            if (status != 0) {
                                transmission->Dispose();
                            }
                        }) ? STATUS_RUNNING_SWAP : STATUS_ERROR;
                }
                else {
                    int status = run(transmission, session_id, y);
                    if (status < 0) {
                        return STATUS_ERROR;
                    }
                    elif(status > 0) {
                        return STATUS_RUNING;
                    }
                    else {
                        return STATUS_RUNNING_SWAP;
                    }
                }
            }

            VirtualEthernetSwitcher::VirtualEthernetNetworkTcpipConnectionPtr VirtualEthernetSwitcher::AddNewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                std::shared_ptr<VirtualEthernetNetworkTcpipConnection> connection = NewConnection(transmission, session_id);
                if (NULLPTR == connection) {
                    return NULLPTR;
                }
                else {
                    SynchronizedObjectScope scope(syncobj_);
                    if (disposed_) {
                        return NULLPTR;
                    }

                    if (Dictionary::TryAdd(connections_, connection.get(), connection)) {
                        return connection;
                    }
                }

                connection->Dispose();
                return NULLPTR;
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::DeleteExchanger(VirtualEthernetExchanger* exchanger) noexcept {
                VirtualEthernetExchangerPtr channel;
                if (NULLPTR != exchanger) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (auto tail = exchangers_.find(exchanger->GetId()); tail != exchangers_.end()) {
                        const VirtualEthernetExchangerPtr& p = tail->second;
                        if (p.get() == exchanger) {
                            channel = std::move(tail->second);
                            exchangers_.erase(tail);
                        }
                    }
                }

                if (channel) {
                    channel->Dispose();
                }
                return channel;
            }

            VirtualEthernetSwitcher::VirtualEthernetNetworkTcpipConnectionPtr VirtualEthernetSwitcher::NewConnection(const ITransmissionPtr& transmission, const Int128& session_id) noexcept {
                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                std::shared_ptr<VirtualEthernetSwitcher> self = shared_from_this();
                return make_shared_object<VirtualEthernetNetworkTcpipConnection>(self, session_id, transmission);
            }

            VirtualEthernetSwitcher::VirtualEthernetLoggerPtr VirtualEthernetSwitcher::NewLogger() noexcept {
                ppp::string& log = configuration_->server.log;
                if (log.empty()) {
                    return NULLPTR;
                }

                VirtualEthernetLoggerPtr logger = make_shared_object<VirtualEthernetLogger>(context_, log);
                if (NULLPTR == logger) {
                    return NULLPTR;
                }

                if (logger->Valid()) {
                    return logger;
                }

                IDisposable::Dispose(logger);
                return NULLPTR;
            }

            bool VirtualEthernetSwitcher::CreateAllAcceptors() noexcept {
                if (disposed_) {
                    return false;
                }

                int acceptor_ports[NetworkAcceptorCategories_Max];
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[i];
                    if (NULLPTR != acceptor) {
                        return false;
                    }

                    acceptor_ports[i] = IPEndPoint::MinPort;
                }

                boost::asio::ip::address interface_ips[] = { GetInterfaceIP(), boost::asio::ip::address_v6::any(), boost::asio::ip::address_v4::any() };
                acceptor_ports[NetworkAcceptorCategories_Tcpip] = configuration_->tcp.listen.port;
                acceptor_ports[NetworkAcceptorCategories_WebSocket] = configuration_->websocket.listen.ws;
                acceptor_ports[NetworkAcceptorCategories_WebSocketSSL] = configuration_->websocket.listen.wss;
                acceptor_ports[NetworkAcceptorCategories_CDN1] = configuration_->cdn[0];
                acceptor_ports[NetworkAcceptorCategories_CDN2] = configuration_->cdn[1];

                bool bany = false;
                auto& cfg = configuration_->tcp;
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    int port = acceptor_ports[i];
                    if (port <= IPEndPoint::MinPort || port > IPEndPoint::MaxPort) {
                        continue;
                    }

                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = make_shared_object<boost::asio::ip::tcp::acceptor>(*context_);
                    if (NULLPTR == acceptor) {
                        return false;
                    }

                    for (boost::asio::ip::address& interface_ip : interface_ips) {
                        if (Socket::OpenAcceptor(*acceptor, interface_ip, port, cfg.backlog, cfg.fast_open, cfg.turbo)) {
                            Socket::SetWindowSizeIfNotZero(acceptor->native_handle(), cfg.cwnd, cfg.rwnd);
                            bany |= true;
                            acceptors_[i] = std::move(acceptor);
                            break;
                        }
                        elif(!Socket::Closesocket(*acceptor)) {
                            return false;
                        }
                    }
                }
                
                return bany;
            }

            bool VirtualEthernetSwitcher::Open(const ppp::string& firewall_rules) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }

                if (timeout_) {
                    return false;
                }

                ipv6s_.clear();
                ipv6_requests_.clear();
                ipv6_leases_.clear();

                bool ok = CreateAllAcceptors() &&
                    CreateAlwaysTimeout() &&
                    CreateFirewall(firewall_rules) &&
                    OpenManagedServerIfNeed() &&
                    OpenIPv6TransitIfNeed() &&
                    OpenNamespaceCacheIfNeed() &&
                    OpenDatagramSocket() &&
                    OpenIPv6NeighborProxyIfNeed();
                if (ok) {
                    OpenLogger();
                }

                return ok;
            }

            bool VirtualEthernetSwitcher::OpenNamespaceCacheIfNeed() noexcept {
                int ttl = configuration_->udp.dns.ttl;
                if (ttl > 0) {
                    VirtualEthernetNamespaceCachePtr cache = NewNamespaceCache(ttl);
                    if (NULLPTR == cache) {
                        return false;
                    }

                    namespace_cache_ = std::move(cache);
                }

                return true;
            }

            bool VirtualEthernetSwitcher::SendIPv6TransitPacket(Byte* packet, int packet_length) noexcept {
                ITapPtr tap = ipv6_transit_tap_;
                if (NULLPTR == tap || NULLPTR == packet || packet_length < 40) {
                    return false;
                }

#if defined(_LINUX)
                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    VirtualEthernetExchangerPtr exchanger = FindIPv6Exchanger(destination);
                    if (NULLPTR != exchanger) {
                        int affinity_fd = exchanger->GetPreferredTunFd();
                        if (affinity_fd >= 0) {
                            DebugLog("server ipv6 transit preferred-fd hit session=%s fd=%d", auxiliary::StringAuxiliary::Int128ToGuidString(exchanger->GetId()).data(), affinity_fd);
                            int last_fd = ppp::tap::TapLinux::SetLastHandle(affinity_fd);
                            bool ok = tap->Output(packet, packet_length);
                            ppp::tap::TapLinux::SetLastHandle(last_fd);
                            return ok;
                        }
                    }
                }
#endif

                return tap->Output(packet, packet_length);
            }

            bool VirtualEthernetSwitcher::SendIPv6PacketToClient(const ITransmissionPtr& transmission, Byte* packet, int packet_length) noexcept {
                if (NULLPTR == transmission || NULLPTR == packet || packet_length < 1) {
                    return false;
                }

                ppp::io::MemoryStream ms;
                if (!ms.WriteByte((Byte)app::protocol::VirtualEthernetLinklayer::PacketAction_NAT)) {
                    return false;
                }

                if (!ms.Write(packet, 0, packet_length)) {
                    return false;
                }

                std::shared_ptr<Byte> buffer = ms.GetBuffer();
                return transmission->Write(buffer.get(), ms.GetPosition(),
                    [transmission](bool ok) noexcept {
                        if (!ok) {
                            transmission->Dispose();
                        }
                    });
            }

            bool VirtualEthernetSwitcher::ReceiveIPv6TransitPacket(Byte* packet, int packet_length) noexcept {
                if (NULLPTR == packet || packet_length < 40) {
                    return false;
                }

                boost::asio::ip::address_v6 source;
                boost::asio::ip::address_v6 destination;
                if (!ppp::ipv6::TryParsePacket(packet, packet_length, source, destination)) {
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                boost::system::error_code prefix_ec;
                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, prefix_ec);
                if (!prefix_ec && prefix.is_v6()) {
                    int allowed_prefix_length = std::max<int>(0, std::min<int>(128, ipv6.prefix_length));
                    if (!ppp::ipv6::PrefixMatch(destination, prefix.to_v6(), allowed_prefix_length)) {
                        DebugLog("server ipv6 transit rejected reason=destination-outside-cidr destination=%s cidr=%s",
                            destination.to_string().c_str(),
                            ipv6.cidr.data());
                        return false;
                    }

                    if (source.is_unspecified() || source.is_multicast() || source.is_loopback()) {
                        DebugLog("server ipv6 transit rejected reason=invalid-source-class source=%s",
                            source.to_string().c_str());
                        return false;
                    }

                    boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                    bool source_is_transit_gateway = transit_gateway.is_v6() && source == transit_gateway.to_v6();
                    if (!source_is_transit_gateway && ppp::ipv6::PrefixMatch(source, prefix.to_v6(), allowed_prefix_length)) {
                        VirtualEthernetExchangerPtr source_owner = FindIPv6Exchanger(source);
                        if (mode != AppConfiguration::IPv6Mode_Gua || source_owner != NULLPTR) {
                            DebugLog("server ipv6 transit rejected reason=source-inside-vpn-cidr source=%s cidr=%s",
                                source.to_string().c_str(),
                                ipv6.cidr.data());
                            return false;
                        }
                    }
                }

                VirtualEthernetExchangerPtr exchanger = FindIPv6Exchanger(destination);
                if (NULLPTR == exchanger) {
                    return false;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

#if defined(_LINUX)
                exchanger->SetPreferredTunFd(ppp::tap::TapLinux::GetLastHandle());
#endif

                app::protocol::ClampTcpMssIPv6(packet, packet_length, app::protocol::ComputeDynamicTcpMss(false, 80));

                return SendIPv6PacketToClient(transmission, packet, packet_length);
            }

            bool VirtualEthernetSwitcher::OpenIPv6TransitIfNeed() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                AppConfiguration::IPv6Mode mode = ipv6.mode;
                bool enable_transit = IsIPv6ServerEnabled() && (mode == AppConfiguration::IPv6Mode_Nat66 || mode == AppConfiguration::IPv6Mode_Gua);
                if (!enable_transit) {
                    return true;
                }

                boost::system::error_code ec;
                ppp::string prefix_string = ipv6.cidr;
                std::size_t slash = prefix_string.find('/');
                if (slash != ppp::string::npos) {
                    prefix_string = prefix_string.substr(0, slash);
                }
                boost::asio::ip::address prefix = StringToAddress(prefix_string, ec);
                if (ec || !prefix.is_v6()) {
                    return false;
                }

                boost::asio::ip::address transit_gateway = GetIPv6TransitGateway();
                boost::asio::ip::address_v6 transit = prefix.to_v6();
                if (transit.is_unspecified()) {
                    boost::asio::ip::address_v6::bytes_type bytes = {};
                    bytes[0] = 0xfd;
                    bytes[1] = 0x42;
                    bytes[2] = 0x42;
                    bytes[3] = 0x42;
                    bytes[4] = 0x42;
                    bytes[15] = 1;
                    transit = boost::asio::ip::address_v6(bytes);
                }

                if (transit_gateway.is_v6()) {
                    transit = transit_gateway.to_v6();
                }
                else {
                    boost::asio::ip::address_v6 derived_transit;
                    if (!TryGetFirstHostIPv6(transit, derived_transit)) {
                        return false;
                    }
                    transit = derived_transit;
                }

                std::string transit_std = transit.to_string();
                ppp::string transit_ip(transit_std.data(), transit_std.size());
                int prefix_length = mode == AppConfiguration::IPv6Mode_Gua ? 128 : std::max<int>(1, std::min<int>(128, ipv6.prefix_length));

                ppp::vector<ppp::string> no_dns;
                ppp::string tun_name = tun_name_;
                if (tun_name.empty()) {
                    tun_name = BOOST_BEAST_VERSION_STRING;
                }

                ITapPtr tap = ppp::tap::ITap::Create(context_, tun_name, "169.254.254.1", "169.254.254.2", "255.255.255.252", false, false, no_dns);
                if (NULLPTR == tap || !tap->Open()) {
                    return false;
                }

                bool address_ok = ppp::tap::TapLinux::SetIPv6Address(tap->GetId(), transit_ip, prefix_length);
                DebugLog("server ipv6 transit address %s name=%s address=%s/%d", address_ok ? "ok" : "fail", tap->GetId().data(), transit_ip.data(), prefix_length);
                if (!address_ok) {
                    tap->Dispose();
                    return false;
                }

                DebugLog("server ipv6 transit connected route managed by kernel name=%s cidr=%s", tap->GetId().data(), ipv6.cidr.data());

                tap->PacketInput =
                    [self = shared_from_this()](ppp::tap::ITap* sender, ppp::tap::ITap::PacketInputEventArgs& e) noexcept -> bool {
                        if (NULLPTR == sender || NULLPTR == e.Packet || e.PacketLength < 40) {
                            return false;
                        }

                        auto switcher = std::dynamic_pointer_cast<VirtualEthernetSwitcher>(self);
                        if (NULLPTR == switcher) {
                            return false;
                        }

                        return switcher->ReceiveIPv6TransitPacket(reinterpret_cast<Byte*>(e.Packet), e.PacketLength);
                    };

                if (!OpenIPv6TransitSsmtIfNeed(tap)) {
                    tap->Dispose();
                    return false;
                }

                ipv6_transit_tap_ = tap;
                DebugLog("server ipv6 transit tap opened name=%s address=%s/%d", tap->GetId().data(), transit_ip.data(), prefix_length);
#else
                if (IsIPv6ServerEnabled()) {
                    DebugLog("server ipv6 transit ignored reason=unsupported-platform");
                }
#endif
                return true;
            }

            bool VirtualEthernetSwitcher::RefreshIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                if (!IsIPv6ServerEnabled() || ipv6.mode != AppConfiguration::IPv6Mode_Gua) {
                    return true;
                }

                ppp::string uplink_name = ResolvePreferredIPv6UplinkInterface(preferred_nic_);

                if (uplink_name.empty()) {
                    return false;
                }

                ppp::string old_ifname;
                bool old_owned = false;
                ppp::vector<std::pair<Int128, boost::asio::ip::address>> replay_entries;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    old_ifname = ipv6_neighbor_proxy_ifname_;
                    old_owned = ipv6_neighbor_proxy_owned_;
                    replay_entries.reserve(ipv6s_.size());
                    for (const auto& kv : ipv6s_) {
                        if (!kv.second) {
                            continue;
                        }

                        boost::system::error_code ec;
                        boost::asio::ip::address ip = StringToAddress(kv.first, ec);
                        if (ec || !ip.is_v6()) {
                            continue;
                        }

                        replay_entries.emplace_back(kv.second->GetId(), ip);
                    }
                }

                bool proxy_enabled = false;
                bool query_ok = ppp::tap::TapLinux::QueryIPv6NeighborProxy(uplink_name, proxy_enabled);
                if (!ppp::tap::TapLinux::EnableIPv6NeighborProxy(uplink_name)) {
                    return false;
                }

                if (!old_ifname.empty() && old_ifname != uplink_name) {
                    for (const auto& entry : replay_entries) {
                        DeleteIPv6NeighborProxy(old_ifname, entry.second);
                    }

                    if (old_owned) {
                        ppp::tap::TapLinux::DisableIPv6NeighborProxy(old_ifname);
                    }
                }

                {
                    SynchronizedObjectScope scope(syncobj_);
                    ipv6_neighbor_proxy_ifname_ = uplink_name;
                    ipv6_neighbor_proxy_owned_ = old_ifname == uplink_name ? old_owned : (query_ok ? !proxy_enabled : false);
                }

                ppp::vector<Int128> broken_sessions;
                for (const auto& entry : replay_entries) {
                    const boost::asio::ip::address& ip = entry.second;
                    bool route_ok = AddIPv6TransitRoute(ip, 128);
                    bool proxy_ok = AddIPv6NeighborProxy(ip);
                    DebugLog("server ipv6 neighbor proxy replay session-address=%s route=%s proxy=%s",
                        ip.to_string().c_str(),
                        route_ok ? "ok" : "fail",
                        proxy_ok ? "ok" : "fail");
                    if (!route_ok || !proxy_ok) {
                        broken_sessions.emplace_back(entry.first);
                    }
                }

                for (const Int128& session_id : broken_sessions) {
                    RevokeIPv6Lease(session_id);
                    DeleteIPv6Exchanger(session_id);
                }

                if (!broken_sessions.empty()) {
                    return false;
                }
#endif
                return true;
            }

            bool VirtualEthernetSwitcher::OpenIPv6TransitSsmtIfNeed(const ITapPtr& tap) noexcept {
#if defined(_LINUX)
                if (tun_ssmt_ <= 0 || !tun_ssmt_mq_) {
                    return true;
                }

                auto linux_tap = std::dynamic_pointer_cast<ppp::tap::TapLinux>(tap);
                if (NULLPTR == linux_tap) {
                    return false;
                }

                ppp::vector<std::shared_ptr<boost::asio::io_context>> contexts;
                contexts.reserve(tun_ssmt_);
                for (int i = 0; i < tun_ssmt_; ++i) {
                    std::shared_ptr<boost::asio::io_context> worker = make_shared_object<boost::asio::io_context>();
                    if (NULLPTR == worker) {
                        for (auto& context : contexts) {
                            context->stop();
                        }
                        return false;
                    }

                    std::thread ssmt_thread(
                        [worker]() noexcept {
                            if (ppp::RT) {
                                SetThreadPriorityToMaxLevel();
                            }

                            SetThreadName("srv-ssmt");
                            boost::system::error_code ec;
                            boost::asio::io_context::work work(*worker);
                            worker->restart();
                            worker->run(ec);
                        });
                    ssmt_thread.detach();

                    if (!linux_tap->Ssmt(worker)) {
                        worker->stop();
                        for (auto& context : contexts) {
                            context->stop();
                        }
                        return false;
                    }

                    contexts.emplace_back(worker);
                }
                DebugLog("server ipv6 transit multiqueue enabled name=%s workers=%d", tap->GetId().data(), tun_ssmt_);

                SynchronizedObjectScope scope(syncobj_);
                ipv6_transit_ssmt_contexts_ = std::move(contexts);
#else
                (void)tap;
#endif
                return true;
            }

            void VirtualEthernetSwitcher::CloseIPv6TransitSsmtContexts() noexcept {
#if defined(_LINUX)
                ppp::vector<std::shared_ptr<boost::asio::io_context>> contexts;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    contexts = std::move(ipv6_transit_ssmt_contexts_);
                    ipv6_transit_ssmt_contexts_.clear();
                }

                for (auto& context : contexts) {
                    context->stop();
                }
#endif
            }

            bool VirtualEthernetSwitcher::OpenLogger() noexcept {
                VirtualEthernetLoggerPtr logger = NewLogger();
                if (NULLPTR == logger) {
                    return false;
                }

                logger_ = std::move(logger);
                return true;
            }

            bool VirtualEthernetSwitcher::OpenDatagramSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                int bind_port = configuration_->udp.listen.port;
                if (bind_port <= IPEndPoint::MinPort || bind_port > IPEndPoint::MaxPort) {
                    return true;
                }

                boost::asio::ip::address interface_ip = GetInterfaceIP();
                boost::asio::ip::udp::endpoint bind_endpoint(interface_ip, bind_port);

                bool ok = VirtualEthernetPacket::OpenDatagramSocket(static_echo_socket_, interface_ip, bind_port, bind_endpoint);
                if (!ok) {
                    return false;
                }
                else {
                    ppp::net::Socket::SetWindowSizeIfNotZero(static_echo_socket_.native_handle(), configuration_->udp.cwnd, configuration_->udp.rwnd);
                }

                boost::system::error_code ec;
                boost::asio::ip::udp::endpoint localEP = static_echo_socket_.local_endpoint(ec);
                if (ec) {
                    return false;
                }

                static_echo_bind_port_ = localEP.port();
                return LoopbackDatagramSocket();
            }

            bool VirtualEthernetSwitcher::LoopbackDatagramSocket() noexcept {
                if (disposed_) {
                    return false;
                }

                bool opened = static_echo_socket_.is_open();
                if (!opened) {
                    return false;
                }

                auto self = shared_from_this();
                static_echo_socket_.async_receive_from(boost::asio::buffer(static_echo_buffers_.get(), PPP_BUFFER_SIZE), static_echo_source_ep_,
                    [self, this](const boost::system::error_code& ec, std::size_t sz) noexcept {
                        if (ec == boost::system::errc::operation_canceled) {
                            return false;
                        }

                        if (disposed_) {
                            return false;
                        }

                        if (ec == boost::system::errc::success && sz > 0) {
                            std::shared_ptr<ppp::threading::BufferswapAllocator> allocator = configuration_->GetBufferAllocator();
                            VirtualEthernetStaticEchoAllocatedContextPtr allocated_context;

                            std::shared_ptr<VirtualEthernetPacket> packet = 
                                VirtualEthernetPacket::Unpack(configuration_, allocator, 
                                    [this, &allocated_context](int session_id) noexcept {
                                        return StaticEchoSelectCiphertext(session_id, true, allocated_context);
                                    }, 
                                    [this, &allocated_context](int session_id) noexcept {
                                        return StaticEchoSelectCiphertext(session_id, false, allocated_context);
                                    }, static_echo_buffers_.get(), sz);
                            if (NULLPTR != allocated_context && NULLPTR != packet) {
                                StaticEchoPacketInput(allocated_context, allocator, packet, sz, static_echo_source_ep_);
                            }
                        }
                        
                        return LoopbackDatagramSocket();
                    });
                return true;
            }

            std::shared_ptr<ppp::cryptography::Ciphertext> VirtualEthernetSwitcher::StaticEchoSelectCiphertext(int allocated_id, bool protocol_or_transport, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept {
                if (NULLPTR == allocated_context && !StaticEchoQuery(allocated_id, allocated_context)) {
                    return NULLPTR;
                }

                return protocol_or_transport ? allocated_context->protocol : allocated_context->transport;
            }

            bool VirtualEthernetSwitcher::StaticEchoPacketInput(const VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context, const std::shared_ptr<ppp::threading::BufferswapAllocator>& allocator, const std::shared_ptr<ppp::app::protocol::VirtualEthernetPacket>& packet, int packet_length, const boost::asio::ip::udp::endpoint& sourceEP) noexcept {
                VirtualEthernetExchangerPtr exchanger;
                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP || packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    SynchronizedObjectScope scope(syncobj_);
                    if (!ppp::collections::Dictionary::TryGetValue(exchangers_, allocated_context->guid, exchanger)) {
                        return false;
                    }

                    if (exchanger->IsDisposed()) {
                        return false;
                    }
                }
                else {
                    return false;
                }

                auto statistics = exchanger->GetStatistics(); 
                if (NULLPTR != statistics) {
                    statistics->AddIncomingTraffic(packet_length);
                }

                exchanger->static_echo_source_ep_ = sourceEP;
                if (packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_UDP) {
                    return exchanger->StaticEchoSendToDestination(packet);
                }
                elif(packet->Protocol == ppp::net::native::ip_hdr::IP_PROTO_IP) {
                    return exchanger->StaticEchoEchoToDestination(packet, sourceEP);
                }
                else {
                    return true;
                }
            }

            VirtualEthernetSwitcher::VirtualEthernetStaticEchoAllocatedContextPtr VirtualEthernetSwitcher::StaticEchoUnallocated(int allocated_id) noexcept {
                if (allocated_id < 1) {
                    return NULLPTR;
                }

                VirtualEthernetStaticEchoAllocatedContextPtr allocated_context;
                for (SynchronizedObjectScope scope(syncobj_);;) {
                    if (Dictionary::TryRemove(static_echo_allocateds_, allocated_id, allocated_context)) {
                        return allocated_context;
                    }

                    return NULLPTR;
                }
            }

            bool VirtualEthernetSwitcher::StaticEchoQuery(int allocated_id, VirtualEthernetStaticEchoAllocatedContextPtr& allocated_context) noexcept {
                if (allocated_id < 1) {
                    return false;
                }

                if (disposed_) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (!Dictionary::TryGetValue(static_echo_allocateds_, allocated_id, allocated_context)) {
                    return false;
                }

                if (NULLPTR != allocated_context) {
                    return true;
                }

                Dictionary::TryRemove(static_echo_allocateds_, allocated_id);
                return false; 
            }

            VirtualEthernetSwitcher::VirtualEthernetStaticEchoAllocatedContextPtr VirtualEthernetSwitcher::StaticEchoAllocated(Int128 session_id, int& allocated_id, int& remote_port) noexcept {
                remote_port = IPEndPoint::MinPort;
                if (session_id == 0) {
                    return NULLPTR;
                }

                if (disposed_) {
                    return NULLPTR;
                }

                int bind_port = static_echo_bind_port_;
                if (bind_port <= IPEndPoint::MinPort || bind_port > IPEndPoint::MaxPort) {
                    return NULLPTR;
                }

                VirtualEthernetStaticEchoAllocatedContextPtr allocated_context;
                SynchronizedObjectScope scope(syncobj_);

                if (allocated_id != 0) {
                    if (!Dictionary::TryGetValue(static_echo_allocateds_, allocated_id, allocated_context)) {
                        return NULLPTR;
                    }

                    remote_port = bind_port;
                    return allocated_context;
                }
                
                for (int i = ppp::net::IPEndPoint::MinPort; i <= ppp::net::IPEndPoint::MaxPort; i++) {
                    int generate_id = abs(RandomNext());
                    if (generate_id < 1) {
                        continue;
                    }

                    if (Dictionary::ContainsKey(static_echo_allocateds_, generate_id)) {
                        continue;
                    }
                    elif(NULLPTR == allocated_context) {
                        allocated_context = make_shared_object<VirtualEthernetStaticEchoAllocatedContext>();
                        if (NULLPTR == allocated_context) {
                            break;
                        }
                        else {
                            Int128 fsid = ppp::auxiliary::StringAuxiliary::GuidStringToInt128(GuidGenerate());
                            allocated_context->guid = session_id;
                            allocated_context->myid = generate_id;
                            allocated_context->fsid = fsid;

                            VirtualEthernetPacket::Ciphertext(configuration_, session_id, fsid, generate_id, allocated_context->protocol, allocated_context->transport);
                        }
                    }

                    if (Dictionary::TryAdd(static_echo_allocateds_, generate_id, allocated_context)) {
                        remote_port  = bind_port;
                        allocated_id = generate_id;
                        return allocated_context;
                    }
                }

                return NULLPTR;
            }

            bool VirtualEthernetSwitcher::OpenManagedServerIfNeed() noexcept {
                if (configuration_->server.node < 1 || configuration_->server.backend.empty()) {
                    return true;
                }

                if (disposed_) {
                    return false;
                }

                VirtualEthernetManagedServerPtr server = NewManagedServer();
                if (NULLPTR == server) {
                    return false;
                }

                auto self = shared_from_this();
                return server->TryVerifyUriAsync(configuration_->server.backend,
                    [self, this, server](bool ok) noexcept {
                        if (ok) {
                            SynchronizedObjectScope scope(syncobj_);
                            ok = false;
                            if (!disposed_) {
                                ok = server->ConnectToManagedServer(configuration_->server.backend);
                                if (ok) {
                                    managed_server_ = server;
                                }
                            }
                        }

                        if (!ok) {
                            server->Dispose();
                        }
                    });
            }

            VirtualEthernetSwitcher::ITransmissionPtr VirtualEthernetSwitcher::Accept(int categories, const ContextPtr& context, const std::shared_ptr<boost::asio::ip::tcp::socket>& socket) noexcept {
                if (NULLPTR == context || NULLPTR == socket) {
                    return NULLPTR;
                }

                std::shared_ptr<ppp::transmissions::ITransmission> transmission;
                if (categories == NetworkAcceptorCategories_Tcpip) {
                    ppp::threading::Executors::StrandPtr strand;
                    transmission = make_shared_object<ppp::transmissions::ITcpipTransmission>(context, strand, socket, configuration_);
                }
                elif(categories == NetworkAcceptorCategories_WebSocket) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::IWebsocketTransmission>(context, socket);
                }
                elif(categories == NetworkAcceptorCategories_WebSocketSSL) {
                    transmission = NewWebsocketTransmission<ppp::transmissions::ISslWebsocketTransmission>(context, socket);
                }

                if (NULLPTR == transmission) {
                    return NULLPTR;
                }

                transmission->Statistics = NewStatistics();
                return transmission;
            }

            void VirtualEthernetSwitcher::Dispose() noexcept {
                auto self = shared_from_this();
                std::shared_ptr<boost::asio::io_context> context = GetContext();
                boost::asio::post(*context, 
                    [self, this]() noexcept {
                        Finalize();
                    });
            }

            bool VirtualEthernetSwitcher::IsDisposed() noexcept {
                return disposed_;
            }

            VirtualEthernetSwitcher::VirtualEthernetNamespaceCachePtr VirtualEthernetSwitcher::NewNamespaceCache(int ttl) noexcept {
                if (ttl < 1) {
                    return NULLPTR;
                }

                return make_shared_object<VirtualEthernetNamespaceCache>(ttl);
            }
            
            VirtualEthernetSwitcher::ITransmissionStatisticsPtr VirtualEthernetSwitcher::NewStatistics() noexcept {
                class NetworkStatistics final : public ppp::transmissions::ITransmissionStatistics {
                public:
                    NetworkStatistics(const ITransmissionStatisticsPtr& owner) noexcept
                        : ITransmissionStatistics()
                        , owner_(owner) {

                    }

                public:
                    virtual uint64_t                                    AddIncomingTraffic(uint64_t incoming_traffic) noexcept {
                        owner_->AddIncomingTraffic(incoming_traffic);
                        return ITransmissionStatistics::AddIncomingTraffic(incoming_traffic);
                    }
                    virtual uint64_t                                    AddOutgoingTraffic(uint64_t outcoming_traffic) noexcept {
                        owner_->AddOutgoingTraffic(outcoming_traffic);
                        return ITransmissionStatistics::AddOutgoingTraffic(outcoming_traffic);
                    }

                private:
                    ITransmissionStatisticsPtr                          owner_;
                };

                VirtualEthernetManagedServerPtr server = managed_server_;
                if (NULLPTR == server) {
                    return statistics_;
                }
                else {
                    return make_shared_object<NetworkStatistics>(statistics_);
                }
            }

            VirtualEthernetSwitcher::VirtualEthernetManagedServerPtr VirtualEthernetSwitcher::NewManagedServer() noexcept {
                std::shared_ptr<VirtualEthernetSwitcher> self = shared_from_this();
                return make_shared_object<VirtualEthernetManagedServer>(self);
            }

            template <typename TProtocol>
            static bool CancelAllResolver(std::shared_ptr<boost::asio::ip::basic_resolver<TProtocol>>& resolver) noexcept {
                std::shared_ptr<boost::asio::ip::basic_resolver<TProtocol>> i = std::move(resolver);
                if (NULLPTR == i) {
                    return false;
                }

                boost::asio::post(i->get_executor(),
                    [i]() noexcept {
                        ppp::net::Socket::Cancel(*i);
                    });
                return true;
            }

            void VirtualEthernetSwitcher::Finalize() noexcept {
                std::shared_ptr<boost::asio::ip::tcp::resolver> tresolver;
                std::shared_ptr<boost::asio::ip::udp::resolver> uresolver;

                VirtualEthernetNamespaceCachePtr cache;
                ITapPtr ipv6_transit_tap;
                NatInformationTable nats;
                VirtualEthernetLoggerPtr logger;
                VirtualEthernetExchangerTable exchangers;
                VirtualEthernetNetworkTcpipConnectionTable connections;

                for (;;) {
                    SynchronizedObjectScope scope(syncobj_);
                    disposed_ = true;

                    CloseAllAcceptors();

                    cache = std::move(namespace_cache_);
                    ipv6_transit_tap = std::move(ipv6_transit_tap_);
                    nats = std::move(nats_);
                    logger = std::move(logger_);

                    exchangers = std::move(exchangers_);
                    exchangers_.clear();

                    connections = std::move(connections_);
                    connections_.clear();

                    ClearIPv6ExchangersUnsafe();

                    static_echo_allocateds_.clear();
                    break;
                }

                CloseIPv6TransitSsmtContexts();
                CloseAlwaysTimeout();
                CloseIPv6NeighborProxyIfNeed();

                CancelAllResolver(tresolver);
                CancelAllResolver(uresolver);

                Dictionary::ReleaseAllObjects(exchangers);
                Dictionary::ReleaseAllObjects(connections);

                if (NULLPTR != ipv6_transit_tap) {
                    ipv6_transit_tap->Dispose();
                }

                if (NULLPTR != cache) {
                    cache->Clear();
                }
                
                if (NULLPTR != logger) {
                    IDisposable::Dispose(logger);
                }
            }

            void VirtualEthernetSwitcher::CloseAllAcceptors() noexcept {
                for (int i = NetworkAcceptorCategories_Min; i < NetworkAcceptorCategories_Max; i++) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor = acceptors_[i];
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor_copy = std::move(acceptor);
                    if (NULLPTR == acceptor_copy) {
                        continue;
                    }

                    acceptor.reset();
                    Socket::Closesocket(acceptor_copy);
                }
            }

            bool VirtualEthernetSwitcher::CloseAlwaysTimeout() noexcept {
                TimerPtr timeout = std::move(timeout_);
                if (timeout) {
                    timeout->Dispose();
                    return true;
                }
                else {
                    return false;
                }
            }

            bool VirtualEthernetSwitcher::CreateFirewall(const ppp::string& firewall_rules) noexcept {
                if (disposed_) {
                    return false;
                }

                FirewallPtr firewall = NewFirewall();
                if (NULLPTR == firewall) {
                    return false;
                }

                firewall_ = firewall;
                firewall->LoadWithFile(firewall_rules);
                return true;
            }

            bool VirtualEthernetSwitcher::CreateAlwaysTimeout() noexcept {
                if (disposed_) {
                    return false;
                }

                std::shared_ptr<Timer> timeout = make_shared_object<Timer>(context_);
                if (!timeout) {
                    return false;
                }

                auto self = shared_from_this();
                timeout->TickEvent = 
                    [self, this](Timer* sender, Timer::TickEventArgs& e) noexcept {
                        UInt64 now = Executors::GetTickCount();
                        OnTick(now);
                    };

                bool ok = timeout->SetInterval(1000) && timeout->Start();
                if (ok) {
                    timeout_ = timeout;
                    return true;
                }
                
                timeout->Dispose();
                return false;
            }

            void VirtualEthernetSwitcher::TickAllExchangers(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                ppp::collections::Dictionary::UpdateAllObjects2(exchangers_, now);
            }

            void VirtualEthernetSwitcher::TickAllConnections(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                Dictionary::UpdateAllObjects(connections_, now);
            }

            void VirtualEthernetSwitcher::TickIPv6Leases(UInt64 now) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                for (auto it = ipv6_leases_.begin(); it != ipv6_leases_.end();) {
                    IPv6LeaseEntry& lease = it->second;
                    if (lease.StaticBinding || lease.ExpiresAt == UINT64_MAX || lease.ExpiresAt > now) {
                        ++it;
                        continue;
                    }

                    auto exchanger_it = exchangers_.find(it->first);
                    if (exchanger_it != exchangers_.end()) {
                        const VirtualEthernetExchangerPtr& exchanger = exchanger_it->second;
                        if (exchanger && !exchanger->IsDisposed()) {
                            if (configuration_->server.ipv6.lease_time > 0) {
                                lease.ExpiresAt = now + static_cast<UInt64>(configuration_->server.ipv6.lease_time) * 1000ULL;
                            }
                            else {
                                lease.ExpiresAt = UINT64_MAX;
                            }
                            ++it;
                            continue;
                        }
                    }

                    it = ipv6_leases_.erase(it);
                }

                for (auto it = ipv6_requests_.begin(); it != ipv6_requests_.end();) {
                    if (ipv6_leases_.find(it->first) == ipv6_leases_.end()) {
                        it = ipv6_requests_.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
            }

            void VirtualEthernetSwitcher::RevokeIPv6Lease(const Int128& session_id) noexcept {
                SynchronizedObjectScope scope(syncobj_);
                ipv6_leases_.erase(session_id);
            }

            bool VirtualEthernetSwitcher::OnTick(UInt64 now) noexcept {
                for (SynchronizedObjectScope scope(syncobj_);;) {
                    if (disposed_) {
                        return false;
                    }

                    break;
                }

                TickAllExchangers(now);
                TickAllConnections(now);
                TickIPv6Leases(now);
                if (!RefreshIPv6NeighborProxyIfNeed()) {
                    DebugLog("server ipv6 neighbor proxy refresh failed");
                }

                VirtualEthernetNamespaceCachePtr cache = namespace_cache_;
                if (NULLPTR != cache) {
                    cache->Update();
                }

                VirtualEthernetManagedServerPtr server = managed_server_; 
                if (NULLPTR != server) {
                    server->Update(now);
                }

                return true;
            }

            bool VirtualEthernetSwitcher::OnInformation(const Int128& session_id, const std::shared_ptr<VirtualEthernetInformation>& info, YieldContext& y) noexcept {
                if (disposed_) {
                    return false;
                }

                VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                if (NULLPTR == exchanger) {
                    return false;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                bool bok = false;
                if (NULLPTR != info) {
                    InformationEnvelope envelope = BuildInformationEnvelope(session_id, *info);
                    DebugLog("server info send update session=%s json=%s",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        envelope.ExtendedJson.data());
                    if (envelope.Extensions.AssignedIPv6Address.is_v6() && !AddIPv6Exchanger(session_id, envelope.Extensions)) {
                        RevokeIPv6Lease(session_id);
                        DeleteIPv6Exchanger(session_id);
                        envelope.Extensions.AssignedIPv6Address = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Gateway = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6RoutePrefix = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6RoutePrefixLength = 0;
                        envelope.Extensions.AssignedIPv6Dns1 = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Dns2 = boost::asio::ip::address();
                        envelope.Extensions.AssignedIPv6Flags = 0;
                        envelope.Extensions.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Failed;
                        envelope.Extensions.IPv6StatusMessage = "server-ipv6-dataplane-install-failed";
                    }
                    bok = exchanger->DoInformation(transmission, envelope, y);
                    if (bok) {
                        bok = info->Valid();
                    }
                }

                if (!bok) {
                    transmission->Dispose();
                }
                
                return bok;
            }

            bool VirtualEthernetSwitcher::UpdateIPv6Request(const Int128& session_id, const VirtualEthernetInformationExtensions& request, VirtualEthernetInformationExtensions& response) noexcept {
                IPv6RequestEntry entry;
                entry.Present = request.RequestedIPv6Address.is_v6();
                entry.Accepted = false;
                entry.RequestedAddress = request.RequestedIPv6Address;
                entry.StatusCode = VirtualEthernetInformationExtensions::IPv6Status_None;

                if (entry.Present) {
                    entry.Accepted = true;
                    entry.StatusCode = VirtualEthernetInformationExtensions::IPv6Status_ClientRequested;
                    entry.StatusMessage = "client-ipv6-request-pending";
                }

                {
                    SynchronizedObjectScope scope(syncobj_);
                    if (entry.Present) {
                        ipv6_requests_[session_id] = entry;
                    }
                    else {
                        ipv6_requests_.erase(session_id);
                    }
                }

                VirtualEthernetInformation info;
                info.Clear();
                BuildInformationIPv6Extensions(session_id, response);
                if (response.AssignedIPv6Address.is_v6()) {
                    if (!AddIPv6Exchanger(session_id, response)) {
                        RevokeIPv6Lease(session_id);
                        DeleteIPv6Exchanger(session_id);
                        response.AssignedIPv6Address = boost::asio::ip::address();
                        response.AssignedIPv6Gateway = boost::asio::ip::address();
                        response.AssignedIPv6RoutePrefix = boost::asio::ip::address();
                        response.AssignedIPv6RoutePrefixLength = 0;
                        response.AssignedIPv6Dns1 = boost::asio::ip::address();
                        response.AssignedIPv6Dns2 = boost::asio::ip::address();
                        response.AssignedIPv6Flags = 0;
                        response.IPv6StatusCode = VirtualEthernetInformationExtensions::IPv6Status_Failed;
                        response.IPv6StatusMessage = "server-ipv6-dataplane-install-failed";
                    }
                }
                else {
                    DeleteIPv6Exchanger(session_id);
                }

                if (!entry.Accepted && entry.StatusCode != VirtualEthernetInformationExtensions::IPv6Status_None) {
                    response.IPv6StatusCode = entry.StatusCode;
                    response.IPv6StatusMessage = entry.StatusMessage;
                    response.RequestedIPv6Address = request.RequestedIPv6Address;
                }
                return response.HasAny();
            }

            bool VirtualEthernetSwitcher::DeleteConnection(const VirtualEthernetNetworkTcpipConnection* connection) noexcept {
                VirtualEthernetNetworkTcpipConnectionPtr ntcp;
                if (connection) {
                    SynchronizedObjectScope scope(syncobj_);
                    Dictionary::RemoveValueByKey(connections_, (void*)connection, &ntcp);
                }

                if (ntcp) {
                    ntcp->Dispose();
                    return true;
                }

                return false;
            }

            boost::asio::ip::udp::endpoint VirtualEthernetSwitcher::ParseDNSEndPoint(const ppp::string& dnserver_endpoint) noexcept {
                boost::asio::ip::address dnsserverIP = boost::asio::ip::address_v4::any();
                int dnsserverPort = PPP_DNS_SYS_PORT;
                if (dnserver_endpoint.empty()) {
                    return boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                }

                boost::asio::ip::udp::udp::endpoint dnsserverEP = Ipep::ParseEndPoint(dnserver_endpoint);
                dnsserverPort = dnsserverEP.port();
                if (dnsserverPort <= IPEndPoint::MinPort || dnsserverPort > IPEndPoint::MaxPort) {
                    dnsserverPort = PPP_DNS_SYS_PORT;
                }

                dnsserverIP = dnsserverEP.address();
                dnsserverEP = boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                if (IPEndPoint::IsInvalid(dnsserverEP.address())) {
                    dnsserverIP = boost::asio::ip::address_v4::any();
                }
                elif(dnsserverIP.is_multicast()) {
                    dnsserverIP = boost::asio::ip::address_v4::any();
                }

                dnsserverEP = boost::asio::ip::udp::endpoint(dnsserverIP, dnsserverPort);
                return dnsserverEP;
            }

            boost::asio::ip::tcp::endpoint VirtualEthernetSwitcher::GetLocalEndPoint(NetworkAcceptorCategories categories) noexcept {
                boost::system::error_code ec;
                if (categories == NetworkAcceptorCategories_Udpip) {
                    if (static_echo_socket_.is_open()) {
                        boost::asio::ip::udp::endpoint localEP = static_echo_socket_.local_endpoint(ec);
                        if (ec == boost::system::errc::success) {
                            return boost::asio::ip::tcp::endpoint(localEP.address(), localEP.port());
                        }
                    }
                }
                elif(categories >= NetworkAcceptorCategories_Min && categories < NetworkAcceptorCategories_Max) {
                    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor = acceptors_[categories];
                    if (NULLPTR != acceptor) {
                        if (acceptor->is_open()) {
                            boost::asio::ip::tcp::endpoint localEP = acceptor->local_endpoint(ec);
                            if (ec == boost::system::errc::success) {
                                return localEP;
                            }
                        }
                    }
                }

                return IPEndPoint::ToEndPoint<boost::asio::ip::tcp>(IPEndPoint::Any(IPEndPoint::MinPort));
            }

            VirtualEthernetSwitcher::NatInformationPtr VirtualEthernetSwitcher::FindNatInformation(uint32_t ip) noexcept {
                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return NULLPTR;
                }

                SynchronizedObjectScope scope(syncobj_);
                return Dictionary::FindObjectByKey(nats_, ip);
            }

            VirtualEthernetSwitcher::NatInformationPtr VirtualEthernetSwitcher::AddNatInformation(const std::shared_ptr<VirtualEthernetExchanger>& exchanger, uint32_t ip, uint32_t mask) noexcept {
                if (IPEndPoint::IsInvalid(IPEndPoint(mask, IPEndPoint::MinPort))) {
                    return NULLPTR;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return NULLPTR;
                }

                if (exchanger->IsDisposed()) {
                    return NULLPTR;
                }

                // Creating a nat information entry mapping does not mean that the mapping will be added to the nats.
                NatInformationPtr nat = make_shared_object<NatInformation>();
                if (NULLPTR == nat) {
                    return NULLPTR;
                }

                nat->Exchanger = exchanger;
                nat->IPAddress = ip;
                nat->SubmaskAddress = mask;

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return NULLPTR;
                }

                // If ip addresses conflict, do not directly conflict like traditional routers, 
                // And abandon the mapping between IP and Ethernet electrical ports.
                auto kv = nats_.emplace(ip, nat);
                if (kv.second) {
                    return nat;
                }

                NatInformationTable::iterator tail = kv.first;
                NatInformationTable::iterator endl = nats_.end();
                if (tail == endl) {
                    return NULLPTR;
                }

                NatInformationPtr& raw = tail->second;
                std::shared_ptr<VirtualEthernetExchanger>& raw_exchanger = raw->Exchanger;
                if (raw_exchanger->IsDisposed()) {
                    raw = nat;
                    return nat;
                }
                else {
                    return NULLPTR;
                }
            }

            bool VirtualEthernetSwitcher::DeleteNatInformation(VirtualEthernetExchanger* key, uint32_t ip) noexcept {
                if (NULLPTR == key) {
                    return false;
                }

                if (IPEndPoint::IsInvalid(IPEndPoint(ip, IPEndPoint::MinPort))) {
                    return false;
                }

                SynchronizedObjectScope scope(syncobj_);
                if (disposed_) {
                    return false;
                }

                NatInformationTable::iterator tail = nats_.find(ip);
                NatInformationTable::iterator endl = nats_.end();
                if (tail == endl) {
                    return false;
                }

                NatInformationPtr& nat = tail->second;
                std::shared_ptr<VirtualEthernetExchanger>& exchanger = nat->Exchanger;
                if (key != exchanger.get()) {
                    return false;
                }

                nats_.erase(tail);
                return true;
            }

            int VirtualEthernetSwitcher::GetAllExchangerNumber() noexcept {
                SynchronizedObjectScope scope(syncobj_);
                return static_cast<int>(exchangers_.size());
            }
        }
    }
}
