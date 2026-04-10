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

extern void DebugLog(const char* format, ...) noexcept;

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
            VirtualEthernetSwitcher::VirtualEthernetSwitcher(const AppConfigurationPtr& configuration, const ppp::string& tun_name) noexcept
                : disposed_(false)
                , configuration_(configuration)
                , context_(Executors::GetDefault())
                , tun_name_(tun_name)
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

            bool VirtualEthernetSwitcher::BuildInformationIPv6Extensions(const Int128& session_id, VirtualEthernetInformationExtensions& extensions) noexcept {
                extensions.Clear();

                const auto& ipv6 = configuration_->server.ipv6;
                if (!ipv6.enabled) {
                    DebugLog("server ipv6 disabled session=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                    return false;
                }

                auto build_stable_ipv6 = [&](boost::asio::ip::address_v6::bytes_type bytes, int prefix_length) noexcept -> bool {
                    ppp::string seed = ipv6.stable_secret;
                    if (seed.empty()) {
                        seed = auxiliary::StringAuxiliary::Int128ToGuidString(session_id);
                    }
                    else {
                        seed.append(":");
                        seed.append(auxiliary::StringAuxiliary::Int128ToGuidString(session_id));
                    }

                    ppp::string digest = ppp::cryptography::hash_hmac(seed.data(), static_cast<int>(seed.size()), ppp::cryptography::DigestAlgorithmic_sha256, false, false);
                    if (digest.size() < 8) {
                        return false;
                    }

                    int prefix_bytes = std::max<int>(0, std::min<int>(16, prefix_length >> 3));
                    int iid_bytes = std::min<int>(8, 16 - prefix_bytes);
                    for (int i = 0; i < iid_bytes; i++) {
                        bytes[16 - iid_bytes + i] = static_cast<unsigned char>(digest[i]);
                    }

                    if (prefix_bytes < 16) {
                        for (int i = prefix_bytes; i < 16 - iid_bytes; i++) {
                            bytes[i] = 0;
                        }
                    }

                    boost::asio::ip::address_v6 candidate = boost::asio::ip::address_v6(bytes);

                    boost::system::error_code gateway_ec;
                    boost::asio::ip::address configured_gateway = StringToAddress(ipv6.gateway, gateway_ec);
                    if (!gateway_ec && configured_gateway.is_v6() && candidate == configured_gateway.to_v6()) {
                        boost::asio::ip::address_v6::bytes_type candidate_bytes = candidate.to_bytes();
                        candidate_bytes[15] ^= 0x01;
                        candidate = boost::asio::ip::address_v6(candidate_bytes);
                    }

                    extensions.AssignedIPv6Address = candidate;
                    return true;
                };

                boost::system::error_code ec;

                ppp::string mode = ToLower(ipv6.mode);
                DebugLog("server ipv6 build session=%s mode=%s prefix=%s/%d gateway=%s dns1=%s dns2=%s",
                    auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                    mode.data(),
                    ipv6.prefix.data(),
                    ipv6.prefix_length,
                    ipv6.gateway.data(),
                    ipv6.dns1.data(),
                    ipv6.dns2.data());
                if (mode == "nat") {
                    extensions.AssignedIPv6Mode = VirtualEthernetInformationExtensions::IPv6Mode_Nat;
                    extensions.AssignedIPv6PrefixLength = static_cast<Byte>(std::max<int>(64, std::min<int>(128, ipv6.prefix_length)));

                    boost::asio::ip::address_v6::bytes_type ula_bytes = {};
                    ec.clear();
                    boost::asio::ip::address configured_prefix = StringToAddress(ipv6.prefix, ec);
                    if (!ec && configured_prefix.is_v6()) {
                        ula_bytes = configured_prefix.to_v6().to_bytes();
                    }
                    else {
                        ula_bytes[0] = 0xfd;
                    }

                    if (!build_stable_ipv6(ula_bytes, extensions.AssignedIPv6PrefixLength)) {
                        extensions.Clear();
                        DebugLog("server ipv6 build failed session=%s reason=stable-address", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                        return false;
                    }

                    ec.clear();
                    boost::asio::ip::address gateway = StringToAddress(ipv6.gateway, ec);
                    if (!ec && gateway.is_v6()) {
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

                    DebugLog("server ipv6 build result session=%s address=%s gateway=%s dns1=%s dns2=%s flags=%u",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        extensions.AssignedIPv6Address.is_v6() ? extensions.AssignedIPv6Address.to_string().c_str() : "",
                        extensions.AssignedIPv6Gateway.is_v6() ? extensions.AssignedIPv6Gateway.to_string().c_str() : "",
                        extensions.AssignedIPv6Dns1.is_v6() ? extensions.AssignedIPv6Dns1.to_string().c_str() : "",
                        extensions.AssignedIPv6Dns2.is_v6() ? extensions.AssignedIPv6Dns2.to_string().c_str() : "",
                        (unsigned)extensions.AssignedIPv6Flags);
                    return extensions.HasAny();
                }
                elif(mode == "prefix") {
                    extensions.AssignedIPv6Mode = VirtualEthernetInformationExtensions::IPv6Mode_Prefix;
                    if (ipv6.routed_prefix) {
                        extensions.AssignedIPv6Flags |= VirtualEthernetInformationExtensions::IPv6Flag_RoutedPrefix;
                    }
                    if (ipv6.neighbor_proxy) {
                        extensions.AssignedIPv6Flags |= VirtualEthernetInformationExtensions::IPv6Flag_NeighborProxy;
                    }
                }
                else {
                    DebugLog("server ipv6 build failed session=%s reason=invalid-mode mode=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(), mode.data());
                    return false;
                }

                int assigned_prefix_length = ipv6.routed_prefix ? 128 : ipv6.prefix_length;
                extensions.AssignedIPv6PrefixLength = static_cast<Byte>(std::max<int>(0, std::min<int>(128, assigned_prefix_length)));

                boost::asio::ip::address prefix = StringToAddress(ipv6.prefix, ec);
                if (ec || !prefix.is_v6()) {
                    extensions.Clear();
                    DebugLog("server ipv6 build failed session=%s reason=invalid-prefix prefix=%s", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(), ipv6.prefix.data());
                    return false;
                }

                boost::asio::ip::address_v6::bytes_type bytes = prefix.to_v6().to_bytes();
                if (!build_stable_ipv6(bytes, extensions.AssignedIPv6PrefixLength)) {
                    extensions.Clear();
                    DebugLog("server ipv6 build failed session=%s reason=stable-prefix-address", auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data());
                    return false;
                }

                ec.clear();
                boost::asio::ip::address gateway = StringToAddress(ipv6.gateway, ec);
                if (!ec && gateway.is_v6()) {
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

                DebugLog("server ipv6 build result session=%s address=%s gateway=%s dns1=%s dns2=%s flags=%u",
                    auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                    extensions.AssignedIPv6Address.is_v6() ? extensions.AssignedIPv6Address.to_string().c_str() : "",
                    extensions.AssignedIPv6Gateway.is_v6() ? extensions.AssignedIPv6Gateway.to_string().c_str() : "",
                    extensions.AssignedIPv6Dns1.is_v6() ? extensions.AssignedIPv6Dns1.to_string().c_str() : "",
                    extensions.AssignedIPv6Dns2.is_v6() ? extensions.AssignedIPv6Dns2.to_string().c_str() : "",
                    (unsigned)extensions.AssignedIPv6Flags);

                if (mode == "prefix") {
                    DebugLog("server ipv6 prefix semantics session=%s routed-prefix=%s neighbor-proxy=%s provider=%s assigned-prefix-length=%u",
                        auxiliary::StringAuxiliary::Int128ToGuidString(session_id).data(),
                        ipv6.routed_prefix ? "yes" : "no",
                        ipv6.neighbor_proxy ? "yes" : "no",
                        ipv6.neighbor_proxy_provider.empty() ? "kernel" : ipv6.neighbor_proxy_provider.data(),
                        (unsigned)extensions.AssignedIPv6PrefixLength);
                }

                return extensions.HasAny();
            }

            bool VirtualEthernetSwitcher::AddIPv6Exchanger(const Int128& session_id, const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v6()) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                VirtualEthernetExchangerPtr exchanger = GetExchanger(session_id);
                if (NULLPTR == exchanger) {
                    return false;
                }

                bool need_ndppd_sync = false;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    for (auto tail = ipv6s_.begin(); tail != ipv6s_.end();) {
                        VirtualEthernetExchangerPtr current = tail->second;
                        if (current && current->GetId() == session_id && tail->first != ip_key) {
                            tail = ipv6s_.erase(tail);
                        }
                        else {
                            ++tail;
                        }
                    }
                    ipv6s_[ip_key] = exchanger;
                    AddIPv6TransitRoute(ip);
                    AddIPv6NeighborProxy(ip);
                    need_ndppd_sync = false;
                }
                if (need_ndppd_sync) {
                    SyncNdppdNeighborProxy();
                }
                return true;
            }

            bool VirtualEthernetSwitcher::DeleteIPv6Exchanger(const Int128& session_id, const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v6()) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                bool need_ndppd_sync = false;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    auto tail = ipv6s_.find(ip_key);
                    if (tail == ipv6s_.end()) {
                        return false;
                    }

                    if (tail->second && tail->second->GetId() != session_id) {
                        return false;
                    }

                    DeleteIPv6TransitRoute(ip);
                    DeleteIPv6NeighborProxy(ip);
                    ipv6s_.erase(tail);
                    need_ndppd_sync = false;
                }
                if (need_ndppd_sync) {
                    SyncNdppdNeighborProxy();
                }
                return true;
            }

            VirtualEthernetSwitcher::VirtualEthernetExchangerPtr VirtualEthernetSwitcher::FindIPv6Exchanger(const boost::asio::ip::address& ip) noexcept {
                if (!ip.is_v6()) {
                    return NULLPTR;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_key(ip_std.data(), ip_std.size());

                SynchronizedObjectScope scope(syncobj_);
                auto tail = ipv6s_.find(ip_key);
                return tail == ipv6s_.end() ? NULLPTR : tail->second;
            }

            bool VirtualEthernetSwitcher::OpenIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                if (!ipv6.enabled || ToLower(ipv6.mode) != "prefix" || !ipv6.neighbor_proxy) {
                    return true;
                }

                ppp::string provider = ToLower(ipv6.neighbor_proxy_provider);
                if (provider.empty()) {
                    provider = "kernel";
                }

                DebugLog("server ipv6 neighbor proxy provider=%s", provider.data());
                if (provider == "ndppd") {
                    DebugLog("server ipv6 ndppd provider is externally managed; skip in-process config generation");
                    return true;
                }

                if (provider == "manual" || provider == "external") {
                    DebugLog("server ipv6 neighbor proxy provider=%s externally managed; skip in-process setup", provider.data());
                    return true;
                }

                if (provider != "kernel") {
                    DebugLog("server ipv6 neighbor proxy provider=%s not yet implemented in-process", provider.data());
                    return true;
                }

                ppp::string uplink_name;
                UInt32 address = 0;
                UInt32 mask = 0;
                UInt32 gw = 0;
                if (!ppp::tap::TapLinux::GetPreferredNetworkInterface(uplink_name, address, mask, gw, ppp::string())) {
                    return false;
                }

                if (!ppp::tap::TapLinux::EnableIPv6NeighborProxy(uplink_name)) {
                    return false;
                }

                ipv6_neighbor_proxy_ifname_ = uplink_name;
                DebugLog("server ipv6 neighbor proxy enabled if=%s", uplink_name.data());
#endif
                return true;
            }

            bool VirtualEthernetSwitcher::CloseIPv6NeighborProxyIfNeed() noexcept {
#if defined(_LINUX)
                if (ipv6_neighbor_proxy_ifname_.empty()) {
                    return true;
                }

                bool ok = ppp::tap::TapLinux::DisableIPv6NeighborProxy(ipv6_neighbor_proxy_ifname_);
                DebugLog("server ipv6 neighbor proxy disabled if=%s status=%s", ipv6_neighbor_proxy_ifname_.data(), ok ? "ok" : "fail");
                ipv6_neighbor_proxy_ifname_.clear();
#endif
                return true;
            }

            bool VirtualEthernetSwitcher::SyncNdppdNeighborProxy() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                if (!ipv6.enabled || ToLower(ipv6.mode) != "prefix" || !ipv6.neighbor_proxy) {
                    return true;
                }

                ppp::string uplink_name;
                UInt32 address = 0;
                UInt32 mask = 0;
                UInt32 gw = 0;
                if (!ppp::tap::TapLinux::GetPreferredNetworkInterface(uplink_name, address, mask, gw, ppp::string())) {
                    return false;
                }

                ppp::string config_path = "/tmp/openppp2-ndppd.conf";
                ppp::string config_text = "proxy ";
                config_text += uplink_name;
                config_text += " {\n";

                int rules = 0;
                {
                    SynchronizedObjectScope scope(syncobj_);
                    for (const auto& [ip_key, exchanger] : ipv6s_) {
                        if (NULLPTR == exchanger) {
                            continue;
                        }

                        config_text += "  rule ";
                        config_text += ip_key;
                        config_text += "/128 {\n";
                        config_text += "    static\n";
                        config_text += "  }\n";
                        rules++;
                    }
                }

                if (rules < 1) {
                    config_text += "  rule ";
                    config_text += ipv6.prefix;
                    config_text += "/";
                    config_text += stl::to_string<ppp::string>(ipv6.prefix_length);
                    config_text += " {\n";
                    config_text += "    static\n";
                    config_text += "  }\n";
                }

                config_text += "}\n";

                if (!ppp::io::File::WriteAllBytes(config_path.data(), config_text.data(), static_cast<int>(config_text.size()))) {
                    return false;
                }

                DebugLog("server ipv6 ndppd config synced path=%s uplink=%s rules=%d", config_path.data(), uplink_name.data(), rules);
                DebugLog("server ipv6 ndppd reload required path=%s", config_path.data());
#endif
                return true;
            }

            bool VirtualEthernetSwitcher::AddIPv6TransitRoute(const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6()) {
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                if (!ipv6.enabled) {
                    return false;
                }

                ppp::string mode = ToLower(ipv6.mode);
                if (!(mode == "nat" || mode == "prefix")) {
                    return false;
                }

                ITapPtr tap = ipv6_transit_tap_;
                if (NULLPTR == tap) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::AddRoute6(tap->GetId(), ip_str, 128, ppp::string());
                DebugLog("server ipv6 transit host-route %s name=%s ip=%s/128", ok ? "add-ok" : "add-fail", tap->GetId().data(), ip_str.data());
                return ok;
#else
                return false;
#endif
            }

            bool VirtualEthernetSwitcher::DeleteIPv6TransitRoute(const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
                if (!ip.is_v6()) {
                    return false;
                }

                const auto& ipv6 = configuration_->server.ipv6;
                if (!ipv6.enabled) {
                    return false;
                }

                ppp::string mode = ToLower(ipv6.mode);
                if (!(mode == "nat" || mode == "prefix")) {
                    return false;
                }

                ITapPtr tap = ipv6_transit_tap_;
                if (NULLPTR == tap) {
                    return false;
                }

                std::string ip_std = ip.to_string();
                ppp::string ip_str(ip_std.data(), ip_std.size());
                bool ok = ppp::tap::TapLinux::DeleteRoute6(tap->GetId(), ip_str, 128, ppp::string());
                DebugLog("server ipv6 transit host-route %s name=%s ip=%s/128", ok ? "del-ok" : "del-fail", tap->GetId().data(), ip_str.data());
                return ok;
#else
                return false;
#endif
            }

            bool VirtualEthernetSwitcher::AddIPv6NeighborProxy(const boost::asio::ip::address& ip) noexcept {
#if defined(_LINUX)
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
                if (NULLPTR == established_information && configuration_->server.ipv6.enabled && configuration_->server.backend.empty()) {
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
                    AddIPv6Exchanger(session_id, envelope.Extensions.AssignedIPv6Address);
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
                if (!ParseVirtualEthernetIPv6Header(packet, packet_length, source, destination)) {
                    return false;
                }

                VirtualEthernetExchangerPtr exchanger = FindIPv6Exchanger(destination);
                if (NULLPTR == exchanger) {
                    return false;
                }

                ITransmissionPtr transmission = exchanger->GetTransmission();
                if (NULLPTR == transmission) {
                    return false;
                }

                app::protocol::ClampTcpMssIPv6(packet, packet_length, app::protocol::ComputeDynamicTcpMss(false, 80));

                return SendIPv6PacketToClient(transmission, packet, packet_length);
            }

            bool VirtualEthernetSwitcher::OpenIPv6TransitIfNeed() noexcept {
#if defined(_LINUX)
                const auto& ipv6 = configuration_->server.ipv6;
                ppp::string mode = ToLower(ipv6.mode);
                bool enable_transit = ipv6.enabled && (mode == "nat" || mode == "prefix");
                if (!enable_transit) {
                    return true;
                }

                boost::system::error_code ec;
                boost::asio::ip::address prefix = StringToAddress(ipv6.prefix, ec);
                if (ec || !prefix.is_v6()) {
                    return false;
                }

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

                if (!ipv6.gateway.empty()) {
                    ec.clear();
                    boost::asio::ip::address configured_gateway = StringToAddress(ipv6.gateway, ec);
                    if (!ec && configured_gateway.is_v6()) {
                        transit = configured_gateway.to_v6();
                    }
                }
                else {
                    boost::asio::ip::address_v6::bytes_type bytes = transit.to_bytes();
                    bytes[15] = 1;
                    transit = boost::asio::ip::address_v6(bytes);
                }

                std::string transit_std = transit.to_string();
                ppp::string transit_ip(transit_std.data(), transit_std.size());
                int prefix_length = std::max<int>(64, std::min<int>(128, ipv6.prefix_length));

                ppp::vector<ppp::string> no_dns;
                ppp::string tun_name = tun_name_;
                if (tun_name.empty()) {
                    tun_name = "ppp";
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

                DebugLog("server ipv6 transit connected route managed by kernel name=%s prefix=%s/%d", tap->GetId().data(), ipv6.prefix.data(), prefix_length);

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

                ipv6_transit_tap_ = tap;
                DebugLog("server ipv6 transit tap opened name=%s address=%s/%d", tap->GetId().data(), transit_ip.data(), prefix_length);
#endif
                return true;
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

                    static_echo_allocateds_.clear();
                    break;
                }

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

            bool VirtualEthernetSwitcher::OnTick(UInt64 now) noexcept {
                for (SynchronizedObjectScope scope(syncobj_);;) {
                    if (disposed_) {
                        return false;
                    }

                    break;
                }

                TickAllExchangers(now);
                TickAllConnections(now);

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
                    AddIPv6Exchanger(session_id, envelope.Extensions.AssignedIPv6Address);
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
