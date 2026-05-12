/**
 * @file ApplicationMainLoop.cpp
 * @brief Runtime loop, periodic tasks, and utility command handlers.
 */

#include <ppp/app/PppApplicationInternal.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/diagnostics/LinkTelemetry.h>
#include <ppp/diagnostics/Telemetry.h>
#include <cstdio>

namespace ppp::app {

/**
 * @brief Appends one formatted line with aligned key column to environment output.
 * @param lines Output line vector.
 * @param key Left-side label text.
 * @param value Right-side value text.
 */
static void AppendEnvLine(ppp::vector<ppp::string>& lines, const char* key, const ppp::string& value) noexcept {
    ppp::string line = key;
    line = ppp::PaddingRight<ppp::string>(line, 22u, ' ');
    line += ": ";
    line += value;
    lines.emplace_back(std::move(line));
}

/**
 * @brief Builds a repeated section separator line at fixed width.
 * @param width Number of characters in the separator.
 * @return String filled with '-' characters.
 */
static ppp::string BuildSectionSeparator(std::size_t width) noexcept {
    ppp::string separator;
    separator = ppp::PaddingRight<ppp::string>(separator, width, '-');
    return separator;
}

/**
 * @brief Converts current build flavor to printable hosting environment text.
 * @param client_mode Whether process currently runs in client mode.
 * @return String in format "client:production" / "server:development".
 */
static ppp::string BuildHostingEnvironmentText(bool client_mode) noexcept {
#if defined(_DEBUG)
    ppp::string env = "development";
#else
    ppp::string env = "production";
#endif
    return (client_mode ? ppp::string("client:") : ppp::string("server:")) + env;
}

/**
 * @brief Formats exchanger link state enum to printable text.
 * @param state Exchanger runtime network state.
 * @return One of connecting/established/reconnecting.
 */
static const char* ToNetworkStateString(VEthernetExchanger::NetworkState state) noexcept {
    switch (state) {
        case VEthernetExchanger::NetworkState_Established:
            return "established";
        case VEthernetExchanger::NetworkState_Reconnecting:
            return "reconnecting";
        default:
            return "connecting";
    }
}

/**
 * @brief Builds full runtime environment lines mirrored from legacy foreground console output.
 * @param lines Output line vector receiving formatted environment rows.
 */
void PppApplication::GetEnvironmentInformationLines(ppp::vector<ppp::string>& lines,
    uint64_t incoming_traffic,
    uint64_t outgoing_traffic,
    const std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept {
    lines.clear();
    lines.reserve(160u);

    static constexpr std::size_t kSectionSeparatorWidth = 96u;
    ppp::string section_separator = BuildSectionSeparator(kSectionSeparatorWidth);

    ppp::string hosting_environment = BuildHostingEnvironmentText(client_mode_);

    ppp::string app_label = PPP_APPLICATION_NAME;
    app_label += " v";
    app_label += PPP_APPLICATION_VERSION;
    app_label += " (";
    app_label += client_mode_ ? "client" : "server";
    app_label += ")";

    AppendEnvLine(lines, "Application", app_label);
    AppendEnvLine(lines, "Max Concurrent", stl::to_string<ppp::string>(
        configuration_ ? configuration_->concurrent : 0));
    AppendEnvLine(lines, "Process", stl::to_string<ppp::string>(
        static_cast<Int32>(ppp::GetCurrentProcessId())));

#if defined(__SIMD__)
    if (aesni::aes_cpu_is_support()) {
        AppendEnvLine(lines, "Triplet", ppp::string(ppp::GetSystemCode()) + ":" + ppp::GetPlatformCode() + "[SIMD]");
    } else {
        AppendEnvLine(lines, "Triplet", ppp::string(ppp::GetSystemCode()) + ":" + ppp::GetPlatformCode());
    }
#else
    AppendEnvLine(lines, "Triplet", ppp::string(ppp::GetSystemCode()) + ":" + ppp::GetPlatformCode());
#endif

    AppendEnvLine(lines, "Cwd", ppp::GetCurrentDirectoryPath());
    AppendEnvLine(lines, "Template", configuration_path_);

    std::shared_ptr<VirtualEthernetSwitcher> server = server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;

    if (NULLPTR != server) {
        auto managed_server = server->GetManagedServer();
        if (NULLPTR != managed_server) {
            const char* link_state = "connecting";
            if (managed_server->LinkIsAvailable()) {
                link_state = "established";
            } else if (managed_server->LinkIsReconnecting()) {
                link_state = "reconnecting";
            }

            AppendEnvLine(lines, "Managed Server", managed_server->GetUri() + " @(" + link_state + ")");
        }
    }

    if (NULLPTR != client) {
#if !defined(_ANDROID) && !defined(_IPHONE)
        if (ppp::string remote_uri = client->GetRemoteUri(); !remote_uri.empty()) {
            std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
            ppp::string mode_text = (NULLPTR != exchanger && exchanger->StaticEchoAllocated()) ? "static" : "dynamic";
            AppendEnvLine(lines, "VPN Server", remote_uri + " [" + mode_text + "]");
        }
#endif

        struct {
            const char* tab;
            std::shared_ptr<VEthernetLocalProxySwitcher> switcher;
        } proxys[] = {
            { "http", client->GetHttpProxy() },
            { "socks", client->GetSocksProxy() }
        };
        for (const auto& proxy : proxys) {
            std::shared_ptr<VEthernetLocalProxySwitcher> switcher = proxy.switcher;
            if (NULLPTR == switcher) {
                continue;
            }

            boost::asio::ip::tcp::endpoint localEP = switcher->GetLocalEndPoint();
            boost::asio::ip::address localIP = localEP.address();
            if (localIP.is_unspecified()) {
#if !defined(_ANDROID) && !defined(_IPHONE)
                if (auto ni = client->GetUnderlyingNetworkInterface(); NULLPTR != ni) {
                    localIP = ni->IPAddress;
                }
#endif
            }

            ppp::string endpoint_text = IPEndPoint::ToEndPoint(boost::asio::ip::tcp::endpoint(localIP, localEP.port())).ToString();
            if ("http" == ppp::string(proxy.tab)) {
                AppendEnvLine(lines, "Http Proxy", endpoint_text + "/http");
            } else {
                AppendEnvLine(lines, "Socks Proxy", endpoint_text + "/socks");
            }
        }

#if defined(_WIN32)
        AppendEnvLine(lines, "P/A Controller", client->GetPaperAirplaneController() ? "on" : "off");
#endif
    }

    if (NULLPTR != server) {
        if (std::shared_ptr<AppConfiguration> configuration = configuration_; NULLPTR != configuration) {
            AppendEnvLine(lines, "Public IP", configuration->ip.public_);
            AppendEnvLine(lines, "Interface IP", configuration->ip.interface_);
        }

        using NAC = VirtualEthernetSwitcher::NetworkAcceptorCategories;
        const char* categories[] = { "ppp+tcp", "ppp+udp", "ppp+ws", "ppp+wss", "cdn+1", "cdn+2" };
        NAC category_values[] = {
            NAC::NetworkAcceptorCategories_Tcpip,
            NAC::NetworkAcceptorCategories_Udpip,
            NAC::NetworkAcceptorCategories_WebSocket,
            NAC::NetworkAcceptorCategories_WebSocketSSL,
            NAC::NetworkAcceptorCategories_CDN1,
            NAC::NetworkAcceptorCategories_CDN2,
        };

        for (int i = 0, service_index = 0; i < arraysizeof(categories); ++i) {
            boost::asio::ip::tcp::endpoint serverEP = server->GetLocalEndPoint(category_values[i]);
            if (serverEP.port() <= IPEndPoint::MinPort || serverEP.port() > IPEndPoint::MaxPort) {
                continue;
            }

            ppp::string service_name = "Service ";
            service_name += stl::to_string<ppp::string>(++service_index);
            service_name = ppp::PaddingRight<ppp::string>(service_name, 22u, ' ');
            service_name += ": ";
            service_name += IPEndPoint::ToEndPoint(serverEP).ToString();
            service_name += "/";
            service_name += categories[i];
            lines.emplace_back(std::move(service_name));
        }
    }

    AppendEnvLine(lines, "Hosting Environment", hosting_environment);
    lines.emplace_back(ppp::string());

#if !defined(_ANDROID) && !defined(_IPHONE)
    if (NULLPTR != client) {
        struct {
            std::shared_ptr<VEthernetNetworkSwitcher::NetworkInterface> ni;
            const char* tab;
            bool tun;
        } stnis[] = {
            { client->GetTapNetworkInterface(), "TUN", true },
            { client->GetUnderlyingNetworkInterface(), "NIC", false },
        };

        for (const auto& sti : stnis) {
            auto ni = sti.ni;
            if (NULLPTR == ni) {
                continue;
            }

            lines.emplace_back(sti.tab);
            lines.emplace_back(section_separator);

#if defined(_WIN32)
            AppendEnvLine(lines, "Name", ni->Name + "[" + ni->Description + "]");
#else
            AppendEnvLine(lines, "Name", ni->Name);
#endif

            AppendEnvLine(lines, "Index", stl::to_string<ppp::string>(ni->Index));

#if !defined(_MACOS)
            if (!ni->Id.empty()) {
                AppendEnvLine(lines, "Id", ni->Id);
            }
#endif

            ppp::string interface_text;
            interface_text += Ipep::ToAddressString<ppp::string>(ni->IPAddress);
            interface_text += " ";
            interface_text += Ipep::ToAddressString<ppp::string>(ni->GatewayServer);
            interface_text += " ";
            interface_text += Ipep::ToAddressString<ppp::string>(ni->SubmaskAddress);
            AppendEnvLine(lines, "Interface", interface_text);

            if (sti.tun) {
                std::shared_ptr<aggligator::aggligator> aggligator = client->GetAggligator();
                if (NULLPTR != aggligator) {
                    const char* aggligator_states[] = { "none", "unknown", "connecting", "reconnecting", "established" };
                    int max_channel = 0;
                    int max_servers = 0;
                    aggligator->client_fetch_concurrency(max_servers, max_channel);

                    aggligator::aggligator::link_status status = aggligator->status();
                    int state_index = static_cast<int>(status);
                    if (0 > state_index || state_index >= arraysizeof(aggligator_states)) {
                        state_index = 1;
                    }

                    ppp::string aggligator_text = aggligator_states[state_index];
                    aggligator_text += ", ";
                    aggligator_text += stl::to_string<ppp::string>(max_servers);
                    aggligator_text += "-server, ";
                    aggligator_text += stl::to_string<ppp::string>(max_channel);
                    aggligator_text += "-channel";
                    AppendEnvLine(lines, "Aggligator", aggligator_text);
                } else {
                    AppendEnvLine(lines, "Aggligator", "none");
                }

                std::shared_ptr<ppp::transmissions::proxys::IForwarding> forwarding = client->GetForwarding();
                if (NULLPTR != forwarding) {
                    AppendEnvLine(lines, "Proxy Interlayer", forwarding->GetProxyUrl());
                } else {
                    AppendEnvLine(lines, "Proxy Interlayer", "none");
                }

                AppendEnvLine(lines, "TCP/IP CC",
                    client->IsLwip() ? "lwip" :
#ifdef SYSNAT
                    (client->IsSysnat() ? "tc" : "ctcp")
#else
                    "ctcp"
#endif
                );
                AppendEnvLine(lines, "Block QUIC", client->IsBlockQUIC() ? "blocked" : "unblocked");

                std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger();
                if (NULLPTR != exchanger) {
                    ppp::string mux_state;
                    if (client->IsMuxEnabled()) {
                        mux_state = ToNetworkStateString(exchanger->GetMuxNetworkState());
                        mux_state += ", ";
                        mux_state += stl::to_string<ppp::string>(client->Mux(NULLPTR));
                        mux_state += "-channel";
                    } else {
                        mux_state = "none";
                    }

                    AppendEnvLine(lines, "Mux State", mux_state);
                    AppendEnvLine(lines, "Link State", ToNetworkStateString(exchanger->GetNetworkState()));
                } else {
                    AppendEnvLine(lines, "Mux State", "none");
                    AppendEnvLine(lines, "Link State", "none");
                }
            }

            /**
             * @brief Resolve a friendly label for a DNS server IP by matching
             *        against the application-level NetworkInterface labels.
             *
             * Labels were captured at GetDnsAddresses() time and may carry the
             * DoH/DoT hostname (e.g. "cloudflare-dns.com (DoH)"). When no label
             * is found we fall back to the literal IP rendering.
             */
            auto resolve_dns_label = [this](const boost::asio::ip::address& ip) noexcept -> ppp::string {
                if (NULLPTR == network_interface_) {
                    return ppp::string();
                }
                const std::size_t n = std::min(network_interface_->DnsAddresses.size(),
                                               network_interface_->DnsLabels.size());
                for (std::size_t k = 0; k < n; ++k) {
                    if (network_interface_->DnsAddresses[k] == ip) {
                        return network_interface_->DnsLabels[k];
                    }
                }
                return ppp::string();
            };

            for (std::size_t i = 0, l = ni->DnsAddresses.size(); i < l; ++i) {
                ppp::string dns_key = "DNS Server ";
                dns_key += stl::to_string<ppp::string>(i + 1u);
                dns_key = ppp::PaddingRight<ppp::string>(dns_key, 22u, ' ');
                dns_key += ": ";
                ppp::string label = sti.tun ? resolve_dns_label(ni->DnsAddresses[i]) : ppp::string();
                if (!label.empty()) {
                    dns_key += label;
                    dns_key += " [";
                    dns_key += Ipep::ToAddressString<ppp::string>(ni->DnsAddresses[i]);
                    dns_key += "]";
                } else {
                    dns_key += Ipep::ToAddressString<ppp::string>(ni->DnsAddresses[i]);
                }
                lines.emplace_back(std::move(dns_key));
            }

            lines.emplace_back(ppp::string());
        }
    }
#endif

    lines.emplace_back("VPN");
    lines.emplace_back(section_separator);
    AppendEnvLine(lines, "Duration", stopwatch_.Elapsed().ToString("TT:mm:ss", false));
    if (NULLPTR != server) {
        AppendEnvLine(lines, "Sessions", stl::to_string<ppp::string>(server->GetAllExchangerNumber()));
    }

    AppendEnvLine(lines, "TX", ppp::StrFormatByteSize(static_cast<Int64>(outgoing_traffic)));
    AppendEnvLine(lines, "RX", ppp::StrFormatByteSize(static_cast<Int64>(incoming_traffic)));
    if (NULLPTR != statistics_snapshot) {
        AppendEnvLine(lines, "IN", ppp::StrFormatByteSize(static_cast<Int64>(statistics_snapshot->IncomingTraffic.load())));
        AppendEnvLine(lines, "OUT", ppp::StrFormatByteSize(static_cast<Int64>(statistics_snapshot->OutgoingTraffic.load())));
    }

    /**
     * @brief Link Telemetry section — displayed in right column (two-column mode)
     * or appended after info lines (single-column mode).
     */
    ppp::vector<ppp::string> telemetry_lines;
    telemetry_lines.emplace_back("Link Telemetry");
    telemetry_lines.emplace_back(section_separator);

    {
        ppp::diagnostics::LinkTelemetry& lt = ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal();
        ppp::diagnostics::LinkTelemetrySnapshot snap = lt.GetSnapshot();

        {
            char quality_buf[64];
            std::snprintf(quality_buf, sizeof(quality_buf), "%.2f%% %s",
                snap.quality_percent,
                ppp::diagnostics::LinkTelemetry::GetQualityGradeName(snap.grade));
            AppendEnvLine(telemetry_lines, "Quality", ppp::string(quality_buf));
        }

        AppendEnvLine(telemetry_lines, "Error Count",
            stl::to_string<ppp::string>(static_cast<Int64>(snap.error_count)));

        AppendEnvLine(telemetry_lines, "Success Count",
            stl::to_string<ppp::string>(static_cast<Int64>(snap.success_count)));

        AppendEnvLine(telemetry_lines, "Total Events",
            stl::to_string<ppp::string>(static_cast<Int64>(snap.total_count)));

        {
            double error_rate = 0.0;
            if (snap.success_count > 0) {
                error_rate = (static_cast<double>(snap.error_count) / static_cast<double>(snap.success_count)) * 100.0;
            } else if (snap.error_count > 0) {
                error_rate = 100.0;
            }
            char rate_buf[64];
            std::snprintf(rate_buf, sizeof(rate_buf), "%.2f%% (relative to OK)", error_rate);
            AppendEnvLine(telemetry_lines, "Error Rate", ppp::string(rate_buf));
        }

        if (snap.grade >= ppp::diagnostics::LinkQualityGrade::Good &&
            snap.grade != ppp::diagnostics::LinkQualityGrade::Unknown) {
            telemetry_lines.emplace_back("  !! Report to OPENPPP2 when quality <= 95%");
        }

        if (snap.grade == ppp::diagnostics::LinkQualityGrade::Unusable) {
            telemetry_lines.emplace_back("  !! CRITICAL: Quality < 90% — STOP OPENPPP2!");
        }
    }

    ConsoleUI::GetInstance().SetTelemetryLines(telemetry_lines);
}

/**
 * @brief Disposes active server/client switchers and clears periodic timers.
 */
void PppApplication::Dispose() noexcept {
    ConsoleUI::GetInstance().Stop();

    std::shared_ptr<VirtualEthernetSwitcher> server = std::move(server_);
    if (NULLPTR != server) {
        server->Dispose();
    }

    std::shared_ptr<VEthernetNetworkSwitcher> client = std::move(client_);
    if (NULLPTR != client) {
#if defined(_WIN32)
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(quic_);
        if (network_interface_->SetHttpProxy) {
            client->ClearHttpProxyToSystemEnv();
        }
#endif
        client->Dispose();
    }

    ClearTickAlwaysTimeout();

    ppp::telemetry::Flush(3000);
    ppp::telemetry::Shutdown();
}

/**
 * @brief Retrieves aggregated traffic counters and optional statistics snapshot.
 * @param incoming_traffic Receives inbound bytes.
 * @param outgoing_traffic Receives outbound bytes.
 * @param statistics_snapshot Receives snapshot object when available.
 * @return True when statistics are available and successfully sampled.
 */
bool PppApplication::GetTransmissionStatistics(
    uint64_t& incoming_traffic,
    uint64_t& outgoing_traffic,
    std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept {
    statistics_snapshot = NULLPTR;
    incoming_traffic = 0;
    outgoing_traffic = 0;

    std::shared_ptr<VirtualEthernetSwitcher> server = server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if ((NULLPTR != server && !server->IsDisposed()) || (NULLPTR != client && !client->IsDisposed())) {
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics> transmission_statistics;
        if (NULLPTR != client) {
            transmission_statistics = client->GetStatistics();
        } else if (NULLPTR != server) {
            transmission_statistics = server->GetStatistics();
        }

        if (NULLPTR != transmission_statistics) {
            return ppp::transmissions::ITransmissionStatistics::GetTransmissionStatistics(
                transmission_statistics,
                transmission_statistics_,
                incoming_traffic,
                outgoing_traffic,
                statistics_snapshot);
        }
    }

    return false;
}

/**
 * @brief Periodic runtime tick for restart policy and dynamic route refresh.
 * @param now Current monotonic tick in milliseconds.
 * @return True when loop remains healthy; false when no active client state exists.
 */
bool PppApplication::OnTick(uint64_t now) noexcept {
    using RouteIPListTablePtr = VEthernetNetworkSwitcher::RouteIPListTablePtr;
    using NetworkState = VEthernetExchanger::NetworkState;

    uint64_t incoming_traffic = 0;
    uint64_t outgoing_traffic = 0;

    std::shared_ptr<ppp::transmissions::ITransmissionStatistics> statistics_snapshot;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    std::shared_ptr<VEthernetExchanger> exchanger = NULLPTR;
    if (NULLPTR != client) {
        exchanger = client->GetExchanger();
    }

    if (!GetTransmissionStatistics(incoming_traffic, outgoing_traffic, statistics_snapshot)) {
        incoming_traffic = 0;
        outgoing_traffic = 0;
    }

    ppp::string vpn_state = "disconnected";
    if (NULLPTR != client) {
        if (NULLPTR == exchanger) {
            vpn_state = "connecting";
        } else {
            NetworkState network_state = exchanger->GetNetworkState();
            if (network_state == NetworkState::NetworkState_Established) {
                vpn_state = "established";
            } else if (network_state == NetworkState::NetworkState_Reconnecting) {
                vpn_state = "reconnecting";
            } else {
                vpn_state = "connecting";
            }
        }
    }

    ppp::string status = "vpn=" + vpn_state;
    status += " rx=" + ppp::StrFormatByteSize((Int64)incoming_traffic);
    status += " tx=" + ppp::StrFormatByteSize((Int64)outgoing_traffic);

    {
        double quality = ppp::diagnostics::LinkTelemetryGlobal::GetInstance().GetTotal().GetQualityPercent();
        ppp::diagnostics::LinkQualityGrade grade = ppp::diagnostics::LinkTelemetry::ClassifyQuality(quality);
        char quality_buf[32];
        std::snprintf(quality_buf, sizeof(quality_buf), " link=%.1f%%", quality);
        status += quality_buf;
        status += " ";
        status += ppp::diagnostics::LinkTelemetry::GetQualityGradeName(grade);
    }

    ConsoleUI::GetInstance().UpdateStatus(status);

    ppp::vector<ppp::string> info;
    GetEnvironmentInformationLines(info, incoming_traffic, outgoing_traffic, statistics_snapshot);
    ConsoleUI::GetInstance().SetInfoLines(info);

#if defined(_WIN32)
    ppp::win32::Win32Native::OptimizedProcessWorkingSize();
#endif

    if (GLOBAL_.auto_restart > 0) {
        int64_t elapsed_milliseconds = stopwatch_.ElapsedMilliseconds() / 1000;
        if (elapsed_milliseconds > 0 && elapsed_milliseconds >= GLOBAL_.auto_restart) {
            return ShutdownApplication(true);
        }
    }

    if (NULLPTR == client) {
        return false;
    }

    if (NULLPTR == exchanger) {
        return false;
    }

    NetworkState network_state = exchanger->GetNetworkState();
    if (network_state == NetworkState::NetworkState_Established) {
        if (GLOBAL_.link_restart > 0) {
            if (exchanger->GetReconnectionCount() >= GLOBAL_.link_restart) {
                return ShutdownApplication(true);
            }
        }
    } else {
        return false;
    }

    if (now >= GLOBAL_VIRR_NEXT.load(std::memory_order_relaxed)) {
        GLOBAL_VIRR_NEXT.store(now + (configuration_->virr.update_interval * 1000), std::memory_order_relaxed);
        if (GLOBAL_VIRR.load(std::memory_order_relaxed)) {
            PullIPList(GLOBAL_.virr_argument, true);
        }
    }

    if ((now - GLOBAL_VBGP_LAST.load(std::memory_order_relaxed)) / 1000 >= (uint64_t)configuration_->vbgp.update_interval) {
        GLOBAL_VBGP_LAST.store(now, std::memory_order_relaxed);
        if (RouteIPListTablePtr vbgp = client->GetVbgp(); GLOBAL_VBGP.load(std::memory_order_relaxed) && NULLPTR != vbgp) {

            /**
             * @brief Pulls each configured V-BGP list and restarts when file content changes.
             *
             * For every registered path/url pair, the callback compares downloaded routes
             * with on-disk content. A write of changed content triggers graceful restart.
             */
            for (auto&& kv : *vbgp) {
                const ppp::string& path = kv.first;
                const ppp::string& url = kv.second;
                PullIPList(url,
                    [path](int count, const ppp::set<ppp::string>& ips) noexcept {
                        if (count < 1) {
                            return -1;
                        }

                        ppp::set<ppp::string> olds;
                        ppp::string iplist = ppp::LTrim(ppp::RTrim(File::ReadAllText(path.data())));

                        chnroutes2_getiplist(olds, ppp::string(), iplist);
                        if (!chnroutes2_equals(ips, olds)) {
                            ppp::string news = chnroutes2_toiplist(ips);
                            if (File::WriteAllBytes(path.data(), news.data(), news.size())) {
                                ShutdownApplication(true);
                                return 1;
                            }
                        }

                        return 0;
                    });
            }
        }
    }

    return true;
}

#if defined(_WIN32)
/**
 * @brief Handles `--no-lsp` command to exclude process from LSP interception.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return True when command was present (whether successful or not), false otherwise.
 */
bool Windows_NoLsp(int argc, const char* argv[]) noexcept {
    char key[] = "--no-lsp";
    if (!ppp::HasCommandArgument(key, argc, argv)) {
        return false;
    }

    bool ok = false;
    ppp::diagnostics::ErrorCode error_code = ppp::diagnostics::ErrorCode::Success;
    do {
        ppp::string line = ppp::GetCommandArgument(argc, argv);
        if (line.empty()) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        std::size_t index = line.find(key);
        if (index == ppp::string::npos) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        line = line.substr(index + sizeof(key) - 1);
        if (line.empty()) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        int ch = line[0];
        if (ch != '=' && ch != ' ') {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        line = ppp::RTrim(ppp::LTrim(line.substr(1)));
        if (line.empty()) {
            error_code = ppp::diagnostics::ErrorCode::AppInvalidCommandLine;
            break;
        }

        ok = ppp::app::client::lsp::PaperAirplaneController::NoLsp(line);
        if (!ok) {
            error_code = ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid;
        }
    } while (false);

    if (!ok) {
        ppp::diagnostics::SetLastErrorCode(error_code);
    }

    return true;
}

/**
 * @brief Handles Windows network utility command-line operations.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return True when a supported command was detected, false otherwise.
 */
bool Windows_PreferredNetwork(int argc, const char* argv[]) noexcept {
    bool ok = false;
    if (ppp::HasCommandArgument("--system-network-preferred-ipv4", argc, argv)) {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(true);
    } else if (ppp::HasCommandArgument("--system-network-preferred-ipv6", argc, argv)) {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(false);
    } else if (ppp::HasCommandArgument("--system-network-reset", argc, argv)) {
        ok = ppp::win32::network::ResetNetworkEnvironment();
    } else {
        return false;
    }

    if (!ok) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
    }

    return true;
}
#endif

} // namespace ppp::app
