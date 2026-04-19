/**
 * @file ApplicationMainLoop.cpp
 * @brief Runtime loop, periodic tasks, and utility command handlers.
 */

#include <ppp/app/PppApplicationInternal.h>

namespace ppp::app {

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
        } elif (NULLPTR != server) {
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

    ppp::string vpn_state = "down";
    if (NULLPTR != client) {
        if (NULLPTR == exchanger) {
            vpn_state = "init";
        } else {
            NetworkState network_state = exchanger->GetNetworkState();
            if (network_state == NetworkState::NetworkState_Established) {
                vpn_state = "up";
            } elif (network_state == NetworkState::NetworkState_Reconnecting) {
                vpn_state = "reconnect";
            } else {
                vpn_state = "connect";
            }
        }
    }

    ppp::string status = "vpn=" + vpn_state;
    status += " rx=" + ppp::StrFormatByteSize((Int64)incoming_traffic);
    status += " tx=" + ppp::StrFormatByteSize((Int64)outgoing_traffic);
    ConsoleUI::GetInstance().UpdateStatus(status);

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
    do {
        ppp::string line = ppp::GetCommandArgument(argc, argv);
        if (line.empty()) {
            break;
        }

        std::size_t index = line.find(key);
        if (index == ppp::string::npos) {
            break;
        }

        line = line.substr(index + sizeof(key) - 1);
        if (line.empty()) {
            break;
        }

        int ch = line[0];
        if (ch != '=' && ch != ' ') {
            break;
        }

        line = ppp::RTrim(ppp::LTrim(line.substr(1)));
        if (line.empty()) {
            break;
        }

        ok = ppp::app::client::lsp::PaperAirplaneController::NoLsp(line);
    } while (false);

    if (!ok) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
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
    } elif (ppp::HasCommandArgument("--system-network-preferred-ipv6", argc, argv)) {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(false);
    } elif (ppp::HasCommandArgument("--system-network-reset", argc, argv)) {
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
