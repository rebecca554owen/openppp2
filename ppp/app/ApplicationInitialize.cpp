/**
 * @file ApplicationInitialize.cpp
 * @brief Startup, teardown, and runtime preflight routines for the PPP application.
 */

#include <ppp/app/PppApplicationInternal.h>

namespace ppp::app {

/**
 * @brief Initializes process-level console state and platform-specific UI settings.
 *
 * @note The terminal cursor visibility is intentionally *not* altered here.
 *       ConsoleUI::Start() owns the cursor state for the duration of the TUI
 *       session and restores it verbatim on Stop().  Touching the cursor at
 *       construction time would corrupt redirected log files (the escape
 *       sequence would be written into the pipe) and race with the TUI's own
 *       save/restore sequence.
 */
PppApplication::PppApplication() noexcept {
#if defined(_WIN32)
    SetConsoleTitle(TEXT("PPP PRIVATE NETWORK™ 2"));

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (NULLPTR != hConsole) {
        COORD cSize = {120, ppp::win32::Win32Native::IsWindows11OrLaterVersion() ? 46 : 47};
        if (SetConsoleScreenBufferSize(hConsole, cSize)) {
            SMALL_RECT rSize = {0, 0, cSize.X - 1, cSize.Y - 1};
            SetConsoleWindowInfo(hConsole, TRUE, &rSize);
        }
    }

    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(false);
#endif
}

/**
 * @brief Releases owned runtime resources before object destruction.
 */
PppApplication::~PppApplication() noexcept {
    Release();
}

/**
 * @brief Restores temporary process state and closes singleton guard handles.
 *
 * @note Cursor restoration is handled by ConsoleUI::Stop(); see the note on
 *       the constructor for the rationale.
 */
void PppApplication::Release() noexcept {
#if defined(_WIN32)
    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(true);
#endif

    prevent_rerun_.Close();
}

/**
 * @brief Prepares tunnel, switcher, and route environment for client/server mode.
 * @param network_interface Resolved tunnel and routing configuration.
 * @return True when all required runtime components are successfully opened.
 */
bool PppApplication::PreparedLoopbackEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept {
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULLPTR == configuration) {
        return false;
    }

    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        return false;
    }

#if defined(_WIN32)
    ppp::string executable_path = File::GetFullPath(File::RewritePath(ppp::GetFullExecutionFilePath().data()).data());
    ppp::win32::network::Fw::NetFirewallAddApplication(PPP_APPLICATION_NAME, executable_path.data());
    ppp::win32::network::Fw::NetFirewallAddAllApplication(PPP_APPLICATION_NAME, executable_path.data());

    if (client_mode_) {
        if (network_interface->HostedNetwork && configuration->client.paper_airplane.tcp) {
            if (ppp::app::client::lsp::PaperAirplaneController::Install() < 0) {
                return false;
            }
        }
        ppp::app::client::lsp::PaperAirplaneController::NoLsp();
        ppp::app::client::lsp::PaperAirplaneController::Reset();
    }
#endif

    bool success = false;
    if (client_mode_) {
        std::shared_ptr<VEthernetNetworkSwitcher> ethernet = NULLPTR;
        std::shared_ptr<ITap> tap = NULLPTR;

        /**
         * @brief Performs client-side tunnel initialization as one transactional block.
         *
         * The sequence creates TAP, opens it, configures switcher options/routes, and
         * opens the virtual ethernet path. Any failure breaks out to centralized cleanup.
         */
        do {
#if defined(_WIN32)
            tap = ITap::Create(context,
                network_interface->ComponentId,
                Ipep::ToAddressString<ppp::string>(network_interface->IPAddress),
                Ipep::ToAddressString<ppp::string>(network_interface->GatewayServer),
                Ipep::ToAddressString<ppp::string>(network_interface->SubmaskAddress),
                network_interface->LeaseTimeInSeconds,
                network_interface->HostedNetwork,
                Ipep::AddressesTransformToStrings(network_interface->DnsAddresses));
#else
            tap = ITap::Create(context,
                network_interface->ComponentId,
                Ipep::ToAddressString<ppp::string>(network_interface->IPAddress),
                Ipep::ToAddressString<ppp::string>(network_interface->GatewayServer),
                Ipep::ToAddressString<ppp::string>(network_interface->SubmaskAddress),
                network_interface->Promisc,
                network_interface->HostedNetwork,
                Ipep::AddressesTransformToStrings(network_interface->DnsAddresses));
#endif
            if (NULLPTR == tap) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                break;
            }

            tap->BufferAllocator = configuration->GetBufferAllocator();
            if (!tap->Open()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelListenFailed);
                break;
            }

            ethernet = ppp::make_shared_object<VEthernetNetworkSwitcher>(context, network_interface->Lwip, network_interface->VNet, configuration->concurrent > 1, configuration);
            if (NULLPTR == ethernet) {
                break;
            }
            if (network_interface->IPv6Address.is_v6()) {
                std::string requested_ipv6_std = network_interface->IPv6Address.to_string();
                ethernet->RequestedIPv6(ppp::string(requested_ipv6_std.data(), requested_ipv6_std.size()));
            }

#if !defined(_WIN32)
            ethernet->Ssmt(&network_interface->Ssmt);
#if defined(_LINUX)
            ethernet->SsmtMQ(&network_interface->SsmtMQ);
            ethernet->ProtectMode(&network_interface->ProtectNetwork);
#endif
#endif
            ethernet->Mux(&network_interface->Mux);
            ethernet->MuxAcceleration(&network_interface->MuxAcceleration);
            ethernet->StaticMode(&network_interface->StaticMode);
            ethernet->PreferredNgw(network_interface->Ngw);
            ethernet->PreferredNic(network_interface->Nic);

#if defined(_LINUX)
            for (auto&& bypass_path : *network_interface->Bypass) {
                ethernet->AddLoadIPList(bypass_path, network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
            }
#else
            for (auto&& bypass_path : *network_interface->Bypass) {
                ethernet->AddLoadIPList(bypass_path, network_interface->BypassNgw, ppp::string());
            }
#endif
            for (auto&& route : configuration->client.routes) {
                ppp::string path = File::GetFullPath(File::RewritePath(route.path.data()).data());
                if (path.empty()) {
                    continue;
                }

#if defined(_LINUX)
                ethernet->AddLoadIPList(path, route.nic, Ipep::ToAddress(route.ngw), route.vbgp);
#else
                ethernet->AddLoadIPList(path, Ipep::ToAddress(route.ngw), route.vbgp);
#endif
            }

            ethernet->LoadAllDnsRules(network_interface->DNSRules, true);
            if (!ethernet->Open(tap)) {
                auto ni = ethernet->GetUnderlyingNetworkInterface();
                if (NULLPTR != ni) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                } else {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }
                break;
            }

            success = true;
            client_ = ethernet;
        } while (false);

        if (!success) {
            client_.reset();
            if (NULLPTR != ethernet) {
                ethernet->Dispose();
            }
            if (NULLPTR != tap) {
                tap->Dispose();
            }
        }
    } else {
        std::shared_ptr<VirtualEthernetSwitcher> ethernet = NULLPTR;

        /**
         * @brief Performs server-side switcher startup as one transactional block.
         *
         * Linux IPv6 prerequisites are prepared first, then the virtual switcher is
         * created, opened, and started. Failure paths finalize platform state.
         */
        do {
            if (!ppp::ipv6::auxiliary::PrepareServerEnvironment(configuration, network_interface->Nic, network_interface->ComponentId)) {
                if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ServerPrepareFailed);
                }
                break;
            }

#if defined(_WIN32)
            ethernet = ppp::make_shared_object<VirtualEthernetSwitcher>(configuration, network_interface->ComponentId);
#else
            ethernet = ppp::make_shared_object<VirtualEthernetSwitcher>(configuration, network_interface->ComponentId, network_interface->Ssmt, network_interface->SsmtMQ);
#endif
            if (NULLPTR == ethernet) {
                break;
            }

            ethernet->PreferredNic(network_interface->Nic);
            if (!ethernet->Open(network_interface->FirewallRules)) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                break;
            }

            if (!ethernet->Run()) {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelListenFailed);
                break;
            }

            success = true;
            server_ = ethernet;
        } while (false);

        if (!success) {
            ppp::ipv6::auxiliary::FinalizeServerEnvironment(configuration, network_interface->Nic, network_interface->ComponentId);
            server_.reset();
            if (NULLPTR != ethernet) {
                ethernet->Dispose();
            }
        }
    }

    return success;
}

#if defined(_WIN32)
/**
 * @brief Ensures a usable Windows TAP/Wintun component id is available.
 * @param network_interface Network interface settings to update in place.
 * @return True when a component id is resolved or already present.
 */
bool Windows_PreparedEthernetEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept {
    if (network_interface->ComponentId.empty()) {
        ppp::string driverPath = File::GetFullPath((ppp::GetApplicationStartupPath() + "\\Driver\\").data());
        if (ppp::tap::TapWindows::InstallDriver(driverPath.data(), NetworkInterface::GetDefaultTun())) {
            network_interface->ComponentId = ppp::tap::TapWindows::FindComponentId(network_interface->Wintun);
            if (network_interface->ComponentId.empty()) {
                network_interface->ComponentId = ppp::tap::ITap::FindAnyDevice();
            }
        }

        if (network_interface->ComponentId.empty()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            return false;
        }
    }
    return true;
}
#endif

/**
 * @brief Executes main startup flow after arguments/configuration are prepared.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Zero on success, negative value on failure.
 */
int PppApplication::Main(int argc, const char* argv[]) noexcept {
    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    if (!ppp::IsUserAnAdministrator()) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppPrivilegeRequired);
        return -1;
    }

    ppp::string rerun_name = (client_mode_ ? "client://" : "server://") + configuration_path_;
    if (prevent_rerun_.Exists(rerun_name.data())) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppAlreadyRunning);
        return -1;
    }

    if (!prevent_rerun_.Open(rerun_name.data())) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppLockAcquireFailed);
        return -1;
    }

#if defined(_WIN32)
    if (client_mode_) {
        if (!Windows_PreparedEthernetEnvironment(network_interface_)) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            return -1;
        }
    }

    quic_ = ppp::net::proxies::HttpProxy::IsSupportExperimentalQuicProtocol();
#endif

    if (!PreparedLoopbackEnvironment(network_interface_)) {
        if (ppp::diagnostics::ErrorCode::Success == ppp::diagnostics::GetLastErrorCode()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppPreflightCheckFailed);
        }
        return -1;
    }

    /**
     * @brief TUI startup with isatty-based fallback.
     *
     * When stdout is not connected to a terminal (pipe / file redirection),
     * the full-screen TUI is skipped to avoid corrupting captured output.
     * A brief plain-text summary is printed instead, and the process continues
     * with full VPN functionality but without an interactive interface.
     */
    bool tui_enabled = ConsoleUI::ShouldEnable();
    if (tui_enabled) {
        if (!ConsoleUI::GetInstance().Start()) {
            /**
             * @brief Non-fatal TUI initialization failure.
             *
             * Terminal setup failure (e.g. PrepareInputTerminal on an unsupported
             * pseudo-terminal) is treated as a warning rather than an error.
             * The process continues with plain-text output mode.
             */
            fprintf(stdout,
                "Warning: ConsoleUI initialization failed. "
                "Continuing in plain-text mode.\n");
            tui_enabled = false;
        }
    }

    if (!tui_enabled) {
        /**
         * @brief Plain-text startup banner for no-tty / redirected-output mode.
         *
         * Printed once at startup so that log files and pipes receive at least
         * basic identification information about this process instance.
         */
        fprintf(stdout,
            "PPP PRIVATE NETWORK(TM) 2  version: %s\n",
            PPP_APPLICATION_VERSION);
        fprintf(stdout,
            "Mode    : %s\n",
            client_mode_ ? "client" : "server");
        fprintf(stdout,
            "Process : %d\n",
            static_cast<int>(ppp::GetCurrentProcessId()));
        fprintf(stdout,
            "Config  : %s\n",
            configuration_path_.data());
        fprintf(stdout,
            "Cwd     : %s\n",
            ppp::GetCurrentDirectoryPath().data());
        std::fflush(stdout);
    }

    stopwatch_.Restart();
    transmission_statistics_.Clear();

    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULLPTR != client) {
#if defined(_WIN32)
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(!network_interface_->BlockQUIC);
#endif
        client->BlockQUIC(network_interface_->BlockQUIC);

#if defined(_WIN32)
        if (network_interface_->SetHttpProxy) {
            client->SetHttpProxyToSystemEnv();
        }
#endif

        GLOBAL_VIRR.store(ppp::HasCommandArgument("--virr", argc, argv), std::memory_order_relaxed);
        if (GLOBAL_VIRR.load(std::memory_order_relaxed)) {
            GLOBAL_.bypass = network_interface_->Bypass;
            GLOBAL_.virr_argument = ppp::GetCommandArgument("--virr", argc, argv);
        }

        GLOBAL_VBGP.store(ppp::ToBoolean(ppp::GetCommandArgument("--vbgp", argc, argv, "y").data()), std::memory_order_relaxed);
    }

    GLOBAL_.auto_restart = std::max<int>(0, atoi(ppp::GetCommandArgument("--auto-restart", argc, argv).data()));
    GLOBAL_.link_restart = (uint8_t)std::max<int>(0, atoi(ppp::GetCommandArgument("--link-restart", argc, argv).data()));

    if (!NextTickAlwaysTimeout(false)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
        Dispose();
        return -1;
    }

    return 0;
}

} // namespace ppp::app
