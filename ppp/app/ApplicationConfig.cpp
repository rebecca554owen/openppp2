/**
 * @file ApplicationConfig.cpp
 * @brief Command-line and configuration loading helpers for PPP application startup.
 */

#include <ppp/app/PppApplicationInternal.h>
#include <ppp/diagnostics/Error.h>

namespace ppp::app {

/**
 * @brief Returns the active buffer allocator from loaded configuration.
 * @return Allocator instance, or null when configuration is unavailable.
 */
std::shared_ptr<BufferswapAllocator> PppApplication::GetBufferAllocator() noexcept {
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULLPTR == configuration) {
        return NULLPTR;
    }
    return configuration->GetBufferAllocator();
}

/**
 * @brief Parses command-line arguments and prepares global runtime configuration.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Zero on success, negative value when initialization should abort.
 */
int PppApplication::PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept {
    Socket::SetDefaultFlashTypeOfService(ppp::ToBoolean(ppp::GetCommandArgument("--tun-flash", argc, argv).data()));

    if (ppp::IsInputHelpCommand(argc, argv)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);
        return -1;
    }

    ppp::string path;
    std::shared_ptr<AppConfiguration> configuration = LoadConfiguration(argc, argv, path);
    if (NULLPTR == configuration) {
        if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigLoadFailed);
        }
        return -1;
    }

    client_mode_ = IsModeClientOrServer(argc, argv);

    int max_concurrent = configuration->concurrent - 1;
    if (max_concurrent > 0) {
        Executors::SetMaxSchedulers(max_concurrent);
        if (!client_mode_) {
            Executors::SetMaxThreads(configuration->GetBufferAllocator(), max_concurrent);
        }
    }

    std::shared_ptr<NetworkInterface> network_interface = GetNetworkInterface(argc, argv);
    if (NULLPTR == network_interface) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        return -1;
    }

    configuration_path_ = path;
    configuration_ = configuration;
    network_interface_ = network_interface;

    ppp::net::asio::vdns::ttl = configuration->udp.dns.ttl;
    ppp::net::asio::vdns::enabled = configuration->udp.dns.turbo;

    return 0;
}

/**
 * @brief Resolves an IPv4/IPv6 address argument or CIDR prefix into an address.
 * @param name Command-line key name.
 * @param MIN_PREFIX_ADDRESS Minimum accepted numeric prefix.
 * @param MAX_PREFIX_ADDRESS Maximum accepted numeric prefix.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Parsed address, or IPv4 any-address when invalid/missing.
 */
boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, int argc, const char* argv[]) noexcept {
    ppp::string address_string = ppp::GetCommandArgument(name, argc, argv);
    if (address_string.empty()) {
        return boost::asio::ip::address_v4::any();
    }

    address_string = ppp::LTrim<ppp::string>(address_string);
    address_string = ppp::RTrim<ppp::string>(address_string);
    if (address_string.empty()) {
        return boost::asio::ip::address_v4::any();
    }

    boost::asio::ip::address address;
    if (StringAuxiliary::WhoisIntegerValueString(address_string)) {
        int prefix = atoll(address_string.data());
        if (prefix < 1 || prefix > MAX_PREFIX_ADDRESS) {
            prefix = MAX_PREFIX_ADDRESS;
        } 
        elif (MIN_PREFIX_ADDRESS > 0 && prefix < MIN_PREFIX_ADDRESS) {
            prefix = MIN_PREFIX_ADDRESS;
        }

        auto prefix_to_netmask = IPEndPoint::PrefixToNetmask(prefix);
        address = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(prefix_to_netmask, 0).address();
    } else {
        address = Ipep::ToAddress(address_string, true);
    }

    if (IPEndPoint::IsInvalid(address)) {
        return boost::asio::ip::address_v4::any();
    }

    return address;
}

/**
 * @brief Resolves an address argument and falls back to a default literal.
 * @param name Command-line key name.
 * @param MIN_PREFIX_ADDRESS Minimum accepted numeric prefix.
 * @param MAX_PREFIX_ADDRESS Maximum accepted numeric prefix.
 * @param default_address_string Fallback textual address when argument is absent/invalid.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Parsed address, or fallback default address.
 */
boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, const char* default_address_string, int argc, const char* argv[]) noexcept {
    boost::asio::ip::address address = GetNetworkAddress(name, MIN_PREFIX_ADDRESS, MAX_PREFIX_ADDRESS, argc, argv);
    if (IPEndPoint::IsInvalid(address)) {
        address = boost::asio::ip::address_v4::any();
    }

    if (IPEndPoint::IsInvalid(address)) {
        if (NULLPTR == default_address_string) {
            default_address_string = "";
        }
        return Ipep::ToAddress(default_address_string, false);
    }

    return address;
}

/**
 * @brief Parses DNS arguments and guarantees a usable default resolver set.
 * @param addresses Output container receiving DNS server addresses.
 * @param argc Argument count.
 * @param argv Argument vector.
 */
void PppApplication::GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept {
#if defined(_WIN32)
    bool at_least_two = client_mode_;
#else
    bool at_least_two = false;
#endif

    ppp::string dns = ppp::GetCommandArgument("--dns", argc, argv);
    if (Ipep::ToDnsAddresses(dns, addresses, at_least_two) < 1) {
        boost::system::error_code ec;
        addresses.emplace_back(ppp::StringToAddress(PPP_PREFERRED_DNS_SERVER_1, ec));
        addresses.emplace_back(ppp::StringToAddress(PPP_PREFERRED_DNS_SERVER_2, ec));
    }
}

/**
 * @brief Builds and populates network interface options from command-line arguments.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Constructed network interface object, or null on allocation failure.
 */
std::shared_ptr<NetworkInterface> PppApplication::GetNetworkInterface(int argc, const char* argv[]) noexcept {
    std::shared_ptr<NetworkInterface> ni = ppp::make_shared_object<NetworkInterface>();
    if (NULLPTR != ni) {
#if defined(_WIN32)
        ni->Lwip = ppp::ToBoolean(ppp::GetCommandArgument("--lwip", argc, argv, ppp::tap::TapWindows::IsWintun() ? ppp::string() : "y").data());
#else
        ni->Lwip = ppp::ToBoolean(ppp::GetCommandArgument("--lwip", argc, argv).data());
#endif
        ni->Nic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--nic", argc, argv)));
        ni->BlockQUIC = ppp::ToBoolean(ppp::GetCommandArgument("--block-quic", argc, argv).data());

        GetDnsAddresses(ni->DnsAddresses, argc, argv);
        if (!ni->DnsAddresses.empty()) {
            auto dns_servers = ppp::net::asio::vdns::servers;
            dns_servers->clear();
            for (const boost::asio::ip::address& dns_server : ni->DnsAddresses) {
                dns_servers->emplace_back(boost::asio::ip::udp::endpoint(dns_server, PPP_DNS_SYS_PORT));
            }
        }

        ni->Ngw = GetNetworkAddress("--ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->IPAddress = GetNetworkAddress("--tun-ip", 0, 32, "10.0.0.2", argc, argv);
        ni->IPv6Address = GetNetworkAddress("--tun-ipv6", 0, 128, argc, argv);
        ni->SubmaskAddress = GetNetworkAddress("--tun-mask", 16, 32, "255.255.255.252", argc, argv);
        ni->GatewayServer = GetNetworkAddress("--tun-gw", 0, 32, "10.0.0.1", argc, argv);

#if defined(_WIN32)
        ni->LeaseTimeInSeconds = strtoul(ppp::GetCommandArgument("--tun-lease-time-in-seconds", argc, argv).data(), NULLPTR, 10);
        if (ni->LeaseTimeInSeconds < 1) {
            ni->LeaseTimeInSeconds = 7200;
        }
#endif

        ni->IPAddress = Ipep::FixedIPAddress(ni->IPAddress, ni->GatewayServer, ni->SubmaskAddress);
        ni->StaticMode = ppp::ToBoolean(ppp::GetCommandArgument("--tun-static", argc, argv).data());
        ni->HostedNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-host", argc, argv, "y").data());
        ni->VNet = ppp::ToBoolean(ppp::GetCommandArgument("--tun-vnet", argc, argv, "y").data());

#if defined(_LINUX)
        ni->BypassNic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--bypass-nic", argc, argv)));
#endif
        ni->BypassNgw = GetNetworkAddress("--bypass-ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->BypassLoadList(File::GetFullPath(File::RewritePath(ppp::LTrim(ppp::RTrim(ppp::GetCommandArgument("--bypass", argc, argv, "./ip.txt"))).data()).data()));

        ni->DNSRules = ppp::GetCommandArgument("--dns-rules", argc, argv, "./dns-rules.txt");
        ni->FirewallRules = ppp::GetCommandArgument("--firewall-rules", argc, argv, "./firewall-rules.txt");

        {
            ppp::string tun_mux_arg = ppp::GetCommandArgument("--tun-mux", argc, argv);
            char* endptr = NULLPTR;
            long tun_mux_val = strtol(tun_mux_arg.data(), &endptr, 10);
            ni->Mux = (NULLPTR != endptr && endptr != tun_mux_arg.data() && *endptr == '\x0') ? static_cast<uint16_t>(std::max<long>(0, tun_mux_val)) : 0;
        }
        {
            ppp::string tun_mux_accel_arg = ppp::GetCommandArgument("--tun-mux-acceleration", argc, argv);
            char* endptr = NULLPTR;
            long tun_mux_accel_val = strtol(tun_mux_accel_arg.data(), &endptr, 10);
            ni->MuxAcceleration = (NULLPTR != endptr && endptr != tun_mux_accel_arg.data() && *endptr == '\x0') ? static_cast<uint8_t>(std::max<long>(0, tun_mux_accel_val)) : 0;
        }
        if (ni->MuxAcceleration > PPP_MUX_ACCELERATION_MAX) {
            ni->MuxAcceleration = 0;
        }

#if defined(_WIN32)
        ni->SetHttpProxy = ppp::ToBoolean(ppp::GetCommandArgument("--set-http-proxy", argc, argv).data());
        ni->Wintun = ppp::GetCommandArgument("--tun", argc, argv, NetworkInterface::GetDefaultTun());
        ni->ComponentId = ppp::tap::TapWindows::FindComponentId(ni->Wintun);
#else
        ni->ComponentId = ppp::GetCommandArgument("--tun", argc, argv, NetworkInterface::GetDefaultTun());

#if defined(_LINUX)
        if (ppp::ToBoolean(ppp::GetCommandArgument("--tun-route", argc, argv).data())) {
            ppp::tap::TapLinux::CompatibleRoute(true);
        }

        ni->ProtectNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-protect", argc, argv, "y").data());
        ni->Ssmt = 0;
        ni->SsmtMQ = false;

        if (ppp::string ssmt = ppp::GetCommandArgument("--tun-ssmt", argc, argv); !ssmt.empty()) {
            char ssmt_mq_keys[] = {'m', 'q'};
            for (int j = 0; j < arraysizeof(ssmt_mq_keys); j++) {
                if (ssmt.find(ssmt_mq_keys[j]) != ppp::string::npos) {
                    ni->SsmtMQ = true;
                    break;
                }
            }
            ni->Ssmt = std::max<int>(0, static_cast<int>(strtol(ssmt.data(), NULLPTR, 10)));
        }
#elif defined(_MACOS)
        {
            ppp::string ssmt_arg = ppp::GetCommandArgument("--tun-ssmt", argc, argv);
            char* endptr = NULLPTR;
            long ssmt_val = strtol(ssmt_arg.data(), &endptr, 10);
            ni->Ssmt = (NULLPTR != endptr && endptr != ssmt_arg.data() && *endptr == '\x0') ? static_cast<int>(std::max<long>(0, ssmt_val)) : 0;
        }
#endif

#if defined(_MACOS) || defined(_LINUX)
        ni->Promisc = ppp::ToBoolean(ppp::GetCommandArgument("--tun-promisc", argc, argv, "y").data());
#endif
#endif

        ni->ComponentId = ppp::LTrim<ppp::string>(ni->ComponentId);
        ni->ComponentId = ppp::RTrim<ppp::string>(ni->ComponentId);
    }
    return ni;
}

/**
 * @brief Determines whether process should run in client mode.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return True for client mode, false for server mode.
 */
bool PppApplication::IsModeClientOrServer(int argc, const char* argv[]) noexcept {
    static constexpr const char* keys[] = {"--mode", "--m", "-mode", "-m"};

    ppp::string mode_string;
    for (const char* key : keys) {
        mode_string = ppp::GetCommandArgument(key, argc, argv);
        if (mode_string.size() > 0) {
            break;
        }
    }

    if (mode_string.empty()) {
        mode_string = "server";
    }

    mode_string = ppp::ToLower<ppp::string>(mode_string);
    mode_string = ppp::LTrim<ppp::string>(mode_string);
    mode_string = ppp::RTrim<ppp::string>(mode_string);
    return mode_string.empty() ? false : mode_string[0] == 'c';
}

/**
 * @brief Loads application configuration from explicit or default candidate paths.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param path Receives the effective configuration path on success.
 * @return Loaded configuration object, or null when loading fails.
 */
std::shared_ptr<AppConfiguration> PppApplication::LoadConfiguration(int argc, const char* argv[], ppp::string& path) noexcept {
    static constexpr const char* argument_keys[] = {"-c", "--c", "-config", "--config"};

    for (const char* argument_key : argument_keys) {
        ppp::string argument_value = ppp::GetCommandArgument(argument_key, argc, argv);
        if (argument_value.empty()) {
            continue;
        }

        argument_value = File::RewritePath(argument_value.data());
        argument_value = File::GetFullPath(argument_value.data());
        if (argument_value.empty()) {
            continue;
        }

        if (File::CanAccess(argument_value.data(), FileAccess::Read)) {
            path = std::move(argument_value);
            break;
        }
    }

    ppp::string configuration_paths[] = {
        path,
        "./config.json",
        "./appsettings.json",
    };

    bool found_configuration_file = false;

    /**
     * @brief Iterates candidate configuration files until one loads successfully.
     *
     * The loop normalizes each candidate path, verifies file existence, allocates a
     * configuration object, then loads and optionally wires a virtual-memory allocator.
     */
    for (ppp::string& configuration_path : configuration_paths) {
        if (configuration_path.empty()) {
            continue;
        }

        configuration_path = File::GetFullPath(File::RewritePath(configuration_path.data()).data());
        if (!File::Exists(configuration_path.data())) {
            continue;
        }

        found_configuration_file = true;

        std::shared_ptr<AppConfiguration> configuration = ppp::make_shared_object<AppConfiguration>();
        if (NULLPTR == configuration) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            path.clear();
            return NULLPTR;
        }

        if (!configuration->Load(configuration_path)) {
            // PlatformNotSupportGUAMode is a soft-degrade condition: the configuration
            // file was parsed successfully but requested GUA mode on a platform that does
            // not support it (e.g. Windows).  Treat this as a non-fatal warning and try
            // the next candidate path rather than aborting the entire config search.
            continue;
        }

#if defined(_WIN32)
        if (configuration->vmem.size > 0)
#else
        if (configuration->vmem.path.size() > 0 && configuration->vmem.size > 0)
#endif
        {
            std::shared_ptr<BufferswapAllocator> allocator = ppp::make_shared_object<BufferswapAllocator>(
                configuration->vmem.path,
                std::max<int64_t>((int64_t)1LL << (int64_t)25LL, (int64_t)configuration->vmem.size << (int64_t)20LL));
            if (NULLPTR != allocator && allocator->IsVaild()) {
                configuration->SetBufferAllocator(allocator);
            }
        }

        path = configuration_path;
        return configuration;
    }

    path.clear();
    if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success) {
        ppp::diagnostics::SetLastErrorCode(found_configuration_file
            ? ppp::diagnostics::ErrorCode::ConfigLoadFailed
            : ppp::diagnostics::ErrorCode::ConfigFileNotFound);
    }

    return NULLPTR;
}

} // namespace ppp::app
