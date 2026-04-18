#include <ppp/app/PppApplication.h>
#include <ppp/configurations/AppConfiguration.h>
#include <ppp/Int128.h>
#include <ppp/io/File.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/http/HttpClient.h>
#include <ppp/net/Ipep.h>
#include <ppp/net/Socket.h>
#include <ppp/net/IPEndPoint.h>
#include <ppp/net/asio/vdns.h>
#include <ppp/auxiliary/StringAuxiliary.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/threading/Timer.h>
#include <ppp/threading/Thread.h>
#include <ppp/threading/Executors.h>
#include <ppp/threading/BufferswapAllocator.h>
#include <ppp/app/server/VirtualEthernetSwitcher.h>
#include <ppp/app/server/VirtualEthernetManagedServer.h>
#include <ppp/app/protocol/VirtualEthernetInformation.h>
#include <ppp/app/client/VEthernetExchanger.h>
#include <ppp/app/client/VEthernetNetworkSwitcher.h>

// Platform-specific includes
#if defined(_WIN32)
#include <windows/ppp/net/proxies/HttpProxy.h>
#include <windows/ppp/tap/TapWindows.h>
#include <windows/ppp/win32/Win32Native.h>
#include <windows/ppp/win32/network/Firewall.h>
#include <windows/ppp/win32/network/NetworkInterface.h>
#else
#include <common/unix/UnixAfx.h>
#if defined(_MACOS)
#include <darwin/ppp/tap/TapDarwin.h>
#else
#include <ppp/ipv6/IPv6Auxiliary.h>
#include <linux/ppp/tap/TapLinux.h>
#include <linux/ppp/diagnostics/UnixStackTrace.h>
#endif
#endif

// Third-party library includes
#if defined(CURLINC_CURL)
#include <curl/curl.h>
#endif

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

#include <common/aesni/aes.h>
#include <common/chnroutes2/chnroutes2.h>

// Using declarations for cleaner code
using ppp::configurations::AppConfiguration;
using ppp::threading::Executors;
using ppp::threading::Thread;
using ppp::threading::Timer;
using ppp::threading::BufferswapAllocator;
using ppp::tap::ITap;
using ppp::net::Ipep;
using ppp::net::IPEndPoint;
using ppp::net::Socket;
using ppp::io::File;
using ppp::io::FileAccess;
using ppp::auxiliary::StringAuxiliary;
using ppp::app::server::VirtualEthernetSwitcher;
using ppp::app::client::VEthernetNetworkSwitcher;
using ppp::app::client::VEthernetExchanger;
using ppp::app::client::proxys::VEthernetLocalProxySwitcher;
using ppp::app::client::proxys::VEthernetHttpProxySwitcher;
using ppp::app::client::proxys::VEthernetSocksProxySwitcher;
using ppp::Int128;

// Custom restart signal definition for Unix-like platforms
#if !defined(_WIN32) && !defined(_ANDROID) && !defined(_IPHONE)  
#define SIGRESTART 64 
#endif

// Network interface configuration structure
struct NetworkInterface final
{
    typedef ppp::unordered_set<ppp::string>             BypassSet;

#if defined(_WIN32)
    uint32_t                                            LeaseTimeInSeconds = 0;     // DHCP lease time
    bool                                                SetHttpProxy       = false; // Enable HTTP proxy
#else   
    bool                                                Promisc            = false; // Promiscuous mode
    int                                                 Ssmt               = 0;     // SSMT thread count
#if defined(_LINUX) 
    bool                                                SsmtMQ             = false; // SSMT message queue mode
    bool                                                ProtectNetwork     = false; // Protect network routes
#endif  
#endif  

    bool                                                StaticMode         = false; // Static tunnel mode
    bool                                                Lwip               = false; // Use LWIP stack
    bool                                                VNet               = false; // Subnet forwarding
    bool                                                HostedNetwork      = false; // Prefer host network
    bool                                                BlockQUIC          = false; // Block QUIC protocol

    uint16_t                                            Mux                = 0;     // MUX connection count
    uint8_t                                             MuxAcceleration    = 0;     // MUX acceleration mode

    const std::shared_ptr<BypassSet>                    Bypass;                     // IP bypass list file path
#if defined(_LINUX)
    ppp::string                                         BypassNic;                  // Network interface for bypass
#endif  
    boost::asio::ip::address                            BypassNgw;                  // Gateway for bypass routes

    ppp::string                                         ComponentId;                // TAP device identifier
#if defined(_WIN32) 
    ppp::string                                         Wintun;                     // TAP device name
#endif  

    ppp::string                                         FirewallRules;              // Firewall rules file path
    ppp::string                                         DNSRules;                   // DNS rules file path
    ppp::string                                         Nic;                        // Physical network interface

    ppp::vector<boost::asio::ip::address>               DnsAddresses;               // DNS server addresses

    boost::asio::ip::address                            Ngw;                        // Preferred gateway
    boost::asio::ip::address                            IPAddress;                  // Virtual adapter IP
    boost::asio::ip::address                            IPv6Address;                // Requested virtual adapter IPv6
    boost::asio::ip::address                            GatewayServer;              // Virtual adapter gateway
    boost::asio::ip::address                            SubmaskAddress;             // Subnet mask

    static ppp::string                                  GetDefaultTun() noexcept;   // Default tun-name

    int                                                 BypassLoadList(const ppp::string& s) noexcept;

    NetworkInterface() noexcept 
        : Bypass(ppp::make_shared_object<BypassSet>()) { }
};

// Global variables
static std::shared_ptr<PppApplication>              DEFAULT_;                            // Application instance
static std::atomic<bool>                            GLOBAL_RESTART{ false };             // Restart flag
static std::atomic<bool>                            GLOBAL_VBGP{ false };                // vBGP enabled
static std::atomic<uint64_t>                        GLOBAL_VBGP_LAST{ 0 };               // Last vBGP update
static std::atomic<bool>                            GLOBAL_VIRR{ false };                // Auto-IP update enabled
static std::atomic<uint64_t>                        GLOBAL_VIRR_NEXT{ 0 };               // Next IP update time
static struct {
    using BypassSet = NetworkInterface::BypassSet;

    int                                             link_restart                = 0;     // Link restart count
    int                                             auto_restart                = 0;     // Auto restart interval
    ppp::string                                     virr_argument;                       // IP update argument

    std::shared_ptr<BypassSet>                      bypass;                              // Bypass file path
}                                                   GLOBAL_;                             // Global application state

// Constructor
PppApplication::PppApplication() noexcept
{
    // Hide console cursor for cleaner output
    ppp::HideConsoleCursor(true);

#if defined(_WIN32)
    // Set console window title
    SetConsoleTitle(TEXT("PPP PRIVATE NETWORK™ 2"));

    // Set console buffer and window size on Windows
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE); 
    if (NULLPTR != hConsole)
    {
        COORD cSize = { 120, ppp::win32::Win32Native::IsWindows11OrLaterVersion() ? 46 : 47 };
        if (SetConsoleScreenBufferSize(hConsole, cSize))
        {
            SMALL_RECT rSize = { 0, 0, cSize.X - 1, cSize.Y - 1 };
            SetConsoleWindowInfo(hConsole, TRUE, &rSize);
        }
    }

    // Disable console close button to prevent accidental termination
    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(false);
#endif
}

// Destructor
PppApplication::~PppApplication() noexcept
{
    Release();
}

// Clean up resources
void PppApplication::Release() noexcept 
{
    // Restore console cursor
    ppp::HideConsoleCursor(false);

#if defined(_WIN32)
    // Re-enable console close button
    ppp::win32::Win32Native::EnabledConsoleWindowClosedButton(true);
#endif

    // Release prevention lock
    prevent_rerun_.Close();
}

// Default tun-name
ppp::string NetworkInterface::GetDefaultTun() noexcept
{
    const char* default_tun_name = NULLPTR;
#if defined(_WIN32)
    default_tun_name = PPP_APPLICATION_NAME;
#elif defined(_MACOS)
    default_tun_name = "utun0";
#else
    default_tun_name = BOOST_BEAST_VERSION_STRING;
#endif
    return default_tun_name;
}

// NetworkInterface::BypassLoadList
// 
// Parses a pipe-separated list of file paths, converts each to an absolute path,
// and inserts them into the bypass set. If the input string contains a single
// entry, it is added directly without tokenization.
//
// Parameters:
//   s - A string containing one or more file paths separated by '|*?<>'
// Returns:
//   Number of successfully added entries (0 if none or input empty)
int NetworkInterface::BypassLoadList(const ppp::string& s) noexcept
{
    // Get reference to the underlying bypass set (shared_ptr is always valid)
    BypassSet& set = *Bypass;
    set.clear();  // Clear any previous entries

    // Nothing to do if input is empty
    if (s.empty())
    {
        return 0;
    }

    // Split the input string by '|' into segments
    ppp::vector<ppp::string> segments;
    ppp::string work = s;
    for (char& ch : work)
    {
        // Replace any of * ? < > with '|'
        if (ch == '*' || ch == '?' || ch == '<' || ch == '>')
        {
            ch = '|';
        }
    }
    ppp::Tokenize<ppp::string>(work, segments, "|");

    // Optimization: if there's only one segment, add it directly without trimming
    if (segments.size() == 1)
    {
        set.emplace(std::move(segments[0]));
        return 1;
    }

    int events = 0;
    // Process each segment
    for (const ppp::string& i : segments)
    {
        // Skip empty segments
        if (i.empty())
        {
            continue;
        }
        
        // Trim whitespace from both ends
        ppp::string t = ppp::LTrim(ppp::RTrim(i));
        if (t.empty())
        {
            continue;
        }

        // Convert to absolute path, handling any path rewriting (e.g., environment variables)
        t = File::GetFullPath(File::RewritePath(t.data()).data());
        if (t.empty())
        {
            continue;
        }

        // Insert the absolute path into the bypass set
        // The move avoids an extra copy of the string
        auto r = set.emplace(std::move(t));
        if (r.second)  // insertion succeeded (path was not already present)
        {
            events++;
        }
    }

    // Return the count of newly added entries
    return events;
}

// Asynchronous IP list download
bool PppApplication::PullIPList(const ppp::string& url, const ppp::function<void(int, const ppp::set<ppp::string>&)>& cb) noexcept
{
    // Download IP list from URL in background thread
    if (NULLPTR == cb || url.empty()) 
    {
        return false;
    }

    auto self = shared_from_this();
    std::thread(
        [self, url, cb]() noexcept
        {
            // The worker keeps the application instance alive through shared_ptr.
            // This avoids capturing a raw this pointer across a detached thread boundary.
            ppp::set<ppp::string> ips;
            ppp::SetThreadName("vbgp");

            int events = self->PullIPList(url, ips);
            cb(events, ips);
        }).detach();
    return true;
}

// Synchronous IP list download
int PppApplication::PullIPList(const ppp::string& url, ppp::set<ppp::string>& ips) noexcept 
{
    // Realize the collection of route lists captured from Internet resources of the HTTP/HTTPS protocol that comply with the ip route configuration rules.
    using HttpClient = ppp::net::http::HttpClient;

    ppp::string host;
    ppp::string path;
    int port = IPEndPoint::MinPort;
    bool https = false;

    // Parse URL components
    if (!HttpClient::VerifyUri(url, ppp::addressof(host), &port, ppp::addressof(path), &https)) 
    {
        return -1;
    }

    // Create HTTP client with SSL support if needed
    HttpClient http_client((https ? "https://" : "http://") + host, chnroutes2_cacertpath_default());
    
    int http_status_code = -1;
    std::string http_response_body = http_client.Get(path, http_status_code);

    // Check HTTP status
    if (http_status_code < 200 || http_status_code >= 300) 
    {
        return -1;
    }

    // Parse IP list from response
    return chnroutes2_getiplist(ips, ppp::string(), stl::transform<ppp::string>(http_response_body));
}

// Download IP list with progress notification
void PppApplication::PullIPList(const ppp::string& command, bool virr) noexcept
{
    // Parse command into path and country code
    ppp::string path;
    ppp::string nation;
    for (ppp::string command_string = ppp::LTrim(ppp::RTrim(command)); command_string.size() > 0;) 
    {
        std::size_t index = command_string.find('<');
        if (index == std::string::npos) 
        {
            index = command_string.find('/');
            if (index == std::string::npos) 
            {
                path = command_string;
                break;
            }
        }

        path = ppp::RTrim(command_string.substr(0, index));
        nation = ppp::LTrim(command_string.substr(index + 1));
        break;
    }

    // Use default path if not specified
    if (path.empty()) 
    {
        path = chnroutes2_filepath_default();
    }

    // Convert to absolute path
    path = File::GetFullPath(File::RewritePath(path.data()).data());

    // Download IP list
    bool ok = false;
    if (virr)
    {
        // Asynchronous download for auto-updates
        chnroutes2_getiplist_async(
            [path, nation, configuration = configuration_](const ppp::string& response_text) noexcept 
            {
                auto process =
                    [&]() noexcept 
                    {
                        ppp::set<ppp::string> ips;
                        if (chnroutes2_getiplist(ips, nation, response_text) < 1)
                        {
                            return -1;
                        }
                    
                        // Only save file if path differs from current bypass
                        auto bypass = GLOBAL_.bypass;
                        if (NULL == bypass || bypass->find(path) == bypass->end())
                        {
                            chnroutes2_saveiplist(path, ips);
                            return 0;
                        }
                    
                        // Compare with existing file to avoid unnecessary restarts
                        ppp::set<ppp::string> olds;
                        ppp::string iplist = ppp::LTrim(ppp::RTrim(File::ReadAllText(path.data())));
                    
                        chnroutes2_getiplist(olds, ppp::string(), iplist);
                        if (chnroutes2_equals(ips, olds))
                        {
                            return 0;
                        }
                    
                        // Save new list and restart if changed
                        ppp::string news = chnroutes2_toiplist(ips);
                        if (!File::WriteAllBytes(path.data(), news.data(), news.size()))
                        {
                            return -1;
                        }
                        
                        // Trigger application restart
                        ShutdownApplication(true);
                        return 1;
                    };

                // Process result and schedule retry on failure
                int return_code = process();
                if (return_code < 0)
                {   
                    uint64_t now = Executors::GetTickCount();
                    GLOBAL_VIRR_NEXT.store(now + (configuration->virr.retry_interval * 1000), std::memory_order_relaxed);
                }

                return return_code;
            });
    }
    else 
    {
        // Synchronous download for manual updates
        ppp::set<ppp::string> ips;
        if (chnroutes2_getiplist(ips, nation) > 0)
        {
            ok = chnroutes2_saveiplist(path, ips);
        }
    }

    if (!virr && !ok)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigRouteLoadFailed);
    }
}

bool PppApplication::LogEnvironmentInformation() noexcept
{
    return true;
}

// Initialize network environment
bool PppApplication::PreparedLoopbackEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept
{
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULLPTR == configuration)
    {
        return false;
    }

    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context)
    {
        return false;
    }
    else
    {
#if defined(_WIN32)
        // Configure Windows Firewall rules
        ppp::string executable_path = File::GetFullPath(File::RewritePath(ppp::GetFullExecutionFilePath().data()).data());

        ppp::win32::network::Fw::NetFirewallAddApplication(PPP_APPLICATION_NAME, executable_path.data());
        ppp::win32::network::Fw::NetFirewallAddAllApplication(PPP_APPLICATION_NAME, executable_path.data());

        // Client-specific Windows setup
        if (client_mode_)
        {
            // Install paper airplane plugin if needed
            if (network_interface->HostedNetwork && configuration->client.paper_airplane.tcp)
            {
                if (ppp::app::client::lsp::PaperAirplaneController::Install() < 0)
                {
                    return false;
                }
            }

            // Prevent problematic programs from loading LSPs
            ppp::app::client::lsp::PaperAirplaneController::NoLsp();

            // Reset paper airplane controller
            ppp::app::client::lsp::PaperAirplaneController::Reset();
        }
#endif
    }

    bool success = false;
    if (client_mode_)
    {
        std::shared_ptr<VEthernetNetworkSwitcher> ethernet = NULLPTR;
        std::shared_ptr<ITap> tap = NULLPTR;
        do
        {
            // Create TAP device
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
            if (NULLPTR == tap)
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                break;
            }

            // Configure TAP device
            tap->BufferAllocator = configuration->GetBufferAllocator();
            if (!tap->Open())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelListenFailed);
                break;
            }

            // Create client switcher
            ethernet = ppp::make_shared_object<VEthernetNetworkSwitcher>(context, network_interface->Lwip, network_interface->VNet, configuration->concurrent > 1, configuration);
            if (NULLPTR == ethernet)
            {
                break;
            }
            if (network_interface->IPv6Address.is_v6())
            {
                std::string requested_ipv6_std = network_interface->IPv6Address.to_string();
                ethernet->RequestedIPv6(ppp::string(requested_ipv6_std.data(), requested_ipv6_std.size()));
            }

#if !defined(_WIN32)
            // Configure SSMT settings
            ethernet->Ssmt(&network_interface->Ssmt);
#if defined(_LINUX)
            ethernet->SsmtMQ(&network_interface->SsmtMQ);
            ethernet->ProtectMode(&network_interface->ProtectNetwork);
#endif
#endif
            // Configure switcher properties
            ethernet->Mux(&network_interface->Mux);
            ethernet->MuxAcceleration(&network_interface->MuxAcceleration);
            ethernet->StaticMode(&network_interface->StaticMode);
            ethernet->PreferredNgw(network_interface->Ngw);
            ethernet->PreferredNic(network_interface->Nic);

            // Load bypass IP lists
#if defined(_LINUX)
            for (auto&& bypass_path : *network_interface->Bypass) 
            {
                ethernet->AddLoadIPList(bypass_path, network_interface->BypassNic, network_interface->BypassNgw, ppp::string());
            }
#else
            for (auto&& bypass_path : *network_interface->Bypass) 
            {
                ethernet->AddLoadIPList(bypass_path, network_interface->BypassNgw, ppp::string());
            }
#endif
            for (auto&& route : configuration->client.routes)
            {
                ppp::string path = File::GetFullPath(File::RewritePath(route.path.data()).data());
                if (path.empty()) 
                {
                    continue;
                }

#if defined(_LINUX)
                ethernet->AddLoadIPList(path, route.nic, Ipep::ToAddress(route.ngw), route.vbgp);
#else
                ethernet->AddLoadIPList(path, Ipep::ToAddress(route.ngw), route.vbgp);
#endif
            }

            // Load DNS rules
            ethernet->LoadAllDnsRules(network_interface->DNSRules, true);
            
            // Open switcher
            if (!ethernet->Open(tap))
            {
                auto ni = ethernet->GetUnderlyingNetworkInterface();
                if (NULLPTR != ni)
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                }
                else
                {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceUnavailable);
                }
                break;
            }

            success = true;
            client_ = ethernet;
        } while (false);

        // Cleanup on failure
        if (!success)
        {
            client_.reset();
            if (NULLPTR != ethernet)
            {
                ethernet->Dispose();
            }

            // Turn off the tun/tap virtual network card driver that has been opened.
            if (NULLPTR != tap)
            {
                tap->Dispose();
            }
        }
    }
    else
    {
        // Server mode setup
        std::shared_ptr<VirtualEthernetSwitcher> ethernet = NULLPTR;
        do
        {
#if defined(_LINUX)
            if (!ppp::ipv6::auxiliary::PrepareServerEnvironment(configuration, network_interface->Nic, network_interface->ComponentId))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::IPv6ServerPrepareFailed);
                break;
            }
#endif

            // Create server switcher
#if defined(_WIN32)
            ethernet = ppp::make_shared_object<VirtualEthernetSwitcher>(configuration, network_interface->ComponentId);
#else
            ethernet = ppp::make_shared_object<VirtualEthernetSwitcher>(configuration, network_interface->ComponentId, network_interface->Ssmt, network_interface->SsmtMQ);
#endif
            if (NULLPTR == ethernet)
            {
                break;
            }

            ethernet->PreferredNic(network_interface->Nic);

            // Open switcher
            if (!ethernet->Open(network_interface->FirewallRules))
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
                break;
            }

            // Run services
            if (!ethernet->Run())
            {
                ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelListenFailed);
                break;
            }

            success = true;
            server_ = ethernet;
        } while (false);

        // Cleanup on failure
        if (!success)
        {
            #if defined(_LINUX)
            ppp::ipv6::auxiliary::FinalizeServerEnvironment(configuration, network_interface->Nic, network_interface->ComponentId);
            #endif
            server_.reset();
            if (NULLPTR != ethernet)
            {
                ethernet->Dispose();
            }
        }
    }
    return success;
}

// Get buffer allocator from configuration
std::shared_ptr<BufferswapAllocator> PppApplication::GetBufferAllocator() noexcept
{
    std::shared_ptr<AppConfiguration> configuration = GetConfiguration();
    if (NULLPTR == configuration)
    {
        return NULLPTR;
    }
    else
    {
        return configuration->GetBufferAllocator();
    }
}

// Parse and prepare command line arguments
int PppApplication::PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept
{
    // Configure socket flash TOS
    Socket::SetDefaultFlashTypeOfService(ppp::ToBoolean(ppp::GetCommandArgument("--tun-flash", argc, argv).data()));
    
    // Show help if requested
    if (ppp::IsInputHelpCommand(argc, argv))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);
        return -1;
    }

    // Load configuration
    ppp::string path;
    std::shared_ptr<AppConfiguration> configuration = LoadConfiguration(argc, argv, path);
    if (NULLPTR == configuration)
    {
        if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success)
        {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::ConfigLoadFailed);
        }
        return -1;
    }
    else
    {
        // Gets whether client mode or server mode is currently running.
        client_mode_ = IsModeClientOrServer(argc, argv);
    }

    // Configure thread pool
    int max_concurrent = configuration->concurrent - 1;
    if (max_concurrent > 0)
    {
        Executors::SetMaxSchedulers(max_concurrent);
        if (!client_mode_)
        {
            Executors::SetMaxThreads(configuration->GetBufferAllocator(), max_concurrent);
        }
    }

    // Parse network interface configuration
    std::shared_ptr<NetworkInterface> network_interface = GetNetworkInterface(argc, argv);
    if (NULLPTR == network_interface)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        return -1;
    }

    // Store configuration
    configuration_path_ = path;
    configuration_ = configuration;
    network_interface_ = network_interface;
    
    // Configure DNS settings
    ppp::net::asio::vdns::ttl = configuration->udp.dns.ttl;
    ppp::net::asio::vdns::enabled = configuration->udp.dns.turbo;
    
    return 0;
}

// Format version string
static ppp::string GetVersionString(int major, int minor, int patch = 0) noexcept
{
    char buf[100];
    *buf = '\x0';

    if (patch != 0) 
    {
        snprintf(buf, sizeof(buf), "%d.%d.%d", major, minor, patch);
    }
    else 
    {
        snprintf(buf, sizeof(buf), "%d.%d", major, minor);
    }

    return buf;
}

// Get Boost library version string
static ppp::string GetBoostVersionString() noexcept 
{
    constexpr int version = BOOST_VERSION;

    int minor = (version / 100) % 100;
    int major = version / 100000;
    int patch = version % 100;

    return GetVersionString(major, minor, patch);
}

// Print comprehensive help information
void PppApplication::PrintHelpInformation() noexcept
{
    ppp::string execution_file_name = ppp::GetExecutionFileName();
    ppp::string cwd = ppp::GetCurrentDirectoryPath();

    // Define column widths for alignment
    static constexpr int col_option_width = 40;
    static constexpr int col_description_width = 48;
    static constexpr int col_default_width = 23;
    static constexpr int col_command_width = 38;
    static constexpr int col_command_width_utlity = col_command_width + 2;

    // Print header
    fputs("┌──────────────────────────────────────────────────────────────────────┐\n", stdout);
    fputs("│                       PPP PRIVATE NETWORK™ 2                         │\n", stdout);
    fputs("│  Next-generation security network access technology, providing high- │\n", stdout);
    fputs("│  performance Virtual Ethernet tunneling service.                     │\n", stdout);
    fputs("└──────────────────────────────────────────────────────────────────────┘\n\n", stdout);

    fprintf(stdout, "Version:      %s\n", PPP_APPLICATION_VERSION);
    fputs("Copyright:    (C) 2017 ~ 2055 SupersocksR ORG. All rights reserved.\n", stdout);
    fprintf(stdout, "Current Dir:  %s\n\n", cwd.data());

    fputs("USAGE:\n", stdout);
    fprintf(stdout, "    %s [OPTIONS]\n\n", execution_file_name.data());

    // GENERAL OPTIONS table
    fputs("GENERAL OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "OPTION",
        col_description_width, "DESCRIPTION",
        col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--rt=[yes|no]",
        col_description_width, "Enable real-time mode",
        col_default_width, "yes");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--mode=[client|server]",
        col_description_width, "Set running mode",
        col_default_width, "server");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--config=<path>",
        col_description_width, "Configuration file path",
        col_default_width, "./appsettings.json");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--dns=<ip-list>",
        col_description_width, "DNS server addresses",
        col_default_width, "8.8.8.8,8.8.4.4");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-flash=[yes|no]",
        col_description_width, "Enable advanced QoS policy",
        col_default_width, "no");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--auto-restart=<seconds>",
        col_description_width, "Auto restart interval",
        col_default_width, "0 (disabled)");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--link-restart=<count>",
        col_description_width, "Link reconnection attempts",
        col_default_width, "0");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--block-quic=[yes|no]",
        col_description_width, "Block QUIC protocol traffic",
        col_default_width, "no");

    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    // SERVER-SPECIFIC OPTIONS table
    fputs("SERVER-SPECIFIC OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "OPTION",
        col_description_width, "DESCRIPTION",
        col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--firewall-rules=<file>",
        col_description_width, "Firewall rules file",
        col_default_width, "./firewall-rules.txt");

    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    // CLIENT-SPECIFIC OPTIONS table
    fputs("CLIENT-SPECIFIC OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "OPTION",
        col_description_width, "DESCRIPTION",
        col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--lwip=[yes|no]",
        col_description_width, "Network protocol stack selection",
        col_default_width,
#if defined(_WIN32)
        ppp::tap::TapWindows::IsWintun() ? "no" : "yes"
#else
        "no"
#endif
    );

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--vbgp=[yes|no]",
        col_description_width, "Enable virtual BGP routing",
        col_default_width, "yes");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--nic=<interface>",
        col_description_width, "Specify physical network interface",
        col_default_width, "auto-select");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--ngw=<ip>",
        col_description_width, "Force gateway address",
        col_default_width, "auto-detect");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun=<name>",
        col_description_width, "Virtual adapter name",
        col_default_width, NetworkInterface::GetDefaultTun().c_str());

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-ip=<ip>",
        col_description_width, "Virtual adapter IP address",
        col_default_width, "10.0.0.2");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-ipv6=<ip>",
        col_description_width, "Requested virtual adapter IPv6",
        col_default_width, "server-assigned");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-gw=<ip>",
        col_description_width, "Virtual adapter gateway",
        col_default_width, "10.0.0.1");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-mask=<bits>",
        col_description_width, "Subnet mask bits",
        col_default_width, "30");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-vnet=[yes|no]",
        col_description_width, "Enable subnet forwarding",
        col_default_width, "yes");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-host=[yes|no]",
        col_description_width, "Prefer host network",
        col_default_width, "yes");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-static=[yes|no]",
        col_description_width, "Enable static tunnel",
        col_default_width, "no");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-mux=<connections>",
        col_description_width, "MUX connection count (0=disabled)",
        col_default_width, "0");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-mux-acceleration=<mode>",
        col_description_width, "MUX acceleration mode (0-3)",
        col_default_width, "0 (standard)");

#if defined(_LINUX) || defined(_MACOS)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-promisc=[yes|no]",
        col_description_width, "Enable promiscuous mode",
        col_default_width, "yes");
#endif

#if defined(_MACOS)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-ssmt=<threads>",
        col_description_width, "SSMT thread optimization",
        col_default_width, "0");
#elif defined(_LINUX)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-ssmt=<N>[/<mode>]",
        col_description_width, "SSMT threads (N), mode: st or mq; mq opens one Linux tun queue per worker",
        col_default_width, "0/st");
#endif

#if defined(_LINUX)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-route=[yes|no]",
        col_description_width, "Route compatibility",
        col_default_width, "no");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-protect=[yes|no]",
        col_description_width, "Route protection",
        col_default_width, "yes");
#endif

#if defined(_WIN32)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--tun-lease-time-in-seconds=<sec>",
        col_description_width, "DHCP lease time",
        col_default_width, "7200");
#endif

    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    // ROUTING OPTIONS table
    fputs("ROUTING OPTIONS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "OPTION",
        col_description_width, "DESCRIPTION",
        col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--bypass=<file1|file2>",
        col_description_width, "Bypass IP list file",
        col_default_width, "./ip.txt");

#if defined(_LINUX)
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--bypass-nic=<interface>",
        col_description_width, "Interface for bypass list",
        col_default_width, "auto-select");
#endif

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--bypass-ngw=<ip>",
        col_description_width, "Gateway for bypass list",
        col_default_width, "auto-detect");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--virr=[file/country]",
        col_description_width, "Auto-update and take effect IP-list",
        col_default_width, "./ip.txt/CN");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--dns-rules=<file>",
        col_description_width, "DNS rules configuration",
        col_default_width, "./dns-rules.txt");

    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    // WINDOWS-SPECIFIC COMMANDS table
#if defined(_WIN32)
    fputs("WINDOWS-SPECIFIC COMMANDS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │\n",
        col_command_width_utlity, "COMMAND",
        col_description_width, "DESCRIPTION");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┤\n", stdout);

    fprintf(stdout, "│ %-*s │ %-*s │\n",
        col_command_width_utlity, "--system-network-reset",
        col_description_width, "Reset Windows network stack");

    fprintf(stdout, "│ %-*s │ %-*s │\n",
        col_command_width_utlity, "--system-network-optimization",
        col_description_width, "Optimize network performance");

    fprintf(stdout, "│ %-*s │ %-*s │\n",
        col_command_width_utlity, "--system-network-preferred-ipv4",
        col_description_width, "Set IPv4 as preferred protocol");

    fprintf(stdout, "│ %-*s │ %-*s │\n",
        col_command_width_utlity, "--system-network-preferred-ipv6",
        col_description_width, "Set IPv6 as preferred protocol");

    fprintf(stdout, "│ %-*s │ %-*s │\n",
        col_command_width_utlity, "--no-lsp <program>",
        col_description_width, "Disable LSP for specified program");

    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┘\n\n", stdout);
#endif

    // UTILITY COMMANDS table
    fputs("UTILITY COMMANDS:\n", stdout);
    fputs("┌──────────────────────────────────────────┬──────────────────────────────────────────────────┬─────────────────────────┐\n", stdout);
    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "COMMAND",
        col_description_width, "DESCRIPTION",
        col_default_width, "DEFAULT");
    fputs("├──────────────────────────────────────────┼──────────────────────────────────────────────────┼─────────────────────────┤\n", stdout);

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--help",
        col_description_width, "Display this help information",
        col_default_width, "none");

    fprintf(stdout, "│ %-*s │ %-*s │ %-*s │\n",
        col_option_width, "--pull-iplist [file/country]",
        col_description_width, "Download country IP list from APNIC",
        col_default_width, "./ip.txt/CN");

    fputs("└──────────────────────────────────────────┴──────────────────────────────────────────────────┴─────────────────────────┘\n\n", stdout);

    // Contact information
    fputs("CONTACT:\n", stdout);
    fputs("    Telegram: https://t.me/supersocksr_group\n\n", stdout);

    // Dependencies information
    fputs("DEPENDENCIES:\n", stdout);
    fprintf(stdout, "    boost@%s", GetBoostVersionString().c_str());

#if defined(__GLIBC__) && defined(__GLIBC_MINOR__)
    fprintf(stdout, ", libc@%s", GetVersionString(__GLIBC__, __GLIBC_MINOR__).c_str());
#if defined(__MUSL__)
    fputs("/musl", stdout);
#else
    fputs("/glibc", stdout);
#endif
#endif

#if defined(LIBCURL_VERSION_MAJOR)
    fprintf(stdout, ", curl@%s", GetVersionString(LIBCURL_VERSION_MAJOR, LIBCURL_VERSION_MINOR, LIBCURL_VERSION_PATCH).c_str());
#endif

#if defined(OPENSSL_VERSION_MAJOR)
    fprintf(stdout, ", openssl@%s", GetVersionString(OPENSSL_VERSION_MAJOR, OPENSSL_VERSION_MINOR, OPENSSL_VERSION_PATCH).c_str());
#else
    fputs(", openssl@1.1.1", stdout);
#endif

#if defined(JEMALLOC_VERSION_MAJOR)
    fprintf(stdout, ", jemalloc@%s", GetVersionString(JEMALLOC_VERSION_MAJOR, JEMALLOC_VERSION_MINOR, JEMALLOC_VERSION_BUGFIX).c_str());
#endif

    fputs("\n", stdout);
    fflush(stdout);
}

// Parse IP address or netmask from command line
boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, int argc, const char* argv[]) noexcept
{
    ppp::string address_string = ppp::GetCommandArgument(name, argc, argv);
    if (address_string.empty())
    {
        return boost::asio::ip::address_v4::any();
    }

    address_string = ppp::LTrim<ppp::string>(address_string);
    address_string = ppp::RTrim<ppp::string>(address_string);
    if (address_string.empty())
    {
        return boost::asio::ip::address_v4::any();
    }

    boost::asio::ip::address address;
    if (StringAuxiliary::WhoisIntegerValueString(address_string))
    {
        // Handle netmask prefix notation (e.g., "24")
        int prefix = atoll(address_string.data());
        if (prefix < 1 || prefix > MAX_PREFIX_ADDRESS)
        {
            prefix = MAX_PREFIX_ADDRESS;
        }
        elif(MIN_PREFIX_ADDRESS > 0 && prefix < MIN_PREFIX_ADDRESS)
        {
            prefix = MIN_PREFIX_ADDRESS;
        }

        auto prefix_to_netmask = IPEndPoint::PrefixToNetmask(prefix);
        address = IPEndPoint::WrapAddressV4<boost::asio::ip::tcp>(prefix_to_netmask, 0).address();
    }
    else
    {
        // Handle dotted-decimal notation
        address = Ipep::ToAddress(address_string, true);
    }

    if (IPEndPoint::IsInvalid(address))
    {
        return boost::asio::ip::address_v4::any();
    }

    return address;
}

// Parse IP address with default value
boost::asio::ip::address PppApplication::GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, const char* default_address_string, int argc, const char* argv[]) noexcept
{
    boost::asio::ip::address address = GetNetworkAddress(name, MIN_PREFIX_ADDRESS, MAX_PREFIX_ADDRESS, argc, argv);
    if (IPEndPoint::IsInvalid(address))
    {
        address = boost::asio::ip::address_v4::any();
    }

    if (IPEndPoint::IsInvalid(address))
    {
        if (NULLPTR == default_address_string)
        {
            default_address_string = "";
        }

        return Ipep::ToAddress(default_address_string, false);
    }
    else
    {
        return address;
    }
}

// Parse DNS server addresses from command line
void PppApplication::GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept
{
#if defined(_WIN32)
    bool at_least_two = true;
    if (!client_mode_) {
        at_least_two = false;
    }

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

// Parse network interface configuration from command line arguments
std::shared_ptr<NetworkInterface> PppApplication::GetNetworkInterface(int argc, const char* argv[]) noexcept
{
    std::shared_ptr<NetworkInterface> ni = ppp::make_shared_object<NetworkInterface>();
    if (NULLPTR != ni)
    {
#if defined(_WIN32)
        ni->Lwip = ppp::ToBoolean(ppp::GetCommandArgument("--lwip", argc, argv, ppp::tap::TapWindows::IsWintun() ? ppp::string() : "y").data());
#else
        ni->Lwip = ppp::ToBoolean(ppp::GetCommandArgument("--lwip", argc, argv).data());
#endif

        ni->Nic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--nic", argc, argv)));
        ni->BlockQUIC = ppp::ToBoolean(ppp::GetCommandArgument("--block-quic", argc, argv).data());

        // Parse DNS servers
        GetDnsAddresses(ni->DnsAddresses, argc, argv);
        if (!ni->DnsAddresses.empty()) {
            auto dns_servers = ppp::net::asio::vdns::servers;
            dns_servers->clear();

            for (const boost::asio::ip::address& dns_server : ni->DnsAddresses) {
                dns_servers->emplace_back(boost::asio::ip::udp::endpoint(dns_server, PPP_DNS_SYS_PORT));
            }
        }

        // Parse network addresses
        ni->Ngw = GetNetworkAddress("--ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->IPAddress = GetNetworkAddress("--tun-ip", 0, 32, "10.0.0.2", argc, argv);
        ni->IPv6Address = GetNetworkAddress("--tun-ipv6", 0, 128, argc, argv);
        ni->SubmaskAddress = GetNetworkAddress("--tun-mask", 16, 32, "255.255.255.252", argc, argv);

        // Suggested Ethernet card address setting.
        ni->GatewayServer = GetNetworkAddress("--tun-gw", 0, 32, "10.0.0.1", argc, argv);

#if defined(_WIN32)
        // DHCP-MASQ lease time in seconds.
        ni->LeaseTimeInSeconds = strtoul(ppp::GetCommandArgument("--tun-lease-time-in-seconds", argc, argv).data(), NULLPTR, 10);
        if (ni->LeaseTimeInSeconds < 1)
        {
            ni->LeaseTimeInSeconds = 7200;
        }
#endif

        // Calculate valid IP address based on gateway and subnet
        ni->IPAddress = Ipep::FixedIPAddress(ni->IPAddress, ni->GatewayServer, ni->SubmaskAddress);
        ni->StaticMode = ppp::ToBoolean(ppp::GetCommandArgument("--tun-static", argc, argv).data());
        ni->HostedNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-host", argc, argv, "y").data());
        ni->VNet = ppp::ToBoolean(ppp::GetCommandArgument("--tun-vnet", argc, argv, "y").data());

#if defined(_LINUX)
        ni->BypassNic = ppp::RTrim(ppp::LTrim(ppp::GetCommandArgument("--bypass-nic", argc, argv)));
#endif
        ni->BypassNgw = GetNetworkAddress("--bypass-ngw", 0, 32, "0.0.0.0", argc, argv);
        ni->BypassLoadList(File::GetFullPath(File::RewritePath(ppp::LTrim(ppp::RTrim(ppp::GetCommandArgument("--bypass", argc, argv, "./ip.txt"))).data()).data()));

        // Parse configuration files
        ni->DNSRules = ppp::GetCommandArgument("--dns-rules", argc, argv, "./dns-rules.txt");
        ni->FirewallRules = ppp::GetCommandArgument("--firewall-rules", argc, argv, "./firewall-rules.txt");
        
        // Parse MUX settings
        ni->Mux = (uint16_t)std::max<int>(0, atoi(ppp::GetCommandArgument("--tun-mux", argc, argv).data()));
        ni->MuxAcceleration = (uint8_t)std::max<int>(0, atoi(ppp::GetCommandArgument("--tun-mux-acceleration", argc, argv).data()));
        if (ni->MuxAcceleration > PPP_MUX_ACCELERATION_MAX) 
        {
            ni->MuxAcceleration = 0;
        }

#if defined(_WIN32)
        ni->SetHttpProxy = ppp::ToBoolean(ppp::GetCommandArgument("--set-http-proxy", argc, argv).data());
        ni->Wintun = ppp::GetCommandArgument("--tun", argc, argv, NetworkInterface::GetDefaultTun());
        ni->ComponentId = ppp::tap::TapWindows::FindComponentId(ni->Wintun);
#else
        ni->ComponentId = ppp::GetCommandArgument("--tun", argc, argv, NetworkInterface::GetDefaultTun());

#if defined(_LINUX)
        // Enable route compatibility mode if requested
        if (ppp::ToBoolean(ppp::GetCommandArgument("--tun-route", argc, argv).data())) 
        {
            ppp::tap::TapLinux::CompatibleRoute(true);
        }

        // Linux requires network protection services to be turned on, but this may not be compatible on some Linux devices.
        ni->ProtectNetwork = ppp::ToBoolean(ppp::GetCommandArgument("--tun-protect", argc, argv, "y").data());
        ni->Ssmt = 0;
        ni->SsmtMQ = false;

        // Parse SSMT configuration
        if (ppp::string ssmt = ppp::GetCommandArgument("--tun-ssmt", argc, argv); !ssmt.empty()) 
        {
            char ssmt_mq_keys[] = { 'm', 'q' };
            for (int j = 0; j < arraysizeof(ssmt_mq_keys); j++) 
            { 
                if (ssmt.find(ssmt_mq_keys[j]) != ppp::string::npos) 
                {
                    ni->SsmtMQ = true;
                    break;
                }
            }

            ni->Ssmt = std::max<int>(0, atoi(ssmt.data()));
        }
#elif defined(_MACOS)
        ni->Ssmt = std::max<int>(0, atoi(ppp::GetCommandArgument("--tun-ssmt", argc, argv).data()));
#endif

#if defined(_MACOS) || defined(_LINUX)
        // MacOS/Linux Virtual Ethernet is set to the promiscuous NIC mode by default.
        ni->Promisc = ppp::ToBoolean(ppp::GetCommandArgument("--tun-promisc", argc, argv, "y").data());
#endif
#endif

        // Clean up component ID
        ni->ComponentId = ppp::LTrim<ppp::string>(ni->ComponentId);
        ni->ComponentId = ppp::RTrim<ppp::string>(ni->ComponentId);
    }
    return ni;
}

// Determine if application should run in client or server mode
bool PppApplication::IsModeClientOrServer(int argc, const char* argv[]) noexcept
{
    static constexpr const char* keys[] = { "--mode", "--m", "-mode", "-m" };

    ppp::string mode_string;
    for (const char* key : keys)
    {
        mode_string = ppp::GetCommandArgument(key, argc, argv);
        if (mode_string.size() > 0)
        {
            break;
        }
    }

    if (mode_string.empty())
    {
        mode_string = "server";
    }

    mode_string = ppp::ToLower<ppp::string>(mode_string);
    mode_string = ppp::LTrim<ppp::string>(mode_string);
    mode_string = ppp::RTrim<ppp::string>(mode_string);
    return mode_string.empty() ? false : mode_string[0] == 'c';
}

// Clean up resources
void PppApplication::Dispose() noexcept
{
    // Clean up server
    std::shared_ptr<VirtualEthernetSwitcher> server = std::move(server_);
    if (NULLPTR != server)
    {
        server->Dispose();
    }

    // Clean up client
    std::shared_ptr<VEthernetNetworkSwitcher> client = std::move(client_);
    if (NULLPTR != client)
    {
#if defined(_WIN32)
        // Restore original QUIC settings
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(quic_);

        // Clear system proxy settings
        if (network_interface_->SetHttpProxy)
        {
            client->ClearHttpProxyToSystemEnv();
        }
#endif

        client->Dispose();
    }

    ClearTickAlwaysTimeout();
}

// Get transmission statistics from current switcher
bool PppApplication::GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept
{
    // Initialization requires the initial value of the FAR outgoing parameter.
    statistics_snapshot = NULLPTR;
    incoming_traffic = 0;
    outgoing_traffic = 0;

    // Get statistics from active switcher
    std::shared_ptr<VirtualEthernetSwitcher> server = server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if ((NULLPTR != server && !server->IsDisposed()) || (NULLPTR != client && !client->IsDisposed()))
    {
        // Obtain transport layer traffic statistics from the client switch or server switch management object.
        std::shared_ptr<ppp::transmissions::ITransmissionStatistics> transmission_statistics;
        if (NULLPTR != client)
        {
            transmission_statistics = client->GetStatistics();
        }
        elif(NULLPTR != server)
        {
            transmission_statistics = server->GetStatistics();
        }

        if (NULLPTR != transmission_statistics)
        {
            return ppp::transmissions::ITransmissionStatistics::GetTransmissionStatistics(transmission_statistics, transmission_statistics_, incoming_traffic, outgoing_traffic, statistics_snapshot);
        }
    }

    return false;
}

// Main periodic tick handler
bool PppApplication::OnTick(uint64_t now) noexcept
{
    using RouteIPListTablePtr = VEthernetNetworkSwitcher::RouteIPListTablePtr;
    using NetworkState        = VEthernetExchanger::NetworkState;

    // Update console display
    LogEnvironmentInformation();

#if defined(_WIN32)
    // Windows platform calls system functions to optimize the size of the working memory used by the program in order to minimize 
    // The use of physical memory resources on low memory desktop platforms.
    ppp::win32::Win32Native::OptimizedProcessWorkingSize();
#endif

    // Check auto-restart timer
    if (GLOBAL_.auto_restart > 0)
    {
        int64_t elapsed_milliseconds = stopwatch_.ElapsedMilliseconds() / 1000;
        if (elapsed_milliseconds > 0 && elapsed_milliseconds >= GLOBAL_.auto_restart)
        {
            return ShutdownApplication(true);
        }
    }

    // Client-specific periodic tasks
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULLPTR == client) 
    {
        return false;
    }

    // Check whether the current VPN exchanger exists.
    std::shared_ptr<VEthernetExchanger> exchanger = client->GetExchanger(); 
    if (NULLPTR == exchanger)
    {
        return false;
    }

    // Check link status
    NetworkState network_state = exchanger->GetNetworkState();
    if (network_state == NetworkState::NetworkState_Established) 
    {
        // Handle link restart count
        if (GLOBAL_.link_restart > 0) 
        {
            // If the number of link reconnections exceeds a certain number, the program needs to be restarted immediately.
            if (exchanger->GetReconnectionCount() >= GLOBAL_.link_restart)
            {
                return ShutdownApplication(true);
            }
        }
    }
    else 
    {
        return false;
    }

    // Check for IP list updates
    if (now >= GLOBAL_VIRR_NEXT.load(std::memory_order_relaxed))
    {
        // Update the last automatic pull time and decide whether to pull the IP list file based on the en1abled options.
        GLOBAL_VIRR_NEXT.store(now + (configuration_->virr.update_interval * 1000), std::memory_order_relaxed);
        if (GLOBAL_VIRR.load(std::memory_order_relaxed))
        {
            PullIPList(GLOBAL_.virr_argument, true);
        }
    }

    // Check for vBGP updates
    if ((now - GLOBAL_VBGP_LAST.load(std::memory_order_relaxed)) / 1000 >= (uint64_t)configuration_->vbgp.update_interval)
    {
        GLOBAL_VBGP_LAST.store(now, std::memory_order_relaxed);
        if (RouteIPListTablePtr vbgp = client->GetVbgp(); GLOBAL_VBGP.load(std::memory_order_relaxed) && NULLPTR != vbgp)
        {
            // Update all vBGP routes
            for (auto&& kv : *vbgp) 
            {
                // The low-version C/C++ compiler of the OS X platform has source code compilation compatibility.  
                // In such scenarios, the temporary local variable auto&& [path, url] cannot be captured.
                const ppp::string& path = kv.first;
                const ppp::string& url = kv.second;
                PullIPList(url, 
                    [path](int count, const ppp::set<ppp::string>& ips) noexcept
                    {
                        if (count < 1)
                        {
                            return -1;
                        }
                        
                        // Compare with existing file
                        ppp::set<ppp::string> olds;
                        ppp::string iplist = ppp::LTrim(ppp::RTrim(File::ReadAllText(path.data())));

                        chnroutes2_getiplist(olds, ppp::string(), iplist);
                        if (!chnroutes2_equals(ips, olds))
                        {
                            ppp::string news = chnroutes2_toiplist(ips);
                            if (File::WriteAllBytes(path.data(), news.data(), news.size()))
                            {
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

// Start/stop periodic tick timer
bool PppApplication::NextTickAlwaysTimeout(bool next) noexcept
{
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context)
    {
        return false;
    }

    std::shared_ptr<PppApplication> app = DEFAULT_;
    if (NULLPTR == app)
    {
        return false;
    }

    std::shared_ptr<VirtualEthernetSwitcher> server = app->server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULLPTR == server && NULLPTR == client)
    {
        return false;
    }

    // Create periodic timer
    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, 
        [](Timer*) noexcept
        {
            std::shared_ptr<PppApplication> app = DEFAULT_;
            if (NULLPTR != app)
            {
                app->NextTickAlwaysTimeout(true);
            }
        });
    if (NULLPTR == timeout)
    {
        return false;
    }

    app->timeout_ = std::move(timeout);
    app->OnTick(Executors::GetTickCount());
    return true;
}

// Stop periodic tick timer
void PppApplication::ClearTickAlwaysTimeout() noexcept
{
    std::shared_ptr<Timer> timeout = std::move(timeout_);
    if (NULLPTR != timeout)
    {
        timeout->Dispose();
    }
}

// Get server switcher instance
std::shared_ptr<VirtualEthernetSwitcher> PppApplication::GetServer() noexcept
{
    return server_;
}

// Get client switcher instance
std::shared_ptr<VEthernetNetworkSwitcher> PppApplication::GetClient() noexcept
{
    return client_;
}

// Get application singleton instance
std::shared_ptr<PppApplication> PppApplication::GetDefault() noexcept
{
    return DEFAULT_;
}

// Get application configuration
std::shared_ptr<AppConfiguration> PppApplication::GetConfiguration() noexcept
{
    return configuration_;
}

// Load configuration from file
std::shared_ptr<AppConfiguration> PppApplication::LoadConfiguration(int argc, const char* argv[], ppp::string& path) noexcept
{
    static constexpr const char* argument_keys[] = { "-c", "--c", "-config", "--config" };

    // Find configuration file from command line
    for (const char* argument_key : argument_keys)
    {
        ppp::string argument_value = ppp::GetCommandArgument(argument_key, argc, argv);
        if (argument_value.empty())
        {
            continue;
        }

        argument_value = File::RewritePath(argument_value.data());
        argument_value = File::GetFullPath(argument_value.data());
        if (argument_value.empty())
        {
            continue;
        }

        if (File::CanAccess(argument_value.data(), FileAccess::Read))
        {
            path = std::move(argument_value);
            break;
        }
    }

    // Try default configuration file locations
    ppp::string configuration_paths[] =
    {
        path,
        "./config.json",
        "./appsettings.json",
    };
    bool found_configuration_file = false;
    for (ppp::string& configuration_path : configuration_paths)
    {
        if (configuration_path.empty())
        {
            continue;
        }

        configuration_path = File::GetFullPath(File::RewritePath(configuration_path.data()).data());
        if (!File::Exists(configuration_path.data()))
        {
            continue;
        }

        found_configuration_file = true;

        std::shared_ptr<AppConfiguration> configuration = ppp::make_shared_object<AppConfiguration>();
        if (NULLPTR == configuration)
        {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            path.clear();
            return NULLPTR;
        }

        if (!configuration->Load(configuration_path))
        {
            continue;
        }

        // Initialize buffer allocator if configured
#if defined(_WIN32)
        if (configuration->vmem.size > 0)
#else
        if (configuration->vmem.path.size() > 0 && configuration->vmem.size > 0)
#endif
        {
            std::shared_ptr<BufferswapAllocator> allocator = ppp::make_shared_object<BufferswapAllocator>(configuration->vmem.path,
                std::max<int64_t>((int64_t)1LL << (int64_t)25LL, (int64_t)configuration->vmem.size << (int64_t)20LL));
            if (NULLPTR != allocator && allocator->IsVaild())
            {
                configuration->SetBufferAllocator(allocator);
            }
        }

        path = configuration_path;
        return configuration;
    }

    path.clear();
    if (ppp::diagnostics::GetLastErrorCode() == ppp::diagnostics::ErrorCode::Success)
    {
        ppp::diagnostics::SetLastErrorCode(found_configuration_file
            ? ppp::diagnostics::ErrorCode::ConfigLoadFailed
            : ppp::diagnostics::ErrorCode::ConfigFileNotFound);
    }

    return NULLPTR;
}

// Shutdown application handler
bool PppApplication::OnShutdownApplication() noexcept 
{
    return ShutdownApplication(false);
}

// Trigger application shutdown or restart
bool PppApplication::ShutdownApplication(bool restart) noexcept 
{
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context)
    {
        return false;
    }
    else
    {
        GLOBAL_RESTART.store(GLOBAL_RESTART.load(std::memory_order_relaxed) || restart, std::memory_order_relaxed);
        boost::asio::post(*context, 
            [restart, context]() noexcept
            {
                // References to move app application domains.
                std::shared_ptr<PppApplication> APP = std::move(DEFAULT_);
                if (NULLPTR == APP)
                {
                    return false;
                }

                // Release app instances.
                APP->Dispose();

                // Delay before exit to allow clean shutdown
                std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, 
                    [](Timer*) noexcept
                    {
                        // Exit all the app loops.
                        Executors::Exit();
                    });
                return NULLPTR != timeout;
            });
        return true;
    }
}

// Register OS-specific shutdown handlers
bool PppApplication::AddShutdownApplicationEventHandler() noexcept
{
#if defined(_WIN32)
    return ppp::win32::Win32Native::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#else
    return ppp::unix__::UnixAfx::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#endif
}

// Windows-specific TAP driver installation
#if defined(_WIN32)
static bool Windows_PreparedEthernetEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept
{
    // Install TAP-Windows driver if not present
    if (network_interface->ComponentId.empty())
    {
        // Install the TAP-Windows vNIC in the Windows operating system.
        ppp::string driverPath = File::GetFullPath((ppp::GetApplicationStartupPath() + "\\Driver\\").data());
        if (ppp::tap::TapWindows::InstallDriver(driverPath.data(), NetworkInterface::GetDefaultTun())) // ppp::ToUpper<ppp::string>(BOOST_BEAST_VERSION_STRING)
        {
            // Find default TAP device if not specified
            network_interface->ComponentId = ppp::tap::TapWindows::FindComponentId(network_interface->Wintun);
            if (network_interface->ComponentId.empty())
            {
                network_interface->ComponentId = ppp::tap::ITap::FindAnyDevice();
            }
        }

        // The virtual Ethernet card device was not successfully deployed on your computer.
        if (network_interface->ComponentId.empty())
        {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            return false;
        }
    }
    return true;
}

// Disable LSP for specific program
static bool Windows_NoLsp(int argc, const char* argv[]) noexcept
{
    char key[] = "--no-lsp";
    if (!ppp::HasCommandArgument(key, argc, argv))
    {
        return false;
    }

    bool ok = false;
    do
    {
        ppp::string line = ppp::GetCommandArgument(argc, argv);
        if (line.empty())
        {
            break;
        }

        std::size_t index = line.find(key);
        if (index == ppp::string::npos)
        {
            break;
        }

        line = line.substr(index + sizeof(key) - 1);
        if (line.empty())
        {
            break;
        }

        int ch = line[0];
        if (ch != '=' && ch != ' ')
        {
            break;
        }

        line = ppp::RTrim(ppp::LTrim(line.substr(1)));
        if (line.empty())
        {
            break;
        }

        ok = ppp::app::client::lsp::PaperAirplaneController::NoLsp(line);
    } while (false);

    if (!ok)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericOperationFailed);
    }

    return true;
}

// Windows network configuration commands
static bool Windows_PreferredNetwork(int argc, const char* argv[]) noexcept 
{
    bool ok = false;
    if (ppp::HasCommandArgument("--system-network-preferred-ipv4", argc, argv))
    {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(true);
    }
    elif(ppp::HasCommandArgument("--system-network-preferred-ipv6", argc, argv))
    {
        ok = ppp::net::proxies::HttpProxy::PreferredNetwork(false);
    }
    elif(ppp::HasCommandArgument("--system-network-reset", argc, argv))
    {
        ok = ppp::win32::network::ResetNetworkEnvironment();
    }
    else
    {
        return false;
    }

    if (!ok)
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
    }

    return true;
}
#endif

// Main application entry point
int PppApplication::Main(int argc, const char* argv[]) noexcept
{
    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    // Require administrator/root privileges
    if (!ppp::IsUserAnAdministrator()) // $ROOT is 0.
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppPrivilegeRequired);
        return -1;
    }

    // Prevent multiple instances
    ppp::string rerun_name = (client_mode_ ? "client://" : "server://") + configuration_path_;
    if (prevent_rerun_.Exists(rerun_name.data()))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppAlreadyRunning);
        return -1;
    }

    // Create instance lock
    if (!prevent_rerun_.Open(rerun_name.data()))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppLockAcquireFailed);
        return -1;
    }

#if defined(_WIN32)
    // Windows-specific setup
    if (client_mode_)
    {
        // Prepare the environment for the virtual Ethernet network device card.
        if (!Windows_PreparedEthernetEnvironment(network_interface_))
        {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
            return -1;
        }
    }

    // Save original QUIC setting
    quic_ = ppp::net::proxies::HttpProxy::IsSupportExperimentalQuicProtocol();
#endif

    // Initialize network environment
    if (!PreparedLoopbackEnvironment(network_interface_))
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::AppPreflightCheckFailed);
        return -1;
    }

    // Initialize timers and statistics
    stopwatch_.Restart();
    transmission_statistics_.Clear();

    // Configure client if running in client mode
    std::shared_ptr<VEthernetNetworkSwitcher> client = client_;
    if (NULLPTR != client)
    {
#if defined(_WIN32)
        // Configure QUIC blocking
        ppp::net::proxies::HttpProxy::SetSupportExperimentalQuicProtocol(!network_interface_->BlockQUIC);
#endif

        // Set up http-proxy and whether to block QUIC traffic!
        client->BlockQUIC(network_interface_->BlockQUIC);

#if defined(_WIN32)
        // Linux does not support global Settings of the http proxy server on the operating system.   
        // This is because you can only change the /etc/profile configuration file.   
        // If the current user is the user, you can change the ~/.  bashrc configuration files implement.

        // The configuration proxy syntax is approximately:
        // export http_proxy="http://proxy.example.com:8080"
        // export https_proxy="http://proxy.example.com:8080"

        // However, there is a big flaw here, if the _tty terminal window that has been opened cannot take effect, 
        // And the Windows platform can take effect globally is different, so directly cancel the function support 
        // Of setting http proxy on Linux above the operating system.
        if (network_interface_->SetHttpProxy)
        {
            client->SetHttpProxyToSystemEnv();
        }
#endif

        // Configure auto-update settings
        GLOBAL_VIRR.store(ppp::HasCommandArgument("--virr", argc, argv), std::memory_order_relaxed);
        if (GLOBAL_VIRR.load(std::memory_order_relaxed)) 
        {
            GLOBAL_.bypass = network_interface_->Bypass;
            GLOBAL_.virr_argument = ppp::GetCommandArgument("--virr", argc, argv);
        }

        // If vbgp is not set up, it is enabled by default; otherwise, the vbgp function is disabled. Enabling the vbgp function will consume performance.
        GLOBAL_VBGP.store(ppp::ToBoolean(ppp::GetCommandArgument("--vbgp", argc, argv, "y").data()), std::memory_order_relaxed);
    }

    // Parse restart configuration
    GLOBAL_.auto_restart = std::max<int>(0, atoi(ppp::GetCommandArgument("--auto-restart", argc, argv).data()));
    GLOBAL_.link_restart = (uint8_t)std::max<int>(0, atoi(ppp::GetCommandArgument("--link-restart", argc, argv).data()));

    // Start periodic updates
    if (!NextTickAlwaysTimeout(false)) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeTimerStartFailed);
        return -1;
    }

    return 0;
}

// Application runner function
static int Run(const std::shared_ptr<PppApplication>& APP, int prepared_status, int argc, const char* argv[]) noexcept
{
    // Handle IP list download command
    if (ppp::HasCommandArgument("--pull-iplist", argc, argv))
    {
        APP->PullIPList(ppp::GetCommandArgument("--pull-iplist", argc, argv), false);
        return -1;
    }

#if defined(_WIN32)
    // Handle Windows-specific commands
    if (Windows_PreferredNetwork(argc, argv))
    {
        return -1;
    }

    // Set the EXE program of the specified PE file path not to load LSPS. If some EXE programs load LSPS, the network cannot be accessed, for example, WSL.
    if (Windows_NoLsp(argc, argv))
    {
        return -1;
    }

    // Handle network optimization command
    if (ppp::HasCommandArgument("--system-network-optimization", argc, argv))
    {
        if (!ppp::win32::Win32Native::OptimizationSystemNetworkSettings())
        {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
        }

        return -1;
    }
#endif

    // Show help if arguments invalid
    if (prepared_status != 0)
    {
        APP->PrintHelpInformation();
        return -1;
    }

    // Register shutdown handlers
    PppApplication::AddShutdownApplicationEventHandler();

    // Register restart signal handler on Unix-like systems
#if SIGRESTART
    signal(SIGRESTART, // SIG_DFL
        [](int) noexcept
        {
            PppApplication::ShutdownApplication(true);
        });
#endif

    // Run main application
    return APP->Main(argc, argv);
}

// Program entry point
int RunPppApplicationMain(int argc, const char* argv[]) noexcept
{
    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    // Configure real-time mode
    ppp::RT = ppp::ToBoolean(ppp::GetCommandArgument("--rt", argc, argv, "y").data());
    
    // Initialize global state
    ppp::global::cctor();

    // Check io_uring compatibility on Linux
#if BOOST_ASIO_HAS_IO_URING != 0
    if (!ppp::diagnostics::IfIOUringKernelVersion()) 
    {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return -1;
    }
#endif

    // Create application instance
    std::shared_ptr<PppApplication> APP = ppp::make_shared_object<PppApplication>();
    if (NULLPTR == APP) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        return -1;
    }

    DEFAULT_ = APP;

    // Prepare environment and run
    int prepared_status = APP->PreparedArgumentEnvironment(argc, argv);
    int result_code = Executors::Run(APP->GetBufferAllocator(), 
        [APP, prepared_status](int argc, const char* argv[]) noexcept -> int
        {
            int result_code = Run(APP, prepared_status, argc, argv);
#if defined(_WIN32)
            if (result_code != 0)
            {
                ppp::win32::Win32Native::PauseWindowsConsole();
            }
#endif
            return result_code;
        }, argc, argv);
    
    // Clean up and optionally restart
    APP->Release();

    // Restart application if requested
    if (GLOBAL_RESTART.load(std::memory_order_relaxed))
    {
#if defined(_WIN32)
        // Build command line for restart
        ppp::string command_line = "\"" + ppp::string(*argv) + "\"";
        for (int i = 1; i < argc; ++i) 
        {
            command_line += " \"" + ppp::string(argv[i]) + "\""; 
        }

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
    
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        // Launch new instance
        if (CreateProcessA(NULLPTR, command_line.data(), NULLPTR, NULLPTR, FALSE, 0, NULLPTR, NULLPTR, &si, &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
#else
        // Unix exec restart
        execvp(*argv, (char**)argv);
#endif
    }

    return result_code;
}
