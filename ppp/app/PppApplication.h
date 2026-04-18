#pragma once

#include <ppp/stdafx.h>
#include <ppp/diagnostics/PreventReturn.h>
#include <ppp/diagnostics/Stopwatch.h>
#include <ppp/transmissions/ITransmissionStatistics.h>

namespace ppp {
    namespace configurations {
        class AppConfiguration;
    }

    namespace threading {
        class BufferswapAllocator;
        class Timer;
    }

    namespace app {
        namespace server {
            class VirtualEthernetSwitcher;
        }

        namespace client {
            class VEthernetNetworkSwitcher;
        }
    }
}

struct NetworkInterface;

class PppApplication : public std::enable_shared_from_this<PppApplication> {
public:
    PppApplication() noexcept;
    virtual ~PppApplication() noexcept;

public:
    int Main(int argc, const char* argv[]) noexcept;
    void Dispose() noexcept;
    void Release() noexcept;

public:
    static std::shared_ptr<PppApplication> GetDefault() noexcept;
    static bool OnShutdownApplication() noexcept;
    static bool ShutdownApplication(bool restart) noexcept;
    static bool AddShutdownApplicationEventHandler() noexcept;

public:
    std::shared_ptr<ppp::configurations::AppConfiguration> GetConfiguration() noexcept;
    std::shared_ptr<ppp::app::server::VirtualEthernetSwitcher> GetServer() noexcept;
    std::shared_ptr<ppp::app::client::VEthernetNetworkSwitcher> GetClient() noexcept;
    std::shared_ptr<ppp::threading::BufferswapAllocator> GetBufferAllocator() noexcept;

public:
    void PrintHelpInformation() noexcept;
    void PullIPList(const ppp::string& command, bool virr) noexcept;
    int PullIPList(const ppp::string& url, ppp::set<ppp::string>& ips) noexcept;
    bool PullIPList(const ppp::string& url, const ppp::function<void(int, const ppp::set<ppp::string>&)>& cb) noexcept;
    int PreparedArgumentEnvironment(int argc, const char* argv[]) noexcept;

protected:
    virtual bool OnTick(uint64_t now) noexcept;

private:
    std::shared_ptr<ppp::configurations::AppConfiguration> LoadConfiguration(int argc, const char* argv[], ppp::string& path) noexcept;
    bool IsModeClientOrServer(int argc, const char* argv[]) noexcept;
    std::shared_ptr<NetworkInterface> GetNetworkInterface(int argc, const char* argv[]) noexcept;
    boost::asio::ip::address GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, int argc, const char* argv[]) noexcept;
    boost::asio::ip::address GetNetworkAddress(const char* name, int MIN_PREFIX_ADDRESS, int MAX_PREFIX_ADDRESS, const char* default_address_string, int argc, const char* argv[]) noexcept;
    void GetDnsAddresses(ppp::vector<boost::asio::ip::address>& addresses, int argc, const char* argv[]) noexcept;
    bool PreparedLoopbackEnvironment(const std::shared_ptr<NetworkInterface>& network_interface) noexcept;
    bool LogEnvironmentInformation() noexcept;

private:
    static bool NextTickAlwaysTimeout(bool next) noexcept;
    void ClearTickAlwaysTimeout() noexcept;

private:
    bool GetTransmissionStatistics(uint64_t& incoming_traffic, uint64_t& outgoing_traffic, std::shared_ptr<ppp::transmissions::ITransmissionStatistics>& statistics_snapshot) noexcept;

private:
    bool client_mode_ = false;
    bool quic_ = false;
    std::shared_ptr<ppp::configurations::AppConfiguration> configuration_;
    std::shared_ptr<ppp::app::server::VirtualEthernetSwitcher> server_;
    std::shared_ptr<ppp::app::client::VEthernetNetworkSwitcher> client_;
    ppp::string configuration_path_;
    std::shared_ptr<NetworkInterface> network_interface_;
    std::shared_ptr<ppp::threading::Timer> timeout_ = 0;
    ppp::diagnostics::Stopwatch stopwatch_;
    ppp::diagnostics::PreventReturn prevent_rerun_;
    ppp::transmissions::ITransmissionStatistics transmission_statistics_;
};

int RunPppApplicationMain(int argc, const char* argv[]) noexcept;
