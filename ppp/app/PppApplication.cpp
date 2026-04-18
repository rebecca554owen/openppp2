#include <ppp/app/PppApplicationInternal.h>

namespace ppp::app {

std::shared_ptr<PppApplication> DEFAULT_;
std::atomic<bool> GLOBAL_RESTART{false};
std::atomic<bool> GLOBAL_VBGP{false};
std::atomic<uint64_t> GLOBAL_VBGP_LAST{0};
std::atomic<bool> GLOBAL_VIRR{false};
std::atomic<uint64_t> GLOBAL_VIRR_NEXT{0};
ApplicationGlobals GLOBAL_;

PppApplication& PppApplication::GetInstance() noexcept {
    static std::shared_ptr<PppApplication> instance = ppp::make_shared_object<PppApplication>();
    if (DEFAULT_ != instance) {
        DEFAULT_ = instance;
    }
    return *instance;
}

int PppApplication::Run(int argc, char** argv) noexcept {
    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::Success);

    ppp::RT = ppp::ToBoolean(ppp::GetCommandArgument("--rt", argc, const_cast<const char**>(argv), "y").data());
    ppp::global::cctor();

#if BOOST_ASIO_HAS_IO_URING != 0
    if (!ppp::diagnostics::IfIOUringKernelVersion()) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeEnvironmentInvalid);
        return -1;
    }
#endif

    std::shared_ptr<PppApplication> app = DEFAULT_;
    if (NULLPTR == app) {
        app = ppp::make_shared_object<PppApplication>();
        if (NULLPTR == app) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
            return -1;
        }
        DEFAULT_ = app;
    }

    int prepared_status = app->PreparedArgumentEnvironment(argc, const_cast<const char**>(argv));
    int result_code = Executors::Run(
        app->GetBufferAllocator(),
        [app, prepared_status](int inner_argc, const char* inner_argv[]) noexcept -> int {
            int rc = RunPreparedApplication(app, prepared_status, inner_argc, inner_argv);
            ConsoleUI::GetInstance().Stop();
#if defined(_WIN32)
            if (rc != 0) {
                ppp::win32::Win32Native::PauseWindowsConsole();
            }
#endif
            return rc;
        },
        argc,
        const_cast<const char**>(argv));

    app->Release();

    if (GLOBAL_RESTART.load(std::memory_order_relaxed)) {
#if defined(_WIN32)
        ppp::string command_line = "\"" + ppp::string(*argv) + "\"";
        for (int i = 1; i < argc; ++i) {
            command_line += " \"" + ppp::string(argv[i]) + "\"";
        }

        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if (CreateProcessA(NULLPTR, command_line.data(), NULLPTR, NULLPTR, FALSE, 0, NULLPTR, NULLPTR, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
#else
        execvp(*argv, argv);
#endif
    }

    return result_code;
}

std::shared_ptr<VirtualEthernetSwitcher> PppApplication::GetServer() noexcept {
    return server_;
}

std::shared_ptr<VEthernetNetworkSwitcher> PppApplication::GetClient() noexcept {
    return client_;
}

std::shared_ptr<PppApplication> PppApplication::GetDefault() noexcept {
    return DEFAULT_;
}

std::shared_ptr<AppConfiguration> PppApplication::GetConfiguration() noexcept {
    return configuration_;
}

bool PppApplication::OnShutdownApplication() noexcept {
    return ShutdownApplication(false);
}

bool PppApplication::ShutdownApplication(bool restart) noexcept {
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        return false;
    }

    GLOBAL_RESTART.store(GLOBAL_RESTART.load(std::memory_order_relaxed) || restart, std::memory_order_relaxed);
    boost::asio::post(*context, [restart, context]() noexcept {
        std::shared_ptr<PppApplication> app = std::move(DEFAULT_);
        if (NULLPTR == app) {
            return false;
        }

        app->Dispose();
        std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, [](Timer*) noexcept { Executors::Exit(); });
        return NULLPTR != timeout;
    });
    return true;
}

bool PppApplication::AddShutdownApplicationEventHandler() noexcept {
#if defined(_WIN32)
    return ppp::win32::Win32Native::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#else
    return ppp::unix__::UnixAfx::AddShutdownApplicationEventHandler(PppApplication::OnShutdownApplication);
#endif
}

bool PppApplication::NextTickAlwaysTimeout(bool next) noexcept {
    std::shared_ptr<boost::asio::io_context> context = Executors::GetDefault();
    if (NULLPTR == context) {
        return false;
    }

    std::shared_ptr<PppApplication> app = DEFAULT_;
    if (NULLPTR == app) {
        return false;
    }

    std::shared_ptr<VirtualEthernetSwitcher> server = app->server_;
    std::shared_ptr<VEthernetNetworkSwitcher> client = app->client_;
    if (NULLPTR == server && NULLPTR == client) {
        return false;
    }

    std::shared_ptr<Timer> timeout = Timer::Timeout(context, 1000, [](Timer*) noexcept {
        std::shared_ptr<PppApplication> inner = DEFAULT_;
        if (NULLPTR != inner) {
            inner->NextTickAlwaysTimeout(true);
        }
    });
    if (NULLPTR == timeout) {
        return false;
    }

    app->timeout_ = std::move(timeout);
    app->OnTick(Executors::GetTickCount());
    return true;
}

void PppApplication::ClearTickAlwaysTimeout() noexcept {
    std::shared_ptr<Timer> timeout = std::move(timeout_);
    if (NULLPTR != timeout) {
        timeout->Dispose();
    }
}

int RunPreparedApplication(const std::shared_ptr<PppApplication>& app, int prepared_status, int argc, const char* argv[]) noexcept {
    if (ppp::HasCommandArgument("--pull-iplist", argc, argv)) {
        app->PullIPList(ppp::GetCommandArgument("--pull-iplist", argc, argv), false);
        return -1;
    }

#if defined(_WIN32)
    if (Windows_PreferredNetwork(argc, argv)) {
        return -1;
    }

    if (Windows_NoLsp(argc, argv)) {
        return -1;
    }

    if (ppp::HasCommandArgument("--system-network-optimization", argc, argv)) {
        if (!ppp::win32::Win32Native::OptimizationSystemNetworkSettings()) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkInterfaceConfigureFailed);
        }
        return -1;
    }
#endif

    if (prepared_status != 0) {
        app->PrintHelpInformation();
        return -1;
    }

    PppApplication::AddShutdownApplicationEventHandler();

#if SIGRESTART
    signal(SIGRESTART, [](int) noexcept { PppApplication::ShutdownApplication(true); });
#endif

    return app->Main(argc, argv);
}

} // namespace ppp::app
