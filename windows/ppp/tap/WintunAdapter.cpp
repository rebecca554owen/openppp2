// -----------------------------------------------------------------------------
//  Implementation
// -----------------------------------------------------------------------------

// Refer: https://git.zx2c4.com/wintun/tree/example/example.c
#include <windows/ppp/tap/WintunAdapter.h>
#include <ppp/diagnostics/Error.h>
#include <ppp/tap/ITap.h>
#include <ppp/net/native/ip.h>
#include <ppp/threading/Executors.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static constexpr int WINTUN_RUNING_STATE_STOP       = 0;
static constexpr int WINTUN_RUNING_STATE_OPEN       = 1;
static constexpr int WINTUN_RUNING_STATE_RUNNING    = 2;

// -------------------- Wintun API function pointers --------------------
typedef WINTUN_ADAPTER_HANDLE(WINAPI*       WintunCreateAdapterFunc)(LPCWSTR, LPCWSTR, const GUID*);
typedef WINTUN_ADAPTER_HANDLE(WINAPI*       WintunOpenAdapterFunc)(LPCWSTR);
typedef VOID(WINAPI*                        WintunCloseAdapterFunc)(WINTUN_ADAPTER_HANDLE);
typedef VOID(WINAPI*                        WintunGetAdapterLUIDFunc)(WINTUN_ADAPTER_HANDLE, NET_LUID*);
typedef WINTUN_SESSION_HANDLE(WINAPI*       WintunStartSessionFunc)(WINTUN_ADAPTER_HANDLE, DWORD);
typedef VOID(WINAPI*                        WintunEndSessionFunc)(WINTUN_SESSION_HANDLE);
typedef HANDLE(WINAPI*                      WintunGetReadWaitEventFunc)(WINTUN_SESSION_HANDLE);
typedef BYTE* (WINAPI*                      WintunReceivePacketFunc)(WINTUN_SESSION_HANDLE, DWORD*);
typedef VOID(WINAPI*                        WintunReleaseReceivePacketFunc)(WINTUN_SESSION_HANDLE, BYTE*);
typedef BYTE* (WINAPI*                      WintunAllocateSendPacketFunc)(WINTUN_SESSION_HANDLE, DWORD);
typedef VOID(WINAPI*                        WintunSendPacketFunc)(WINTUN_SESSION_HANDLE, BYTE*);

static HMODULE                              DLL_HANDLE = NULL;

static WintunCreateAdapterFunc              WintunCreateAdapter = NULL;
static WintunOpenAdapterFunc                WintunOpenAdapter = NULL;
static WintunCloseAdapterFunc               WintunCloseAdapter = NULL;
static WintunGetAdapterLUIDFunc             WintunGetAdapterLUID = NULL;
static WintunStartSessionFunc               WintunStartSession = NULL;
static WintunEndSessionFunc                 WintunEndSession = NULL;
static WintunGetReadWaitEventFunc           WintunGetReadWaitEvent = NULL;
static WintunReceivePacketFunc              WintunReceivePacket = NULL;
static WintunReleaseReceivePacketFunc       WintunReleaseReceivePacket = NULL;
static WintunAllocateSendPacketFunc         WintunAllocateSendPacket = NULL;
static WintunSendPacketFunc                 WintunSendPacket = NULL;

// Helper: load/unload Wintun DLL
struct ReadyWintunAdapter
{
    ReadyWintunAdapter() noexcept { READY = LoadWintun(); }
    ~ReadyWintunAdapter() noexcept { UnloadWintun(); }

    bool                                    LoadWintun() noexcept {
        if (DLL_HANDLE) return true;

        // Search for wintun.dll from multiple local or system directories; 
        // if this driver exists, use Wintun, otherwise fall back to TAP-Windows as originally designed, ensuring deployment flexibility.
        DLL_HANDLE = LoadLibraryW(L"wintun.dll");
        if (!DLL_HANDLE) {
            DLL_HANDLE = LoadLibraryW(L"Driver\\wintun.dll");
            if (!DLL_HANDLE) {
#ifdef _WIN64
                LPCWSTR wzDllPath = L"Driver\\x64\\wintun.dll";
#else
                LPCWSTR wzDllPath = L"Driver\\x86\\wintun.dll";
#endif
                DLL_HANDLE = LoadLibraryW(wzDllPath);
                if (!DLL_HANDLE) {
                    ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
                    return false; // LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32
                }
            }
        }
        
#define GET_PROC(name) \
    name = (decltype(name))GetProcAddress(DLL_HANDLE, #name); \
    if (!name) { ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed); FreeLibrary(DLL_HANDLE); DLL_HANDLE = NULL; return false; }

        GET_PROC(WintunCreateAdapter);
        GET_PROC(WintunOpenAdapter);
        GET_PROC(WintunCloseAdapter);
        GET_PROC(WintunGetAdapterLUID);
        GET_PROC(WintunStartSession);
        GET_PROC(WintunEndSession);
        GET_PROC(WintunGetReadWaitEvent);
        GET_PROC(WintunReceivePacket);
        GET_PROC(WintunReleaseReceivePacket);
        GET_PROC(WintunAllocateSendPacket);
        GET_PROC(WintunSendPacket);
#undef GET_PROC
        return true;
    }

    void                                    UnloadWintun() noexcept {
        if (DLL_HANDLE) {
            FreeLibrary(DLL_HANDLE);
            DLL_HANDLE = NULL;
        }
    }

    bool                                    READY = false;
};

// -----------------------------------------------------------------------------
//  WintunAdapter implementation
// -----------------------------------------------------------------------------
WintunAdapter::~WintunAdapter() noexcept {
    Stop();   // Ensures all resources are released
}

bool WintunAdapter::Open() noexcept {
    int expected = WINTUN_RUNING_STATE_STOP;
    if (!running_flag_.compare_exchange_strong(expected, WINTUN_RUNING_STATE_OPEN)) {
        return true;   // Already opened
    }

    // Try to open existing adapter, otherwise create a new one
    adapter_handle_ = WintunOpenAdapter(adapter_name_.c_str());
    if (!adapter_handle_) {
        adapter_handle_ = WintunCreateAdapter(adapter_name_.c_str(),
            adapter_desc_.c_str(),
            adapter_guid_ptr_);
        if (!adapter_handle_) {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunCreateFailed);
            running_flag_.store(WINTUN_RUNING_STATE_STOP);
            return false;
        }
    }

    // Start the Wintun session
    session_handle_ = WintunStartSession(adapter_handle_, ring_buffer_size_);
    if (!session_handle_) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::WindowsWintunSessionStartFailed);
        if (adapter_handle_) WintunCloseAdapter(adapter_handle_);
        adapter_handle_ = NULL;

        running_flag_.store(WINTUN_RUNING_STATE_STOP);
        return false;
    }

    // Create an event that can be used to wake the receive thread
    quit_event_ = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!quit_event_) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
        WintunEndSession(session_handle_);
        session_handle_ = NULL;

        if (adapter_handle_) WintunCloseAdapter(adapter_handle_);
        adapter_handle_ = NULL;

        running_flag_.store(WINTUN_RUNING_STATE_STOP);
        return false;
    }

    return true;
}

bool WintunAdapter::Start() noexcept {
    using Executors = ppp::threading::Executors;
    using Awaitable = Executors::Awaitable;

    std::shared_ptr<Awaitable> awaitable = ppp::make_shared_object<Awaitable>();
    if (!awaitable) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::MemoryAllocationFailed);
        return false;
    }

    int expected = WINTUN_RUNING_STATE_OPEN;
    if (!running_flag_.compare_exchange_strong(expected, WINTUN_RUNING_STATE_RUNNING, std::memory_order_acquire)) {
        return true;   // Already started
    }

    std::shared_ptr<WintunAdapter> self = shared_from_this();
    std::weak_ptr<Awaitable> awaitable_weak = awaitable;

    try {
        std::thread(
            [self, awaitable_weak]() {
                ppp::SetThreadPriorityToMaxLevel();
                ppp::SetThreadName("wintun");

                // Signal that the thread has started
                if (std::shared_ptr<Awaitable> a = awaitable_weak.lock(); a) {
                    a->Processed();
                }

                self->ReceiveLoop();
            }).detach();
    }
    catch (...) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::RuntimeThreadStartFailed);
        Stop();   // Clean up if thread creation fails
        return false;
    }

    return awaitable->Await();
}

void WintunAdapter::Finalize() noexcept {
    // 1. Wake the receive thread if it's waiting
    if (quit_event_) SetEvent(quit_event_);

    // 2. Wait for the receive thread to exit
    while (running_flag_.load(std::memory_order_acquire) >= WINTUN_RUNING_STATE_RUNNING) std::this_thread::sleep_for(std::chrono::milliseconds(1));

    // 3. Nullify the callback to prevent further calls
    PacketInput.reset();

    // 4. Release Wintun resources
    if (session_handle_) {
        WintunEndSession(session_handle_);
        session_handle_ = NULL;
    }

    if (adapter_handle_) {
        WintunCloseAdapter(adapter_handle_);
        adapter_handle_ = NULL;
    }

    if (quit_event_) {
        CloseHandle(quit_event_);
        quit_event_ = NULL;
    }

    // 5. After complete exit, set the status to "completed".
    finalized_.exchange(-1, std::memory_order_release);
}

void WintunAdapter::Stop() noexcept {
    // Atomically set the stop flag. The in-flight counter remains protected by the same state word.
    // The returned value is intentionally ignored because only the stop bit transition matters here.
    state_.fetch_or(STOP_BIT, std::memory_order_acq_rel);

    // Wait for all in‑flight packets to complete.
    // The load with acquire ensures we see every release from fetch_sub.
    while ((state_.load(std::memory_order_acquire) & COUNT_MASK) != 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1)); 
    }

    // Ensure Finalize runs only once. Multiple Stop calls are harmless and will wait for completion.
    int excepted = 0;
    if (finalized_.compare_exchange_weak(excepted, 1, std::memory_order_acq_rel, std::memory_order_relaxed)) {
        Finalize();
    }
    else {
        while (finalized_.load(std::memory_order_acquire) > 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Tell the receive loop to exit (if it is still running)
    running_flag_.store(WINTUN_RUNING_STATE_STOP, std::memory_order_release);
}

bool WintunAdapter::SendPacket(const uint8_t* data, uint32_t len) noexcept {
    if (!session_handle_) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelOpenFailed);
        return false;
    }

    // Atomically increment the in‑flight counter and check the stop flag
    uint32_t old = state_.fetch_add(1, std::memory_order_acq_rel);
    if (old & STOP_BIT) {
        // Already stopped – rollback and reject
        state_.fetch_sub(1, std::memory_order_release);
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidState);
        return false;
    }

    // At this point the packet is considered "in flight".
    // The stop flag is not set, so we can proceed safely.
    bool success = false;
    if (len > 0 && len <= static_cast<uint32_t>(ppp::tap::ITap::Mtu)) {
        BYTE* buf = WintunAllocateSendPacket(session_handle_, len);
        if (buf) {
            memcpy(buf, data, len);
            WintunSendPacket(session_handle_, buf);

            success = true;
        }
        else {
            ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::TunnelPacketInjectFailed);
        }
    }
    else {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::NetworkPacketTooLarge);
    }

    // Decrement the in‑flight counter (release order pairs with acquire in Stop)
    state_.fetch_sub(1, std::memory_order_release);
    return success;
}

bool WintunAdapter::Ready() noexcept {
    static ReadyWintunAdapter ready;
    return ready.READY;
}

void WintunAdapter::ReceiveLoop() noexcept {
    HANDLE read_event = WintunGetReadWaitEvent(session_handle_);
    if (!read_event || !quit_event_) {
        ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::GenericInvalidState);
        return;
    }

    HANDLE events[2] = { read_event, quit_event_ };

    while (running_flag_.load(std::memory_order_acquire)) {
        DWORD packet_size = 0;
        BYTE* packet = WintunReceivePacket(session_handle_, &packet_size);

        if (packet) {
            // Valid packet received – dispatch to callback if present
            if (packet_size >= static_cast<DWORD>(ppp::net::native::ip_hdr::IP_HLEN)) {
                std::shared_ptr<PacketHandler> handler = PacketInput;
                if (handler && *handler) {
                    (*handler)(packet, packet_size);
                }
            }

            WintunReleaseReceivePacket(session_handle_, packet);
            continue;
        }

        DWORD err = GetLastError();

        if (err == ERROR_HANDLE_EOF) {
            // Adapter was removed – exit
            running_flag_.store(WINTUN_RUNING_STATE_STOP, std::memory_order_release);
            break;
        }

        if (err == ERROR_NO_MORE_ITEMS) {
            // No packets available – wait for either data or stop event
            DWORD wait = WaitForMultipleObjects(2, events, FALSE, INFINITE);
            if (wait == WAIT_OBJECT_0 + 1) {      // quit_event_ signalled
                running_flag_.store(WINTUN_RUNING_STATE_STOP, std::memory_order_release);
                break;
            }

            if (wait != WAIT_OBJECT_0) {           // Unexpected error
                running_flag_.store(WINTUN_RUNING_STATE_STOP, std::memory_order_release);
                break;
            }
            continue;
        }

        // Any other error – exit
        running_flag_.store(WINTUN_RUNING_STATE_STOP, std::memory_order_release);
        break;
    }
}

WintunAdapter::WintunAdapter(const std::wstring& adapter_name, const std::wstring& adapter_desc, const GUID* adapter_guid, uint32_t ring_buffer_size) noexcept
    : adapter_name_(adapter_name)
    , adapter_desc_(adapter_desc)
    , adapter_guid_ptr_(NULL)
    , ring_buffer_size_(ring_buffer_size)
    , adapter_handle_(NULL)
    , session_handle_(NULL)
    , quit_event_(NULL)
    , running_flag_(WINTUN_RUNING_STATE_STOP)
    , state_(0)
{
    if (adapter_guid) {
        adapter_guid_ = *adapter_guid;
        adapter_guid_ptr_ = &adapter_guid_;
    }
}
