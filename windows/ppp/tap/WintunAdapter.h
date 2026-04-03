#pragma once

// -----------------------------------------------------------------------------
//  WintunAdapter.h
//  A lock‑free, multi‑thread safe adapter for Wintun TUN driver.
//  Design highlights:
//    • Single 32‑bit atomic state combining stop flag and in‑flight packet count.
//    • All operations use acquire/release memory ordering for precise
//      happens‑before relationships.
//    • No mutexes, no critical sections – only CPU atomics.
//    • Graceful shutdown that waits for all in‑flight sends to complete.
//    • Exception‑safe construction and destruction.
// -----------------------------------------------------------------------------

#include <ppp/stdafx.h>

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <stdio.h>
#include <stdint.h>

#include <string>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <chrono>

// -------------------- Wintun API types (as declared by wintun.h) --------------------
typedef struct _WINTUN_ADAPTER*         WINTUN_ADAPTER_HANDLE;
typedef struct _WINTUN_SESSION*         WINTUN_SESSION_HANDLE;

// -------------------- WintunAdapter class --------------------
class WintunAdapter : public std::enable_shared_from_this<WintunAdapter> {
public:
    using PacketHandler                 = ppp::function<void(const uint8_t* data, uint32_t len)>;

    std::shared_ptr<PacketHandler>      PacketInput;                            // Thread‑safe shared callback

    static constexpr int                MAX_RING_BUFFER_SIZE = 1 << 20;         // 1 MiB ring buffer

public:
    WintunAdapter(const WintunAdapter&) = delete;
    ~WintunAdapter() noexcept;

public:
    WintunAdapter&                      operator=(const WintunAdapter&) = delete;

public:
    bool                                Open() noexcept;                        // Create or open adapter
    bool                                Start() noexcept;                       // Start receive thread
    void                                Stop() noexcept;                        // Graceful shutdown
    bool                                SendPacket(const uint8_t* data, uint32_t len) noexcept;

    bool                                IsOpen() noexcept {
        return NULL != session_handle_ && NULL != adapter_handle_ && NULL != quit_event_;
    }

    static bool                         Ready() noexcept;                       // Check if Wintun DLL is loaded

public:
    // adapter_guid may be nullptr → Wintun generates a random GUID
    WintunAdapter(const std::wstring& adapter_name,
        const std::wstring& adapter_desc,
        const GUID* adapter_guid,
        uint32_t ring_buffer_size) noexcept;

private:
    void                                ReceiveLoop() noexcept;                 // Receive thread main function
    void                                Finalize() noexcept;                    // Release all resources (called once)

private:
    // State encoding: bit 31 = stop flag, bits 0‑30 = in‑flight packet count.
    static constexpr uint32_t           STOP_BIT   = 1U << 31;
    static constexpr uint32_t           COUNT_MASK = ~STOP_BIT;

    std::wstring                        adapter_name_;
    std::wstring                        adapter_desc_;
    GUID                                adapter_guid_;                          // Copy of user‑supplied GUID (if any)
    const GUID*                         adapter_guid_ptr_;                      // Points to adapter_guid_ or nullptr

    uint32_t                            ring_buffer_size_;                      // Ring buffer size for Wintun session

    WINTUN_ADAPTER_HANDLE               adapter_handle_;
    WINTUN_SESSION_HANDLE               session_handle_;
    HANDLE                              quit_event_;                            // Used to wake the receive thread

    std::atomic<int >                   running_flag_{ 0 };                     // Controls receive loop
    std::atomic<int>                    finalized_{ 0 };                        // Ensures Finalize() runs once
    std::atomic<uint32_t>               state_{ 0 };                            // Combined stop flag + in‑flight count
};