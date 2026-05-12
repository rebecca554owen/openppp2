# Startup, Process Ownership, and Lifecycle Control

[中文版本](STARTUP_AND_LIFECYCLE_CN.md)

## Scope

This document explains how `ppp` starts, how process ownership is structured, how client and server diverge, and how maintenance and shutdown controls work. It covers every stage from the first OS instruction to the moment the runtime enters steady-state forwarding — and then how it shuts down cleanly.

Audience: contributors who are reading the code for the first time, operators who need to understand what the process is doing during startup, and engineers debugging startup failures using diagnostics codes.

---

## Why Startup Matters

OPENPPP2 startup is not just read-config-and-run. It has to handle:

- Privilege checks (root or Administrator required for TAP/TUN manipulation)
- Single-instance protection (prevent two servers from conflicting on the same config)
- Configuration loading and normalization (JSON → validated in-memory representation)
- Local host shaping (network interface setup, routing, DNS, firewall)
- Platform preparation (platform-specific TAP driver, Wintun rings, Android JNI)
- Role selection (client creates a TAP device; server creates a listener)
- Runtime creation (event loop threads, coroutine infrastructure, cipher objects)
- Maintenance tick loop (keepalive tracking, statistics, auto-restart checks)
- Shutdown and restart (clean resource release, routing rollback, process exit or re-exec)

Each of these is a distinct failure domain. A failure at any stage sets a `ppp::diagnostics::ErrorCode` and returns a non-zero process exit code.

---

## Process Owner

`PppApplication` is the process owner. It coordinates:

| Concern | Owned by |
|---------|---------|
| Configuration | `AppConfiguration` via `PppApplication::LoadConfiguration()` |
| Network environment | Platform-specific TAP/TUN and routing code |
| Runtime creation | `VEthernetNetworkSwitcher` (client) or `VirtualEthernetSwitcher` (server) |
| Statistics | `TransmissionStatistics` + `Stopwatch` |
| Timers | `NextTickAlwaysTimeout` tick loop |
| Lifecycle | `prevent_rerun_` lock, `ShutdownApplication()`, `Dispose()` |
| TUI | `ConsoleUI` (optional, suppressed when stdout is not a terminal) |

`PppApplication` is a singleton accessed via `PppApplication::GetInstance()`. The constructor runs before argument processing and sets up console attributes (cursor hide, window title, buffer size on Windows).

Source: `main.cpp`, `ppp/app/PppApplication.h`, `ppp/app/PppApplication.cpp`

---

## Startup Pipeline

```mermaid
flowchart TD
    A[OS exec ppp] --> B[main: PppApplication::GetInstance + Run]
    B --> C[PreparedArgumentEnvironment\nparse CLI: NIC, IP, GW, DNS, bypass, firewall]
    C --> D[LoadConfiguration\nread appsettings.json + normalize]
    D --> E[Main\nIsUserAnAdministrator]
    E -->|fail| ERR1[SetLastErrorCode AppPrivilegeRequired\nreturn -1]
    E -->|ok| F[prevent_rerun_.Exists]
    F -->|already running| ERR2[SetLastErrorCode AppAlreadyRunning\nreturn -1]
    F -->|ok| G[prevent_rerun_.Open]
    G -->|fail| ERR3[SetLastErrorCode AppLockAcquireFailed\nreturn -1]
    G -->|ok| H{Windows client?}
    H -->|yes| I[Windows_PreparedEthernetEnvironment\nComponent ID check]
    H -->|no| J
    I -->|fail| ERR4[SetLastErrorCode NetworkInterfaceConfigureFailed\nreturn -1]
    I -->|ok| J[PreparedLoopbackEnvironment\nTAP + switcher open]
    J -->|fail| ERR5[specific ErrorCode\nreturn -1]
    J -->|ok| K[ConsoleUI::ShouldEnable + Start]
    K --> L[NextTickAlwaysTimeout false\narm tick timer]
    L -->|fail| ERR6[SetLastErrorCode RuntimeTimerStartFailed\nDispose + return -1]
    L -->|ok| M[io_context::run\nsteady-state event loop]
    M --> N[Shutdown or Restart]
    N --> O[Dispose + Release]
    O --> P[process exits]
```

---

## Phase 1: Argument Preparation

`PreparedArgumentEnvironment()` parses command-line arguments before any configuration file is read. CLI arguments take precedence over JSON config for most fields. The following inputs are established:

| CLI Argument | Effect |
|-------------|--------|
| `--mode=client\|server` | Role selection |
| `--config=<path>` | Path to `appsettings.json` |
| `--nic=<name>` | Override NIC name |
| `--ip=<addr>` | Override virtual IP address |
| `--gw=<addr>` | Override virtual gateway |
| `--mask=<mask>` | Override subnet mask |
| `--dns=<addr>[,<addr>]` | Override DNS server list |
| `--bypass=<cidr>[,<cidr>]` | Add bypass routes |
| `--firewall=<path>` | Firewall rule file |
| `--virr` | Enable VIRR routing flag |
| `--vbgp` | Enable VBGP routing flag |
| `--auto-restart` | Auto-restart on network failure |
| `--link-restart` | Restart on link failure |

These are stored in the `GLOBAL_` struct and in `PppApplication` instance fields. They are applied during `PreparedLoopbackEnvironment()`.

---

## Phase 2: Configuration Loading

`LoadConfiguration()` reads `appsettings.json` from the path given by `--config`. The JSON is parsed into `AppConfiguration`. Immediately after parsing, `AppConfiguration::Loaded()` runs — this is the **policy compiler** step.

`Loaded()` performs:

- Clamps numeric fields to valid ranges (e.g., connection timeout cannot be zero)
- Validates string fields (cipher names, URL formats)
- Derives computed fields (e.g., maps boolean flags to subsystem enable/disable)
- Disables invalid subsystem combinations (e.g., IPv6 transit without a valid NIC)
- Sets defaults for omitted fields

After `Loaded()`, the `AppConfiguration` object is considered final. Code that reads configuration fields after this point can rely on the invariants that `Loaded()` enforces.

```mermaid
flowchart LR
    A[appsettings.json] --> B[JSON parse]
    B --> C[AppConfiguration struct]
    C --> D[AppConfiguration::Loaded\npolicy compiler]
    D --> E[Validated in-memory config]
    E --> F[Runtime uses config]
```

Source: `ppp/configurations/AppConfiguration.h`, `ppp/configurations/AppConfiguration.cpp`

---

## Phase 3: Privilege and Instance Checks

> **Status**: Design / planning document. The checklist below describes the intended
> implementation contract and acceptance criteria; it does **not** claim that every
> item is complete in the current codebase.  Source files referenced are the current
> implementation and serve as the authoritative contract for verification.

Phase 3 is the gate between "configuration is loaded" and "platform environment
preparation begins."  It consists of two logically independent checks that run
sequentially:

1. **Privilege check** — confirm the OS-level capabilities required for TUN/TAP
   manipulation, routing table mutation, and (on Windows) driver installation.
2. **Single-instance guard** — confirm that no other `ppp` process is already
   running with the same configuration file, then acquire a platform lock that
   prevents concurrent execution until `Dispose()`.

Both checks execute in `PppApplication::Main()` before any TAP, switcher, or
routing code runs.  Failure at either check sets a `ppp::diagnostics::ErrorCode`
and returns `-1` from `Main()`, which propagates as a non-zero exit code.

Source: `ppp/app/ApplicationInitialize.cpp` (lines 334–351),
        `ppp/stdafx.cpp` (`IsUserAnAdministrator`),
        `ppp/diagnostics/PreventReturn.h`, `ppp/diagnostics/PreventReturn.cpp`,
        `windows/ppp/win32/Win32Event.h`, `windows/ppp/win32/Win32Event.cpp`

---

### 3.1 Implementation Checklist

| # | Step | Source Location | Error Code on Failure |
|---|------|----------------|-----------------------|
| 3.1.1 | Reset diagnostics: `SetLastErrorCode(Success)` | `ApplicationInitialize.cpp:335` | — |
| 3.1.2 | Call `ppp::IsUserAnAdministrator()` | `ApplicationInitialize.cpp:337` | `AppPrivilegeRequired` |
| 3.1.3 | Build lock name: `"<role>://<config_path>"` where role is `client` or `server` | `ApplicationInitialize.cpp:342` | — |
| 3.1.4 | Call `prevent_rerun_.Exists(lock_name)` — non-destructive probe | `ApplicationInitialize.cpp:343` | `AppAlreadyRunning` |
| 3.1.5 | Call `prevent_rerun_.Open(lock_name)` — acquire persistent lock | `ApplicationInitialize.cpp:348` | `AppLockAcquireFailed` |
| 3.1.6 | Proceed to Phase 4 (platform/network environment) | `ApplicationInitialize.cpp:353+` | — |

Steps 3.1.2 through 3.1.5 are the **fail-fast gate**.  Any failure causes an
immediate `return -1`; no TAP device, switcher, or routing mutation occurs.

Lock release happens in `PppApplication::Release()` → `prevent_rerun_.Close()`
at the end of the shutdown path (see "Shutdown Path" section below).

---

### 3.2 Cross-Platform Privilege Check

`ppp::IsUserAnAdministrator()` is a single function with platform-specific
implementations.  It must be called **before** any privilege-requiring operation.

#### 3.2.1 Linux and macOS

```cpp
// ppp/stdafx.cpp:564-570
bool IsUserAnAdministrator() noexcept {
    return ::getuid() == 0;  // root UID is 0
}
```

| Aspect | Detail |
|--------|--------|
| Mechanism | `getuid() == 0` |
| Scope | Entire process (UID is process-wide) |
| Required for | `/dev/net/tun` ioctl (`TUNSETIFF`), routing table mutation (`ip route`), DNS override, firewall rules |
| False positive | None — `getuid() == 0` is the definitive root test |
| False negative | None for the "is root" question; does not check capabilities (`CAP_NET_ADMIN` etc.) |

**Design note**: A future enhancement could use `cap_get_proc()` / `CAP_NET_ADMIN`
on Linux to allow non-root operation with file capabilities.  This is out of scope
for the current design.

#### 3.2.2 Windows

```cpp
// windows/ppp/win32/Win32Native.cpp:337-365
bool Win32Native::IsUserAnAdministrator() noexcept {
    if (IsUserAnAdmin()) return true;          // Shell32 API, returns true if admin group
    // Fallback: check token elevation
    OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
    GetTokenInformation(hToken, TokenElevation, ...);
    return tokenElevation.TokenIsElevated;
}
```

| Aspect | Detail |
|--------|--------|
| Mechanism | Two-stage: `IsUserAnAdmin()` (Shell32) then `TokenElevation` (Advapi32) |
| Scope | Per-process token |
| Required for | Wintun adapter creation, routing table (`route` / `netsh`), DNS override, driver installation |
| Edge case | Running as a member of the Administrators group without elevation → `IsUserAnAdmin()` returns true, but `TokenElevation` is false.  The current implementation returns true in this case (first check passes).  This matches the behavior of `runas` scenarios. |

**Design note**: On Windows, the process may need UAC elevation even when the user
is an admin.  The caller should manifest the exe with `requireAdministrator` or
invoke via an elevated shell.  `IsUserAnAdministrator()` does **not** trigger UAC
itself.

#### 3.2.3 Android

| Aspect | Detail |
|--------|--------|
| Mechanism | Current non-Windows branch uses `getuid() == 0`; Android is not specially exempted in this helper |
| Rationale | Android VPN permission model (`VpnService.prepare()`) handles app-level VPN authorization, but the core helper still follows the generic POSIX root check unless Android startup bypasses this core path |
| Source | `ppp/stdafx.cpp` — the generic non-Windows branch covers Android unless a platform-specific override is added |

#### 3.2.4 Privilege Check — Failure Behavior

| Error Code | Severity | Meaning | Operator Action |
|-----------|----------|---------|-----------------|
| `AppPrivilegeRequired` | Error | Process not running as root/Administrator under the core startup path | Run with `sudo` (Linux/macOS), run as Administrator (Windows), or ensure Android JNI startup uses its intended VpnService-managed path |

The process prints `[error] AppPrivilegeRequired — Administrator or root privilege required for this operation` to stderr and exits with code `-1`.

---

### 3.3 Single-Instance Guard: Lock Name Construction

The lock name is constructed as:

```
<role>://<absolute_config_path>
```

where `role` is `client` or `server` (determined by `--mode`).  This means:

- Two `ppp client` instances with **different** config files can coexist.
- A `ppp client` and `ppp server` with the **same** config file can coexist.
- Two `ppp server` instances with the **same** config file are blocked.

The raw name is then transformed by `NameTransform()`:

1. Compute MD5 hash of the name string (using `ppp::cryptography::ComputeMD5`).
2. Prefix with `BOOST_BEAST_VERSION_STRING + "."` (e.g., `"Boost.Beast.347"`).
3. The result is a platform-safe string used as the kernel object name or file path component.

This transformation ensures the lock name is stable across runs and safe for
both Windows kernel object namespaces and POSIX filesystem paths.

Source: `ppp/diagnostics/PreventReturn.cpp` — `NameTransform()` (lines 32–49)

---

### 3.4 Single-Instance Guard: Platform Strategies

#### 3.4.1 POSIX (Linux, macOS, generic Unix including Android builds) — PID Lock File + Advisory Lock

| Aspect | Detail |
|--------|--------|
| Lock file location (Linux) | `/var/run/<transformed_name>.pid` |
| Lock file location (macOS) | `/tmp/<transformed_name>.pid` |
| Lock file location (Android/generic non-macOS Unix) | Current generic non-Windows path follows the Linux-style `/var/run/<transformed_name>.pid` unless a platform override is introduced |
| File creation | `open(path, O_CREAT \| O_RDWR, 0666)` |
| Lock acquisition | `flock(fd, LOCK_EX \| LOCK_NB)` — non-blocking exclusive |
| Lock detection | `flock()` returns `-1` with `errno == EWOULDBLOCK` or `EAGAIN` |
| Lock release | `flock(fd, LOCK_UN)` + `close(fd)` + `unlink(path)` |
| PID write | Current PID is written to the file (informational; not used for liveness) |
| Crash recovery | If the process crashes, the OS releases the `flock` automatically.  The `.pid` file remains on disk but the lock is no longer held.  Subsequent `Exists()` → `FLOCK_OPEN()` will succeed, and `Open()` will acquire the lock.  The stale file is overwritten. |

**POSIX flow — `Exists()` (non-destructive probe)**:

```
FLOCK_OPEN(name)
  → open(path, O_CREAT|O_RDWR)
  → flock(fd, LOCK_EX|LOCK_NB)
    → success: no other instance → FLOCK_CLOSE → return false
    → EWOULDBLOCK: another instance holds lock → return true
    → other error: inconclusive → return false
```

**POSIX flow — `Open()` (acquire persistent lock)**:

```
FLOCK_OPEN(name)
  → success: store fd and path in pid_file_ / pid_path_ → return true
  → EWOULDBLOCK: set AppAlreadyRunning → return false
  → other error: set AppLockAcquireFailed → return false
```

**POSIX flow — `Close()` (release)**:

```
FLOCK_CLOSE(path, fd)
  → flock(fd, LOCK_UN)
  → close(fd)
  → unlink(path)
  → reset pid_file_ = -1, pid_path_ = ""
```

**Edge case — `/var/run` permissions**: On some Linux distributions, `/var/run` is
world-writable (`tmpfs`).  On others, it requires root.  Since privilege check
(Step 3.1.2) has already passed, the process has root and can write to `/var/run`.

**Edge case — macOS `/tmp`**: macOS uses a per-user temp directory via `$TMPDIR`,
but `/tmp` is shared.  The lock file path uses `/tmp` directly (not `$TMPDIR`) to
ensure cross-session visibility.

Source: `ppp/diagnostics/PreventReturn.cpp` — `FLOCK_OPEN`, `FLOCK_CLOSE` (lines 122–277)

#### 3.4.2 Windows — Named Kernel Event

| Aspect | Detail |
|--------|--------|
| Mechanism | Named `Event` kernel object via `CreateEventA()` / `OpenEventA()` |
| Object name | The transformed name string (MD5-prefixed) |
| Scope | Named kernel object in the default Windows object namespace for the process/session; no `Global\` prefix is used, so cross-session visibility must not be assumed |
| Detection | `OpenEventA(EVENT_ALL_ACCESS, FALSE, name)` — if it succeeds, the event already exists |
| Creation | `CreateEventA(NULL, TRUE, FALSE, name)` — manual-reset event, initially non-signaled |
| Release | `CloseHandle()` on the event handle; the kernel object is destroyed when the last handle closes |
| Crash recovery | If the process crashes, Windows closes the handle automatically.  The kernel event object is destroyed.  Subsequent `Exists()` → `OpenEventA()` will fail (object gone), `CreateEventA()` will succeed. |

**Windows flow — `Exists()` (probe)**:

```
h = OpenEventA(EVENT_ALL_ACCESS, FALSE, name)
  → success: close handle → return true (another instance exists)
  → failure: return false (no event with that name)
```

**Windows flow — `Open()` (acquire)**:

```
h = OpenEventA(EVENT_ALL_ACCESS, FALSE, name)
  → success: event already exists; current Win32Event::Open() stores that handle and returns success
  → failure:
     h = CreateEventA(NULL, TRUE, FALSE, name)
       → success: store in hKrlEvt → return true
       → failure: set AppLockAcquireFailed → return false
```

**Design note — race between `Exists()` and `Open()`**: On Windows, there is a
TOCTOU window between `Exists()` returning false and `Open()` acquiring the event.
The current `Win32Event::Open()` first calls `OpenEventA()`; if that succeeds, it
stores the existing handle and reports success rather than treating the race as an
instance conflict. A future hardening step should consider using a named mutex or
`CreateEventA` with `GetLastError() == ERROR_ALREADY_EXISTS` handling if strict
single-instance acquisition is required.

**Alternative considered — Named Mutex**: A named mutex (`CreateMutexA`) would also
work and has the advantage that `WAIT_OBJECT_0` vs `WAIT_ABANDONED` can detect
crashed owners.  However, the current implementation uses events, which are simpler
and sufficient for the "exists or not" check pattern.

Source: `windows/ppp/win32/Win32Event.cpp` (lines 27–176)

#### 3.4.3 Android

Android uses the POSIX path (PID lock file + `flock`).  The lock file is created
through the generic non-macOS Unix branch, which currently means `/var/run/` unless
Android startup bypasses this core guard or a platform-specific path is added. This
may not be writable for an ordinary Android app process; therefore Android behavior
must be validated against the JNI/VpnService startup path rather than inferred from
Linux server assumptions. Android's VPN permission model can still be treated as the
primary app-level authorization mechanism, while this guard is only a secondary
safety net when the core path is used.

---

### 3.5 Failure Strategy

All Phase 3 failures follow the same pattern:

1. Set `ppp::diagnostics::ErrorCode` via `SetLastErrorCode()`.
2. `Main()` returns `-1`.
3. `Run()` propagates the return value to `main()`.
4. `main()` returns the non-zero exit code.
5. The diagnostics code is available via `GetLastErrorCode()` for programmatic
   consumers (e.g., the Go management backend, Android JNI).

| Failure | Error Code | Severity | Behavior | Operator Recovery |
|---------|-----------|----------|----------|-------------------|
| Not root/admin | `AppPrivilegeRequired` | Error | Immediate exit | Run with elevated privileges |
| Another instance running | `AppAlreadyRunning` | Warning | Immediate exit | Stop the other instance or use a different config path |
| Lock acquisition OS error | `AppLockAcquireFailed` | Error | Immediate exit | Check filesystem permissions, disk space, `/var/run` existence |
| Lock name transform failure | `PreventReturnNameTransformEmptyInput` | Error | Immediate exit | Ensure `--config` path is non-empty |
| Lock release failure | `AppLockReleaseFailed` | Warning | Logged, does not block exit | Manual cleanup of stale `.pid` file (Linux/macOS) |

**Design invariant**: No partial initialization is left behind on Phase 3 failure.
The process has not opened any TAP device, socket, or routing table entry, so no
rollback is needed.  The only resource that might leak is the lock itself, but
the lock is only acquired in Step 3.1.5, and if that step fails, the lock was
never held.

---

### 3.6 Detailed Sequence Diagram

```mermaid
sequenceDiagram
    participant main as PppApplication::Main()
    participant priv as IsUserAnAdministrator()
    participant pr as PreventReturn
    participant lock as Platform Lock (flock/Event)
    participant diag as diagnostics

    main->>diag: SetLastErrorCode(Success)
    main->>priv: IsUserAnAdministrator()
    alt Linux/macOS/generic non-Windows including Android core path
        priv->>priv: getuid() == 0
    else Windows
        priv->>priv: IsUserAnAdmin() || TokenElevation
    end
    priv-->>main: result
    alt result == false
        main->>diag: SetLastErrorCode(AppPrivilegeRequired)
        main-->>main: return -1
    end

    main->>main: Build lock name: "<role>://<config_path>"
    main->>pr: prevent_rerun_.Exists(lock_name)
    pr->>pr: NameTransform(lock_name) → MD5 hash
    pr->>lock: Platform probe (flock/OPEN_EX)
    lock-->>pr: held / not held / error
    pr-->>main: true (already running) / false
    alt already running
        main->>diag: SetLastErrorCode(AppAlreadyRunning)
        main-->>main: return -1
    end

    main->>pr: prevent_rerun_.Open(lock_name)
    pr->>pr: NameTransform(lock_name) → MD5 hash
    pr->>lock: Platform acquire (flock/CreateEventA)
    lock-->>pr: acquired / blocked / error
    pr-->>main: true (lock held) / false
    alt lock failed
        main->>diag: SetLastErrorCode(AppLockAcquireFailed)
        main-->>main: return -1
    end

    Note over main: Lock held until Dispose() → Release() → Close()
    main->>main: Proceed to Phase 4
```

---

### 3.7 Lifecycle Integration

| Lifecycle Event | Effect on Phase 3 |
|----------------|-------------------|
| Normal shutdown | `Release()` → `prevent_rerun_.Close()` releases the lock |
| Restart (`ShutdownApplication(true)`) | `Release()` releases the lock; `re-exec` re-acquires it in the new process |
| Crash (SIGSEGV, unhandled exception) | OS releases `flock` / closes Event handle automatically; lock file may remain on disk but is not held |
| `Dispose()` failure | `Release()` is called regardless; lock is always released even if other cleanup fails |

The lock lifetime is:

```
prevent_rerun_.Open()  →  ... [entire runtime lifetime] ...  →  prevent_rerun_.Close()
     (Step 3.1.5)                                                     (Release())
```

---

### 3.8 Acceptance Criteria

These criteria define what "Phase 3 is correct" means for review and testing:

| # | Criterion | Verification Method |
|---|-----------|-------------------|
| AC-1 | Non-root process on Linux/macOS is rejected with `AppPrivilegeRequired` | Run `./ppp --mode=client --config=./appsettings.json` as non-root; verify exit code `-1` and stderr message |
| AC-2 | Windows process that is neither elevated nor accepted by the current `IsUserAnAdmin()` fallback is rejected with `AppPrivilegeRequired` | Run `ppp.exe --mode=client --config=appsettings.json` from a standard non-Administrators account; verify exit code `-1`. UAC unelevated Administrator accounts require separate validation because the current helper first consults `IsUserAnAdmin()` |
| AC-3 | Two server instances with same config: second is rejected with `AppAlreadyRunning` | Start `ppp --mode=server`, then start another with same `--config`; verify second exits with `-1` |
| AC-4 | Two client instances with same config: second is rejected with `AppAlreadyRunning` | Same as AC-3 but with `--mode=client` |
| AC-5 | Client and server with same config can coexist | Start `ppp --mode=client --config=X`, then `ppp --mode=server --config=X`; both should start (lock names differ) |
| AC-6 | Two instances with different configs can coexist | Start two `ppp --mode=client` with different `--config` paths; both should start |
| AC-7 | Crash recovery: after abnormal exit, new instance can start | Start `ppp`, kill with `SIGKILL`, start again; second instance should succeed |
| AC-8 | Normal shutdown releases the lock | Start `ppp`, send `SIGINT`, start again; second instance should succeed |
| AC-9 | Restart re-acquires the lock | Start `ppp --auto-restart`, trigger restart; new process should acquire the lock |
| AC-10 | Lock file is cleaned up after shutdown on Linux/macOS | After shutdown, verify `/var/run/<hash>.pid` (Linux) or `/tmp/<hash>.pid` (macOS) does not exist |
| AC-11 | `AppLockAcquireFailed` is set when OS lock call fails with unexpected error | (Requires fault injection or unusual `/var/run` permissions) |
| AC-12 | Error codes are propagated to `GetLastErrorCode()` | After each failure scenario, verify `GetLastErrorCode()` returns the expected code |

---

## Phase 4: Platform and Network Environment Preparation

### Windows Client Only: `Windows_PreparedEthernetEnvironment()`

On Windows, the client TAP path requires a Component Object Model (COM) identifier to select the Wintun or TAP-Windows adapter. `Windows_PreparedEthernetEnvironment()` checks that the adapter component ID is available and, if not, creates or assigns one. Failure sets `NetworkInterfaceConfigureFailed`.

This step does not exist on other platforms.

### All Platforms: `PreparedLoopbackEnvironment()`

This is the largest initialization step. It creates the platform-specific TAP device and the entire VPN runtime.

#### Client Path (detailed)

```mermaid
sequenceDiagram
    participant app as PppApplication
    participant tap as ITap::Create
    participant eth as VEthernetNetworkSwitcher
    participant diag as diagnostics

    app->>tap: Create(context, componentId, ip, gw, mask, ...)
    alt tap == nullptr
        app->>diag: TunnelOpenFailed
        app-->>app: break cleanup
    end
    app->>tap: tap->Open()
    alt fail
        app->>diag: TunnelListenFailed
        app-->>app: break cleanup
    end
    app->>eth: new VEthernetNetworkSwitcher(context, lwip, vnet, concurrent, config)
    app->>eth: SetIPv6(), SetSsmt(), SetProtectMode()
    app->>eth: SetRoutes(), SetDNS(), SetBypassRules()
    app->>eth: ethernet->Open(tap)
    alt UnderlyingNIC != null
        app->>diag: TunnelOpenFailed
    else
        app->>diag: NetworkInterfaceUnavailable
    end
    app->>app: client_ = ethernet
```

Platform-specific `ITap::Create()` signatures:

| Platform | Extra parameters |
|---------|-----------------|
| Windows | `leaseTimeInSeconds` (Wintun adapter lease duration) |
| Linux / macOS | `promisc` (promiscuous mode flag for bridge deployments) |
| Android | Takes existing `fd` from `VpnService` rather than opening `/dev/net/tun` |

Linux-only client options applied to `VEthernetNetworkSwitcher`:

| Method | Effect |
|--------|--------|
| `Ssmt(true)` | Enable multi-queue TUN (one fd per io_context thread via `IFF_MULTI_QUEUE`) |
| `SsmtMQ(true)` | Enable message-queue variant for SSMT |
| `ProtectMode(path)` | Enable socket bypass via Unix domain socket |

#### Server Path (detailed)

The server path does not create a TAP adapter. It creates an IPv6 environment (if configured) and opens listener sockets.

```mermaid
sequenceDiagram
    participant app as PppApplication
    participant ipv6 as ipv6::auxiliary
    participant sw as VirtualEthernetSwitcher
    participant diag as diagnostics

    app->>ipv6: PrepareServerEnvironment(config, nic, componentId)
    alt fail
        app->>diag: IPv6ServerPrepareFailed
        app-->>app: break cleanup
    end
    app->>sw: new VirtualEthernetSwitcher(config, componentId)
    app->>sw: ethernet->PreferredNic(nic)
    app->>sw: ethernet->Open(firewallRules)
    alt fail
        app->>diag: TunnelOpenFailed
        app-->>app: break cleanup
    end
    app->>sw: ethernet->Run()
    alt fail
        app->>diag: TunnelListenFailed
        app-->>app: break cleanup
    end
    app->>app: server_ = ethernet
```

On any failure, `ppp::ipv6::auxiliary::FinalizeServerEnvironment()` is called to roll back IPv6 host-side mutations (neighbor proxy entries, address assignments) before the process exits.

---

## Phase 5: TUI and Statistics Initialization

After `PreparedLoopbackEnvironment()` succeeds:

1. **TUI detection**: `ConsoleUI::ShouldEnable()` calls `isatty(STDOUT_FILENO)`. If stdout is a pipe or redirected, the full-screen TUI is suppressed and a plain-text startup banner is printed instead.
2. **TUI start**: `ConsoleUI::Start()` attempts to spawn two dedicated threads (render + input) outside the Boost.Asio event loop. If optional UI startup fails after tty detection, the process falls back to plain-text mode and publishes `RuntimeOptionalUiStartFailed`.
3. **Statistics reset**: `stopwatch_.Restart()` and `transmission_statistics_.Clear()` mark the start of the measurement window. Statistics are accumulated from this point for display in the TUI status panels.
4. **Windows QUIC toggle** (client only): `HttpProxy::SetSupportExperimentalQuicProtocol()` enables or disables QUIC based on configuration.
5. **VIRR / VBGP flags**: Written into process-global atomics used by the routing subsystem.
6. **Auto-restart / link-restart flags**: Parsed from CLI args and stored in `GLOBAL_` for the tick loop.

---

## Phase 6: Tick Loop

`NextTickAlwaysTimeout(false)` arms the first tick timer. After this call, the process enters `io_context::run()`, which blocks the main thread until the event loop is stopped.

The tick handler `OnTick()` fires at a configured interval (typically 1–5 seconds) and performs:

| Task | Description |
|------|-------------|
| Statistics update | Refresh `TransmissionStatistics` for TUI display |
| TUI refresh trigger | Signal render thread to redraw status panels |
| Keepalive check | Check if the session is still alive (client path) |
| Auto-restart check | Evaluate link health; trigger restart if configured |
| Backend reconnect | Retry management backend connection if lost |
| Timer wheel advance | Advance any deadline timers waiting on the tick |

```mermaid
graph TD
    A[io_context::run starts] --> B[OnTick fires]
    B --> C[UpdateStatistics]
    C --> D[TriggerTUIRedraw]
    D --> E[CheckKeepalive]
    E --> F[CheckAutoRestart]
    F --> G[CheckBackend]
    G --> H[AdvanceTimers]
    H --> I{Shutdown requested?}
    I -->|no| B
    I -->|yes| J[Stop event loop]
    J --> K[Dispose + Release]
```

---

## Complete Application Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> Constructed : PppApplication()
    Constructed --> ArgumentsPrepared : PreparedArgumentEnvironment()
    ArgumentsPrepared --> ConfigLoaded : LoadConfiguration()
    ConfigLoaded --> PrivilegeChecked : IsUserAnAdministrator()
    PrivilegeChecked --> [*] : FAIL AppPrivilegeRequired
    PrivilegeChecked --> InstanceGuarded : prevent_rerun_.Open()
    InstanceGuarded --> [*] : FAIL AppAlreadyRunning / AppLockAcquireFailed
    InstanceGuarded --> WindowsPrep : Windows_PreparedEthernetEnvironment (Win client only)
    WindowsPrep --> [*] : FAIL NetworkInterfaceConfigureFailed
    WindowsPrep --> LoopbackReady : PreparedLoopbackEnvironment()
    InstanceGuarded --> LoopbackReady : PreparedLoopbackEnvironment() (non-Win paths)
    LoopbackReady --> [*] : FAIL TunnelOpenFailed / TunnelListenFailed / NetworkInterfaceUnavailable
    LoopbackReady --> TUIStarted : ConsoleUI::Start() or plain-text fallback
    TUIStarted --> TickRunning : NextTickAlwaysTimeout(false)
    TickRunning --> [*] : FAIL RuntimeTimerStartFailed
    TickRunning --> Running : io_context::run() active
    Running --> Running : periodic OnTick()
    Running --> ShuttingDown : ShutdownApplication(restart=false)
    Running --> Restarting : ShutdownApplication(restart=true)
    ShuttingDown --> Disposed : Dispose() + Release()
    Restarting --> Disposed : Dispose() + Release() + re-exec
    Disposed --> [*]
```

---

## Detailed Client Startup Sequence

```mermaid
sequenceDiagram
    participant CLI as Command Line
    participant main as main()
    participant app as PppApplication
    participant cfg as AppConfiguration
    participant tap as ITap (Linux/Windows)
    participant eth as VEthernetNetworkSwitcher
    participant tui as ConsoleUI
    participant tick as Timer

    CLI->>main: exec ppp --mode=client --config=appsettings.json
    main->>app: GetInstance() + Run(argc, argv)
    app->>app: HideConsoleCursor(true)
    app->>app: PreparedArgumentEnvironment() — parse NIC, IP, GW, DNS, bypass lists
    app->>cfg: LoadConfiguration() — read and normalize appsettings.json
    app->>app: Main()
    app->>app: IsUserAnAdministrator() → abort if false
    app->>app: prevent_rerun_.Open("client://<config_path>")
    note over app: Windows only
    app->>app: Windows_PreparedEthernetEnvironment() — ensure Component ID
    app->>app: PreparedLoopbackEnvironment()
    app->>tap: ITap::Create(context, componentId, ip, gw, mask, ...)
    tap->>tap: OpenDriver() — open /dev/net/tun or Wintun ring buffer
    tap->>tap: ioctl(TUNSETIFF) / WintunOpenAdapter()
    tap->>tap: SetIPAddress(), SetMtu(), SetNetifUp(true)
    app->>tap: tap->Open() — start AsynchronousReadPacketLoops()
    app->>eth: new VEthernetNetworkSwitcher(context, lwip, vnet, ...)
    app->>eth: Configure IPv6, Ssmt, routes, DNS rules, bypass lists
    app->>eth: ethernet->Open(tap) — bind TAP to lwIP virtual ethernet
    app->>tui: ConsoleUI::ShouldEnable() + Start()
    app->>tick: NextTickAlwaysTimeout(false) — arm maintenance timer
    tick-->>app: OnTick() every interval
    note over app,tick: Runtime steady state — VPN active
```

---

## Detailed Server Startup Sequence

```mermaid
sequenceDiagram
    participant CLI as Command Line
    participant main as main()
    participant app as PppApplication
    participant cfg as AppConfiguration
    participant ipv6 as ipv6::auxiliary
    participant sw as VirtualEthernetSwitcher
    participant tui as ConsoleUI
    participant tick as Timer

    CLI->>main: exec ppp --mode=server --config=appsettings.json
    main->>app: GetInstance() + Run(argc, argv)
    app->>app: PreparedArgumentEnvironment() — parse NIC, firewall rules, etc.
    app->>cfg: LoadConfiguration() — read and normalize appsettings.json
    app->>app: Main()
    app->>app: IsUserAnAdministrator() → abort if false
    app->>app: prevent_rerun_.Open("server://<config_path>")
    app->>app: PreparedLoopbackEnvironment()
    app->>ipv6: PrepareServerEnvironment(config, nic, componentId)
    note over ipv6: Mutates host IPv6 state (neighbor proxy, addresses)
    app->>sw: new VirtualEthernetSwitcher(config, componentId)
    app->>sw: ethernet->PreferredNic(nic)
    app->>sw: ethernet->Open(firewallRules) — bind listener sockets
    app->>sw: ethernet->Run() — start accept loop
    app->>tui: ConsoleUI::ShouldEnable() + Start()
    app->>tick: NextTickAlwaysTimeout(false) — arm maintenance timer
    tick-->>app: OnTick() every interval
    note over app,tick: Runtime steady state — server accepting connections
```

---

## Initialization Error Code Reference

Every failure during startup sets a `ppp::diagnostics::ErrorCode` before returning:

| Stage | Error Code | Meaning |
|-------|-----------|---------|
| Privilege check | `AppPrivilegeRequired` | Process not running as root/admin |
| Instance check | `AppAlreadyRunning` | Another instance already holds the config lock |
| Instance lock | `AppLockAcquireFailed` | Failed to acquire the process lock file |
| Windows adapter | `NetworkInterfaceConfigureFailed` | Cannot find or create Wintun/TAP component |
| TAP creation | `TunnelOpenFailed` | `ITap::Create()` returned null |
| TAP open | `TunnelListenFailed` | `ITap::Open()` failed to start read loops |
| NIC unavailable | `NetworkInterfaceUnavailable` | The named NIC does not exist |
| IPv6 prep | `IPv6ServerPrepareFailed` | Server IPv6 environment preparation failed |
| Switcher open | `TunnelOpenFailed` | `VirtualEthernetSwitcher::Open()` failed |
| Switcher run | `TunnelListenFailed` | `VirtualEthernetSwitcher::Run()` failed |
| Tick timer | `RuntimeTimerStartFailed` | Cannot arm the maintenance timer |

---

## Ownership Model

```mermaid
graph TD
    OS[OS Process] --> APP[PppApplication\nProcess owner]
    APP --> ENV[VEthernetNetworkSwitcher / VirtualEthernetSwitcher\nEnvironment owner]
    ENV --> SES[VEthernetExchanger / VirtualEthernetExchanger\nSession owner]
    SES --> CON[ITransmission\nConnection owner]
    SES --> UDP[VirtualEthernetDatagramPort\nUDP flow owner]
    SES --> TCP[TcpConnection\nTCP flow owner]
```

| Level | Owner | Lifecycle |
|-------|-------|-----------|
| Process | `PppApplication` | From `main()` to `exit()` |
| Environment | Switchers | From `PreparedLoopbackEnvironment()` to `Dispose()` |
| Session | Exchangers | From connection acceptance to session close |
| Transport connection | `ITransmission` | From carrier connect to carrier close |
| UDP flow | `VirtualEthernetDatagramPort` | From first datagram to timeout or session close |
| TCP flow | `TcpConnection` | From `SYN` to `FIN` |

---

## Shutdown Path

When `ShutdownApplication(restart)` is called (from signal handler, tick loop, or TUI input):

1. The tick timer is cancelled.
2. `ConsoleUI::Stop()` is called — render and input threads are joined.
3. `Dispose()` is called on the client or server runtime, which triggers a cascade:
   - All active sessions call their own `Dispose()` (atomic CAS pattern)
   - All open sockets are cancelled via `async_cancel`
   - All coroutines resume from suspension with error and exit their loops
   - TAP device is closed (client) or listeners are closed (server)
   - IPv6 host state is rolled back (server, if IPv6 was prepared)
   - Routing changes are reverted (client)
   - DNS changes are reverted (client)
4. `prevent_rerun_.Release()` frees the config lock.
5. If `restart == true`, the process re-execs itself with the same arguments.
6. Otherwise, the event loop stops and `main()` returns the exit code.

```mermaid
flowchart TD
    A[ShutdownApplication called] --> B[Cancel tick timer]
    B --> C[ConsoleUI::Stop]
    C --> D[Runtime Dispose]
    D --> E[All sessions Dispose]
    E --> F[Sockets cancelled]
    F --> G[Coroutines exit]
    G --> H[TAP / listeners closed]
    H --> I[IPv6 rollback if server]
    I --> J[Route rollback if client]
    J --> K[DNS rollback if client]
    K --> L[prevent_rerun_.Release]
    L --> M{restart?}
    M -->|yes| N[re-exec with same args]
    M -->|no| O[io_context::stop]
    O --> P[main returns exit code]
```

---

## Android Lifecycle Sync Notes

Android bridge lifecycle (`run`, `stop`, and release paths in `/mnt/e/Desktop/openppp2-next/openppp2/android/libopenppp2.cpp`) must maintain parity with core lifecycle semantics:

- JNI `run()` follows the Android-specific bridge path in `/mnt/e/Desktop/openppp2-next/openppp2/android/libopenppp2.cpp`: `Java_supersocksr_ppp_android_c_libopenppp2_run()` → `libopenppp2_try_open_ethernet_switcher()` → `libopenppp2_from_tuntap_driver_new()` → `libopenppp_try_open_ethernet_switcher_new()`. It does **not** call the desktop `PppApplication::Main()` / `PreparedLoopbackEnvironment()` startup pipeline.
- Since Android provides an existing VPN file descriptor from `VpnService`, the bridge wraps that fd via the Android TUN/TAP helper path instead of opening `/dev/net/tun` through the desktop startup path.
- JNI `stop()` follows the Android bridge release path in `/mnt/e/Desktop/openppp2-next/openppp2/android/libopenppp2.cpp`: `Java_supersocksr_ppp_android_c_libopenppp2_stop()` → `libopenppp2_application::Invoke(...)` → `app->Release()`. This is semantically the Android stop/release operation, but it is not a direct call to `PppApplication::ShutdownApplication(false)`.
- The JNI bridge (`__LIBOPENPPP2__` macro) exports these functions for consumption by the Android Java/Kotlin layer.
- App-uninitialized and not-running states must map consistently across JNI and core diagnostics so managed callers can react predictably.
- Release/cleanup failures must be reported with stable error codes — the JNI layer propagates them back as integer return values.

Android-specific differences:

| Concern | How Android differs |
|---------|-------------------|
| TAP creation | `TapLinux::From(fd)` wraps existing VpnService fd |
| jemalloc | Android system already uses jemalloc; no additional layer added |
| Socket protection | All control sockets must be protected via `VpnService.protect()` |
| Privilege check | JNI/VpnService startup may bypass the core root/admin check; if the generic core path is used, the non-Windows helper still applies `getuid() == 0` |

---

## Error Handling Registration in Startup Window

`RegisterErrorHandler` is key-based and should be finalized during startup initialization:

- Use a stable key per registration site (e.g., `"ppp.application"`, `"ppp.client.tap"`).
- Passing a null handler removes the registration for that key.
- Complete all registration changes before multi-thread runtime branches begin.

Registration-time mutation is treated as initialization work. Runtime diagnostics dispatch is thread-safe for readers, but registration churn during active worker execution is outside the supported contract.

---

## Diagnostics Propagation Across Lifecycle

For each lifecycle stage (load, normalize, prepare, open, tick maintenance, dispose/rollback):

- Failure returns carry diagnostics codes, not only sentinel values.
- Process-wide snapshot APIs are used by the Console UI status surfaces.
- Lifecycle troubleshooting starts from the diagnostics timeline, then maps to subsystem logs.

This policy keeps startup and shutdown troubleshooting deterministic even when failure originates on worker threads.

---

## API Reference

### `PppApplication::Run`

```cpp
/**
 * @brief Entry point: prepares arguments, loads config, and runs the application.
 * @param argc  Argument count from OS.
 * @param argv  Argument vector from OS.
 * @return      0 on clean exit; non-zero error code on failure.
 * @note        Blocks until the event loop stops. Called from main().
 */
int Run(int argc, const char* argv[]) noexcept;
```

### `PppApplication::ShutdownApplication`

```cpp
/**
 * @brief Request process shutdown or restart.
 * @param restart  true to re-exec the process with the same arguments after cleanup.
 * @note           Safe to call from any thread. Posts shutdown work to the main context.
 */
void ShutdownApplication(bool restart) noexcept;
```

### `PppApplication::GetLastErrorCode`

```cpp
/**
 * @brief Retrieve the most recent process-level diagnostics code.
 * @return  The current ErrorCode value. ErrorCode::None if no error has been set.
 */
ppp::diagnostics::ErrorCode GetLastErrorCode() const noexcept;
```

---

## Common Startup Failure Patterns

### Pattern: Process exits immediately with code -1

Cause: Privilege check failed. Run as root on Linux/macOS or as Administrator on Windows.

```bash
sudo ./ppp --mode=server --config=./appsettings.json
```

### Pattern: Process exits with `AppAlreadyRunning`

Cause: Another instance is running with the same config file. Check:

```bash
pgrep -a ppp
```

If no process is found but the lock persists (e.g., after a crash), remove the lock file (platform-dependent location, typically `/tmp/ppp.<hash>` on Linux).

### Pattern: `TunnelOpenFailed` on client startup

Causes (in order of likelihood):
1. TAP/TUN driver not installed (Linux: check `modprobe tun`; Windows: Wintun not present)
2. Wrong Component ID in config (Windows)
3. Another process has the TAP adapter open
4. Insufficient permissions for TAP ioctl (confirm privilege check passed)

### Pattern: `TunnelListenFailed` on server startup

Causes:
1. Port already in use — check `ss -tlnp` (Linux) or `netstat -ano` (Windows)
2. Firewall blocking bind
3. `VirtualEthernetSwitcher::Run()` returned false (check DNS cache, listener socket creation)

---

## Usage Examples

### Starting the server in debug mode

```bash
sudo ./ppp --mode=server --config=./appsettings.json
```

### Starting the client and overriding DNS

```bash
sudo ./ppp --mode=client --config=./appsettings.json --dns=8.8.8.8,1.1.1.1
```

### Starting with auto-restart on link failure

```bash
sudo ./ppp --mode=client --config=./appsettings.json --auto-restart --link-restart
```

### Android NDK: starting via JNI

```java
// From Java/Kotlin Activity or Service
int fd = vpnInterface.getFd();
int result = LibOpenPPP2.run(configJson, fd, protectSocketCallback);
if (result != 0) {
    Log.e("PPP", "Startup failed: " + result);
}
```

---

## Related Documents

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — System-level architecture overview
- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md) — Client subsystem detail
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md) — Server subsystem detail
- [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md) — Where to start reading the code
- [`ERROR_HANDLING_API.md`](ERROR_HANDLING_API.md) — Error code API reference
- [`CONFIGURATION.md`](CONFIGURATION.md) — AppConfiguration fields and Loaded() behavior
- [`CONCURRENCY_MODEL.md`](CONCURRENCY_MODEL.md) — Thread pool, io_context, and coroutine model
- [`PLATFORMS.md`](PLATFORMS.md) — Platform-specific startup differences
