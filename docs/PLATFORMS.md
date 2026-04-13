# Platform Integration

[中文版本](PLATFORMS_CN.md)

## Purpose

OPENPPP2 has one shared protocol core and several OS-specific networking integrations.

This split is necessary because virtual adapters, route APIs, DNS control, and socket protection are different on each host platform.

## Windows

Windows integration includes:

- Wintun support
- TAP-Windows fallback support
- route management through Win32/IP Helper APIs
- DNS configuration changes on interfaces
- DNS cache flush
- optional local-system proxy integration
- Windows-specific PaperAirplane support

### Design reason

Windows requires explicit integration with the host networking stack and adapter drivers. A pure cross-platform abstraction would hide too much of the actual behavior.

## Linux

Linux integration includes:

- TUN open through `/dev/tun` or `/dev/net/tun`
- multiqueue support where available
- route add/delete behavior
- protect mode to keep sockets on the underlying network
- IPv6 transit and neighbor-proxy support on the server side

### Design reason

Linux is the most complete infrastructure host in this codebase. It is where the project can expose the richest low-level networking behavior.

## macOS

macOS integration uses:

- `utun`
- route and interface configuration via platform tools and control sockets
- utun-specific packet handling

### Design reason

macOS networking behavior is not equivalent to Linux TUN. The project therefore keeps a separate Darwin path instead of pretending the two are interchangeable.

## Android

Android integration is different from desktop CLI builds.

It uses:

- shared-library output
- external TUN file descriptor supplied by Android VPN integration
- JNI-based socket protection

### Design reason

Android VPN integration is application-hosted. The C++ runtime therefore becomes an engine used by Android code rather than a standalone CLI process.

## Build System Split

The repository supports:

- root CMake for the main C++ runtime
- Visual Studio / Ninja / vcpkg workflow on Windows
- GCC/Clang workflow on Linux and Unix-like systems
- Android-specific CMake build
- Linux multi-architecture cross-build scripts

This reflects a serious infrastructure intent: the project is expected to be built for multiple deployment targets, not only one desktop environment.

## Why Platform Code Is Not Hidden

The platform-specific code is visible and relatively direct because network infrastructure depends on real host behavior.

If the project tried to bury all platform differences under one tiny abstraction, the operational meaning of route changes, adapter behavior, and DNS handling would become much harder to understand.

## What To Verify After Platform Changes

- adapter creation/open still succeeds
- routes are installed and removed correctly
- DNS changes are applied and rolled back correctly
- protected sockets still stay on the intended underlying network
- IPv6 behavior still matches platform expectations

## Related Documents

- [`OPERATIONS.md`](OPERATIONS.md)
- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
