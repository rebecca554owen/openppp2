# Platform Integration

[中文版本](PLATFORMS_CN.md)

## Scope

This document explains how OPENPPP2 binds one shared runtime core to different host networking models.

## Main Idea

The shared core covers configuration, transport, handshake, link-layer actions, routing policy, and session management. The platform layer covers adapter creation, route mutation, DNS mutation, socket protection, and IPv6 host plumbing.

## Build-Time Split

The root build selects platform source trees:

- Windows: `windows/*`
- Linux: `linux/*`
- macOS: `darwin/*`
- Android: `android/*` via its own `CMakeLists.txt`

## Windows

Windows uses multiple host integration paths:

- Wintun when available
- TAP-Windows fallback
- WMI-based adapter configuration
- IP Helper route APIs
- DNS cache flush support
- optional proxy and QUIC-related behavior

## Linux

Linux uses native tun/tap and host networking behavior, plus Linux-specific IPv6 and protection helpers.

## macOS

macOS uses utun/TAP-style integration and platform-specific route and IPv6 helpers.

## Android

Android is built as a shared library and relies on the host app plus JNI glue for VPN-style integration.

## Why This Is Explicit

The platform code is explicit because virtual interface setup, route behavior, DNS behavior, and IPv6 behavior are not identical across operating systems.

## Related Documents

- `ARCHITECTURE.md`
- `DEPLOYMENT.md`
- `OPERATIONS.md`
