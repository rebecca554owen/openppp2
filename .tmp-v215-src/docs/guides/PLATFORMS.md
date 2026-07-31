# Platform Integration

> **Status:** Current implementation boundary
> **Type:** Guide
> **Last verified:** Root/platform CMake and platform networking sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [平台集成](PLATFORMS_CN.md)

## What is shared and what is platform-specific

The shared runtime lives primarily under `ppp/`. It owns configuration, session/transport behavior, tunnel policy, and platform-neutral abstractions such as `ITap`. Platform trees provide the host-network work that cannot be portable by itself: virtual interfaces, routes, DNS integration, and platform-specific socket/tunnel behavior.

The root CMake build creates the `ppp` executable and selects source sets for Windows, Darwin, or Linux according to the target system. Android and iOS have bundled platform projects with their own CMake/application integration; they are not interchangeable desktop builds.

| Surface | Current implementation boundary |
|---|---|
| Windows | Sources under `windows/`; virtual-adapter and host-network integration are Windows-specific. |
| Linux | Sources under `linux/`; client TUN/route integration and the supported server IPv6 data plane live here. |
| macOS | Sources under `darwin/`; utun and BSD-style host integration are platform-specific. |
| Android | The bundled app obtains a VPN interface through `VpnService` and passes its descriptor into native code. |
| iOS | The bundled app uses its packet-tunnel integration; do not infer Linux/Android server capabilities from it. |

## Operational implications

- A normal client may create or use a virtual interface and alter routes/DNS through its platform implementation. Required privileges and host behavior differ by OS.
- Desktop CLI proxy mode is intentionally different: it uses `TapStub` and skips the ordinary client TUN route/DNS-rule/bypass setup. See [Proxy-only mode](PROXY_MODE.md).
- Linux server IPv6 data-plane support is source-gated to Linux excluding Android. It is not a portable server feature for Windows, macOS, Android, or iOS.
- Android proxy-only behavior still uses a VPN interface and has Android-specific route/DNS handling.

## Build and source-reading boundary

The repository gives CMake source selection and platform projects, not one universal installer/service procedure. Use the current build/development documentation for toolchain setup, then validate the exact target platform instead of copying machine-specific paths or commands from old notes.

Useful source anchors:

- `CMakeLists.txt` — `ppp` target and platform-source selection;
- `ppp/tap/ITap.h` — shared tunnel-interface abstraction;
- `windows/`, `linux/`, and `darwin/` — platform implementations;
- `android/` and `ios/` — bundled application/platform integrations.

## Before deploying to a host

1. Verify the exact target build and required virtual-interface permissions.
2. Decide whether the role is a normal client, a server, or desktop proxy mode.
3. Test route/DNS effects on an isolated host or maintenance window.
4. Keep host firewall, DNS service, and service-manager policy under operator control; they are not universal configuration surfaces of `ppp`.
5. For server IPv6, use the Linux-only constraints in [IPv6 transit plane](IPV6_TRANSIT_PLANE.md).

## Related pages

- [Deployment model](../operations/DEPLOYMENT.md)
- [Routing and DNS](ROUTING_AND_DNS.md)
- [IPv6 transit plane](IPV6_TRANSIT_PLANE.md)