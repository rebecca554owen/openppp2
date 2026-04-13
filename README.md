# OPENPPP2

English | [简体中文](README_CN.md)

OPENPPP2 is a C++17 virtual Ethernet VPN/SD-WAN system. It builds a Layer 2 / Layer 3 overlay around a unified packet, session, and transport model, with platform specializations for Windows, Linux, macOS, and Android.

The project is organized around one executable, `ppp`, with two operating modes:

- Server mode: accepts tunnel sessions, allocates virtual network state, enforces policy, and optionally connects to a management backend.
- Client mode: creates a virtual adapter, selects routes and DNS handling, connects to a remote server, and can expose local proxy and mapping functions.

## Documentation

Documentation center:

- Main index: [`docs/README.md`](docs/README.md)
- Chinese index: [`docs/README_CN.md`](docs/README_CN.md)

Core architecture documents:

- System architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Startup and lifecycle: [`docs/STARTUP_AND_LIFECYCLE.md`](docs/STARTUP_AND_LIFECYCLE.md)
- Client architecture: [`docs/CLIENT_ARCHITECTURE.md`](docs/CLIENT_ARCHITECTURE.md)
- Server architecture: [`docs/SERVER_ARCHITECTURE.md`](docs/SERVER_ARCHITECTURE.md)
- Platform architecture: [`docs/PLATFORMS.md`](docs/PLATFORMS.md)
- Management backend: [`docs/MANAGEMENT_BACKEND.md`](docs/MANAGEMENT_BACKEND.md)

Tunnel and protocol documents:

- Tunnel design: [`docs/TUNNEL_DESIGN.md`](docs/TUNNEL_DESIGN.md)
- Transport and tunnel model: [`docs/TRANSMISSION.md`](docs/TRANSMISSION.md)
- Session and control plane: [`docs/TRANSMISSION_PACK_SESSIONID.md`](docs/TRANSMISSION_PACK_SESSIONID.md)
- Link-layer protocol: [`docs/LINKLAYER_PROTOCOL.md`](docs/LINKLAYER_PROTOCOL.md)
- Routing and DNS: [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md)

Engineering and operations documents:

- Engineering philosophy: [`docs/ENGINEERING_PHILOSOPHY.md`](docs/ENGINEERING_PHILOSOPHY.md)
- Source reading guide: [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md)
- Configuration reference: [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
- Deployment patterns: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
- Operations and troubleshooting: [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
- Security model: [`docs/SECURITY.md`](docs/SECURITY.md)

Chinese versions are provided in the same directory with `_CN` suffixes.

## Reading Paths

Recommended path for architects and maintainers:

1. [`docs/README.md`](docs/README.md)
2. [`docs/ENGINEERING_PHILOSOPHY.md`](docs/ENGINEERING_PHILOSOPHY.md)
3. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
4. [`docs/STARTUP_AND_LIFECYCLE.md`](docs/STARTUP_AND_LIFECYCLE.md)
5. [`docs/TUNNEL_DESIGN.md`](docs/TUNNEL_DESIGN.md)
6. [`docs/CLIENT_ARCHITECTURE.md`](docs/CLIENT_ARCHITECTURE.md)
7. [`docs/SERVER_ARCHITECTURE.md`](docs/SERVER_ARCHITECTURE.md)
8. [`docs/PLATFORMS.md`](docs/PLATFORMS.md)
9. [`docs/MANAGEMENT_BACKEND.md`](docs/MANAGEMENT_BACKEND.md)

Recommended path for source readers:

1. [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md)
2. `main.cpp`
3. `ppp/configurations/*`
4. `ppp/transmissions/*`
5. `ppp/app/protocol/*`
6. `ppp/app/client/*`
7. `ppp/app/server/*`
8. platform directories
9. `go/*`

## What The Codebase Implements

- Layer 2 / Layer 3 virtual Ethernet overlay
- Client/server runtime in a single binary
- TCP, UDP, WebSocket, and WebSocket over TLS transports
- Dual-layer payload protection through protocol and transport ciphers
- TUN/TAP based virtual interface integration
- Split tunnel and route steering using bypass lists, route files, and DNS rules
- Reverse access and port mapping through mapping and FRP-style control actions
- Optional multiplexing, static UDP mode, and bandwidth aggregation hooks
- IPv6 assignment extensions for server-managed IPv6 service
- Optional Go management backend for node, user, and traffic control

## Repository Layout

- `ppp/`: core protocol, session, tunnel, crypto, routing, client, and server logic
- `common/`: shared libraries and embedded third-party components
- `windows/`: Windows TAP/Wintun, Win32 routing, firewall, and proxy integration
- `linux/`: Linux TAP, route protection, diagnostics, and system networking helpers
- `darwin/`: macOS `utun` support and platform adaptations
- `android/`: Android-specific specializations
- `go/`: management backend and persistence-facing service code
- `docs/`: bilingual engineering documentation

## Architecture Summary

The core runtime is built around a small set of central types:

- `main.cpp`: unified entry point, mode selection, CLI parsing, runtime startup
- `ppp/configurations/AppConfiguration.*`: JSON configuration model and normalization
- `ppp/transmissions/ITransmission.*`: handshake, framed I/O, protocol cipher, transport cipher
- `ppp/app/protocol/VirtualEthernetLinklayer.*`: tunnel action set for NAT, TCP, UDP, info, echo, mux, and mapping
- `ppp/app/server/VirtualEthernetSwitcher.*`: server session switch, acceptors, firewall, IPv6 lease management
- `ppp/app/client/VEthernetNetworkSwitcher.*`: client virtual NIC, routing, DNS, proxy, and forwarding logic
- `ppp/app/client/VEthernetExchanger.*`: client session establishment, reconnection, mapping, static echo, and mux control
- `ppp/app/server/VirtualEthernetManagedServer.*`: optional management-plane WebSocket client

## What This Project Is

- A network infrastructure runtime
- A virtual Ethernet overlay engine
- A programmable VPN / SD-WAN foundation
- A system that prioritizes explicit topology, explicit policy, and deterministic runtime control

## What This Project Is Not

- Not a consumer VPN application focused on one-click usability
- Not only a tunnel binary with no routing, DNS, or session policy model
- Not a thin wrapper over a single OS VPN API
- Not a management backend first and data plane second system

## Supported Build Environments

### Windows

- Toolchain: Visual Studio 2022, CMake, Ninja, vcpkg
- Build script: `build_windows.bat`
- Project files: `ppp.sln`, `ppp.vcxproj`

Example:

```bat
build_windows.bat Release x64
```

### Linux / WSL

- Toolchain: GCC 7.5+ or compatible Clang, CMake, Make
- Third-party default path in `CMakeLists.txt`: `/root/dev`

Example:

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j32
```

Cross-build helpers are included in:

- `build-openppp2-by-builds.sh`
- `build-openppp2-by-cross.sh`

### macOS and Android

- Platform code exists in-tree.
- Treat them as normal CMake / NDK integration targets and verify in the platform toolchain before release.

## Runtime Modes

### Server

Typical responsibilities:

- Listen on TCP, UDP, WS, or WSS
- Authenticate or admit sessions
- Allocate tunnel-side addressing and optional IPv6 state
- Apply firewall, subnet, and mapping policy
- Report to the management backend when enabled

### Client

Typical responsibilities:

- Create and configure a virtual adapter
- Connect to the remote tunnel endpoint
- Maintain routes, bypass sets, DNS steering, and optional host-network preference
- Expose local HTTP or SOCKS proxy services if configured
- Register reverse mappings and optional static / mux data paths

## Common Deployment Patterns

- Full-tunnel remote access
- Split-tunnel enterprise access
- Branch-to-branch overlay with subnet forwarding
- Local proxy gateway on the client edge
- Reverse exposure of internal services through mappings
- WebSocket or WSS tunnel behind reverse proxy or CDN edge
- IPv6-capable overlay using server-managed prefixes

Detailed deployment analysis is in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Configuration Entry Points

Default configuration file:

```text
./appsettings.json
```

The major configuration groups are:

- `key`: cryptographic and framing behavior
- `tcp`, `udp`, `mux`, `websocket`: transport behavior
- `server`: node behavior, management backend, IPv6 service
- `client`: remote endpoint, reconnection, local proxy, mappings, route files
- `vmem`: virtual memory workspace
- `ip`: public and interface address hints

See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for details.

## CLI Entry Points

The binary exposes a large command-line surface. The most important options are:

- `--mode=[client|server]`
- `--config=<path>`
- `--dns=<ip-list>`
- `--nic=<interface>`
- `--ngw=<ip>`
- `--tun=<name>`
- `--tun-ip=<ip>`
- `--tun-ipv6=<ip>`
- `--tun-gw=<ip>`
- `--tun-mask=<bits>`
- `--tun-vnet=[yes|no]`
- `--tun-host=[yes|no]`
- `--tun-static=[yes|no]`
- `--tun-mux=<connections>`
- `--tun-mux-acceleration=<mode>`
- `--bypass=<file>`
- `--bypass-ngw=<ip>`
- `--dns-rules=<file>`
- `--firewall-rules=<file>`

For the full runtime help:

```bash
ppp --help
```

## Engineering Principles

- One binary, two roles, shared protocol core
- Favor explicit local policy over heavy external orchestration
- Keep packet processing deterministic and recoverable
- Separate transport, link-layer control, and platform networking concerns
- Make route, DNS, and access control visible in configuration instead of hidden side effects

For the full design stance, see [`docs/ENGINEERING_PHILOSOPHY.md`](docs/ENGINEERING_PHILOSOPHY.md).

## Notes

- Existing sample configuration files contain environment-specific addresses and credentials. Treat them as local examples, not reusable production defaults.
- Documentation was rewritten to reflect the codebase structure and operational intent, and to remove non-technical or misleading material.
