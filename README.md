# OPENPPP2

English | [简体中文](README_CN.md)

OPENPPP2 is a source-driven, cross-platform network runtime centered on one C++ executable named `ppp`, with an optional Go management backend.

It should not be read as only a VPN client, only a VPN server, or only a custom transport. The codebase combines multiple functional layers that work together as an integrated system:

| Layer | Description | Key Components |
|-------|-------------|-----------------|
| Protected Transport | Multi-carrier transport with cipher layering | Transmission families, framing, session management |
| Tunnel Protocol | Role-aware action protocol | Link-layer opcodes, packet formats, control plane |
| Client Runtime | Virtual adapter, routing, DNS integration | Switcher, exchanger, routes, proxies, mappings, MUX |
| Server Runtime | Session switching, forwarding, mapping, IPv6 | Listeners, session switch, mappings, static paths |
| Platform Integration | Host networking on Windows/Linux/macOS/Android | Adapter, protect, route, DNS, namespace |
| Management Backend | Optional Go service for managed deployments | REST API, persistence, orchestration |

The documentation in this repository was rewritten to explain the system from the code upward rather than from product slogans downward.

## Start Here

- Documentation index: [`docs/README.md`](docs/README.md)
- Chinese documentation index: [`docs/README_CN.md`](docs/README_CN.md)
- Top-level architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Source reading guide: [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md)

## Recommended Reading Paths

### If you want to understand the whole system

1. [`docs/ENGINEERING_CONCEPTS.md`](docs/ENGINEERING_CONCEPTS.md) - Engineering principles and design stance
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) - Top-level system boundaries and runtime relationships
3. [`docs/STARTUP_AND_LIFECYCLE.md`](docs/STARTUP_AND_LIFECYCLE.md) - Process bootstrap and lifecycle
4. [`docs/TRANSMISSION.md`](docs/TRANSMISSION.md) - Protected transport model
5. [`docs/HANDSHAKE_SEQUENCE.md`](docs/HANDSHAKE_SEQUENCE.md) - Connection establishment
6. [`docs/PACKET_FORMATS.md`](docs/PACKET_FORMATS.md) - Wire format specifications
7. [`docs/CLIENT_ARCHITECTURE.md`](docs/CLIENT_ARCHITECTURE.md) - Client runtime architecture
8. [`docs/SERVER_ARCHITECTURE.md`](docs/SERVER_ARCHITECTURE.md) - Server runtime architecture
9. [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md) - Route and DNS integration
10. [`docs/PLATFORMS.md`](docs/PLATFORMS.md) - Platform-specific behavior
11. [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) - Deployment model
12. [`docs/OPERATIONS.md`](docs/OPERATIONS.md) - Operational guidance

### If you want to read the code efficiently

1. [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md) - Practical reading order
2. `main.cpp` - Unified entry point
3. `ppp/configurations/*` - Configuration model
4. `ppp/transmissions/*` - Transport implementations
5. `ppp/app/protocol/*` - Protocol definitions
6. `ppp/app/client/*` - Client runtime
7. `ppp/app/server/*` - Server runtime
8. Platform directories - Platform-specific code
9. `go/*` - Management backend (optional)

### If you want deployment and runtime guidance

1. [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) - Configuration model
2. [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) - Command-line reference
3. [`docs/PLATFORMS.md`](docs/PLATFORMS.md) - Platform-specific notes
4. [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md) - Route and DNS
5. [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) - Deployment guide
6. [`docs/OPERATIONS.md`](docs/OPERATIONS.md) - Operations guide
7. [`docs/SECURITY.md`](docs/SECURITY.md) - Security considerations

## Core Documents

### Architecture and Runtime

| Document | Purpose | Audience |
|----------|---------|----------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Top-level system map, main boundaries, planes, and runtime relationships | All readers |
| [`docs/STARTUP_AND_LIFECYCLE.md`](docs/STARTUP_AND_LIFECYCLE.md) | Process startup, configuration load, role selection, tick loop, cleanup | Developers, operators |
| [`docs/CLIENT_ARCHITECTURE.md`](docs/CLIENT_ARCHITECTURE.md) | Client switcher, exchanger, routes, DNS, proxies, mappings, MUX, static path, IPv6 apply | Developers |
| [`docs/SERVER_ARCHITECTURE.md`](docs/SERVER_ARCHITECTURE.md) | Listeners, session switch, exchangers, mappings, static path, IPv6, backend integration | Developers |
| [`docs/PLATFORMS.md`](docs/PLATFORMS.md) | Windows, Linux, macOS, Android host integration and build/deployment differences | All readers |

### Transport and Protocol

| Document | Purpose | Key Topics |
|----------|---------|------------|
| [`docs/TRANSMISSION.md`](docs/TRANSMISSION.md) | Protected transport, framing families, ciphertext layering, runtime transport model | Transport architecture |
| [`docs/HANDSHAKE_SEQUENCE.md`](docs/HANDSHAKE_SEQUENCE.md) | Actual client/server handshake order and connection-level key shaping | Connection setup |
| [`docs/PACKET_FORMATS.md`](docs/PACKET_FORMATS.md) | Wire-level packet forms, headers, framing, static packet structure | Protocol formats |
| [`docs/TRANSMISSION_PACK_SESSIONID.md`](docs/TRANSMISSION_PACK_SESSIONID.md) | Session identity, control-plane meaning, session envelope interpretation | Session management |
| [`docs/LINKLAYER_PROTOCOL.md`](docs/LINKLAYER_PROTOCOL.md) | Tunnel action vocabulary and opcode-level runtime behavior | Tunnel protocol |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Trust boundaries, local enforcement, realistic security claims and limits | Security model |

### Configuration, Deployment, and Operations

| Document | Purpose | Audience |
|----------|---------|----------|
| [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) | Configuration model, defaults, normalization, and important groups | Operators, developers |
| [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md) | Command-line switches by role and platform | Operators |
| [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md) | Route steering, bypass, DNS redirect, namespace cache, vBGP-style inputs | Operators, developers |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | Actual deployment model, host requirements, optional management backend, Linux IPv6 server requirements | Operators |
| [`docs/OPERATIONS.md`](docs/OPERATIONS.md) | Runtime evidence, restart logic, cleanup, failure classes, troubleshooting order | Operators |

### Engineering and Source Study

| Document | Purpose | Audience |
|----------|---------|----------|
| [`docs/ENGINEERING_CONCEPTS.md`](docs/ENGINEERING_CONCEPTS.md) | Engineering concepts and design stance | All readers |
| [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md) | Practical order for reading the repository | Developers |
| [`docs/USER_MANUAL.md`](docs/USER_MANUAL.md) | Operator-oriented usage guide | Operators |
| [`docs/MANAGEMENT_BACKEND.md`](docs/MANAGEMENT_BACKEND.md) | Go backend role, dependencies, and interaction model | Developers, operators |

## System Capabilities

### Transport Features

| Feature | Client | Server | Description |
|---------|--------|--------|-------------|
| Multiple carriers | Yes | Yes | TCP, UDP, and custom carriers supported |
| Cipher layering | Yes | Yes | ChaCha20-Poly1305, AES-256-GCM |
| Session multiplexing | Yes | Yes | MUX paths for optimized throughput |
| Static packet path | Yes | Yes | Low-latency bypass mode |
| IPv6 support | Yes | Yes | Full IPv6 data plane on Linux |
| Session persistence | Yes | Yes | Reconnection and session resume |

### Client Features

| Feature | Windows | Linux | macOS | Android |
|---------|---------|-------|-------|---------|
| Virtual adapter | Yes | Yes | Yes | Yes |
| Route injection | Yes | Yes | Yes | N/A |
| DNS redirect | Yes | Yes | Yes | Yes |
| Proxy integration | Yes | Yes | Yes | Yes |
| Split tunneling | Yes | Yes | Yes | Yes |
| IPv6 apply | Yes | Yes | Yes | Limited |

### Server Features

| Feature | Windows | Linux | macOS |
|---------|---------|-------|-------|
| Session switching | Yes | Yes | Yes |
| Port forwarding | Yes | Yes | Yes |
| Protocol mapping | Yes | Yes | Yes |
| Static path | Yes | Yes | Yes |
| IPv6 gateway | Partial | Yes | Partial |
| Backend integration | Yes | Yes | Yes |

## Repository Layout

```
.
├── main.cpp              # Unified entry point and top-level lifecycle
├── ppp/                  # Shared runtime code
│   ├── configurations/   # Configuration model and loading
│   ├── transmissions/    # Transport implementations
│   ├── app/
│   │   ├── protocol/    # Protocol definitions
│   │   ├── client/     # Client runtime
│   │   └── server/     # Server runtime
│   └── ...
├── windows/              # Windows platform code
│   ├── adapter/         # Virtual adapter implementation
│   ├── route/           # Route management
│   ├── dns/             # DNS redirect
│   └── proxy/            # Proxy integration
├── linux/                # Linux platform code
│   ├── adapter/          # TUN/TAP implementation
│   ├── protect/         # Firewall integration
│   ├── route/           # Route management
│   └── ipv6/            # IPv6 gateway
├── darwin/               # macOS platform code
│   └── utun/             # utun integration
├── android/              # Android platform code
│   └── library/          # Shared library build
├── go/                   # Optional management backend
│   └── backend/          # REST API and persistence
└── docs/                 # Bilingual documentation
    ├── *.md              # English docs
    └── *_CN.md           # Chinese docs
```

## Build Notes

### Windows Build

| Item | Requirement |
|------|-------------|
| Build script | `build_windows.bat` |
| Toolchain | Visual Studio 2022, Ninja, vcpkg |
| Architecture | x64 (primary), ARM64 (optional) |
| Build type | Release/Debug |

Example:
```bat
build_windows.bat Release x64
```

### Linux Build

| Item | Requirement |
|------|-------------|
| Build system | CMake |
| Toolchain | GCC 11+ or Clang 14+ |
| Dependencies | libuv, OpenSSL, libpthread |
| Cross-build | Via `build-openppp2-by-cross.sh` |

Example:
```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j32
```

### macOS Build

| Item | Requirement |
|------|-------------|
| Build system | CMake |
| Toolchain | Xcode 15+ |
| SDK | macOS SDK 13.0+ |
| Target | arm64, x86_64 |

### Android Build

| Item | Requirement |
|------|-------------|
| Build system | CMake + NDK |
| Output | Shared library (.so) |
| ABI | arm64-v8a, x86_64 |
| Integration | Embed in host application |

## Platform-Specific Features

### Feature Comparison Matrix

| Feature | Windows | Linux | macOS | Android |
|---------|--------|-------|-------|---------|
| Virtual adapter | Wintun | tun/tap | utun | VPNService API |
| Protect/bypass | Windows Firewall | iptables/nftables | pf | VPNService |
| DNS interception | Registry | /etc/resolv.conf | scutil | VPNService |
| Route management | routing table | routing table | routing table | Limited |
| IPv6 tunnel | Limited | Full | Limited | Limited |
| MUX multiplexing | Yes | Yes | Yes | Yes |
| Static path | Yes | Yes | Yes | Yes |
| Proxy support | Yes | Yes | Yes | Yes |
| Management API | Local | Local | Local | N/A |

### Build Differences

| Aspect | Windows | Linux | macOS | Android |
|--------|---------|-------|-------|---------|
| Binary type | Executable | Executable | Executable | Shared library |
| Installation | MSI/EXE | DEB/RPM/PKG | APP bundle | APK embed |
| Service model | Windows Service | systemd | launchd | Foreground service |
| Required packages | Visual Studio | Build tools | Xcode | NDK |
| Runtime dependencies | vcpkg | System libs | System libs | Android lib |

## Important Boundaries

### What This Project Is Not

| Misconception | Reality |
|--------------|----------|
| Consumer VPN app | This is a developer-oriented network runtime |
| One-click solution | Requires configuration and integration work |
| Symmetric client/server | Client and server have different roles |
| Drop-in replacement | Platform integration required per deployment |
| Magic solution | Requires understanding of networking |

### Actual Capabilities

| Capability | Status | Notes |
|------------|--------|-------|
| Multi-carrier transport | Core | TCP, UDP, custom carriers |
| Role-aware protocol | Core | Tunnel action protocol with opcodes |
| Client runtime | Full | Virtual adapter, routing, DNS |
| Server runtime | Full | Session switching, forwarding |
| IPv6 data plane | Linux-centric | Most complete on Linux |
| Management backend | Optional | Go service for orchestration |
| Static packet path | Optional | Low-latency mode |
| MUX multiplexing | Optional | Optimized throughput |

### Design Constraints

| Constraint | Impact |
|------------|--------|
| Not a consumer app | Requires technical expertise to deploy |
| IPv6 Linux-centric | Windows/macOS IPv6 limited |
| Go optional | Not required for basic operation |
| Platform integration | Must be implemented per platform |
| Source-driven | Requires reading code to understand |

## Configuration Model

### Primary Configuration Groups

| Group | Description | File |
|-------|-------------|------|
| Network | Address, port, protocol settings | server.conf / client.conf |
| Transport | Carrier selection, cipher settings | transport.conf |
| Routing | Route tables, bypass rules | routes.conf |
| DNS | DNS servers, redirect rules | dns.conf |
| Platform | Platform-specific settings | platform.conf |
| Management | Backend connection (optional) | management.conf |

### Configuration Format Support

| Format | Extension | Status |
|--------|-----------|--------|
| JSON | .json | Primary |
| HOCON | .conf | Optional |
| Environment | ENV | Partial |
| Command line | N/A | Full |

## Operational Considerations

### Runtime Monitoring

| Metric | Access Method |
|--------|----------------|
| Connection status | CLI status command |
| Session list | CLI sessions command |
| Traffic statistics | CLI stats command |
| Error logs | Log file |
| Performance data | Management API |

### Failure Modes

| Class | Description | Recovery |
|-------|-------------|----------|
| Network failure | Carrier down | Auto-reconnect |
| Authentication failure | Invalid credentials | Manual intervention |
| Configuration error | Invalid settings | Restart with fixed config |
| Platform failure | OS integration error | Platform-specific recovery |
| Resource exhaustion | Memory/FD limits | Restart process |

### Troubleshooting Order

1. Verify network connectivity
2. Check configuration syntax
3. Review error logs
4. Validate platform integration
5. Test with minimal configuration
6. Enable debug logging
7. Analyze packet captures

## Notes

- Example configuration values in the repository may contain local addresses, ports, or credentials and should be treated as examples, not production defaults.
- The current documentation set is intentionally long-form, implementation-driven, and bilingual.
- Client and server share a message vocabulary but do not behave as symmetric peers.
- Route, DNS, adapter, and platform side effects are part of the real system behavior, not incidental details.
- The most complete server-side IPv6 data-plane implementation is Linux-centric.
- The Go backend is optional and is not the primary data plane.
- This project is not a consumer one-click VPN application.

## Documentation Index

### English Documentation

| Category | Documents |
|----------|-----------|
| Getting started | README.md, ARCHITECTURE.md, SOURCE_READING_GUIDE.md |
| Core concepts | ENGINEERING_CONCEPTS.md, TRANSMISSION.md, HANDSHAKE_SEQUENCE.md |
| Protocol | PACKET_FORMATS.md, LINKLAYER_PROTOCOL.md, TRANSMISSION_PACK_SESSIONID.md |
| Architecture | CLIENT_ARCHITECTURE.md, SERVER_ARCHITECTURE.md, STARTUP_AND_LIFECYCLE.md |
| Platform | PLATFORMS.md |
| Configuration | CONFIGURATION.md, CLI_REFERENCE.md, ROUTING_AND_DNS.md |
| Deployment | DEPLOYMENT.md, OPERATIONS.md, SECURITY.md |
| Management | MANAGEMENT_BACKEND.md, USER_MANUAL.md |

### Chinese Documentation

| Category | Documents |
|----------|-----------|
| Getting started | README_CN.md, ARCHITECTURE_CN.md, SOURCE_READING_GUIDE_CN.md |
| Core concepts | ENGINEERING_CONCEPTS_CN.md, TRANSMISSION_CN.md, HANDSHAKE_SEQUENCE_CN.md |
| Protocol | PACKET_FORMATS_CN.md, LINKLAYER_PROTOCOL_CN.md, TRANSMISSION_PACK_SESSIONID_CN.md |
| Architecture | CLIENT_ARCHITECTURE_CN.md, SERVER_ARCHITECTURE_CN.md, STARTUP_AND_LIFECYCLE_CN.md |
| Platform | PLATFORMS_CN.md |
| Configuration | CONFIGURATION_CN.md, CLI_REFERENCE_CN.md, ROUTING_AND_DNS_CN.md |
| Deployment | DEPLOYMENT_CN.md, OPERATIONS_CN.md, SECURITY_CN.md |
| Management | MANAGEMENT_BACKEND_CN.md, USER_MANUAL_CN.md |

## Version and Build Information

| Item | Value |
|------|-------|
| Primary language | C++ (C++20) |
| Secondary language | Go (1.21+) |
| Build system | CMake |
| Minimum CMake | 3.24 |
| C++ standard | C++20 |
| Target platforms | Windows 10+, Linux 5.4+, macOS 12+, Android API 24+ |

## Contributing

This is a developer-oriented project. Contributions should:
- Follow existing code style
- Include documentation updates
- Pass all build verification
- Maintain cross-platform compatibility

## License

See repository root for license information.

## Quick Reference

### Common CLI Commands

| Command | Description |
|---------|-------------|
| `ppp --client` | Run as client |
| `ppp --server` | Run as server |
| `ppp --status` | Show status |
| `ppp --sessions` | List sessions |
| `ppp --stats` | Show statistics |
| `ppp --reload` | Reload configuration |

### Key Files

| File | Purpose |
|------|---------|
| main.cpp | Entry point |
| ppp/config.hpp | Configuration header |
| ppp/transmission.hpp | Transport header |
| ppp/protocol.hpp | Protocol header |
| ppp/client.hpp | Client header |
| ppp/server.hpp | Server header |