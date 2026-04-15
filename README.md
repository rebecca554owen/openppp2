# OPENPPP2

English | [简体中文](README_CN.md)

OPENPPP2 is a source-driven, cross-platform network runtime centered on one C++ executable named `ppp`, with an optional Go management backend.

It should not be read as only a VPN client, only a VPN server, or only a custom transport. The codebase combines:

- protected transport over multiple carriers
- a role-aware tunnel action protocol
- client-side virtual adapter, route, and DNS integration
- server-side session switching, forwarding, mapping, and IPv6 logic
- optional static packet and MUX paths
- platform-specific host networking behavior on Windows, Linux, macOS, and Android
- an optional Go management backend for managed deployments

The documentation in this repository was rewritten to explain the system from the code upward rather than from product slogans downward.

## Start Here

- Documentation index: [`docs/README.md`](docs/README.md)
- Chinese documentation index: [`docs/README_CN.md`](docs/README_CN.md)
- Top-level architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- Source reading guide: [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md)

## Recommended Reading Paths

### If you want to understand the whole system

1. [`docs/ENGINEERING_CONCEPTS.md`](docs/ENGINEERING_CONCEPTS.md)
2. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
3. [`docs/STARTUP_AND_LIFECYCLE.md`](docs/STARTUP_AND_LIFECYCLE.md)
4. [`docs/TRANSMISSION.md`](docs/TRANSMISSION.md)
5. [`docs/HANDSHAKE_SEQUENCE.md`](docs/HANDSHAKE_SEQUENCE.md)
6. [`docs/PACKET_FORMATS.md`](docs/PACKET_FORMATS.md)
7. [`docs/CLIENT_ARCHITECTURE.md`](docs/CLIENT_ARCHITECTURE.md)
8. [`docs/SERVER_ARCHITECTURE.md`](docs/SERVER_ARCHITECTURE.md)
9. [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md)
10. [`docs/PLATFORMS.md`](docs/PLATFORMS.md)
11. [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
12. [`docs/OPERATIONS.md`](docs/OPERATIONS.md)

### If you want to read the code efficiently

1. [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md)
2. `main.cpp`
3. `ppp/configurations/*`
4. `ppp/transmissions/*`
5. `ppp/app/protocol/*`
6. `ppp/app/client/*`
7. `ppp/app/server/*`
8. platform directories
9. `go/*` if managed deployment matters

### If you want deployment and runtime guidance

1. [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
2. [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md)
3. [`docs/PLATFORMS.md`](docs/PLATFORMS.md)
4. [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md)
5. [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
6. [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
7. [`docs/SECURITY.md`](docs/SECURITY.md)

## Core Documents

### Architecture and runtime

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): top-level system map, main boundaries, planes, and runtime relationships
- [`docs/STARTUP_AND_LIFECYCLE.md`](docs/STARTUP_AND_LIFECYCLE.md): process startup, configuration load, role selection, tick loop, cleanup
- [`docs/CLIENT_ARCHITECTURE.md`](docs/CLIENT_ARCHITECTURE.md): client switcher, exchanger, routes, DNS, proxies, mappings, MUX, static path, IPv6 apply
- [`docs/SERVER_ARCHITECTURE.md`](docs/SERVER_ARCHITECTURE.md): listeners, session switch, exchangers, mappings, static path, IPv6, backend integration
- [`docs/PLATFORMS.md`](docs/PLATFORMS.md): Windows, Linux, macOS, Android host integration and build/deployment differences

### Transport and protocol

- [`docs/TRANSMISSION.md`](docs/TRANSMISSION.md): protected transport, framing families, ciphertext layering, runtime transport model
- [`docs/HANDSHAKE_SEQUENCE.md`](docs/HANDSHAKE_SEQUENCE.md): actual client/server handshake order and connection-level key shaping
- [`docs/PACKET_FORMATS.md`](docs/PACKET_FORMATS.md): wire-level packet forms, headers, framing, static packet structure
- [`docs/TRANSMISSION_PACK_SESSIONID.md`](docs/TRANSMISSION_PACK_SESSIONID.md): session identity, control-plane meaning, session envelope interpretation
- [`docs/LINKLAYER_PROTOCOL.md`](docs/LINKLAYER_PROTOCOL.md): tunnel action vocabulary and opcode-level runtime behavior
- [`docs/SECURITY.md`](docs/SECURITY.md): trust boundaries, local enforcement, realistic security claims and limits

### Configuration, deployment, and operations

- [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md): configuration model, defaults, normalization, and important groups
- [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md): command-line switches by role and platform
- [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md): route steering, bypass, DNS redirect, namespace cache, vBGP-style inputs
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md): actual deployment model, host requirements, optional management backend, Linux IPv6 server requirements
- [`docs/OPERATIONS.md`](docs/OPERATIONS.md): runtime evidence, restart logic, cleanup, failure classes, troubleshooting order

### Engineering and source study

- [`docs/ENGINEERING_CONCEPTS.md`](docs/ENGINEERING_CONCEPTS.md): engineering concepts and design stance
- [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md): practical order for reading the repository
- [`docs/USER_MANUAL.md`](docs/USER_MANUAL.md): operator-oriented usage guide
- [`docs/MANAGEMENT_BACKEND.md`](docs/MANAGEMENT_BACKEND.md): Go backend role, dependencies, and interaction model

## Repository Layout

- `main.cpp`: unified entry point and top-level lifecycle
- `ppp/`: shared configuration, transport, protocol, client, and server runtime code
- `windows/`: Windows adapter, route, DNS, proxy, and host integration code
- `linux/`: Linux adapter, protect, route, IPv6, and system-integration code
- `darwin/`: macOS `utun` and Darwin-specific integration code
- `android/`: Android shared-library and VPN-host integration code
- `go/`: optional management backend and persistence-facing service code
- `docs/`: bilingual system documentation

## Build Notes

### Windows

- main script: `build_windows.bat`
- expected toolchain: Visual Studio 2022, Ninja, vcpkg

Example:

```bat
build_windows.bat Release x64
```

### Linux / WSL

- root build uses normal CMake flow
- extra packaging and cross-build helpers exist in `build-openppp2-by-builds.sh` and `build-openppp2-by-cross.sh`

Example:

```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j32
```

### macOS and Android

- platform code exists in-tree
- Android is built as a shared library and embedded into an application host
- verify platform-specific changes in the corresponding toolchain before release

## Important Boundaries

- This project is not a consumer one-click VPN application.
- The Go backend is optional and is not the primary data plane.
- The most complete server-side IPv6 data-plane implementation is Linux-centric.
- Client and server share a message vocabulary but do not behave as symmetric peers.
- Route, DNS, adapter, and platform side effects are part of the real system behavior, not incidental details.

## Notes

- Example configuration values in the repository may contain local addresses, ports, or credentials and should be treated as examples, not production defaults.
- The current documentation set is intentionally long-form, implementation-driven, and bilingual.
