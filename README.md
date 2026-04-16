# OPENPPP2

English | [简体中文](README_CN.md)

OPENPPP2 is a source-driven, cross-platform network runtime built around the C++ executable `ppp`, with an optional Go management backend. The real implementation boundary lives in `main.cpp`, `ppp/configurations`, `ppp/transmissions`, `ppp/app/protocol`, `ppp/app/client`, `ppp/app/server`, and the platform-specific integration directories.

It is not a single-purpose VPN app. The code implements a layered system:

| Layer | What it actually does | Main code areas |
|-------|------------------------|-----------------|
| Protected transport | Frames, encrypts, obfuscates, and shapes handshake traffic | `ppp/transmissions/*` |
| Tunnel protocol | Defines session identity, link-layer opcodes, and packet meaning | `ppp/app/protocol/*` |
| Client runtime | Attaches to a virtual adapter, steers routes, DNS, proxy, and MUX | `ppp/app/client/*` |
| Server runtime | Accepts sessions, switches exchangers, forwards traffic, and manages IPv6/static paths | `ppp/app/server/*` |
| Platform integration | Binds the runtime to Windows/Linux/macOS/Android networking APIs | `windows/*`, `linux/*`, `darwin/*`, `android/*` |
| Management backend | Optional Go service for managed deployments | `go/*` |

The documentation is written from code facts upward. It explains what the system does, why each layer exists, and where the implementation boundaries really are.

## Start Here

| Document | Purpose |
|----------|---------|
| [`docs/README.md`](docs/README.md) | Documentation index and reading paths |
| [`docs/README_CN.md`](docs/README_CN.md) | Chinese documentation index |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Top-level architecture map |
| [`docs/USER_MANUAL.md`](docs/USER_MANUAL.md) | End-user quick start and appendices |
| [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md) | Source reading order |

## Reading Paths

### Whole System

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

### Code Reading

1. [`docs/SOURCE_READING_GUIDE.md`](docs/SOURCE_READING_GUIDE.md)
2. `main.cpp`
3. `ppp/configurations/*`
4. `ppp/transmissions/*`
5. `ppp/app/protocol/*`
6. `ppp/app/client/*`
7. `ppp/app/server/*`
8. Platform directories
9. `go/*` when managed deployment is used

### Deployment And Operations

1. [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md)
2. [`docs/CLI_REFERENCE.md`](docs/CLI_REFERENCE.md)
3. [`docs/PLATFORMS.md`](docs/PLATFORMS.md)
4. [`docs/ROUTING_AND_DNS.md`](docs/ROUTING_AND_DNS.md)
5. [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)
6. [`docs/OPERATIONS.md`](docs/OPERATIONS.md)
7. [`docs/SECURITY.md`](docs/SECURITY.md)

## Documentation Set

The repository contains 20 paired English/Chinese documents plus the root README pair. Each Chinese document has a one-to-one English counterpart.

| Area | English | Chinese |
|------|---------|---------|
| Foundation | `ENGINEERING_CONCEPTS.md` | `ENGINEERING_CONCEPTS_CN.md` |
| Foundation | `ARCHITECTURE.md` | `ARCHITECTURE_CN.md` |
| Foundation | `STARTUP_AND_LIFECYCLE.md` | `STARTUP_AND_LIFECYCLE_CN.md` |
| Transport | `TRANSMISSION.md` | `TRANSMISSION_CN.md` |
| Transport | `HANDSHAKE_SEQUENCE.md` | `HANDSHAKE_SEQUENCE_CN.md` |
| Transport | `PACKET_FORMATS.md` | `PACKET_FORMATS_CN.md` |
| Transport | `TRANSMISSION_PACK_SESSIONID.md` | `TRANSMISSION_PACK_SESSIONID_CN.md` |
| Protocol | `LINKLAYER_PROTOCOL.md` | `LINKLAYER_PROTOCOL_CN.md` |
| Runtime | `CLIENT_ARCHITECTURE.md` | `CLIENT_ARCHITECTURE_CN.md` |
| Runtime | `SERVER_ARCHITECTURE.md` | `SERVER_ARCHITECTURE_CN.md` |
| Runtime | `ROUTING_AND_DNS.md` | `ROUTING_AND_DNS_CN.md` |
| Platform | `PLATFORMS.md` | `PLATFORMS_CN.md` |
| Configuration | `CONFIGURATION.md` | `CONFIGURATION_CN.md` |
| Configuration | `CLI_REFERENCE.md` | `CLI_REFERENCE_CN.md` |
| Operations | `DEPLOYMENT.md` | `DEPLOYMENT_CN.md` |
| Operations | `OPERATIONS.md` | `OPERATIONS_CN.md` |
| Security | `SECURITY.md` | `SECURITY_CN.md` |
| Management | `MANAGEMENT_BACKEND.md` | `MANAGEMENT_BACKEND_CN.md` |
| Usage | `USER_MANUAL.md` | `USER_MANUAL_CN.md` |
| Reading | `SOURCE_READING_GUIDE.md` | `SOURCE_READING_GUIDE_CN.md` |

## Code Facts That Shape The Docs

| Fact | Consequence |
|------|-------------|
| `main.cpp` owns startup, role selection, lifecycle, and host setup | The documentation separates bootstrap from runtime behavior |
| `AppConfiguration` normalizes many fields after load | The configuration docs must explain defaults and invalid-state cleanup |
| `ITransmission` performs handshake, framing, masking, delta encoding, and cipher layering | The transport docs must be implementation-driven, not abstract |
| `VirtualEthernetLinklayer` defines opcode-based tunnel actions | The protocol docs must explain actual opcodes and message flow |
| Client and server runtimes are different roles | The architecture docs must not treat them as symmetric peers |
| Platform code changes route, DNS, adapter, and firewall behavior | Platform docs must be explicit about side effects |
| The Go backend is optional | Managed deployment must be documented separately |

## Repository Layout

```text
.
├── main.cpp
├── ppp/
│   ├── configurations/
│   ├── transmissions/
│   ├── app/
│   │   ├── protocol/
│   │   ├── client/
│   │   └── server/
│   └── ...
├── windows/
├── linux/
├── darwin/
├── android/
├── go/
└── docs/
    ├── *.md
    └── *_CN.md
```

## Boundaries

| Not true | True |
|---------|------|
| Consumer one-click VPN | Developer-oriented network runtime |
| Symmetric client/server peers | Role-specific runtimes with different responsibilities |
| Pure transport library | End-to-end system with host integration |
| Go is required | Go backend is optional |
| Routing is incidental | Routing and DNS are first-class runtime behavior |

## Build Notes

| Platform | Notes |
|----------|-------|
| Windows | `build_windows.bat`, Visual Studio 2022, Ninja, vcpkg |
| Linux | CMake, GCC/Clang, system libraries |
| macOS | CMake, Xcode, macOS SDK |
| Android | CMake + NDK, shared library integration |

## Quick Reference

| Command | Purpose |
|---------|---------|
| `ppp --help` | Show the real CLI help |
| `ppp --mode=client` | Start in client mode |
| `ppp --mode=server` | Start in server mode |
| `ppp --config=./config.json` | Load an explicit config file |
| `ppp --pull-iplist [file/country]` | Download an IP list and exit |

## Notes

- Example configuration values are examples, not production defaults.
- Linux is the most complete server-side IPv6 data-plane target.
- The documentation uses long-form bilingual writing because the system is implementation-heavy.
- `main.cpp` is the fastest entry point for understanding how the pieces connect.
