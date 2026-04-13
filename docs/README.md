# Documentation Index

[中文版本](README_CN.md)

This directory is the documentation center for OPENPPP2.

OPENPPP2 is not a small single-purpose tunnel tool. The codebase combines:

- tunnel transport
- virtual Ethernet forwarding
- route and DNS control
- reverse access and proxy functions
- optional multiplexing and static UDP paths
- platform-specific adapter integration
- optional management backend integration

Because of that, the documents are organized in layers, not as one monolithic manual.

## Recommended Reading Order

### If you want to understand the system as an infrastructure product

1. [`../README.md`](../README.md)
2. [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md)
3. [`ARCHITECTURE.md`](ARCHITECTURE.md)
4. [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md)
5. [`TUNNEL_DESIGN.md`](TUNNEL_DESIGN.md)
6. [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
7. [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
8. [`PLATFORMS.md`](PLATFORMS.md)
9. [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md)

### If you want to read the source code efficiently

1. [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md)
2. [`ARCHITECTURE.md`](ARCHITECTURE.md)
3. [`TUNNEL_DESIGN.md`](TUNNEL_DESIGN.md)
4. [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md)
5. `main.cpp`
6. `ppp/configurations/*`
7. `ppp/transmissions/*`
8. `ppp/app/protocol/*`
9. `ppp/app/client/*`
10. `ppp/app/server/*`
11. platform directories
12. `go/*`

### If you want deployment and operations guidance

1. [`CONFIGURATION.md`](CONFIGURATION.md)
2. [`DEPLOYMENT.md`](DEPLOYMENT.md)
3. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md)
4. [`PLATFORMS.md`](PLATFORMS.md)
5. [`OPERATIONS.md`](OPERATIONS.md)
6. [`SECURITY.md`](SECURITY.md)

## Document Map

### System documents

- [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md): why the project is shaped as infrastructure instead of a consumer VPN

### Product manuals

- [`USER_MANUAL.md`](USER_MANUAL.md): operator-focused guide for running client and server roles on supported platforms
- [`CLI_REFERENCE.md`](CLI_REFERENCE.md): command-line reference organized by common, role-specific, and platform-specific switches
- [`ARCHITECTURE.md`](ARCHITECTURE.md): overall structure, major modules, and data/control plane boundaries
- [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md): process startup, config loading, runtime ownership, and periodic maintenance
- [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md): practical reading path through the repository

### Tunnel and protocol documents

- [`TUNNEL_DESIGN.md`](TUNNEL_DESIGN.md): why the tunnel is layered this way and how handshake, framing, and protected transport work
- [`TRANSMISSION.md`](TRANSMISSION.md): concise transport and tunnel model summary
- [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md): session identity, information objects, and control-plane behavior
- [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md): opcode-level protocol guide for NAT, TCP, UDP, ICMP, FRP, static mode, and mux

### Runtime documents

- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md): client virtual NIC, routes, DNS, proxies, mappings, mux, and static mode
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md): server acceptors, session switch, NAT, IPv6, mappings, and backend cooperation
- [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md): route steering, bypass, vBGP-style route lists, DNS redirection, and cache behavior

### Platform and backend documents

- [`PLATFORMS.md`](PLATFORMS.md): Windows, Linux, macOS, Android, and build-system integration
- [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md): Go backend role, WebSocket protocol, and HTTP management APIs

### Operational documents

- [`CONFIGURATION.md`](CONFIGURATION.md): configuration model and important fields
- [`DEPLOYMENT.md`](DEPLOYMENT.md): deployment patterns and tunnel usage styles
- [`OPERATIONS.md`](OPERATIONS.md): runtime verification and troubleshooting
- [`SECURITY.md`](SECURITY.md): trust boundaries, local enforcement, and hardening guidance

## Reading Principle

When documenting OPENPPP2, keep four layers separate:

- transport carrier
- protected transmission and handshake
- tunnel control/data protocol
- platform networking integration

Most confusion in this project comes from mixing those four layers together.
