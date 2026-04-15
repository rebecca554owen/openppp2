# Documentation Index

[中文版本](README_CN.md)

This directory is the documentation center for OPENPPP2.

The documentation set is intentionally layered. OPENPPP2 is not one thing. It combines:

- protected transport
- tunnel action protocol
- client-side host integration
- server-side session switching and forwarding
- route and DNS steering
- optional static packet and MUX paths
- platform-specific host networking behavior
- an optional external management backend

Because of that, the most useful way to read the docs is by path rather than by file name alone.

## Reading Paths

### Understand The Whole System

1. [`../README.md`](../README.md)
2. [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md)
3. [`ARCHITECTURE.md`](ARCHITECTURE.md)
4. [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md)
5. [`TRANSMISSION.md`](TRANSMISSION.md)
6. [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md)
7. [`PACKET_FORMATS.md`](PACKET_FORMATS.md)
8. [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
9. [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
10. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md)
11. [`PLATFORMS.md`](PLATFORMS.md)
12. [`DEPLOYMENT.md`](DEPLOYMENT.md)
13. [`OPERATIONS.md`](OPERATIONS.md)

### Read The Code Efficiently

1. [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md)
2. [`ARCHITECTURE.md`](ARCHITECTURE.md)
3. [`TRANSMISSION.md`](TRANSMISSION.md)
4. [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md)
5. `main.cpp`
6. `ppp/configurations/*`
7. `ppp/transmissions/*`
8. `ppp/app/protocol/*`
9. `ppp/app/client/*`
10. `ppp/app/server/*`
11. platform directories
12. `go/*` if managed deployment matters

### Focus On Deployment And Runtime

1. [`CONFIGURATION.md`](CONFIGURATION.md)
2. [`CLI_REFERENCE.md`](CLI_REFERENCE.md)
3. [`PLATFORMS.md`](PLATFORMS.md)
4. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md)
5. [`DEPLOYMENT.md`](DEPLOYMENT.md)
6. [`OPERATIONS.md`](OPERATIONS.md)
7. [`SECURITY.md`](SECURITY.md)

## Document Map

### Foundation

- [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md): engineering stance, system intent, and the vocabulary used by the documentation set
- [`ARCHITECTURE.md`](ARCHITECTURE.md): top-level architecture map, main boundaries, roles, and planes
- [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md): startup, role selection, environment preparation, tick loop, shutdown

### Transport And Protocol

- [`TRANSMISSION.md`](TRANSMISSION.md): protected transport, framing, ciphertext layering, and runtime transport model
- [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md): actual handshake order and connection-level key shaping behavior
- [`PACKET_FORMATS.md`](PACKET_FORMATS.md): packet structures, static packet format, and wire-level framing facts
- [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md): session identity, control-plane meaning, and information-envelope context
- [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md): tunnel action vocabulary used between client and server
- [`SECURITY.md`](SECURITY.md): trust boundaries, enforcement points, realistic security claims, and hardening guidance

### Runtime

- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md): client switcher, exchanger, routes, DNS, proxies, mappings, MUX, static path, managed IPv6
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md): acceptors, session switch, forwarding, mappings, static path, IPv6, backend cooperation
- [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md): route steering, bypass, DNS redirect, namespace cache, vBGP-style route inputs

### Platform And Management

- [`PLATFORMS.md`](PLATFORMS.md): Windows, Linux, macOS, Android, and host-integration differences
- [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md): Go backend role, dependencies, APIs, and interaction model

### Configuration, Usage, And Operations

- [`CONFIGURATION.md`](CONFIGURATION.md): configuration model, defaults, normalization, and key fields
- [`CLI_REFERENCE.md`](CLI_REFERENCE.md): runtime CLI organized by common, role-specific, and platform-specific arguments
- [`USER_MANUAL.md`](USER_MANUAL.md): operator-focused usage guide
- [`DEPLOYMENT.md`](DEPLOYMENT.md): actual deployment model, host requirements, optional backend and Linux IPv6 server requirements
- [`OPERATIONS.md`](OPERATIONS.md): observability, restart logic, cleanup, failure classes, and troubleshooting order
- [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md): practical reading order for developers

## Reading Principle

When reading OPENPPP2, keep these layers separate:

- carrier transport
- protected transmission and handshake
- tunnel action protocol
- client or server runtime behavior
- platform-specific host integration
- optional management backend

Most confusion in this codebase comes from mixing those layers together.
