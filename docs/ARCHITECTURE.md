# Architecture

[中文版本](ARCHITECTURE_CN.md)

## System Shape

OPENPPP2 is a single-process tunnel runtime with shared protocol core and platform-specific networking adapters.

Its major layers are:

1. Entry and lifecycle
2. Configuration model
3. Transport and handshake
4. Tunnel control/data protocol
5. Client and server orchestration
6. Platform integration
7. Optional management backend

## Entry And Lifecycle

`main.cpp` is the unified entry point.

It is responsible for:

- parsing CLI arguments
- loading `appsettings.json`
- selecting client or server mode
- preparing platform network state
- constructing the client or server runtime
- printing operational state and statistics

This keeps process lifecycle in one place instead of splitting startup paths across many binaries.

## Configuration Model

`ppp/configurations/AppConfiguration.*` is the canonical runtime configuration model.

It owns:

- default values
- JSON loading
- normalization and trimming
- validation and field shaping

Important groups:

- `key`
- `tcp`
- `udp`
- `mux`
- `websocket`
- `server`
- `client`
- `vmem`
- `ip`

The codebase is heavily configuration-driven. A large part of the runtime behavior is selected by this object rather than by compile-time forks.

## Transport Layer

`ppp/transmissions/` contains the transport abstraction.

Important classes:

- `ITransmission`: handshake, framing, cipher management, read/write flow
- `ITcpipTransmission`: TCP-oriented socket implementation
- `IWebsocketTransmission`: WS/WSS integration
- `ITransmissionQoS`: throughput shaping hooks
- `ITransmissionStatistics`: traffic statistics

This layer should be read as the byte transport and session bootstrap layer, not the packet-routing layer.

## Tunnel Protocol Layer

`ppp/app/protocol/` defines the internal tunnel protocol.

Important classes:

- `VirtualEthernetLinklayer`: tunnel actions and message dispatch
- `VirtualEthernetInformation`: session policy envelope
- `VirtualEthernetPacket`: packet container and serialization helpers
- `VirtualEthernetMappingPort`: reverse mapping state
- `VirtualEthernetLogger`: tunnel logging abstraction

The main actions include:

- info and keepalive
- NAT and LAN signaling
- TCP connect/data/close relay
- UDP sendto relay
- echo and static path control
- MUX control
- FRP-style reverse mapping control

## Server Runtime

The server side is centered on `ppp/app/server/VirtualEthernetSwitcher.*`.

Responsibilities:

- create acceptors for enabled transports
- authenticate and admit sessions
- build and maintain exchangers
- manage firewall and namespace cache
- track tunnel statistics
- manage IPv6 requests, leases, and neighbor/proxy state
- cooperate with the optional management backend

Support classes around it handle TCP/IP relay, static datagram behavior, and server-side exchange operations.

## Client Runtime

The client side is centered on:

- `ppp/app/client/VEthernetNetworkSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`

Responsibilities:

- open the virtual adapter
- choose local stack behavior (`lwip`, vnet, route strategy)
- connect to the server
- manage reconnection and keepalive
- maintain route and bypass sets
- apply DNS rules and DNS redirection behavior
- host local HTTP and SOCKS proxy entry points
- manage reverse mappings and optional MUX or static modes
- apply assigned IPv6 state

`VEthernetNetworkSwitcher` owns local system/network integration. `VEthernetExchanger` owns the remote session relationship.

## Platform Layers

### Windows

`windows/` contains:

- TAP / Wintun integration
- Win32 route and firewall helpers
- local proxy and PaperAirplane hooks
- native socket and registry helpers

### Linux

`linux/` contains:

- TAP integration
- route protection
- diagnostics and stack trace helpers
- Linux-specific network helper code

### macOS

`darwin/` contains `utun`-based support and macOS-specific integration.

### Android

`android/` contains Android-specific branches used by the shared runtime.

## Optional Management Backend

The Go service under `go/` is not the data plane. It is an auxiliary management system.

It appears intended to provide:

- node registration and lookup
- user state and policy lookup
- traffic accounting
- persistence via Redis and MySQL
- webhook-style coordination with the C++ server runtime

The main bridge from the C++ side is `VirtualEthernetManagedServer`.

## Data Plane Vs Control Plane

The codebase draws a useful boundary:

- Data plane: packet forwarding, connect/push/sendto, local adapter I/O
- Control plane: handshake, information exchange, keepalive, mapping registration, mux/static setup, IPv6 assignment, backend authentication

This is important for maintainability. When reading or modifying the system, keep those concerns separate.

## Directory Reading Guide

When studying the repository, read in this order:

1. `main.cpp`
2. `ppp/configurations/AppConfiguration.*`
3. `ppp/transmissions/*`
4. `ppp/app/protocol/*`
5. `ppp/app/server/*`
6. `ppp/app/client/*`
7. platform directories for your target OS
8. `go/` if you need managed deployment behavior

## Design Philosophy

- one executable, one core protocol
- explicit local state over hidden orchestration
- transport-independent tunnel actions
- policy-driven operation through config and control messages
- platform specialization only where required by the host OS

## Related Documents

- [`TRANSMISSION.md`](TRANSMISSION.md)
- [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md)
- [`CONFIGURATION.md`](CONFIGURATION.md)
- [`DEPLOYMENT.md`](DEPLOYMENT.md)
