# Source Reading Guide

[中文版本](SOURCE_READING_GUIDE_CN.md)

## Goal

This guide is for engineers who want to read the OPENPPP2 source without getting lost in platform details too early.

## Step 1: Start At The Process Entry

Read:

- `main.cpp`

Focus on:

- how mode is selected
- how config is loaded
- how runtime network options are parsed
- where client and server objects are created
- what periodic tasks the process keeps running

## Step 2: Understand The Configuration Model

Read:

- `ppp/configurations/AppConfiguration.h`
- `ppp/configurations/AppConfiguration.cpp`

Focus on:

- default values
- top-level config groups
- which behaviors are policy-driven instead of hard-coded
- IPv6-related normalization

## Step 3: Understand The Protected Transport Layer

Read:

- `ppp/transmissions/ITransmission.h`
- `ppp/transmissions/ITransmission.cpp`
- `ppp/transmissions/ITcpipTransmission.*`
- `ppp/transmissions/IWebsocketTransmission.*`

Focus on:

- handshake
- re-keying by `ivv`
- framing and read/write pipeline
- the difference between carrier transport and protected transmission

## Step 4: Understand The Tunnel Opcode Protocol

Read:

- `ppp/app/protocol/VirtualEthernetLinklayer.h`
- `ppp/app/protocol/VirtualEthernetLinklayer.cpp`
- `ppp/app/protocol/VirtualEthernetInformation.*`

Focus on:

- packet action enum
- control plane vs data plane actions
- information exchange
- how TCP, UDP, ICMP, FRP, static, and mux are all modeled inside one protocol family

## Step 5: Understand Auxiliary Packet Formats

Read:

- `ppp/app/protocol/VirtualEthernetPacket.h`
- `ppp/app/protocol/VirtualEthernetPacket.cpp`

Focus on:

- static UDP packet format
- session-based packet encryption
- checksum and obfuscation pipeline
- why this format exists separately from `VirtualEthernetLinklayer`

## Step 6: Read The Client Runtime

Read:

- `ppp/app/client/VEthernetNetworkSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`
- `ppp/app/client/VEthernetNetworkTcpipStack.*`
- `ppp/app/client/VEthernetNetworkTcpipConnection.*`

Focus on:

- TUN input handling
- route and DNS management
- proxy exposure
- connection and reconnection logic
- static mode, mux, mappings, and IPv6 application

## Step 7: Read The Server Runtime

Read:

- `ppp/app/server/VirtualEthernetSwitcher.*`
- `ppp/app/server/VirtualEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetNetworkTcpipConnection.*`

Focus on:

- listener setup
- session acceptance and establishment
- NAT forwarding
- UDP forwarding
- mappings and static mode
- IPv6 assignment and transit handling

## Step 8: Read Platform-Specific Integration

Read only after the core protocol is clear.

Windows:

- `windows/ppp/tap/*`
- `windows/ppp/win32/network/*`

Linux:

- `linux/ppp/tap/*`
- `linux/ppp/net/*`

macOS:

- `darwin/ppp/tun/*`
- `darwin/ppp/tap/*`

Android:

- `android/*`

Focus on:

- how each OS provides virtual adapter access
- how routes and DNS are manipulated
- what platform safety mechanisms exist to avoid route loops or broken sockets

## Step 9: Read The Go Backend Last

Read:

- `go/main.go`
- `go/ppp/*`
- `go/io/*`

Focus on:

- how the backend authenticates nodes
- how users and traffic quotas are stored
- how the C++ server talks to it over WebSocket

## Common Reading Mistakes

- reading platform code before understanding the shared protocol core
- confusing `ITransmission` framing with `VirtualEthernetPacket`
- treating the client and server exchangers as unrelated implementations
- assuming the Go backend is the data plane
- assuming route/DNS behavior is incidental instead of central to the design

## Best Companion Documents

- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`TUNNEL_DESIGN.md`](TUNNEL_DESIGN.md)
- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
- [`PLATFORMS.md`](PLATFORMS.md)
