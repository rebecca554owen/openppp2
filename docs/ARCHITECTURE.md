# System Architecture

[中文版本](ARCHITECTURE_CN.md)

## Scope

This is the top-level architecture map for OPENPPP2. It explains how the repository is divided, where the shared core ends, and where host-specific behavior begins.

The map is code-driven. The relevant anchors are `main.cpp`, `ppp/configurations/AppConfiguration.*`, `ppp/transmissions/*`, `ppp/app/protocol/*`, `ppp/app/client/*`, `ppp/app/server/*`, and the platform directories.

## Main Idea

OPENPPP2 is a virtual Ethernet infrastructure runtime. It is built from a shared protocol core plus host-specific consequences.

## Core Layout

```mermaid
graph TD
    A[main.cpp] --> B[AppConfiguration]
    A --> C[ITransmission]
    A --> D[Client runtime]
    A --> E[Server runtime]
    B --> C
    C --> F[VirtualEthernetLinklayer]
    D --> G[VEthernetNetworkSwitcher]
    D --> H[VEthernetExchanger]
    E --> I[VirtualEthernetSwitcher]
    E --> J[VirtualEthernetExchanger]
    G --> K[Platform layer]
    I --> K
    I --> L[go/* optional backend]
```

## Shared Core Vs Host Consequences

The most important split is this:

| Area | Responsibility |
|---|---|
| Shared core | Configuration, transport, handshake, framing, link-layer actions |
| Host consequences | Adapter creation, route changes, DNS changes, firewall behavior, platform-specific IPv6 and socket handling |

Shared core logic can be reused. Host consequences cannot be assumed to match across operating systems.

## Shared Core

The shared core owns tunnel semantics:

- `AppConfiguration` decides runtime shape
- `ITransmission` owns carrier, handshake, framing, and protected I/O
- `VirtualEthernetLinklayer` owns tunnel action vocabulary
- client and server exchangers own session-level behavior

```mermaid
flowchart TD
    A[Configuration load] --> B[Normalize AppConfiguration]
    B --> C[Choose carrier and role]
    C --> D[ITransmission]
    D --> E[Handshake]
    E --> F[VirtualEthernetLinklayer]
    F --> G[Client exchanger]
    F --> H[Server exchanger]
```

## Host Consequences

The platform layer owns local operating-system side effects:

- virtual interface setup
- route table changes
- DNS changes
- socket protection
- platform-specific IPv6 behavior

These are not implementation details that can be hand-waved away. They are part of the observable runtime behavior.

## Runtime Entry

`main.cpp` is the C++ entry point and process coordinator. Its flow is:

1. parse arguments
2. load configuration
3. normalize configuration
4. choose role
5. prepare host environment
6. start client or server runtime
7. run the maintenance tick loop
8. report status
9. cleanly shut down

```mermaid
stateDiagram-v2
    [*] --> ArgsParsed
    ArgsParsed --> ConfigLoaded
    ConfigLoaded --> ConfigNormalized
    ConfigNormalized --> RoleChosen
    RoleChosen --> HostPrepared
    HostPrepared --> RuntimeStarted
    RuntimeStarted --> MaintenanceLoop
    MaintenanceLoop --> Shutdown
    Shutdown --> [*]
```

## Object Ownership

| Level | Owner |
|---|---|
| Process | `PppApplication` |
| Environment | `VEthernetNetworkSwitcher` or `VirtualEthernetSwitcher` |
| Session | `VEthernetExchanger` or `VirtualEthernetExchanger` |
| Connection | `ITransmission` |

## Role Asymmetry

The client and server are not symmetric:

- client: host integration, routing, DNS, proxy, mapping, optional static and mux behavior
- server: listener setup, session switching, forwarding, mapping, IPv6, optional backend integration

```mermaid
graph LR
    A[Client] --> B[Route/DNS steering]
    A --> C[Local proxy surfaces]
    A --> D[Remote session exchange]
    E[Server] --> F[Listener setup]
    E --> G[Session switching]
    E --> H[Forwarding]
    E --> I[Optional management backend]
```

## Configuration As Architecture

`AppConfiguration` is architectural, not just parsing code. It determines which transports are enabled, which listeners are opened, what key material is used, and how client/server policy is shaped.

## Transmission Versus Protocol

| Layer | Owns |
|---|---|
| Transmission | Carrier selection, handshake, frame protection, cipher state |
| Protocol | Session meaning, opcode meaning, tunnel semantics |

## Related Documents

- `CLIENT_ARCHITECTURE.md`
- `SERVER_ARCHITECTURE.md`
- `TUNNEL_DESIGN.md`
- `STARTUP_AND_LIFECYCLE.md`
