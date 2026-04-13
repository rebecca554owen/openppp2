# Engineering Concepts

[中文版本](ENGINEERING_CONCEPTS_CN.md)

## Positioning

OPENPPP2 is positioned more like network infrastructure than like a consumer VPN application.

From the codebase, that means:

- one runtime is responsible for transport, session policy, route control, and adapter integration
- the system assumes operators understand topology and policy
- design effort is spent on state management, survivability, and explicit control, not on hiding complexity

## What The Project Optimizes For

### 1. Explicit network state

The code repeatedly makes route, DNS, session, IPv6, mapping, and listener state explicit in objects and configuration.

Examples:

- `AppConfiguration`
- `VirtualEthernetInformation`
- `VirtualEthernetInformationExtensions`
- `VirtualEthernetSwitcher`
- `VEthernetNetworkSwitcher`

This is closer to router software than to application-level tunneling.

### 2. Local autonomy

The runtime tries to enforce policy locally.

Examples visible in code:

- session validity is checked in the C++ process
- traffic statistics are maintained locally
- route and DNS policy are applied locally
- the server can bootstrap local session information even without a management backend

This fits infrastructure requirements where the forwarding process should not become useless the moment an external controller is unavailable.

### 3. Deterministic lifecycle ownership

Most core runtime objects own clear responsibilities:

- `PppApplication`: process lifecycle
- `ITransmission`: connection handshake and protected I/O lifecycle
- `VEthernetExchanger` / `VirtualEthernetExchanger`: session lifecycle
- `VEthernetNetworkSwitcher` / `VirtualEthernetSwitcher`: environment and system integration lifecycle

This is a deliberate style. The code avoids scattering lifecycle across too many unrelated helpers.

### 4. Shared protocol core across roles

Client and server share the same protocol vocabulary in `VirtualEthernetLinklayer`.

That reduces conceptual fragmentation. Instead of maintaining separate mini-protocols for each feature, the code extends one tunnel action model.

### 5. Platform specialization only where the host requires it

The system does not try to make Windows, Linux, macOS, and Android look identical internally.

Instead it keeps:

- protocol logic shared in `ppp/`
- adapter and route logic specialized in `windows/`, `linux/`, `darwin/`, `android/`

That is a practical infrastructure design choice.

## Why The System Is Complex

The codebase is complex because it is trying to solve several hard problems inside one runtime:

- protected transport
- virtual Ethernet forwarding
- route and DNS steering
- reverse service exposure
- static UDP paths
- multiplexed subchannels
- IPv6 assignment and enforcement
- platform-dependent network integration

Any documentation that pretends this is a tiny “VPN client” will fail to prepare readers for the actual design.

## Why Ease Of Use Is Not The Primary Goal

The code suggests the project is intended for operators who are willing to manage:

- addresses and masks
- gateways and route tables
- DNS policies
- mappings and reverse exposure
- transport types and certificates
- platform-dependent runtime behavior

This is consistent with infrastructure software. Routers, firewalls, and overlay gateways are rarely useful because they are “simple”; they are useful because they are explicit and controllable.

## Tunnel Design Concepts

The tunnel is not treated as a single opaque socket. It is divided into:

- carrier transport
- protected transmission and handshake
- tunnel action protocol
- platform I/O and route behavior

This separation is what allows the same runtime to support:

- TCP and WebSocket transport
- TUN/TAP integration
- FRP-style reverse mappings
- static UDP packet mode
- MUX connection reuse

## Control Plane Concepts

OPENPPP2 keeps control close to the data plane.

Examples:

- the management backend is optional rather than mandatory
- the server itself maintains session tables and IPv6 lease state
- the client itself maintains route and DNS steering decisions

That is important for infrastructure. Control-plane integration exists, but the local node still has to function as a networking system.

## Defense Concepts

From the code, the practical security posture is based more on disciplined state management than on marketing language.

Important defensive characteristics are:

- explicit handshake
- timeout-driven cleanup
- explicit session identity
- local validation of policy and expiry
- explicit firewall and route checks
- explicit feature gating by configuration

This is the right center of gravity for a system that wants to behave like network infrastructure.

## How To Read The Code With The Right Mindset

Do not read OPENPPP2 as if it were one algorithm.

Read it as a stack of cooperating subsystems:

1. process startup and lifecycle
2. configuration shaping
3. protected transport and framing
4. tunnel opcode protocol
5. client-side networking environment
6. server-side session switch
7. platform-specific adapter and route integration
8. optional management backend

That is the mental model the rest of the documentation follows.
