# Engineering Concepts

[中文版本](ENGINEERING_CONCEPTS_CN.md)

## Project Positioning

OPENPPP2 is positioned more like network infrastructure than like a consumer VPN application. This distinction is fundamental to understanding the architectural decisions and design philosophy that permeate throughout the codebase. While consumer VPN applications typically aim to provide a simple, transparent tunnel that hides all complexity from end users, OPENPPP2 takes a fundamentally different approach by exposing network internals to operators who manage the system.

From the codebase, that means:

- One runtime is responsible for transport, session policy, route control, and adapter integration. Rather than splitting these concerns across separate processes or microservices, OPENPPP2 consolidates them into a single runtime that manages the entire lifecycle of network operations. This design choice prioritizes consistency and atomicity of network state over separation of concerns that would require inter-process communication and synchronization.

- The system assumes operators understand topology and policy. Unlike consumer applications that guide users through simplified interfaces with defaults for every decision, OPENPPP2 exposes full control over network configuration. Operators are expected to understand concepts such as CIDR notation, subnet masks, gateway addressing, DNS forwarding rules, and routing tables. This assumption allows the system to provide complete flexibility without the overhead of user-friendly abstraction layers that would limit what's possible.

- Design effort is spent on state management, survivability, and explicit control, not on hiding complexity. The codebase invests heavily in making network state visible and manageable. Every aspect of the tunnel, from packet forwarding to session lifecycle to routing decisions, is exposed through configuration and observable through logging. Complexity is managed through explicit handling rather than abstraction.

This positioning directly influences how the system handles failure modes, scales, and integrates with existing network infrastructure. Unlike overlay networks that attempt to hide behind simple APIs, OPENPPP2 integrates at the network layer, requiring operators to understand the interaction between virtual networks and physical infrastructure.

## What The Project Optimizes For

OPENPPP2 optimizes for a specific set of characteristics that reflect its infrastructure positioning. These optimization targets shape every architectural decision, from object design to module boundaries to error handling strategies.

### 1. Explicit Network State

The code repeatedly makes route, DNS, session, IPv6, mapping, and listener state explicit in objects and configuration. This is a deliberate departure from systems that treat network state as implicit or hidden from configuration. Every significant piece of network state in OPENPPP2 has a corresponding configuration object or observable interface.

Examples of explicit state objects include:

- `AppConfiguration`: This is the top-level configuration container that holds all runtime parameters. It explicitly specifies transport types, session parameters, adapter configurations, and routing policies. Unlike systems that derive configuration through inference or environment detection, AppConfiguration requires operators to specify their intent explicitly.

- `VirtualEthernetInformation`: This object maintains the complete state of the virtual Ethernet adapter, including MAC address, MTU settings, link status, and packet statistics. All of these state elements are first-class citizens that can be queried, modified through runtime operations, and observed through the management interface.

- `VirtualEthernetInformationExtensions`: This extends the base virtual Ethernet state with platform-specific extensions. Different platforms (Windows, Linux, macOS, Android) have different networking capabilities and constraints. Rather than normalizing these differences away, the extensions make platform-specific state explicit, allowing operators to understand what's possible on each platform.

- `VirtualEthernetSwitcher` and `VEthernetNetworkSwitcher`: These objects manage the switching behavior of virtual Ethernet frames. They maintain explicit state about VLAN configurations, bridge memberships, and forwarding rules. Rather than implicitly forwarding frames based on simple MAC learning, these switchers allow operators to define precise forwarding policies.

This approach is closer to router software than to application-level tunneling. In router software, every forwarding decision is based on explicitly configured rules and observable state tables. OPENPPP2 follows this model, providing operators with complete visibility into and control over packet processing.

The benefits of explicit state become clear when troubleshooting. With implicit state, operators must reason about what the system might be doing internally. With explicit state, they can inspect actual objects, query configuration values, and understand exactly what decisions the system will make. This transparency is essential for infrastructure that must integrate with complex existing networks and comply with organizational policies.

### 2. Local Autonomy

The runtime tries to enforce policy locally. Rather than depending on external controllers for every decision, OPENPPP2 maintains the capability to operate independently when connectivity to management systems is impaired. This design priority reflects infrastructure requirements where network availability is critical and must not depend on control plane connectivity.

Examples visible in code:

- Session validity is checked in the C++ process. The session lifecycle is managed locally, with periodic validity checks that don't require external validation. If the management backend becomes unreachable, existing sessions continue to operate based on locally cached policy information. This prevents sudden session terminations that would disrupt connectivity.

- Traffic statistics are maintained locally. Byte counters, packet counters, and bandwidth utilization are tracked within the runtime process. These statistics are available immediately without needing to query external systems. During network partitions, operators can still observe traffic patterns and make informed capacity decisions.

- Route and DNS policy are applied locally. The runtime applies routing and DNS policies without round-trips to external systems. Each packet is classified and forwarded based on locally available policy, ensuring that routing decisions are made within bounded latency regardless of external system availability.

- The server can bootstrap local session information even without a management backend. Server implementations include fallback mechanisms that allow initial session establishment using locally configured credentials and certificates. This enables deployment scenarios where the management backend is brought online after initial startup.

This fits infrastructure requirements where the forwarding process should not become useless the moment an external controller is unavailable. Critical infrastructure must continue operating through network partitions, equipment failures, and management system outages. By maintaining local autonomy, OPENPPP2 ensures that transient control plane failures don't cascade into data plane outages.

The local autonomy design also simplifies deployment architecture. Operators don't need to deploy high-availability management infrastructure before deploying the tunneling system. They can start with simple configurations and add management integration incrementally as operational maturity increases.

### 3. Deterministic Lifecycle Ownership

Most core runtime objects own clear responsibilities. This deterministic ownership model simplifies reasoning about system behavior and ensures that lifecycle management follows predictable patterns. Rather than distributing lifecycle responsibilities across many small objects with unclear ownership, OPENPPP2 concentrates lifecycle ownership in well-defined objects.

Core lifecycle ownership examples:

- `PppApplication`: Manages process lifecycle from startup through shutdown. This object coordinates all initialization steps, handles signals and termination requests, and ensures clean shutdown of all child components. The clear ownership ensures that process resources are properly released regardless of shutdown cause.

- `ITransmission`: Manages connection handshake and protected I/O lifecycle. This interface controls TCP connection establishment, TLS handshakes, and the subsequent protected read/write operations. By encapsulating connection lifecycle in this interface, the code ensures consistent connection handling across different transport types.

- `VEthernetExchanger` / `VirtualEthernetExchanger`: These objects manage session lifecycle. They handle session establishment, authentication, negotiation of capabilities, and session termination. The session lifecycle is complex, involving multiple round-trips and state transitions, and these objects ensure that transitions happen correctly.

- `VEthernetNetworkSwitcher` / `VirtualEthernetSwitcher`: These manage environment and system integration lifecycle. They coordinate with platform-specific networking APIs, handle virtual adapter creation and deletion, and manage system-level resource allocation. Platform integration involves many subtle interactions, and these objects consolidate that complexity.

This is a deliberate style. The code avoids scattering lifecycle across too many unrelated helpers. In some codebases, lifecycle responsibilities are distributed across many small helper objects, making it difficult to understand what happens at each phase. By consolidating lifecycle ownership, OPENPPP2 makes it easier to understand and verify system behavior.

Deterministic lifecycle ownership also simplifies testing. Each well-defined lifecycle owner can be tested in isolation, and integration tests can verify that ownership boundaries are respected. This approach reduces test complexity and increases confidence in system behavior.

### 4. Shared Protocol Core Across Roles

Client and server share the same protocol vocabulary in `VirtualEthernetLinklayer`. Rather than maintaining separate protocol implementations for client and server, OPENPPP2 uses a single protocol definition that both sides understand. This design reduces conceptual fragmentation and ensures consistent behavior.

The sharing works as follows:

- Both client and server use the same message formats for tunnel establishment, data transfer, and session management. There is no client-specific or server-specific subset of the protocol; both sides use the complete protocol.

- The protocol is designed as a symmetric exchange rather than an asymmetric request-response model. Either side can initiate actions within the session, allowing for bidirectional communication patterns.

- Extensions to the protocol apply to both client and server uniformly. New features can be added without needing to coordinate client and server versions separately.

That reduces conceptual fragmentation. Instead of maintaining separate mini-protocols for each feature, the code extends one tunnel action model. Each new capability is added as an extension to the existing protocol rather than a replacement. This approach simplifies understanding and evolution of the protocol.

The shared protocol also simplifies testing. Test tools can use the same protocol implementation to act as either client or server, allowing comprehensive testing without needing separate client and server test implementations.

### 5. Platform Specialization Only Where The Host Requires It

The system does not try to make Windows, Linux, macOS, and Android look identical internally. Some abstractions are possible across platforms, but OPENPPP2 recognizes that network integration fundamentally differs between operating systems and that pretending otherwise leads to subtle bugs and performance issues.

Instead it keeps:

- Protocol logic shared in `ppp/`. The core tunnel protocol, session management, and data forwarding logic is platform-independent. This code handles message formats, state machines, and forwarding decisions without platform-specific branches.

- Adapter and route logic specialized in `windows/`, `linux/`, `darwin/`, `android/`. Each platform directory contains code specific to that platform's networking APIs. This includes socket operations, interface configuration, routing table manipulation, and system notification handling. Platform-specific code is isolated but interconnected through well-defined interfaces.

This separation allows platform-specific optimizations while maintaining protocol consistency. Each platform can use its native APIs for best performance and compatibility while sharing the core protocol implementation.

That is a practical infrastructure design choice. Infrastructure software must integrate correctly with each platform's networking stack. Attempting to abstract away platform differences inevitably leads to either missing functionality or poor performance. By accepting platform specialization, OPENPPP2 provides full functionality on each supported platform.

Platform specialization also enables rapid adoption of platform-specific features. When a platform introduces new networking capabilities, they can be integrated directly without needing to modify platform-agnostic code or worry about compatibility with other platforms.

## Why The System Is Complex

The codebase is complex because it is trying to solve several hard problems inside one runtime. This complexity is not accidental but reflects the genuine difficulty of the problems being solved. Understanding why complexity exists helps operators appreciate the system's capabilities.

The system addresses multiple problem domains simultaneously:

- Protected transport. The tunnel must secure all traffic between endpoints, using modern cryptographic protocols. This includes certificate management, key exchange, cipher negotiation, and encrypted frame handling. Transport security is essential for deployment in untrusted networks.

- Virtual Ethernet forwarding. The system implements full Ethernet bridging at the tunnel layer. This includes MAC address learning, frame forwarding, VLAN support, and broadcast handling. Virtual Ethernet forwarding enables integration with existing Ethernet-based infrastructure.

- Route and DNS steering. The system can override routing decisions and DNS resolution for traffic passing through the tunnel. This enables split-tunneling configurations where some traffic goes through the tunnel while other traffic uses direct Internet paths. Route and DNS steering are complex because they must integrate with existing networking configuration without causing conflicts.

- Reverse service exposure. The system can expose local services through the tunnel to remote clients. This enables scenarios where remote clients access services on the local network as if they were locally connected. Reverse exposure requires mapping address spaces, handling NAT traversal, and managing service registration.

- Static UDP paths. The system supports UDP-based transport for latency-sensitive traffic. UDP provides lower latency than TCP but requires additional handling for NAT traversal and connection tracking. Static UDP paths are useful for real-time applications that can tolerate some packet loss.

- Multiplexed subchannels. The system can carry multiple logical connections over a single tunnel. Multiplexing improves efficiency by sharing a single handshake and encryption context across multiple streams. Subchannel management adds complexity but significantly improves performance for many concurrent connections.

- IPv6 assignment and enforcement. The system must handle IPv6 alongside IPv4. This includes address assignment, neighbor discovery, and IPv6-specific routing policies. IPv6 support is increasingly important as IPv4 address space exhaustion continues.

- Platform-dependent network integration. Each platform has different networking capabilities and APIs. The system must correctly integrate with Windows networking APIs, Linux netfilter/iptables, macOS network extensions, and Android VPN service APIs. Platform integration is complex because each platform's networking model differs fundamentally.

Any documentation that pretends this is a tiny "VPN client" will fail to prepare readers for the actual design. The complexity exists because the problems are genuinely hard. Attempting to simplify the description would misrepresent the system's capabilities and lead to misaligned expectations.

Complexity also provides capability. The same complexity that makes the system difficult to understand also enables its advanced features. Operators who understand the complexity can leverage the system's full capabilities in ways that simpler systems cannot support.

## Why Ease Of Use Is Not The Primary Goal

The code suggests the project is intended for operators who are willing to manage complexity in exchange for capability. OPENPPP2 targets professional operators rather than end users, and this targeting influences every design decision.

The system expects operators to manage:

- Addresses and masks. Operators must understand CIDR notation, subnet masks, and address allocation. For complex configurations, they must design address schemes that avoid conflicts with existing networks. This understanding is fundamental to IP networking.

- Gateways and route tables. Operators must understand routing concepts including default routes, static routes, and route metrics. They must design routing policies that correctly forward traffic based on destination addresses. Routing is complex because multiple routes can match, and the most specific route wins.

- DNS policies. Operators must understand DNS resolution, DNS zones, and DNS forwarding. They must configure DNS policies that correctly resolve names while respecting organizational policies. DNS configuration interacts with routing configuration.

- Mappings and reverse exposure. Operators must understand address mapping, port mapping, and service exposure. They must configure reverse proxies that correctly expose local services to remote clients. Mappings require understanding of address translation and NAT.

- Transport types and certificates. Operators must understand the differences between TCP, WebSocket, and UDP transports. They must manage certificates for TLS-based transports, understanding certificate chains, expiration, and renewal. Transport selection affects performance and compatibility.

- Platform-dependent runtime behavior. Operators must understand how the system behaves differently on each platform. They must adjust configurations based on platform capabilities and limitations. Platform differences affect available features and performance characteristics.

This is consistent with infrastructure software. Routers, firewalls, and overlay gateways are rarely useful because they are "simple"; they are useful because they are explicit and controllable. Professional infrastructure operators value control and visibility over simplicity. They are willing to invest in understanding complex systems because that understanding translates into operational capability.

Consumer VPN applications optimize for ease of use because their users are not network experts and won't invest in understanding complexity. Infrastructure software optimizes for control because its users are operators who need complete control over their network configurations.

The design philosophy prioritizes capability over ease of use. As a result, the learning curve is steeper, but the operational capability is greater. Operators who invest in understanding OPENPPP2 gain access to features and control that consumer VPN applications cannot provide.

## Tunnel Design Concepts

The tunnel is not treated as a single opaque socket. It is divided into multiple layers, each handling a specific concern. This separation enables flexibility in transport selection, platform integration, and feature development.

The tunnel architecture divides functionality into four main layers:

- Carrier transport. This layer handles the underlying transport protocol used to carry tunnel traffic. It supports TCP, WebSocket, and UDP transports. Each transport has different characteristics: TCP provides reliability, WebSocket provides HTTP compatibility, and UDP provides low latency. The carrier transport layer abstracts these differences.

- Protected transmission and handshake. This layer handles TLS handshake, key exchange, and encrypted-frame handling. It ensures that all tunnel traffic is protected using strong cryptography. The handshake layer manages certificate validation, cipher negotiation, and session key establishment.

- Tunnel action protocol. This layer defines the messages exchanged between client and server. It includes messages for session establishment, data transfer, and session management. The action protocol is defined in `VirtualEthernetLinklayer` and is shared across all transport types.

- Platform I/O and route behavior. This layer handles interaction with platform-specific networking APIs. It manages TUN/TAP device operations on each platform, handles routing table updates, and coordinates with platform firewalls. This layer enables the tunnel to integrate with each platform's networking stack.

This separation allows the same runtime to support diverse configurations:

- TCP and WebSocket transport. Both are supported through the carrier transport abstraction. TCP uses native sockets, while WebSocket adds a framing layer over HTTP. Operators can choose based on their network environment.

- TUN/TAP integration. The platform I/O layer abstracts the differences between TUN (IP-level) and TAP (Ethernet-level) devices. Operators can use either depending on their integration requirements.

- FRP-style reverse mappings. Reverse exposure uses the tunnel action protocol to expose local services. The protocol includes messages for service registration and address mapping that enable complex reverse proxy configurations.

- Static UDP packet mode. UDP transport uses the carrier transport layer with UDP-specific handling. This mode provides lower latency for applications that can tolerate some packet loss.

- MUX connection reuse. Multiplexing combines multiple logical streams over a single transport connection. The MUX subchannel handling is integrated into the tunnel action protocol.

The layered architecture enables evolution. New transport types can be added by implementing a new carrier transport. New features can be added to the tunnel action protocol. Platform integration can be improved by updating the platform I/O layer. This separation of concerns enables incremental development without affecting other layers.

## Control Plane Concepts

OPENPPP2 keeps control close to the data plane. Rather than requiring all control decisions to go through an external management backend, the system can operate with local control while optionally integrating with external control systems.

The control plane design reflects infrastructure requirements:

- The management backend is optional rather than mandatory. The system can operate with local configuration files alone. This enables deployment scenarios where management infrastructure is not available or not desired. Operators can start with local configuration and add management integration gradually.

- The server itself maintains session tables and IPv6 lease state. Server-side session management is fully local. The server tracks active sessions, their authentication state, and their resource usage. IPv6 address allocation and lease tracking are also local. This ensures that the server can continue operating independently.

- The client itself maintains route and DNS steering decisions. Client-side routing and DNS policies are applied locally. The client evaluates each packet's destination and applies routing policy without consulting external systems. This ensures that routing decisions are made immediately.

That is important for infrastructure. Infrastructure systems must continue operating through management outages and network partitions. Control-plane integration exists, but the local node still has to function as a networking system. The management backend provides centralized policy and visibility, but the local node provides operational continuity.

The control plane design also simplifies deployment. Organizations can deploy OPENPPP2 without deploying management infrastructure. They can add management integration later if needed. This flexibility enables a range of deployment scenarios from fully autonomous to fully managed.

## Defense Concepts

From the code, the practical security posture is based more on disciplined state management than on marketing language. Rather than making broad security claims, the system implements specific defensive measures that can be verified and understood.

Important defensive characteristics include:

- Explicit handshake. The tunnel establishes through a defined handshake protocol before any data transfers. This handshake validates peer identity and negotiates security parameters. The explicit handshake ensures that both parties consent to the connection.

- Timeout-driven cleanup. Unused sessions and resources are cleaned up through timeout mechanisms. This prevents resource accumulation when peers become unavailable. Timeout behavior is predictable and configurable.

- Explicit session identity. Each session has a unique identifier that can be tracked through logs and management interfaces. Session identity enables auditing and troubleshooting. Explicit identity also enables session management operations like forced termination.

- Local validation of policy and expiry. Session policies are validated locally before application. This ensures that local policy overrides are enforced even if management policy changes. Local validation provides defense in depth.

- Explicit firewall and route checks. All packet forwarding goes through explicit firewall and route checks. There is no implicit packet passing. Each packet is evaluated against configured policies before forwarding.

- Explicit feature gating by configuration. Features are enabled or disabled through explicit configuration. There are no hidden features or unconfigurable behaviors. This ensures that operators know exactly what capabilities are active.

This is the right center of gravity for a system that wants to behave like network infrastructure. Security claims without specifics are not useful for operators who must verify and justify their system's security posture. OPENPPP2's defensive characteristics can be audited, tested, and verified. The focus on practical security rather than marketing language reflects the infrastructure orientation.

## How To Read The Code With The Right Mindset

Do not read OPENPPP2 as if it were one algorithm. It's not a single function that processes input into output. It's a complex system with multiple interacting components, each handling different concerns.

Read it as a stack of cooperating subsystems. Understanding the subsystem stack provides context for individual components:

1. Process startup and lifecycle. At the bottom, the process manages its own lifecycle. This includes argument parsing, configuration loading, signal handling, and graceful shutdown. All other subsystems depend on correct lifecycle management.

2. Configuration shaping. Above lifecycle, configuration objects shape system behavior. This includes configuration parsing, validation, and object construction. Configuration provides the parameters that all other subsystems use.

3. Protected transport and framing. The transport layer handles connection establishment and frame protection. This includes TLS handshake, cipher selection, and encrypted frame handling. All tunnel traffic passes through this layer.

4. Tunnel opcode protocol. The protocol layer defines the messages exchanged between peers. This includes session establishment messages, data transfer messages, and control messages. The protocol provides semantic meaning to transported frames.

5. Client-side networking environment. On the client, this subsystem manages virtual adapter state, routing policy, and DNS configuration. It intercepts and redirects network traffic based on policy.

6. Server-side session switch. On the server, this subsystem manages session state, address allocation, and packet forwarding. It coordinates between multiple clients and the local network.

7. Platform-specific adapter and route integration. At the platform layer, each subsystem integrates with platform networking APIs. This includes socket operations, interface configuration, and routing table manipulation.

8. Optional management backend. At the top, the management backend provides centralized control and visibility. This subsystem is optional and is not required for basic operation.

That is the mental model the rest of the documentation follows. Understanding the subsystem stack helps operators locate features in the codebase and understand how components interact. When troubleshooting or extending the system, understanding which subsystem handles the relevant concern guides investigation.