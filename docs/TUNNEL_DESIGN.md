# Tunnel Design Deep Dive

[中文版本](TUNNEL_DESIGN_CN.md)

## Why This Document Exists

OPENPPP2 does not treat a tunnel as "just an encrypted socket". This is a critical design philosophy that sets it apart from simpler tunnel implementations that treat the connection as a simple pipe for encrypted bytes.

From examining the codebase, the tunnel is deliberately and thoughtfully split into multiple distinct layers. This architectural decision is not accidental—it is the fundamental reason why the system can simultaneously support an impressive range of capabilities:

- **TCP and WebSocket carriers**: The ability to transport tunnel traffic over either raw TCP connections or WebSocket protocol, enabling traversal of HTTP-aware proxies and firewalls
- **Virtual Ethernet forwarding**: Full Layer 2 Ethernet frame tunneling that allows the remote endpoint to appear as a real network interface on the local system
- **Session policy and information exchange**: Rich metadata exchange between peers to negotiate capabilities, exchange network information, and establish session-specific behaviors
- **FRP-style reverse mappings**: The ability to expose local services to the remote side, similar to how FRP (Fast Reverse Proxy) enables inbound connections through a relay server
- **Static UDP packet mode**: A dedicated mode for handling UDP datagrams that need to traverse the tunnel with different semantics than TCP traffic
- **Mux-based subchannels**: Multiplexing capability that allows multiple logical streams to share a single underlying connection, improving efficiency
- **Platform-specific route and adapter behavior**: Different handling logic for different operating systems and network environments

Each of these capabilities would be extremely difficult to implement if the tunnel were designed as a monolithic protocol. The layered approach allows each concern to be addressed independently while maintaining clean interfaces between layers.

## Layer 1: Carrier Transport (The Foundation)

The outermost layer is the transport carrier—the underlying socket mechanism used to move bytes between the two tunnel endpoints. This is literally the "pipe" that connects the peers.

The following implementations exist in the codebase:

- `ITcpipTransmission`: Plain TCP/IP transport that establishes raw TCP connections between peers. This is the most basic transport mechanism and provides the lowest overhead when direct TCP connectivity is available.

- `IWebsocketTransmission`: WebSocket protocol transport that tunnels data over WebSocket frames. WebSocket is an application-layer protocol that starts as an HTTP upgrade request and then switches to a bidirectional binary frame format. This is particularly useful when traversing HTTP proxies, load balancers, or firewalls that understand HTTP but not raw TCP tunnels.

- `ISslWebsocketTransmission`: WebSocket over TLS (Transport Layer Security). This adds encryption at the TLS layer in addition to the tunnel's own encryption. It provides better privacy guarantees and can sometimes work better with certain middleboxes that inspect or manipulate TLS traffic.

This layer decides **only** how bytes move from one end to the other:

- Raw TCP connections with no application-layer protocol overhead
- WebSocket frames that add framing and can pass through HTTP-aware infrastructure
- WebSocket over TLS that adds another layer of encryption and authentication

Everything else—the actual tunnel semantics, the protocol operations, the virtual network interface—sits above this layer. This separation allows the same high-level tunnel logic to work over any of these transport mechanisms without modification.

## Layer 2: Protected Transmission (The Security Foundation)

`ITransmission` builds a protected framing layer on top of the raw carrier transport. This is where the cryptographic protection and connection management happens.

This layer owns the following critical responsibilities:

- **Handshake timeout**: Connection establishment must complete within a reasonable time. The timeout mechanism prevents resources from being tied up indefinitely by failed or stalled handshakes. If the handshake does not complete in time, the connection is terminated and resources are cleaned up.

- **Handshake sequencing**: The specific order and types of messages that must be exchanged to transition from "not connected" to "connected" state. This includes version negotiation, capability exchange, and cryptographic parameter agreement.

- **Session identifier exchange**: Each connection receives a unique session identifier that can be used for logging, debugging, correlation, and in some cases for deriving session-specific cryptographic keys.

- **Per-connection re-keying by `ivv`**: The initialization vector variation (`ivv`) is a runtime value that gets mixed with the configured keys to produce unique cryptographic contexts for each connection. This prevents the situation where all connections share exactly the same encryption state.

- **Read/write framing**: Raw bytes from the carrier are framed into discrete messages with length prefixes, checksums, and optional additional protection. This ensures complete messages are delivered and allows the receiver to know how much data to expect.

- **Protocol-layer cipher**: Encryption applied to the tunnel's internal protocol messages (control messages, keepalives, etc.)

- **Transport-layer cipher**: Encryption applied to the actual payload data being forwarded through the tunnel.

### Why This Layer Exists

Without this layer, every carrier implementation would need to understand all session bootstrapping details directly. This would lead to code duplication and inconsistency—if the handshake logic was implemented separately in TCP and WebSocket carriers, they might behave differently in subtle ways.

The code instead centralizes those concerns once in `ITransmission`. Each carrier implementation simply wraps the raw socket and delegates all security, framing, and session management to this shared layer. This means:

1. **Consistency**: All carriers behave identically from a security and session perspective
2. **Maintainability**: Fixes and improvements to security logic only need to happen in one place
3. **Extensibility**: Adding a new carrier (e.g., QUIC in the future) only requires implementing the raw socket handling

## Handshake Design (Establishing Trust)

The transport handshake performs much more than just "connect and hope it works." From analyzing the code, it simultaneously establishes several critical pieces of state:

- **A session ID**: A unique identifier for this particular connection. This ID is used for logging, correlation, and sometimes for cryptographic purposes.

- **Mux orientation**: Whether this connection will participate in multiplexing. Some connections are dedicated to a single logical stream, while others will carry multiple subchannels.

- **Per-connection key variation through `ivv`**: The runtime `ivv` value is incorporated into the key derivation process, ensuring that even if the configured keys are the same, each connection gets a unique cryptographic context.

- **The transition into handshaked framing behavior**: Before handshake, the connection might use different framing rules (or no framing at all). After successful handshake, the full framing protocol takes effect.

An interesting implementation detail: the code sends "handshake dummy traffic"—meaningless bytes that are sent before the real handshake values are accepted. This serves multiple possible purposes:

1. It warms up the connection and allows TCP slow-start to progress
2. It can help detect certain types of network issues early
3. It provides a buffer of data that can be discarded if something goes wrong during handshake
4. It makes the handshake appear more like normal traffic to observers

Regardless of the exact operational motivation, the code clearly treats the early phase of the connection as special and more conservative than steady-state traffic. This is a good engineering practice—it applies extra scrutiny during the vulnerable bootstrapping phase.

## Why Re-Key After Handshake

After the handshake completes, the code derives new `protocol_` and `transport_` cipher instances using the configured keys **plus** the runtime `ivv` value that was negotiated during handshake.

This is a significant design decision with important implications:

- **Configured keys are base secrets**: The keys in the configuration file are not used directly as working keys. Instead, they serve as master secrets from which session-specific keys are derived.

- **Each established connection gets unique working ciphers**: Even if multiple connections use identical configuration, each one derives its own independent cryptographic context.

From an engineering perspective, this gives the transport layer several important properties:

- **Per-session variability**: An attacker who compromises one session's keys cannot immediately compromise other sessions that used the same configuration. Each session's traffic looks cryptographically different.

- **Reduced dependency on static key state**: The system does not rely on a single static key being secure forever. Even if the configured key were somehow exposed, the exposure is limited to sessions that used that specific `ivv` value.

- **Clean transition from bootstrap to established state**: The handshake phase and the data phase have different security contexts. This makes it easier to reason about what state is accessible at what point in the connection lifecycle.

This approach is similar to how TLS derives different keys for different purposes (client write, server write, etc.) and is a best practice in secure protocol design.

## Framing Design (Structuring the Stream)

After the carrier socket is established, bytes are not sent raw. They are passed through framed read/write logic that adds structure to the byte stream.

The implementation includes several components:

- **Length handling**: Each frame begins with a length field that tells the receiver how many bytes to expect in the payload. This prevents ambiguity about where one message ends and another begins.

- **Optional protocol-layer protection of length/header data**: The length and other header fields can be encrypted or integrity-protected separately from the payload. This prevents an attacker from learning message sizes or other metadata.

- **Payload transformation**: The actual tunnel data (Ethernet frames, protocol messages) goes through encryption and possibly other transformations before being sent.

- **Optional formatting behavior that changes pre- and post-handshake**: Before the handshake completes, the framing might be simpler or different. After handshake, full security and framing take effect.

### Why This Framing Exists

Because the tunnel must carry **structured** actions and payloads, not only arbitrary byte streams. Consider:

- Virtual Ethernet frames have specific formats (Ethernet header, IP header, TCP/UDP header, etc.)
- Protocol messages have specific opcodes and payloads
- The tunnel needs to distinguish between control messages and data messages

The framing layer gives the upper protocol a stable substrate that is independent of whether the carrier is TCP or WebSocket. It provides:

1. **Message boundaries**: Clear delineation between discrete messages
2. **Metadata protection**: Optional hiding of message sizes and types
3. **Carrier independence**: The same high-level logic works over any transport

## Layer 3: Tunnel Action Protocol (The Application Logic)

Above `ITransmission`, `VirtualEthernetLinklayer` defines the actual tunnel protocol used by the application runtime. This is where the tunnel's purpose is fulfilled—moving traffic and coordinating between peers.

This layer models a rich set of operations:

- `INFO`: Network information exchange. This allows peers to tell each other about their local network configuration, capabilities, and other metadata.

- `KEEPALIVED`: Keepalive messages that verify the tunnel is still alive and functioning. These are essential for detecting when the remote peer has become unreachable.

- `LAN`: Local Area Network advertisements. This tells the remote side what IP addresses and subnets are locally reachable.

- `NAT`: Network Address Translation information. This helps the tunnel understand how to properly route traffic when one or both endpoints are behind NAT.

- `SYN`, `SYNOK`, `PSH`, `FIN`: TCP connection lifecycle messages. These model the TCP three-way handshake and connection termination within the tunnel.

- `SENDTO`: Send-to operation for UDP-style datagram delivery. This carries UDP packets through the tunnel.

- `ECHO`, `ECHOACK`: Echo request and reply for connectivity testing. These are similar to ICMP echo but operate at the tunnel level.

- `STATIC`, `STATICACK`: Static path negotiation. These messages set up the dedicated UDP path when using static mode.

- `MUX`, `MUXON`: Multiplexing negotiation. These messages negotiate whether to enable multiplexing and how to manage subchannels.

- `FRP_*`: FRP-style reverse proxy operations. These handle the exposure of local services to the remote side.

### Why This Action Model Exists

Because OPENPPP2 is not only forwarding one class of traffic. It needs **one unified internal vocabulary** that can represent:

- **Routed payload traffic**: The actual data being forwarded from one network to another
- **TCP stream control**: Connection establishment, data transfer, and graceful termination
- **UDP datagram relay**: Connectionless packet delivery
- **Reverse service exposure**: Making local services available to the remote network (like FRP)
- **Keepalive and health signals**: Verifying connectivity and detecting failures
- **Mux negotiation**: Establishing and managing multiplexed subchannels
- **Static-path negotiation**: Setting up the optimized UDP data path

If these were all treated as "just packets," the code would lose the ability to handle them appropriately. TCP connections need different handling than UDP datagrams; FRP mappings need different handling than regular routing. The opcode model captures these semantic differences.

## Layer 4: Virtual Packet Format For Static UDP Paths

`VirtualEthernetPacket` is a separate encapsulation path used specifically for static-style packet transport. While `VirtualEthernetLinklayer` handles the general opcode-driven communication, this layer handles a specific use case with different requirements.

It is distinct from `VirtualEthernetLinklayer` and carries additional information:

- **Pseudo source/destination metadata**: Since UDP packets traverse the tunnel differently than TCP streams, additional metadata about the original source and destination is needed to properly deliver packets.

- **Per-packet mask and checksum**: Each packet can have its own integrity check and optional obfuscation mask. This is different from the connection-level encryption in the main tunnel.

- **Per-session crypto selection**: Different sessions might use different cryptographic algorithms or parameters. The packet format supports this flexibility.

- **Packet-level shuffle/XOR/delta stages**: Additional transformations that can be applied to individual packets for various purposes (obfuscation, compression, etc.).

### Why It Is Separate

Because static UDP transport has fundamentally different needs from the opcode-driven link layer:

1. **Different delivery semantics**: TCP is stream-oriented; UDP is datagram-oriented. The packet format must preserve datagram boundaries.

2. **Different state management**: TCP connections have stateful lifecycles; UDP packets are independent.

3. **Different optimization opportunities**: UDP can often be optimized in ways that don't make sense for TCP.

The code treats `VirtualEthernetPacket` as a **packetized transport path** rather than as a stream of control actions. This separation allows each to be optimized for its specific use case without compromising the other.

## Why The Tunnel Is Not One Flat Protocol

If all behaviors were merged into one flat protocol—where every message is just a type-number and payload—the implementation would become much harder to evolve. Consider what would happen if we tried to combine:

- The transport carrier logic (TCP vs WebSocket)
- The cryptographic framing
- The opcode protocol
- The static packet format

Each of these concerns evolves at different rates and for different reasons:

- New carriers might be needed (QUIC, HTTP/3)
- New cryptographic algorithms or configurations
- New protocol features or optimizations
- New transport modes

By separating these concerns into distinct layers, the code can add or change one layer without rewriting the whole system. This is the essence of **layered architecture**: each layer has a clear responsibility and well-defined interfaces to its neighbors.

## Why The Client And Server Both Use The Same Link-Layer Class

Both the client and server sides inherit from `VirtualEthernetLinklayer`. They do not use different classes or different protocol definitions. Instead, each side simply overrides the handlers for messages they should legally accept.

This is a strong and interesting design choice:

- **One shared opcode model**: Both sides agree on the same message types and their meanings. There's no confusion about "client opcodes" vs "server opcodes."

- **Role-specific behavior through overrides**: The client might handle `FRP_*` messages while the server might not, or vice versa. This is implemented by overriding methods, not by having different base classes.

- **Suspicious or impossible direction messages can be rejected explicitly**: If a client receives a message that should only come from a server, it can explicitly reject it rather than ignoring it silently.

This approach is more robust than maintaining separate client and server protocol definitions:

- Protocol documentation is unified
- Implementation bugs that cause asymmetry are caught earlier
- New features that apply to both sides only need to be implemented once

## Why TCP, UDP, ICMP, Mappings, Static Mode, And MUX Are Separate Internal Paths

The code deliberately separates these traffic types because they are operationally fundamentally different:

- **TCP needs connect/data/close sequencing**: TCP is a connection-oriented protocol with a well-defined lifecycle. The tunnel must model this lifecycle to properly handle connection establishment, data transfer, and graceful or abrupt termination.

- **UDP needs per-endpoint relay and NAT-style association**: UDP is connectionless, but for tunneling purposes, we often need to maintain state about which local endpoint corresponds to which remote endpoint. This requires different state management than TCP.

- **ICMP needs synthetic echo and TTL handling**: ICMP (Internet Control Message Protocol) messages like echo requests require special handling. The tunnel might need to generate echo replies locally, or forward them to the other side, depending on configuration.

- **Mappings need reverse registration and per-port lifecycle**: FRP-style reverse mappings have their own lifecycle. A mapping is registered, remains active until explicitly removed or until the connection closes, and might need to be re-established if the connection drops.

- **Static mode needs packetized UDP transport**: Static mode is optimized for bulk data transfer and has different requirements than the regular tunnel opcode path.

- **MUX needs logical subchannel negotiation and reuse**: Multiplexing adds another layer of complexity—managing multiple logical channels over one physical connection, handling flow control per channel, etc.

Trying to fake all of these with one generic "packet forward" function would make the runtime less explicit and harder to debug. Each traffic type has its own code path because each has genuinely different requirements.

## Why Route And DNS Logic Are Outside The Tunnel Core

The tunnel protocol itself does not own host route tables or system DNS settings. Those remain in the "switcher" and platform-specific code.

This separation is correct for several reasons:

- **Host environment concerns vs wire protocol concerns**: Routes and DNS are properties of the host environment, not properties of how bytes are transmitted over a tunnel. The tunnel should not need to understand or manage the host's network configuration.

- **Separation of concerns**: The tunnel is complex enough without adding operating system-specific route management code. Keeping them separate makes both easier to maintain.

- **Portability**: The tunnel core can remain platform-independent, while the platform-specific code handles the OS integration.

- **Security**: Modifying system routes and DNS requires elevated privileges. Keeping this code separate from the core tunnel logic reduces the attack surface and makes security auditing easier.

## Design Consequence: A System That Evolves

The result is a tunnel system that is harder to explain in one sentence, but much easier to evolve as infrastructure. It cannot be summarized as "just encrypted packets" because it does much more than that.

The codebase is not organized around a single trick or technique. It is organized around **stable separation of responsibilities**. Each layer has a clear purpose and well-defined boundaries. This allows:

- Independent evolution of each layer
- Testing of individual components in isolation
- Clear attribution of bugs to specific responsibilities
- Addition of new capabilities without disrupting existing ones

This architecture has proven itself by supporting the simultaneous implementation of features (TCP, UDP, WebSocket, mux, static mode, FRP mappings) that would be extremely difficult to combine in a less structured approach.

## Technical Implementation Details

### The Role of ivv (Initialization Vector Variation)

The `ivv` value deserves special attention. It is a per-connection random or pseudo-random value that is negotiated during the handshake phase. Its primary purpose is to ensure cryptographic isolation between sessions.

When the same base keys are used for multiple connections, without `ivv`, all connections would produce identical ciphertexts for identical plaintexts. This leaks information:

- An observer could tell when the same message is being sent
- If a key is compromised, all historical traffic could be decrypted
- Pattern analysis becomes possible

By incorporating `ivv` into the key derivation:

- Each session gets a unique encryption context
- Identical payloads result in different ciphertexts
- Compromise of one session's keys does not affect others
- Forward secrecy is improved (even within a single server instance)

### The Relationship Between Layers

Each layer provides specific guarantees to the layer above:

1. **Carrier transport** guarantees: "I will deliver bytes (or not) between endpoints"
2. **Protected transmission** guarantees: "I will deliver complete, integrity-protected, encrypted messages within a session"
3. **Tunnel action protocol** guarantees: "I will deliver structured operations with semantic meaning"
4. **Virtual Ethernet/Static Packet** guarantees: "I will deliver network-layer or datagram payloads with appropriate framing"

This layered model allows each layer to be tested, replaced, or enhanced independently.

### Error Handling Philosophy

The tunnel uses different error handling strategies at different layers:

- **Carrier layer**: Retry logic, fallback to alternative carriers
- **Transmission layer**: Session teardown, reconnection attempts
- **Protocol layer**: Individual message rejection, connection-specific error codes
- **Application layer**: User notification, logging, automatic recovery where possible

This graduated approach to errors allows the system to be resilient without being complex.

## Conclusion

OPENPPP2's tunnel design represents a thoughtful approach to a complex problem. By recognizing that tunnel networking involves multiple distinct concerns—from transport to security to protocol semantics to packet formats—it creates a system that is both capable and maintainable.

The layered architecture is not just academic—it enables real-world features like WebSocket support, multiplexing, static UDP paths, and FRP-style reverse proxying to coexist in one codebase. Each feature can be understood, implemented, tested, and improved independently.

Understanding this architecture is essential for anyone looking to extend, debug, or optimize OPENPPP2. The design choices documented here are not accidental—they represent hard-won lessons about what makes a tunnel system flexible and maintainable.

## Read Next

- [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md) - Detailed protocol specification for the link layer opcodes
- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md) - How the client side is organized and operates
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md) - How the server side is organized and operates
