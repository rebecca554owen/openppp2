# Tunnel Design Deep Dive

[中文版本](TUNNEL_DESIGN_CN.md)

## Why This Document Exists

OPENPPP2 does not treat a tunnel as “just a socket with encryption”.

From the code, the tunnel is deliberately split into multiple layers. That design decision is the main reason the system can simultaneously support:

- TCP and WebSocket carriers
- virtual Ethernet forwarding
- session policy and information exchange
- FRP-style reverse mappings
- static UDP packet mode
- mux-based subchannels
- platform-specific route and adapter behavior

## Layer 1: Carrier Transport

The outermost transport carrier is the socket style used between peers.

Implemented by:

- `ITcpipTransmission`
- `IWebsocketTransmission`
- `ISslWebsocketTransmission`

This layer decides only how bytes move:

- raw TCP
- WebSocket
- WebSocket over TLS

The rest of the tunnel semantics sit above it.

## Layer 2: Protected Transmission

`ITransmission` builds a protected framing layer on top of the carrier.

It owns:

- handshake timeout
- handshake sequencing
- session identifier exchange
- per-connection re-keying by `ivv`
- read/write framing
- protocol-layer cipher
- transport-layer cipher

### Why this layer exists

Without this layer, every carrier implementation would need to understand all session bootstrapping details directly. The code instead centralizes those concerns once in `ITransmission`.

## Handshake Design

The transport handshake performs more than just “connect”. From code facts, it is establishing:

- a session id
- whether the connection is mux-oriented
- per-connection key variation through `ivv`
- final transition into handshaked framing behavior

The implementation also sends handshake dummy traffic before the real values are accepted. Regardless of the exact operational motivation, the code clearly treats the early phase of the connection as special and more conservative than steady-state traffic.

## Why Re-Key After Handshake

The code derives new `protocol_` and `transport_` cipher instances using configured keys plus the runtime `ivv` value.

That matters because it means the configured keys act as base secrets, while each established connection gets differentiated working ciphers.

From an engineering perspective, this gives the transport layer:

- per-session variability
- less dependence on one static key state for all sessions
- a clean transition from bootstrap state to established state

## Framing Design

After the carrier socket is established, bytes are not sent raw. They are passed through framed read/write logic.

The implementation includes:

- length handling
- optional protocol-layer protection of length/header data
- payload transformation
- optional formatting behavior that changes pre- and post-handshake

### Why this framing exists

Because the tunnel must carry structured actions and payloads, not only arbitrary bytestreams. The framing layer gives the upper protocol a stable substrate independent of whether the carrier is TCP or WebSocket.

## Layer 3: Tunnel Action Protocol

Above `ITransmission`, `VirtualEthernetLinklayer` defines the actual tunnel protocol used by the application runtime.

This layer models:

- `INFO`
- `KEEPALIVED`
- `LAN`
- `NAT`
- `SYN`, `SYNOK`, `PSH`, `FIN`
- `SENDTO`
- `ECHO`, `ECHOACK`
- `STATIC`, `STATICACK`
- `MUX`, `MUXON`
- `FRP_*`

### Why this action model exists

Because OPENPPP2 is not only forwarding one class of traffic. It needs one internal vocabulary that can represent:

- routed payload traffic
- TCP stream control
- UDP datagram relay
- reverse service exposure
- keepalive and health signals
- mux negotiation
- static-path negotiation

## Layer 4: Virtual Packet Format For Static UDP Paths

`VirtualEthernetPacket` is a separate encapsulation path used for static-style packet transport.

It is distinct from `VirtualEthernetLinklayer` and carries:

- pseudo source/destination metadata
- per-packet mask and checksum
- per-session crypto selection
- packet-level shuffle/XOR/delta stages

### Why it is separate

Because static UDP transport has different needs from the opcode-driven link layer. The code treats it as a packetized transport path rather than as a stream of control actions.

## Why The Tunnel Is Not One Flat Protocol

If all behaviors were merged into one flat protocol, the implementation would become much harder to evolve.

By separating:

- carrier transport
- protected transmission
- tunnel opcode protocol
- static packet format

the code can add or change one layer without rewriting the whole system.

## Why The Client And Server Both Use The Same Link-Layer Class

Both sides inherit from `VirtualEthernetLinklayer` and override only the handlers they should legally accept.

This is a strong design choice:

- one shared opcode model
- role-specific behavior through overrides
- suspicious or impossible direction messages can be rejected explicitly

That is more robust than maintaining separate client and server protocol definitions.

## Why TCP, UDP, ICMP, Mappings, Static Mode, And MUX Are Separate Internal Paths

The code separates them because they are operationally different:

- TCP needs connect/data/close sequencing
- UDP needs per-endpoint relay and NAT-style association
- ICMP needs synthetic echo and TTL handling
- mappings need reverse registration and per-port lifecycle
- static mode needs packetized UDP transport
- mux needs logical subchannel negotiation and reuse

Trying to fake all of these with one generic “packet forward” function would make the runtime less explicit and harder to debug.

## Why Route And DNS Logic Are Outside The Tunnel Core

The tunnel protocol itself does not own host route tables or system DNS settings. Those remain in switcher and platform code.

That separation is correct because route and DNS operations are host-environment concerns, not wire-protocol concerns.

## Design Consequence

The result is a tunnel system that is harder to explain in one sentence, but much easier to evolve as infrastructure.

The codebase is not organized around a single trick. It is organized around stable separation of responsibilities.

## Read Next

- [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md)
- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
