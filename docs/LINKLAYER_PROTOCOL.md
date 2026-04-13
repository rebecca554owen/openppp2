# Link-Layer Protocol Guide

[中文版本](LINKLAYER_PROTOCOL_CN.md)

## Scope

This document describes the internal tunnel opcode protocol implemented by `VirtualEthernetLinklayer`.

## Why This Layer Exists

OPENPPP2 needs one shared protocol vocabulary for:

- session information
- keepalive
- virtual subnet forwarding
- UDP relay
- TCP relay
- reverse mappings
- static path negotiation
- mux negotiation

`VirtualEthernetLinklayer` is that vocabulary.

## Main Action Families

### Information and keepalive

- `INFO`
- `KEEPALIVED`

Used for session information, health, and session maintenance.

### Data and forwarding actions

- `LAN`
- `NAT`
- `SENDTO`
- `ECHO`
- `ECHOACK`

Used for subnet signaling, packet forwarding, UDP relay, and ICMP-related behavior.

### TCP relay actions

- `SYN`
- `SYNOK`
- `PSH`
- `FIN`

Used to create logical TCP connections over the tunnel.

### Static path actions

- `STATIC`
- `STATICACK`

Used to allocate and confirm the static UDP-oriented path.

### MUX actions

- `MUX`
- `MUXON`

Used to negotiate and acknowledge multiplexed logical channels.

### FRP-style reverse mapping actions

- `FRP_ENTRY`
- `FRP_CONNECT`
- `FRP_CONNECTOK`
- `FRP_PUSH`
- `FRP_DISCONNECT`
- `FRP_SENDTO`

Used to expose client-side services through the server side.

## Information Payload

`INFO` carries:

- a packed `VirtualEthernetInformation` base object
- optional extension JSON string

The extension JSON is mainly used for IPv6 assignment and status fields.

This is a useful design because the stable binary part remains compact while the extensible part can grow without breaking the fixed base layout.

## TCP Relay Semantics

The logical TCP relay behaves like a mini control protocol inside the tunnel:

1. requester sends `SYN`
2. responder tries to connect the destination
3. responder replies `SYNOK`
4. stream data flows with `PSH`
5. teardown uses `FIN`

This is why TCP relay is implemented as its own session-aware subsystem rather than as plain packet copy.

## UDP Relay Semantics

UDP relay is endpoint-oriented:

- source and destination endpoints are encoded in the action payload
- datagram state is tracked by dedicated datagram-port objects
- replies can be routed back either to a stored tunnel state object or reconstructed for TUN output

## ICMP Semantics

`ECHO` and `ECHOACK` give the tunnel a way to support echo-style health and synthetic response behavior.

This is operationally useful because it lets the virtual network behave more like a routable network and less like an opaque user-space socket tunnel.

## FRP Mapping Semantics

FRP-style mapping actions let the tunnel do controlled reverse exposure.

At a high level:

1. client registers a mapping with `FRP_ENTRY`
2. server accepts external access for that mapping
3. connection setup uses `FRP_CONNECT` and `FRP_CONNECTOK`
4. payload moves with `FRP_PUSH` or `FRP_SENDTO`
5. teardown uses `FRP_DISCONNECT`

## Static Path Semantics

The static path is negotiated in the opcode protocol, but the actual packet carriage later moves through `VirtualEthernetPacket`.

This split is intentional:

- `STATIC` / `STATICACK` belong to control
- `VirtualEthernetPacket` belongs to packet transport on that allocated path

## MUX Semantics

MUX is explicitly negotiated rather than assumed.

That matters because mux is not just an optimization toggle. It introduces a different logical flow model that both peers must agree on.

## Defensive Directionality

One important property of the implementation is that both sides do not accept every action in every direction.

Examples visible in code:

- the server rejects unexpected client-side TCP control directions
- the client rejects unexpected server-side connect/push directions

This makes the shared protocol safer to operate because role legality is enforced in handlers.

## Why This Protocol Is Worth Documenting Separately

Without understanding `VirtualEthernetLinklayer`, it is hard to understand why the rest of the runtime is split into so many classes.

This protocol is the center of the system’s control/data semantics.
