# Transport And Tunnel Model

[中文版本](TRANSMISSION_CN.md)

## Purpose

OPENPPP2 separates the tunnel into three layers:

- Transport carrier: TCP, UDP, WS, or WSS
- Protected transmission: framed read/write with protocol and transport ciphers
- Virtual Ethernet control/data plane: tunnel actions for LAN, NAT, TCP, UDP, echo, mapping, static mode, and mux

This separation is visible in the code:

- `ppp/transmissions/ITransmission.*`
- `ppp/transmissions/ITcpipTransmission.*`
- `ppp/transmissions/IWebsocketTransmission.*`
- `ppp/app/protocol/VirtualEthernetLinklayer.*`

## Transport Carriers

The runtime can carry the tunnel over multiple socket styles:

- Native TCP
- Native UDP
- WebSocket
- WebSocket over TLS

The carrier only decides how bytes move between peers. Session identity, framing, keepalive, encryption, and tunnel actions are handled above it.

## Handshake Model

`ITransmission` owns the handshake entry points:

- `HandshakeClient(...)`
- `HandshakeServer(...)`

The handshake establishes:

- a session identifier
- framing state
- optional multiplexing flag
- protocol-layer and transport-layer cipher state

The handshake is guarded by timeout logic inside `ITransmission`, so an incomplete session does not stay half-open forever.

## Protection Layers

The project uses two logically distinct cipher slots:

- Protocol cipher: protects tunnel metadata framing and protocol-level payload handling
- Transport cipher: protects the carried byte stream

Relevant configuration fields are under `key`:

- `protocol`
- `protocol-key`
- `transport`
- `transport-key`
- `masked`
- `plaintext`
- `delta-encode`
- `shuffle-data`
- `kf`, `kh`, `kl`, `kx`, `sb`

The implementation intent is not just confidentiality. It also allows the runtime to control framing shape, payload formatting, and compatibility behavior during the early part of the session.

## Framing And Read/Write Flow

At the transmission layer, data flow is:

1. Caller submits payload to `Write(...)`
2. `ITransmission` applies framing and enabled transformations
3. The carrier sends bytes on the active socket type
4. Receiver reads framed bytes through `Read(...)`
5. `ITransmission` reverses the enabled transformations
6. Decoded tunnel payload is passed to link-layer packet handling

This design lets the upper protocol remain mostly independent from whether the underlying path is TCP, UDP, or WebSocket.

## Virtual Ethernet Actions

`VirtualEthernetLinklayer` defines the action set used inside the tunnel. The important action groups are:

- Information and keepalive: `INFO`, `KEEPALIVED`
- Layer 3 and virtual LAN actions: `LAN`, `NAT`, `SENDTO`, `ECHO`, `ECHOACK`
- TCP relay actions: `SYN`, `SYNOK`, `PSH`, `FIN`
- Reverse access actions: `FRP_ENTRY`, `FRP_CONNECT`, `FRP_CONNECTOK`, `FRP_PUSH`, `FRP_DISCONNECT`, `FRP_SENDTO`
- Static path actions: `STATIC`, `STATICACK`
- Multiplexing actions: `MUX`, `MUXON`

These are not separate products. They are all carried by the same session and packet model.

## Tunnel Styles Supported By The Design

### 1. Standard client/server tunnel

The client creates a virtual adapter and sends traffic to the server over one selected carrier.

### 2. Split tunnel

The client keeps only selected prefixes, domains, or DNS flows inside the overlay. Everything else follows the local network.

### 3. Reverse access / service exposure

Mappings and FRP-style control messages let the client expose local TCP or UDP services through the server side.

### 4. Static UDP mode

The codebase includes a static UDP path with keepalive behavior and optional multi-server support. This is useful when a more stable datagram path is preferred over session-heavy behavior.

### 5. Multiplexed tunnel

MUX can open multiple logical channels over one established path, reducing repeated handshake cost and improving reuse of an already healthy connection.

### 6. WebSocket fronted tunnel

The tunnel can ride inside WS or WSS, which is useful when the deployment sits behind reverse proxies, HTTP infrastructure, or TLS termination layers.

## WebSocket Integration

The `websocket` configuration block controls:

- `listen.ws`
- `listen.wss`
- `host`
- `path`
- `ssl.certificate-file`
- `ssl.certificate-key-file`
- `ssl.certificate-chain-file`
- `ssl.ciphersuites`
- request and response header decoration

This allows the runtime to align with an HTTP-facing edge without changing the upper tunnel protocol.

## MUX Design Intent

MUX is a tunnel efficiency feature, not a different transport family.

Its purpose is to:

- reuse an established session
- reduce setup overhead for multiple logical flows
- keep the control plane simpler than opening many independent sessions

The key entry points are in:

- `VirtualEthernetLinklayer::DoMux(...)`
- `VirtualEthernetLinklayer::DoMuxON(...)`
- client/server exchanger implementations that create and manage `vmux_net`

## Static UDP And Aggregation

The `udp.static` section controls behavior for long-lived UDP-oriented paths:

- `keep-alived`
- `dns`
- `quic`
- `icmp`
- `aggligator`
- `servers`

This part of the design is aimed at making datagram-based deployments explicit and configurable, especially when multiple upstream UDP servers are available.

## IPv6 Transport Extensions

IPv6 is carried as an extension of the session and information model, not as a separate product line.

Important behavior is implemented in:

- `VirtualEthernetInformationExtensions`
- `VirtualEthernetSwitcher` IPv6 lease and route handling
- `VEthernetNetworkSwitcher` IPv6 application and restore flow

Server-side IPv6 data-plane support is primarily implemented for Linux.

## Engineering Tradeoffs

The transport model favors:

- one protocol core over many unrelated data paths
- explicit layering over hidden coupling
- recoverable timeouts and reconnection over implicit long-blocking behavior
- route and tunnel policy in configuration instead of hard-coded assumptions

The tradeoff is that the tunnel surface is broad. Operators should decide deliberately which features they actually need instead of turning on every option.

## Related Documents

- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md)
- [`CONFIGURATION.md`](CONFIGURATION.md)
- [`SECURITY.md`](SECURITY.md)
