# Link-Layer Protocol Guide

[中文版本](LINKLAYER_PROTOCOL_CN.md)

## Scope

This document describes the internal tunnel opcode protocol implemented by `VirtualEthernetLinklayer`.
It is based on the actual source in `ppp/app/protocol/VirtualEthernetLinklayer.*`, `VirtualEthernetInformation.*`, and the client/server handlers that consume those actions.

---

## Why This Layer Exists

OPENPPP2 needs one shared vocabulary for:

1. Session information
2. Keepalive
3. LAN/NAT signaling
4. TCP relay
5. UDP relay
6. Reverse mappings
7. Static path negotiation
8. MUX negotiation

Without a shared vocabulary, the client and server would have to guess what every packet means, making the system fragile and hard to extend.

---

## Protocol Position

```mermaid
flowchart TD
    A[Physical network] --> B[ITransmission: encrypted framed stream]
    B --> C[VirtualEthernetLinklayer: opcode dispatch]
    C --> D[INFO handler]
    C --> E[KEEPALIVED handler]
    C --> F[TCP relay handlers: SYN/SYNOK/PSH/FIN]
    C --> G[UDP relay handler: SENDTO]
    C --> H[FRP handlers: FRP_*]
    C --> I[Static path: STATIC/STATICACK]
    C --> J[MUX: MUX/MUXON]
    C --> K[Traversal: LAN/NAT]
```

The linklayer sits between the protected transport and the runtime action handlers.

---

## Opcode Families

`VirtualEthernetLinklayer` defines these families:

| Family | Opcodes | Purpose |
|--------|---------|---------|
| Control | `INFO = 0x7E` | Session information and control-plane data |
| Liveness | `KEEPALIVED = 0x7F` | Heartbeat |
| FRP | `FRP_ENTRY = 0x20` to `FRP_SENDTO = 0x25` | Reverse mapping control and data |
| Traversal | `LAN = 0x28`, `NAT = 0x29` | Subnet and NAT traversal signaling |
| TCP relay | `SYN = 0x2A`, `SYNOK = 0x2B`, `PSH = 0x2C`, `FIN = 0x2D` | Logical TCP inside tunnel |
| UDP relay | `SENDTO = 0x2E` | UDP datagram relay |
| Echo | `ECHO = 0x2F`, `ECHOACK = 0x30` | Echo health path |
| Static path | `STATIC = 0x31`, `STATICACK = 0x32` | Static path negotiation |
| MUX | `MUX = 0x35`, `MUXON = 0x36` | Multiplexing negotiation |

Source: `ppp/app/protocol/VirtualEthernetLinklayer.h`

---

## Action Dispatch Map

```mermaid
flowchart TD
    A[Incoming opcode] --> B{Family}
    B -->|INFO 0x7E| C[Session information]
    B -->|KEEPALIVED 0x7F| D[Heartbeat]
    B -->|LAN 0x28| E[LAN subnet advertisement]
    B -->|NAT 0x29| F[NAT traversal signal]
    B -->|SYN 0x2A| G[TCP relay: connect request]
    B -->|SYNOK 0x2B| H[TCP relay: connect OK]
    B -->|PSH 0x2C| I[TCP relay: data push]
    B -->|FIN 0x2D| J[TCP relay: disconnect]
    B -->|SENDTO 0x2E| K[UDP relay: datagram]
    B -->|ECHO 0x2F| L[Echo health probe]
    B -->|ECHOACK 0x30| M[Echo health response]
    B -->|STATIC 0x31| N[Static path negotiate]
    B -->|STATICACK 0x32| O[Static path confirm]
    B -->|MUX 0x35| P[MUX negotiate]
    B -->|MUXON 0x36| Q[MUX confirm]
    B -->|FRP_ENTRY 0x20| R[FRP: mapping entry]
    B -->|FRP_CONNECT 0x21| S[FRP: connect]
    B -->|FRP_CONNECTOK 0x22| T[FRP: connect OK]
    B -->|FRP_PUSH 0x23| U[FRP: data push]
    B -->|FRP_DISCONNECT 0x24| V[FRP: disconnect]
    B -->|FRP_SENDTO 0x25| W[FRP: UDP relay]
```

---

## Directionality

The code does not accept every action in every direction.
Client and server handlers enforce role legality. Unexpected directions are rejected.

```mermaid
flowchart TD
    A[Opcode received] --> B{Which endpoint?}
    B -->|Client| C[Client handler checks: is this direction valid for client?]
    B -->|Server| D[Server handler checks: is this direction valid for server?]
    C -->|valid| E[Process]
    C -->|invalid| F[Reject]
    D -->|valid| E
    D -->|invalid| F
```

This matters because the same opcode can mean different operational things depending on whether it is handled on the client or server side.

---

## `INFO` — The Control Plane

`INFO` is not just a status blob. It is the control-plane carrier.

### What `INFO` Carries

| Field | Description |
|-------|-------------|
| Bandwidth QoS | Server-set bandwidth limit |
| Traffic accounting | Session traffic counters |
| Expiration | Session validity window |
| IPv6 assignment | IPv6 address assigned to client |
| IPv6 status | IPv6 operational state |
| Host-side state | Application-level host state feedback |

### `INFO` Packet Structure

```
[VirtualEthernetInformation base struct]
[optional extension JSON text]
```

The extension JSON is deliberately optional so the same packet family works for both plain status and richer IPv6 control data.

### `INFO` Flow

```mermaid
sequenceDiagram
    participant Server as Server
    participant Linklayer as VirtualEthernetLinklayer
    participant Client as Client runtime

    Server->>Linklayer: INFO (base + optional extension JSON)
    Linklayer->>Client: OnInformation(info, extension_json)
    Client->>Client: Apply bandwidth limit
    Client->>Client: Update traffic counters
    Client->>Client: Apply expiration
    alt IPv6 in extension
        Client->>Client: Apply IPv6 address
        Client->>Client: Update IPv6 state
    end
    Client->>Client: Apply host-side state
```

Source: `ppp/app/protocol/VirtualEthernetInformation.h`

---

## Keepalive

`KEEPALIVED` is the heartbeat mechanism.

The transmission layer has its own timeout and framing state, but the linklayer still needs an explicit keepalive opcode for tunnel liveness semantics — specifically to detect silent connectivity loss at the overlay level.

```mermaid
sequenceDiagram
    participant Client as Client
    participant Server as Server

    loop every keepalive interval
        Client->>Server: KEEPALIVED (echo)
        Server-->>Client: KEEPALIVED (echo ack)
        Note over Client: Session alive
    end
    Client->>Server: KEEPALIVED (echo)
    Note over Client: No response within timeout
    Client->>Client: Declare session dead
    Client->>Client: Trigger reconnect
```

---

## LAN And NAT Signaling

`LAN` and `NAT` are not generic traffic opcodes. They are signaling lanes for subnet visibility and traversal.

| Opcode | Purpose | Consumed by |
|--------|---------|-------------|
| `LAN` | Announce subnet reachability | Runtime packet classifier |
| `NAT` | Signal NAT traversal parameters | Forwarding decision engine |

On client and server sides, they feed packet classification and forwarding decisions.

---

## TCP Relay Family

`SYN`, `SYNOK`, `PSH`, and `FIN` model logical TCP inside the tunnel.

The point is not to reimplement TCP. The point is to relay TCP-like semantics across the overlay in a controlled, explicit way.

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> SynSent : SYN sent (client requests connection)
    SynSent --> SynAcked : SYNOK received (server accepts)
    SynAcked --> DataTransfer : PSH (data flowing)
    DataTransfer --> DataTransfer : PSH (more data)
    DataTransfer --> Closed : FIN (connection ended)
    SynSent --> Closed : FIN (connection refused)
    Closed --> [*]
```

### TCP Relay Sequence

```mermaid
sequenceDiagram
    participant Client as Client
    participant Server as Server
    participant Destination as Real destination

    Client->>Server: SYN (conn_id, destination)
    Server->>Destination: TCP connect
    Destination-->>Server: Connected
    Server-->>Client: SYNOK (conn_id)
    Client->>Server: PSH (conn_id, data)
    Server->>Destination: Forward data
    Destination-->>Server: Response data
    Server-->>Client: PSH (conn_id, data)
    Client->>Server: FIN (conn_id)
    Server->>Destination: Close
```

---

## UDP Relay Family

`SENDTO` is the UDP relay opcode. It carries source and destination endpoint information plus payload bytes.

```mermaid
sequenceDiagram
    participant Client as Client
    participant Server as Server
    participant Destination as Real destination

    Client->>Server: SENDTO (src_endpoint, dst_endpoint, payload)
    Server->>Destination: UDP sendto
    Destination-->>Server: UDP response
    Server-->>Client: SENDTO (src_endpoint, dst_endpoint, response)
```

The endpoint parser in `VirtualEthernetLinklayer.cpp` supports:
- IPv4 and IPv6 literals
- Domain names with optional async DNS resolution
- IPv4-in-IPv6 mapped addresses

---

## Echo Family

`ECHO` and `ECHOACK` support echo-style health behavior.

Unlike `KEEPALIVED` (which is a tunnel-level heartbeat), `ECHO`/`ECHOACK` can be used for more targeted health probing, such as measuring round-trip latency or verifying specific path reachability.

---

## Static Path Family

`STATIC` and `STATICACK` negotiate the static packet path.

Static path is a separate concept from normal UDP relay:
- It has different state.
- It has different delivery semantics.
- It is used for alternative path setups (e.g., when the main tunnel path has high latency or loss).

```mermaid
sequenceDiagram
    participant Client as Client
    participant Server as Server

    Client->>Server: STATIC (static path parameters)
    Server-->>Client: STATICACK (confirmed parameters)
    Note over Client,Server: Static path active
```

---

## MUX Family

`MUX` and `MUXON` negotiate multiplexing.

```mermaid
sequenceDiagram
    participant Client as Client
    participant Server as Server

    Client->>Server: MUX (mux parameters)
    Server-->>Client: MUXON (mux confirmed)
    Note over Client,Server: Multiple logical linklayers under one mux
```

The runtime uses MUX to create and confirm a mux instance, then connect multiple logical link layers under that mux. This allows more efficient use of the underlying transport connection.

---

## FRP Family

`FRP_*` opcodes implement reverse-mapping and reverse-path behavior.

This is how the runtime can expose services back through the tunnel instead of only forwarding traffic outwards.

| Opcode | Purpose |
|--------|---------|
| `FRP_ENTRY` | Register a reverse mapping entry |
| `FRP_CONNECT` | Client requests connection to mapped service |
| `FRP_CONNECTOK` | Server confirms connection to mapped service |
| `FRP_PUSH` | Data push for FRP connection |
| `FRP_DISCONNECT` | FRP connection closed |
| `FRP_SENDTO` | UDP relay for FRP path |

```mermaid
sequenceDiagram
    participant External as External client
    participant Server as OPENPPP2 server
    participant Client as OPENPPP2 client
    participant LocalSvc as Local service

    Client->>Server: FRP_ENTRY (mapping: remote_port → local_port)
    Note over Server: Port bound on server
    External->>Server: TCP connect to remote_port
    Server->>Client: FRP_CONNECT (conn_id, remote_port)
    Client->>LocalSvc: TCP connect to local_port
    LocalSvc-->>Client: Connected
    Client-->>Server: FRP_CONNECTOK (conn_id)
    External->>Server: Data
    Server->>Client: FRP_PUSH (conn_id, data)
    Client->>LocalSvc: Forward data
    LocalSvc-->>Client: Response
    Client-->>Server: FRP_PUSH (conn_id, response)
    Server-->>External: Forward response
```

---

## Packet Layout Overview

```mermaid
erDiagram
    LINKLAYER_PACKET {
        uint8_t opcode
        uint16_t length
        bytes payload
    }
    INFO_PAYLOAD {
        VirtualEthernetInformation base_info
        string optional_extension_json
    }
    TCP_RELAY_PAYLOAD {
        int32_t conn_id
        bytes data
    }
    UDP_RELAY_PAYLOAD {
        IPEndPoint src_endpoint
        IPEndPoint dst_endpoint
        bytes payload
    }
    LINKLAYER_PACKET ||--o| INFO_PAYLOAD : "opcode = INFO"
    LINKLAYER_PACKET ||--o| TCP_RELAY_PAYLOAD : "opcode = SYN/PSH/FIN"
    LINKLAYER_PACKET ||--o| UDP_RELAY_PAYLOAD : "opcode = SENDTO"
```

---

## `INFO` As The Control Plane

```mermaid
sequenceDiagram
    participant P as Peer
    participant L as Linklayer
    participant C as Client runtime
    participant S as Server runtime
    P->>L: INFO
    L->>C: base info + extension json
    C->>C: apply routes / DNS / IPv6
    L->>S: INFO
    S->>S: allocate lease / report status
```

---

## Reading Strategy

If you want to understand the protocol layer from source, read in this order:

1. Opcode enum in `VirtualEthernetLinklayer.h`
2. Packet dispatch in `VirtualEthernetLinklayer.cpp`
3. `VirtualEthernetInformation.*` — control plane data structure
4. `VirtualEthernetPacket.*` — packet building helpers
5. Client handler overrides of `On*` methods in `VEthernetExchanger.*`
6. Server handler overrides of `On*` methods in `VirtualEthernetExchanger.*`

That sequence keeps action vocabulary separate from transport and separate from host consequence.

---

## Error Code Reference

Linklayer-related `ppp::diagnostics::ErrorCode` values (from `ppp/diagnostics/ErrorCodes.def`):

| ErrorCode | Description |
|-----------|-------------|
| `ProtocolPacketActionInvalid` | Received opcode not recognized |
| `ProtocolFrameInvalid` | Opcode frame structure invalid |
| `SessionHandshakeFailed` | INFO exchange during handshake failed |
| `SessionAuthFailed` | Session authentication failed |
| `KeepaliveTimeout` | Peer keepalive heartbeat timed out |
| `ProtocolMuxFailed` | MUX/MUXON exchange failed |
| `MappingCreateFailed` | FRP entry registration failed |
| `SocketConnectFailed` | TCP relay connect failed |

---

## Related Documents

- [`TRANSMISSION.md`](TRANSMISSION.md)
- [`TUNNEL_DESIGN.md`](TUNNEL_DESIGN.md)
- [`PACKET_FORMATS.md`](PACKET_FORMATS.md)
- [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md)
- [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
- [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)

---

## Main Conclusion

The link-layer protocol is the tunnel's shared semantic language. It is the part of OPENPPP2 that turns a protected byte stream into a set of explicit overlay actions. Without it, the runtime would have no way to express session information, TCP relay semantics, UDP relay, reverse mappings, or multiplexing in a controlled and extensible way.
