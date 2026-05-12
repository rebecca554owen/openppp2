# Tunnel Design Deep Dive

[中文版本](TUNNEL_DESIGN_CN.md)

## Why This Exists

OPENPPP2 does not treat a tunnel as a single encrypted socket. The code splits the tunnel into transport carrier, protected framing, link-layer actions, and static packet handling. Understanding this split is essential for:

- Extending or modifying transport carriers (add a new one without touching crypto)
- Understanding handshake security properties
- Reasoning about packet lifecycle from TAP to remote destination
- Diagnosing per-session issues with the right mental model
- Writing correct unit tests for individual layers

---

## Layer Map

```mermaid
graph TB
    A["Carrier transport\nTCP / WebSocket / TLS-WS"] --> B["ITransmission\nProtected framing + session key"]
    B --> C["VirtualEthernetLinklayer\nTunnel action protocol"]
    B --> D["Static UDP path\nSeparate delivery semantics"]
    C --> E["VirtualEthernetSwitcher\nServer session management"]
    C --> F["VEthernetExchanger\nClient session management"]
    E --> G["VirtualEthernetDatagramPort\nUDP relay per session"]
    E --> H["TcpConnection\nTCP relay per flow"]
    F --> I["VNetstack / lwIP\nVirtual TCP/IP stack"]
    I --> J["ITap / TapLinux / TapWindows\nVirtual NIC"]
```

Each layer has a distinct responsibility and can be reasoned about independently.

---

## Layer 1: Carrier Transport

The outer carrier decides how bytes move between peers.

### Supported Carrier Types

| Carrier | Description | Config key |
|---------|-------------|------------|
| Raw TCP | Plain TCP socket connection | `tcp.listen.port` |
| WebSocket | HTTP upgrade to WebSocket | `websocket.listen.ws` |
| TLS WebSocket | TLS-backed WebSocket | `websocket.listen.wss` |
| WebSocket over CONNECT proxy | WebSocket through HTTP CONNECT proxy | `client.server-proxy` |

### Client URI Schemes

| URI Scheme | Meaning |
|-----------|---------|
| `ppp://host:port/` | Raw TCP carrier |
| `ppp://ws/host:port/` | WebSocket carrier |
| `ppp://wss/host:port/` | TLS WebSocket carrier |

### Carrier Responsibilities

The carrier layer is responsible for:
- Establishing the TCP or WebSocket connection (including HTTP Upgrade for WS/WSS)
- TLS negotiation for WSS (via Boost.Asio SSL)
- Delivering a reliable byte stream to the next layer
- Reporting connection errors to `ITransmission`

The carrier does **not** know about session identities, encryption keys, or link-layer actions.

```mermaid
flowchart LR
    A[Client process] -->|TCP connect| B[TCP socket]
    A -->|HTTP Upgrade| C[WebSocket]
    A -->|TLS + HTTP Upgrade| D[TLS WebSocket]
    B --> E[ITransmission]
    C --> E
    D --> E
```

### Carrier Selection Logic

```mermaid
flowchart TD
    A[Parse server URL] --> B{URL scheme?}
    B -->|ppp://| C[Raw TCP\nITcpipTransmission]
    B -->|ppp://ws/| D[WebSocket\nIWebsocketTransmission]
    B -->|ppp://wss/| E[TLS WebSocket\nISslWebsocketTransmission]
    C --> F[Carrier connected]
    D --> F
    E --> F
    F --> G[Promote to ITransmission]
    G --> H[Begin handshake]
```

### Key Source Files

- `ppp/transmissions/ITcpipTransmission.h` — TCP carrier
- `ppp/transmissions/IWebsocketTransmission.h` — WebSocket carrier
- `ppp/transmissions/ISslWebsocketTransmission.h` — TLS WebSocket carrier

---

## Layer 2: Protected Transmission (`ITransmission`)

`ITransmission` is the protection and framing layer above the raw carrier.

### Responsibilities

| Responsibility | Description |
|---------------|-------------|
| Transport handshake timeout | Limits how long the handshake phase can take |
| Handshake sequencing | Controls message order: NOP prelude → sid → ivv → nmux |
| Session identifier exchange | Establishes the `Int128` session ID |
| Per-connection `ivv` key variation | Derives session-specific working keys from base keys |
| Read/write framing | Encodes and decodes framed messages with seed + length header |
| Protocol-layer cipher state | Maintains `protocol-key` cipher context (`protocol_`) |
| Transport-layer cipher state | Maintains `transport-key` cipher context (`transport_`) |
| Statistics | Reports byte counters via `ITransmissionStatistics` |
| QoS | Consumes bandwidth tokens if `ITransmissionQoS` is attached |

### Key Derivation

The configured keys in `appsettings.json` are **base secrets**. In the current `ITransmission.cpp` implementation, working cipher state for each connection is rebuilt from the base secret plus the connection-specific `ivv_str`:

```
protocol_working_key  = Cipher(key.protocol-key  + ivv_str)
transport_working_key = Cipher(key.transport-key + ivv_str)
```

This provides per-session key isolation: even if one session's working key is compromised, other sessions remain protected because each has a different `ivv`.

### Two Independent Cipher Layers

```mermaid
flowchart TD
    A[Plaintext payload] --> B[Protocol cipher\nprotocol-key + ivv_str\nProtects header metadata]
    B --> C[Protocol-encrypted payload]
    C --> D[Transport cipher\ntransport-key + ivv_str\nProtects payload body]
    D --> E[Transport-encrypted frame]
    E --> F[Optional transforms\ndelta-encode + shuffle-data + masked]
    F --> G[Carrier transport]
```

Why two ciphers? The **protocol cipher** protects the frame header (length field and related metadata). An attacker who can read header metadata can perform traffic-shape fingerprinting attacks even without reading payload content. The **transport cipher** protects the actual payload. Two separate ciphers from two separate base keys means breaking one does not break the other.

### Optional Framing Transforms

| Flag | Config key | Effect |
|------|-----------|--------|
| `masked` | `key.masked` | Additional XOR masking layer on top of ciphers |
| `plaintext` | `key.plaintext` | Disable both ciphers (development/testing only; **never use in production**) |
| `delta-encode` | `key.delta-encode` | Delta-encode the ciphertext bytes; reduces entropy in repetitive patterns |
| `shuffle-data` | `key.shuffle-data` | Byte-level shuffle of payload; alters traffic fingerprint |

These flags affect traffic fingerprinting resistance. They do **not** replace proper cipher configuration.

### Pre-Handshake vs Post-Handshake Framing

The framing format changes at handshake completion:

| Phase | Header format | Cipher state |
|-------|--------------|-------------|
| Pre-handshake | Extended header (4+3 bytes), base94 encoding possible | Base key only, or plaintext |
| Post-handshake | Simple binary header (3 bytes: seed + 2 length bytes) | Working cipher (`base_key + ivv_str`) |

The transition is controlled by `handshaked_` (atomic bool) and `frame_tn_` / `frame_rn_` (framing state counters).

### API Reference

```cpp
/**
 * @brief Run the client-side handshake sequence.
 * @param y    Yield context for coroutine suspension.
 * @param mux  Output flag indicating negotiated multiplexing capability.
 * @return     Negotiated session identifier (Int128), or zero on failure.
 * @note       Sets diagnostics on failure. Handshake has a configurable timeout.
 */
virtual Int128 HandshakeClient(YieldContext& y, bool& mux) noexcept;

/**
 * @brief Run the server-side handshake sequence.
 * @param y          Yield context.
 * @param session_id Session identifier provided by upper layer.
 * @param mux        Requested multiplexing behavior.
 * @return           true if handshake succeeds; otherwise false.
 */
virtual bool HandshakeServer(YieldContext& y, const Int128& session_id, bool mux) noexcept;

/**
 * @brief Read and decrypt one framed message from the protected transmission.
 * @param y       Yield context.
 * @param outlen  Output payload length (bytes).
 * @return        Decrypted payload buffer, or null on failure/EOF.
 * @note          Decrypts and validates the frame before returning to caller.
 */
virtual std::shared_ptr<Byte> Read(YieldContext& y, int& outlen) noexcept;

/**
 * @brief Encrypt and write one framed message to the protected transmission.
 * @param y             Yield context.
 * @param packet        Payload pointer.
 * @param packet_length Payload length in bytes.
 * @return              true on success.
 * @note                Encrypts, frames, and writes atomically through the strand.
 */
virtual bool Write(YieldContext& y, const void* packet, int packet_length) noexcept;

/**
 * @brief Dispose this transmission and release all resources.
 * @note  Idempotent. Safe to call from any thread. Uses atomic CAS pattern.
 */
virtual void Dispose() noexcept override;
```

Source: `ppp/transmissions/ITransmission.h`

---

## Transport Handshake Behavior

The handshake establishes session identity and per-connection keys. It also shapes traffic to resist passive traffic analysis.

```mermaid
sequenceDiagram
    participant Client as Client
    participant Server as Server

    Note over Client,Server: Early phase — base94 frames, dummy traffic
    Client->>Server: NOP prelude (variable length random dummy bytes, session_id=0)
    Server->>Client: NOP prelude (variable length random dummy bytes, session_id=0)

    Note over Client,Server: Identity phase
    Server->>Client: real session_id (Int128, assigned by VirtualEthernetSwitcher)
    Client->>Server: ivv (Int128 random value, per-connection key variation seed)
    Server->>Client: nmux (random Int128; low bit = mux enable flag)

    Note over Client,Server: Both sides: rebuild protocol_ and transport_ ciphers
    Note over Client,Server: handshaked_ = true; working cipher state active
    Note over Client,Server: Switch to binary protected frame family
```

Handshake security properties:

| Property | Mechanism |
|---------|-----------|
| Passive traffic analysis resistance | NOP prelude uses random length and content |
| Session binding | `session_id` binds the logical session to this transport |
| Per-session key variation | `ivv` ensures each connection has distinct working keys |
| Mux state delivery | `nmux` low bit carries mux enable without a separate trivial boolean packet |
| Timeout bound | Handshake timer prevents half-open sessions from consuming server resources |
| Key confirmation | Key mismatch → cipher state mismatch → connection drop |

### Handshake Order Detail

Client:
1. Send NOP prelude
2. Receive `session_id` (loop until high bit clear = real packet)
3. Generate `ivv` (GUID-seeded random `Int128`)
4. Send `ivv`
5. Receive `nmux`
6. Set `handshaked_ = true`
7. Extract mux flag: `mux = (nmux & 1) != 0`
8. Rebuild both ciphers from `base_key + ivv_str`

Server:
1. Send NOP prelude
2. Send real `session_id` (assigned by switcher)
3. Generate random `nmux`; force low bit per mux config
4. Send `nmux`
5. Receive `ivv`
6. Set `handshaked_ = true`
7. Rebuild both ciphers from `base_key + ivv_str`

---

## Layer 3: Link-Layer Actions (`VirtualEthernetLinklayer`)

`VirtualEthernetLinklayer` defines the tunnel action vocabulary — the protocol spoken between client and server after the handshake is complete. Every operation that moves a packet, manages a flow, or changes session state is expressed as one of these actions.

### Action Opcode Table

| Opcode | Hex | Direction | Purpose |
|--------|-----|-----------|---------|
| `INFO` | `0x7E` | S→C, C→S | Session policy, quota, IPv6 assignment |
| `KEEPALIVED` | `0x7F` | C↔S | Heartbeat / liveness probe |
| `FRP_ENTRY` | `0x20` | C→S | Register reverse port mapping |
| `FRP_CONNECT` | `0x21` | S→C | Notify incoming reverse connection |
| `FRP_CONNECTOK` | `0x22` | C→S | Acknowledge reverse connection |
| `FRP_PUSH` | `0x23` | C↔S | Data on reverse connection |
| `FRP_DISCONNECT` | `0x24` | C↔S | Close reverse connection |
| `FRP_SENDTO` | `0x25` | C↔S | UDP relay on reverse path |
| `LAN` | `0x28` | C↔S | Subnet advertisement |
| `NAT` | `0x29` | C↔S | Raw IP / NAT forwarding |
| `SYN` | `0x2A` | C→S | TCP connect request |
| `SYNOK` | `0x2B` | S→C | TCP connect acknowledgment |
| `PSH` | `0x2C` | C↔S | TCP stream data |
| `FIN` | `0x2D` | C↔S | TCP close |
| `SENDTO` | `0x2E` | C↔S | UDP datagram relay |
| `ECHO` | `0x2F` | C↔S | Echo / latency probe |
| `ECHOACK` | `0x30` | C↔S | Echo acknowledgment |
| `STATIC` | `0x31` | C→S | Static path query |
| `STATICACK` | `0x32` | S→C | Static path confirmation |
| `MUX` | `0x35` | C→S | MUX channel setup request |
| `MUXON` | `0x36` | S→C | MUX channel setup acknowledgment |

### `Do*` vs `On*` Naming Convention

- **`Do*` methods**: serialize the action and send it to the remote peer. Example: `DoSendTo()` serializes a UDP datagram and writes it to `ITransmission`.
- **`On*` methods**: virtual methods invoked when a packet with the corresponding opcode is received. Example: `OnSendTo()` is called when the remote peer sends a `SENDTO` packet.

This naming convention cleanly separates send-path (outbound) from receive-path (inbound) logic throughout the codebase.

### Class Hierarchy

```mermaid
classDiagram
    class VirtualEthernetLinklayer {
        +PacketInput(transmission, p, len, y)
        +DoConnect(y, conn_id, dest)
        +DoSendTo(y, src, dst, payload, len)
        +DoKeepAlived(y)
        +OnInformation(info, ext_json)
        +OnConnect(y, conn_id, dest)
        +OnSendTo(y, src, dst, payload, len)
        +OnKeepAlived(y)
        -protocol_
        -transport_
        -handshaked_
        -last_
    }
    class VirtualEthernetExchanger {
        +ForwardTcp(y, conn_id, dest)
        +ForwardUdp(y, dest, data, len)
        +SendKeepalive(y)
        -session_id_
        -tcp_connections_
        -udp_ports_
    }
    class VEthernetExchanger {
        +RequestConnect(y, dest)
        +SendData(y, conn_id, data, len)
        -session_id_
        -exchange_
    }
    VirtualEthernetLinklayer <|-- VirtualEthernetExchanger
    VirtualEthernetLinklayer <|-- VEthernetExchanger
```

Source: `ppp/app/protocol/VirtualEthernetLinklayer.h`

---

## Layer 4: Static Packet Path

Static UDP is handled separately from the link-layer action path because it has:
1. Different delivery semantics (raw UDP, not framed actions)
2. Different state needs (aggregator multiplexing across multiple server endpoints)
3. Independent operation from the main tunnel session

### Static UDP Architecture

```mermaid
flowchart TD
    A[Client application UDP] --> B{Routing decision}
    B -->|static endpoint| C[Static UDP aggregator\nVirtualEthernetPacket format]
    B -->|normal tunnel| D[Link-layer SENDTO action\nVirtualEthernetLinklayer]
    C --> E[Endpoint 1: server-1:20000]
    C --> F[Endpoint 2: server-2:20000]
    C --> G[Endpoint N: server-N:20000]
    E --> H[Server static UDP listener]
    F --> H
    G --> H
    D --> I[Main tunnel ITransmission]
    I --> J[VirtualEthernetExchanger]
```

### Static Packet Wire Format

The `VirtualEthernetPacket` format used by static UDP encodes all session metadata in a self-contained packet:

| Field | Bytes | Description |
|-------|-------|-------------|
| `mask_id` | 1 | Non-zero random byte; drives per-packet key factor |
| `header_length` | 1 | Obfuscated total header length |
| `session_id` | 4 | Signed: positive = UDP family, negative = IP family (`~id`) |
| `checksum` | 2 | CRC over header + payload after transforms |
| `source_ip` | 4 | Source IPv4 address |
| `source_port` | 2 | Source UDP port |
| `destination_ip` | 4 | Destination IPv4 address |
| `destination_port` | 2 | Destination port |
| `payload` | variable | UDP data or raw IP datagram |

### Static UDP Configuration

```json
"udp": {
    "static": {
        "aggligator": 4,
        "servers": ["1.0.0.1:20000", "1.0.0.2:20000"]
    }
}
```

`aggligator` is the aggregation factor — how many parallel static UDP connections to maintain.

Source: `ppp/app/client/VEthernetNetworkSwitcher.h`

---

## Why The Split Matters

The four-layer split serves several engineering goals:

| Goal | How the split helps |
|------|---------------------|
| Carrier extensibility | New transports only need to satisfy the `ITransmission` interface |
| Security isolation | Encryption logic is contained in Layer 2, not spread across the codebase |
| Protocol extensibility | New link-layer actions can be added without touching crypto or transport |
| Static path independence | UDP aggregation can be deployed without modifying session logic |
| Testability | Each layer can be tested independently with mock implementations |
| Debugging | A bug in the cipher code cannot mask a bug in the FRP logic |

---

## Connection Lifecycle

```mermaid
stateDiagram-v2
    [*] --> CarrierConnecting : client initiates connection
    CarrierConnecting --> CarrierConnected : TCP/WS connected
    CarrierConnected --> HandshakeInProgress : ITransmission::Open
    HandshakeInProgress --> HandshakeFailed : timeout, error, or key mismatch
    HandshakeInProgress --> SessionEstablished : handshake OK
    SessionEstablished --> InformationExchanged : VirtualEthernetInformation delivered
    InformationExchanged --> Forwarding : routing, DNS, IPv6 applied
    Forwarding --> KeepaliveChecking : keepalive timer fires
    KeepaliveChecking --> Forwarding : reply received
    KeepaliveChecking --> SessionTimedOut : no reply within timeout
    Forwarding --> SessionClosed : either side initiates close
    SessionTimedOut --> [*]
    HandshakeFailed --> [*]
    SessionClosed --> [*]
```

---

## TCP Relay Flow

```mermaid
sequenceDiagram
    participant Client as Client VEthernetExchanger
    participant LL as VirtualEthernetLinklayer
    participant Server as VirtualEthernetExchanger
    participant Dest as Real TCP Destination

    Client->>LL: DoConnect(conn_id, dest_endpoint)
    LL->>Server: SYN (0x2A) frame
    Server->>Dest: TCP connect()
    Dest-->>Server: SYN-ACK
    Server->>LL: DoConnectOK(conn_id, ERRORS_SUCCESS)
    LL->>Client: SYNOK (0x2B) frame
    Client->>LL: DoPush(conn_id, data)
    LL->>Server: PSH (0x2C) frame
    Server->>Dest: write(data)
    Dest-->>Server: response data
    Server->>LL: DoPush(conn_id, response)
    LL->>Client: PSH (0x2C) frame
    Client->>LL: DoDisconnect(conn_id)
    LL->>Server: FIN (0x2D) frame
    Server->>Dest: close()
```

---

## UDP Relay Flow

```mermaid
sequenceDiagram
    participant App as Local Application
    participant Client as VEthernetExchanger
    participant LL as VirtualEthernetLinklayer
    participant Server as VirtualEthernetExchanger
    participant Dest as Real UDP Destination

    App->>Client: sendto(data, dest_addr)
    Client->>LL: DoSendTo(src_ep, dst_ep, payload)
    LL->>Server: SENDTO (0x2E) frame
    Server->>Dest: OS UDP sendto(payload)
    Dest-->>Server: UDP reply
    Server->>LL: DoSendTo(dst_ep_as_src, src_ep, reply)
    LL->>Client: SENDTO (0x2E) frame
    Client->>App: inject reply into TAP
```

---

## FRP Reverse Mapping Flow

FRP (Fast Reverse Proxy) allows clients to expose local services through the server:

```mermaid
sequenceDiagram
    participant External as External Client
    participant Server as VirtualEthernetSwitcher
    participant LL as VirtualEthernetLinklayer
    participant Client as VEthernetExchanger
    participant Local as Local Service

    Client->>LL: DoFrpEntry(protocol, remote_port, local_port)
    LL->>Server: FRP_ENTRY (0x20) frame
    Server->>Server: bind remote_port
    External->>Server: TCP connect to remote_port
    Server->>LL: DoFrpConnect(conn_id, remote_port)
    LL->>Client: FRP_CONNECT (0x21) frame
    Client->>Local: TCP connect to local_port
    Local-->>Client: connected
    Client->>LL: DoFrpConnectOK(conn_id)
    LL->>Server: FRP_CONNECTOK (0x22) frame
    External->>Server: data
    Server->>LL: DoFrpPush(conn_id, data)
    LL->>Client: FRP_PUSH (0x23) frame
    Client->>Local: forward data
    Local-->>Client: response
    Client->>LL: DoFrpPush(conn_id, response)
    LL->>Server: FRP_PUSH frame
    Server->>External: forward response
```

---

## Error Code Reference

Tunnel-related `ppp::diagnostics::ErrorCode` values:

| ErrorCode | Description |
|-----------|-------------|
| `SessionHandshakeFailed` | Protected transport handshake did not complete |
| `SessionHandshakeFailed` | Handshake exceeded the configured timeout |
| `EvpInitKeyDerivationFailed` | Cipher/KDF initialization failed while rebuilding working cipher state |
| `TunnelReadFailed` | Framed tunnel read failed |
| `TunnelWriteFailed` | Framed tunnel write failed |
| `SocketConnectFailed` / `TcpConnectFailed` | Carrier TCP/WebSocket connection failed |
| `SslHandshakeFailed` | TLS negotiation failed (WSS carrier) |
| `ProtocolFrameInvalid` | Invalid action type, malformed action frame, or opcode received from a disallowed direction |
| `ProtocolPacketActionInvalid` | Opcode byte not in recognized range |
| `KeepaliveTimeout` | No keepalive reply within timeout |
| `SessionHandshakeFailed` | STATIC/STATICACK exchange failed |
| `ProtocolMuxFailed` | MUX/MUXON exchange failed |
| `MappingCreateFailed` | Server rejected FRP_ENTRY registration |

> **Note**: Older design-only names for key-derivation, transmission read/write, and carrier-connection failures are not current `ErrorCodes.def` entries; use the nearest existing codes shown in the table above.

---

## Performance Considerations

### Zero-Copy Goals

The tunnel is designed to minimize data copies on the hot path:

| Stage | Copy cost |
|-------|-----------|
| TAP → `OnPacketInput()` | One copy: kernel fd read into user-space buffer |
| `OnPacketInput()` → `IPFrame::Parse()` | Zero-copy: `IPFrame` holds pointer into existing buffer |
| `IPFrame` → `DoSendTo()` | One copy: serialize into transmission write buffer |
| Encrypt | In-place: cipher operates on the same buffer |
| Write to socket | Zero-copy: `async_write` with scatter-gather |

The per-thread 64 KB buffer in `Executors` is the key to avoiding repeated heap allocation on the hot path. All operations within one `io_context` thread use this shared buffer without synchronization.

### Cipher Performance

AES-based ciphers with hardware AES-NI acceleration (x86/x64 with `-DENABLE_SIMD=ON`) operate at several GB/s per core, well above VPN throughput requirements. AEAD/ChaCha20-family cipher performance should be evaluated after target-build support is verified.

---

## Usage Examples

### Checking which transport carrier is active

```cpp
// ppp/app/server/VirtualEthernetExchanger.cpp
auto transmission = exchanger->GetTransmission();
if (transmission != NULLPTR) {
    auto kind = transmission->GetKind();
    // kind: TcpTransmission, WebSocketTransmission, SslWebSocketTransmission
}
```

### Sending a keepalive from the server side

```cpp
// ppp/app/server/VirtualEthernetExchanger.cpp
bool VirtualEthernetExchanger::SendKeepalive(
    const boost::asio::yield_context& y) noexcept
{
    auto linklayer = GetLinklayer();
    if (NULLPTR == linklayer) {
        return false;
    }
    return linklayer->DoKeepAlived(y);
}
```

### Handling an incoming TCP connect action

```cpp
// ppp/app/protocol/VirtualEthernetLinklayer.cpp
bool VirtualEthernetLinklayer::OnConnect(
    const boost::asio::yield_context& y,
    ppp::Int32                        connection_id,
    const IPEndPoint&                 destination) noexcept
{
    // Validate destination against firewall
    // Create outbound TCP socket
    // Register connection in session table
    // Send DoConnectOK with ERRORS_SUCCESS
    return true;
}
```

### Sending a UDP datagram through the tunnel

```cpp
// ppp/app/client/VEthernetExchanger.cpp
bool VEthernetExchanger::OnSendTo(
    const boost::asio::yield_context& y,
    const boost::asio::ip::udp::endpoint& src,
    const boost::asio::ip::udp::endpoint& dst,
    const Byte* payload,
    int         payload_length) noexcept
{
    return DoSendTo(y, src, dst, payload, payload_length);
}
```

---

## Source Reading Order

To understand the tunnel design from source, read in this order:

1. `ppp/transmissions/ITransmission.h` — framing and cipher interface
2. `ppp/transmissions/ITransmission.cpp` — handshake implementation
3. `ppp/app/protocol/VirtualEthernetLinklayer.h` — opcode enum and Do/On declarations
4. `ppp/app/protocol/VirtualEthernetLinklayer.cpp` — `PacketInput` dispatch
5. `ppp/app/protocol/VirtualEthernetInformation.h` — `INFO` envelope structure
6. `ppp/app/client/VEthernetExchanger.cpp` — client-side `On*` implementations
7. `ppp/app/server/VirtualEthernetExchanger.cpp` — server-side `On*` implementations
8. `ppp/app/server/VirtualEthernetSwitcher.cpp` — connection acceptance and session routing

---

## Related Documents

- [`TRANSMISSION.md`](TRANSMISSION.md) — ITransmission framing, cipher, and handshake in detail
- [`PACKET_FORMATS.md`](PACKET_FORMATS.md) — Wire format specifications for all frame types
- [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md) — Step-by-step handshake sequence
- [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md) — Full opcode vocabulary reference
- [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md) — Session identity and control plane
- [`PACKET_LIFECYCLE.md`](PACKET_LIFECYCLE.md) — Complete packet journey from TAP to remote
- [`SECURITY.md`](SECURITY.md) — Security model and threat analysis
