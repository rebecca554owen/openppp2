# Session And Control Plane Model

[中文版本](TRANSMISSION_PACK_SESSIONID_CN.md)

## Why This Exists

The old file name is historical. The useful topic is how OPENPPP2 carries session identity and control actions after the transport handshake is complete.

## Main Types

- `ppp/transmissions/ITransmission.*`
- `ppp/app/protocol/VirtualEthernetInformation.*`
- `ppp/app/protocol/VirtualEthernetLinklayer.*`
- `ppp/app/server/VirtualEthernetSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetManagedServer.*`

## Session Identity

Session identity is centered on `Int128`. It is used to bind one logical tunnel exchange to one transport session and to track server-side exchanger state, accounting, and control callbacks.

## Information Exchange

`VirtualEthernetInformation` carries the session envelope used for policy and lifetime data, including:

- `BandwidthQoS`
- `IncomingTraffic`
- `OutgoingTraffic`
- `ExpiredTime`

The point is to keep policy exchange separate from raw forwarding.

## IPv6 Extension Data

The IPv6 extension adds assigned mode, address, prefix length, gateway, DNS, and result status. The same message family can therefore carry both generic policy and IPv6 provisioning results.

## Control Actions After Handshake

After transport setup, the link layer can carry actions such as:

- information sync
- keepalive
- TCP connect / push / disconnect
- UDP sendto
- echo / echo reply
- static path setup
- mux setup
- FRP-style mapping registration and forwarding

## Client Flow

1. Build config and local network context
2. Open the virtual adapter and route policy
3. Create `VEthernetExchanger`
4. Establish transport
5. Complete handshake and obtain session identity
6. Exchange `VirtualEthernetInformation`
7. Apply routing, DNS, mux, proxy, mapping, and optional IPv6 state
8. Enter steady-state forwarding and keepalive

## Server Flow

1. Open listeners for enabled transports
2. Accept a new connection
3. Complete handshake
4. Create or attach `VEthernetExchanger`
5. Build the information envelope
6. Optionally consult the management backend
7. Maintain traffic, leases, mappings, and statistics

`VirtualEthernetSwitcher` coordinates this lifecycle on the server side.

## Management Plane

`VirtualEthernetManagedServer` is optional. It links the tunnel server to an external control system over WebSocket or secure WebSocket for authentication, accounting, reachability checks, and reconnect handling.

## Quota and Expiry

The session model has explicit hooks for quota, expiry, bandwidth limits, and backend-mediated authentication. That lets the runtime enforce policy locally even if the backend is slow or unavailable.

## Mappings and Reverse Access

Client `mappings` drive FRP-style registration, connection setup, data push, disconnect, and UDP relay actions. So the overlay is not only for remote access; it can also expose services in a controlled reverse direction.

## Failure Model

The design expects failures and includes hooks for handshake timeout, reconnection timeout, cleanup, keepalive checks, and management-link reconnects.

## Related Documents

- `TRANSMISSION.md`
- `ARCHITECTURE.md`
- `CONFIGURATION.md`
- `SECURITY.md`
