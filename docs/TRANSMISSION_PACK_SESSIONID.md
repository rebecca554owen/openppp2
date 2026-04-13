# Session And Control Plane Model

[中文版本](TRANSMISSION_PACK_SESSIONID_CN.md)

## Why This Document Exists

The old file name refers to `PACK_SESSIONID`, but the useful engineering topic is broader: how OPENPPP2 identifies a session, exchanges tunnel metadata, and drives control actions after the transport is up.

This document focuses on that control-plane model.

## Core Objects

The main types involved are:

- `ppp/transmissions/ITransmission.*`
- `ppp/app/protocol/VirtualEthernetInformation.*`
- `ppp/app/protocol/VirtualEthernetLinklayer.*`
- `ppp/app/server/VirtualEthernetSwitcher.*`
- `ppp/app/client/VEthernetExchanger.*`
- `ppp/app/server/VirtualEthernetManagedServer.*`

## Session Identity

Session identity is centered on `Int128` values used across client, server, and management flows.

That identifier is used to:

- bind one logical tunnel exchange to a transport session
- locate the server-side exchanger
- associate traffic accounting and authentication state
- manage IPv6 requests, leases, and control callbacks

The use of a wide identifier is consistent with the project design goal of long-lived sessions that should be globally distinct inside one deployment domain.

## Information Exchange Object

`VirtualEthernetInformation` carries the tunnel-side session envelope for quota and validity controls:

- `BandwidthQoS`
- `IncomingTraffic`
- `OutgoingTraffic`
- `ExpiredTime`

This is the minimum unit for telling a client what it is allowed to do and for how long.

It is deliberately separate from raw packet forwarding, which keeps policy exchange lightweight.

## IPv6 Extensions

`VirtualEthernetInformationExtensions` extends the base information object with IPv6-specific state:

- assigned IPv6 mode
- assigned IPv6 address and prefix length
- assigned gateway and route prefix
- assigned DNS servers
- request/response status and status message

This allows the same control-plane message family to carry both generic session policy and IPv6 provisioning results.

## Control Actions After Handshake

After the transport handshake, the link layer can exchange multiple control actions:

- information sync
- keepalive
- TCP connect/push/disconnect
- UDP sendto
- echo / echo reply
- static path setup
- mux setup
- FRP-style mapping registration and data forwarding

The important point is that OPENPPP2 does not treat these as unrelated subsystems. They are all modeled as actions within one tunnel control plane.

## Client-Side Flow

At a high level, the client path is:

1. Build configuration and local network context
2. Open the virtual adapter and route policy
3. Create `VEthernetExchanger`
4. Establish transport session to remote server
5. Complete transmission handshake and obtain session identity
6. Exchange `VirtualEthernetInformation`
7. Apply routing, DNS, mux, proxy, mapping, and optional IPv6 state
8. Enter steady-state packet forwarding and keepalive

`VEthernetExchanger` is the operational bridge between the transport session and the client virtual network state.

## Server-Side Flow

At a high level, the server path is:

1. Open listeners for enabled transports
2. Accept a new transport connection
3. Complete server-side handshake
4. Create or attach a `VirtualEthernetExchanger`
5. Admit the session and build information envelope
6. Optionally verify or enrich state through the management backend
7. Maintain tunnel traffic, IPv6 leases, NAT state, mappings, and statistics

`VirtualEthernetSwitcher` acts as the session switch and lifecycle coordinator.

## Management Plane Role

`VirtualEthernetManagedServer` is optional. It connects the tunnel server to an external control system over WebSocket or secure WebSocket.

Its responsibilities include:

- asynchronous authentication
- traffic upload and accounting
- backend reachability checks
- reconnect behavior for the management link

This keeps the data plane in the C++ process while allowing external policy or billing systems to remain outside it.

## Quota, Expiry, And Admission

The session model has explicit hooks for:

- traffic quota
- expiry time
- bandwidth QoS limits
- backend-mediated authentication

This is important for SD-WAN and managed VPN deployments because the tunnel runtime needs to enforce policy locally even if the external backend becomes slow or temporarily unavailable.

## Mappings And Reverse Access

The control plane also carries mapping state. On the client side, `client.mappings` defines services to be exported. The corresponding FRP-style actions handle:

- registration
- connection setup
- data push
- disconnect
- UDP sendto relay

This lets the overlay do more than simple remote access. It can also work as a controlled reverse-exposure channel.

## Static Echo Path

The codebase includes a static echo mechanism in the client and server exchangers. Its purpose is operational rather than cosmetic:

- maintain liveness on static UDP-style paths
- verify reachability
- keep datagram-oriented session state active

It belongs to the control plane because it carries session-health intent, not just arbitrary payload.

## Failure And Recovery Model

The session design expects failure and includes explicit recovery hooks:

- handshake timeout
- reconnection timeout
- transport disposal and cleanup
- keepalive-driven health checks
- session state transitions on the client exchanger
- management-link reconnect behavior on the server side

This fits the infrastructure requirement of autonomy and low operator surprise.

## Design Philosophy

The control plane reflects a few stable principles:

- keep identity, policy, and packet forwarding related but not mixed together
- make session state explicit in types, not hidden in ad hoc socket code
- let one exchange object own lifecycle for one logical client/server relationship
- keep external management optional instead of making the data plane dependent on it

## Related Documents

- [`TRANSMISSION.md`](TRANSMISSION.md)
- [`ARCHITECTURE.md`](ARCHITECTURE.md)
- [`CONFIGURATION.md`](CONFIGURATION.md)
- [`SECURITY.md`](SECURITY.md)
