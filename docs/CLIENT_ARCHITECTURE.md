# Client Architecture

[中文版本](CLIENT_ARCHITECTURE_CN.md)

## Scope

This document describes the real client runtime in `ppp/app/client/`. It is not a generic VPN description. It is the host-side edge node for the overlay network.

## Runtime Position

The client has two major jobs:

- shape local host networking
- maintain the remote tunnel session

## Core Split

The two central types are:

- `VEthernetNetworkSwitcher`
- `VEthernetExchanger`

That split is the key architectural boundary.

| Type | Responsibility |
|---|---|
| `VEthernetNetworkSwitcher` | Virtual adapter, routes, DNS, bypass, local classification, proxy surface |
| `VEthernetExchanger` | Remote session, handshake, keepalive, key state, static path, IPv6, mapping |

## Client Flow

1. Build local network context
2. Create the virtual adapter environment
3. Classify traffic
4. Open the remote transport session
5. Complete handshake
6. Exchange session information
7. Apply routing, DNS, proxy, mapping, and optional IPv6 state
8. Enter steady-state forwarding

## `VEthernetNetworkSwitcher`

This object owns the host-network side:

- adapter creation
- route changes
- DNS changes
- traffic classification
- bypass policy
- reinjection of data returned from the server

It sits on the host side and decides what goes to the tunnel and what stays local.

## `VEthernetExchanger`

This object owns the remote-session side:

- transport connection establishment
- client-side handshake
- session keepalive
- key management
- static path state
- mapping registration
- IPv6 application

## Host Integration

The client is also responsible for local proxy surfaces and platform-specific virtual adapter behavior. That makes it a host integration layer, not just a dialer.

## Boundaries

The important boundary is that route/DNS/bypass logic stays in the switcher, while remote connection and handshake logic stays in the exchanger.

## Related Documents

- `ARCHITECTURE.md`
- `SERVER_ARCHITECTURE.md`
- `TUNNEL_DESIGN.md`
