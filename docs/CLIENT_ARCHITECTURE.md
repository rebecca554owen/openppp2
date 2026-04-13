# Client Architecture

[中文版本](CLIENT_ARCHITECTURE_CN.md)

## Core Types

The client side is centered on:

- `VEthernetNetworkSwitcher`
- `VEthernetExchanger`
- `VEthernetNetworkTcpipStack`
- `VEthernetNetworkTcpipConnection`
- proxy switchers and local proxy connections

The switcher owns the host-side environment. The exchanger owns the remote session.

## Client Responsibilities

From the code, the client is not only a tunnel dialer. It also owns:

- virtual adapter lifecycle
- route installation and cleanup
- bypass and route-list logic
- DNS steering and DNS redirection
- local HTTP and SOCKS proxy exposure
- reverse mapping registration
- static UDP mode behavior
- mux negotiation and use
- optional IPv6 application

## Startup Path

The client startup path is roughly:

1. parse config and CLI overrides
2. create TUN/TAP
3. build `VEthernetNetworkSwitcher`
4. inject runtime mode flags such as static, mux, vnet, protect
5. load bypass list and route lists
6. load DNS rules
7. call `Open(tap)`
8. create `VEthernetExchanger`
9. let the exchanger establish and maintain the remote tunnel

## Why The Client Is Split Into Switcher And Exchanger

The split is visible in code responsibilities:

- `VEthernetNetworkSwitcher` deals with host networking state
- `VEthernetExchanger` deals with remote session state

That is the correct boundary. Route tables and DNS policies live longer than any single remote connection attempt.

## Virtual Adapter Integration

The switcher runs on top of `ITap` and therefore treats the virtual adapter as a platform abstraction.

Once the adapter is open, the client becomes responsible for:

- handling packets from the adapter
- deciding whether they should stay local or enter the tunnel
- reinjecting returned traffic back into the adapter

## IPv4 Packet Path

For virtual-subnet traffic, IPv4 packets from TUN are examined by `OnPacketInput(...)`.

The logic is intentionally selective:

- only TCP, UDP, and ICMP are relevant on the path shown in code
- traffic must belong to the expected virtual subnet context
- traffic aimed at the local gateway is treated separately

Accepted traffic is forwarded to the exchanger through `Nat(...)`.

## UDP Path

The UDP path is more complex than generic NAT forwarding because the client also supports:

- DNS interception and redirection
- QUIC blocking
- static UDP mode
- per-endpoint datagram state

That is why UDP is handled through explicit datagram-port objects instead of only through one generic forwarder.

## ICMP Path

The ICMP path includes special handling for:

- echo behavior
- synthetic replies
- TTL-related responses

This matters for operator-visible behavior. A virtual network that cannot produce sane ICMP behavior is harder to diagnose and less router-like.

## TCP Path

Client-side TCP handling is split out into dedicated classes because TCP needs more than packet forwarding.

The implementation has to manage:

- logical connect/open
- stream payload forwarding
- close semantics
- optional mux participation
- possible local bypass behavior

This is why TCP uses `VEthernetNetworkTcpipStack` and `VEthernetNetworkTcpipConnection` rather than the simpler UDP path.

## Route Control

The client is heavily route-aware.

From code and config structure, route logic includes:

- preferred NIC and gateway
- bypass file loading
- route-list loading from file
- remote route-list refresh support
- default-route protection
- hosted-network preference

This is one of the main reasons the project behaves more like an overlay edge node than like a thin VPN client.

## DNS Control

DNS is treated as a first-class routing/control mechanism.

Client-side DNS features include:

- DNS rule loading
- DNS server override
- optional DNS redirect inside the tunnel path
- DNS cache cooperation through the wider runtime

That is important because in overlay systems, name resolution policy often determines actual traffic steering policy.

## Local Proxy Functions

The client can expose:

- HTTP proxy
- SOCKS proxy

This means local applications can use the overlay without sending their traffic directly to the virtual adapter.

This is a deployment-style feature, not just a convenience feature.

## Reverse Mapping Registration

The client also acts as the registration side for reverse mappings.

Configured `client.mappings` are registered into the tunnel control plane so that remote access can be created through the server side.

This is one reason the client is more than a packet source. It is also an endpoint service exposer.

## Static Mode

Static mode gives the client a datagram-oriented path that is separate from the main control transport.

The client allocates static echo state, derives session-specific ciphers, and can move selected UDP, DNS, QUIC, or ICMP traffic through this path depending on configuration.

## MUX

Client-side mux exists to reuse an established relationship for multiple logical flows.

The code shows that mux is mostly used for additional logical TCP/IP relay work, not as a replacement for the main control session.

## IPv6 Application

The client can request a specific IPv6 and can apply server-assigned IPv6 state.

The applied state includes:

- address
- gateway
- route prefix
- DNS servers

The code also verifies that transmitted IPv6 packets actually match the assigned address, which keeps the client from using arbitrary IPv6 source identities inside the managed overlay.

## Why The Client Looks Like This

The client architecture is shaped by one core fact: the client must be both a host-network integration layer and a tunnel endpoint.

If those two concerns were not separated cleanly, the implementation would be much harder to reason about.
