# Server Architecture

[中文版本](SERVER_ARCHITECTURE_CN.md)

## Core Types

The server side is centered on:

- `VirtualEthernetSwitcher`
- `VirtualEthernetExchanger`
- `VirtualEthernetNetworkTcpipConnection`
- static datagram helpers
- namespace cache and managed backend client

The switcher is the session switch. Each exchanger represents one client session.

## Server Responsibilities

The server is responsible for much more than accepting a socket.

From code, it owns:

- listener creation
- transport acceptance
- handshake and session establishment
- optional backend authentication
- NAT and UDP forwarding
- reverse mapping support
- mux support
- static UDP path support
- session statistics
- IPv6 request, lease, and transit state
- firewall and namespace-cache integration

## Listener Model

The server can expose multiple listener categories:

- TCP
- WebSocket
- WebSocket over TLS
- CDN/SNI proxy style listeners
- UDP static socket path

This makes the server a multi-front-door overlay node rather than a single-port tunnel daemon.

## Accept Path

After a carrier connection is accepted, the server turns it into an `ITransmission` and runs handshake logic.

At that point the connection can become one of two things:

- a main session establishment path
- an additional connection path for TCP relay or mux-related work

The distinction is visible in `Establish(...)` and `Connect(...)`.

## Why The Server Uses A Switcher

The name is accurate. `VirtualEthernetSwitcher` is not only a listener owner. It switches sessions, connections, NAT state, IPv6 lease state, and management interactions.

This is the right shape for an overlay server node.

## Session Establishment

When the server establishes a new client session, it:

1. creates or replaces the exchanger for that session id
2. obtains policy information
3. builds an information envelope
4. optionally installs IPv6 state
5. sends session information to the client
6. runs the exchanger loop for that session

The code also supports a local bootstrap path when no management backend is configured.

## Management Backend Cooperation

When `server.backend` is configured, the server can authenticate sessions through `VirtualEthernetManagedServer`.

This is important because the server architecture is designed so that:

- the data plane remains in the C++ process
- admission and accounting can be delegated outward

That split is cleaner than trying to move all networking logic into the management service.

## NAT And UDP Forwarding

Server-side exchangers receive tunnel actions such as `NAT` and `SENDTO` and forward them into the real network.

This is why the server holds:

- datagram port tables
- NAT information tables
- firewall references

The server is acting as the real network edge for remote clients.

## Why Some Inbound Actions Are Rejected Immediately

The server-side exchanger explicitly rejects certain control directions, such as unexpected TCP relay control from the wrong side.

That is a defensive design decision. The protocol model is symmetric in vocabulary, but not in legal direction for every action.

## Reverse Mapping Support

When mapping is enabled, the server participates in FRP-style reverse service exposure.

That means the server is not only forwarding client traffic outward. It can also provide an external access face for services registered from the client side.

## MUX On The Server

The server can build and maintain `vmux_net` instances associated with a session.

This allows additional logical flows to reuse the session relationship while still being mediated by explicit mux setup and acknowledgment steps.

## Static UDP Path On The Server

The server also owns the other half of static mode:

- static allocation context
- static echo bind port
- static datagram forwarding
- session-specific packet decrypt/encrypt behavior

This is why the server keeps separate static socket state outside the normal stream-oriented transmission path.

## IPv6 State

Server-side IPv6 support is one of the more infrastructure-like parts of the design.

The server maintains:

- IPv6 request table
- IPv6 lease table
- address-to-session association
- transit TAP state
- optional neighbor proxy state

It can derive stable addresses from session identity, honor static bindings, and install data-plane support for the assigned addresses.

This is not an afterthought. It is a real control and forwarding subsystem.

## Namespace Cache And DNS

The server contains a namespace cache for DNS-style data. This reduces repeated resolution work and gives the server a role in name-handling policy, not only packet forwarding.

## Why The Server Looks Like Infrastructure

The server is designed as an overlay node with:

- multiple ingress styles
- explicit session switching
- local forwarding state
- optional policy backend
- IPv6 service logic

That is exactly why it should be documented more like a network node than like an application server.
