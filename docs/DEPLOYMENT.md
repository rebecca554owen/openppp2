# Deployment Patterns

[中文版本](DEPLOYMENT_CN.md)

## Scope

This document summarizes practical ways to deploy OPENPPP2 as a VPN or SD-WAN component.

## Pattern 1: Basic Remote Access VPN

Topology:

- one server node
- multiple clients
- each client gets a virtual adapter and sends selected or full traffic to the server

Use when:

- users need access to remote internal networks
- you want one operationally simple entry point

Minimum ingredients:

- server listener on TCP, UDP, WS, or WSS
- client `client.server`
- TUN settings

## Pattern 2: Split-Tunnel Enterprise Access

Topology:

- client keeps public traffic local
- only private prefixes, route files, or DNS-selected destinations enter the overlay

Key features:

- `client.routes`
- `--bypass`
- `--bypass-ngw`
- `--dns-rules`
- `--virr` and route-list refresh workflows

Use when:

- you want lower bandwidth cost
- only some business systems must traverse the tunnel

## Pattern 3: Site-To-Site Overlay

Topology:

- fixed clients or branch nodes connect to a central server
- subnet forwarding is enabled
- route policy determines which remote subnets are reachable

Key features:

- `server.subnet`
- `--tun-vnet=yes`
- client route lists

Use when:

- branch offices need stable interconnect
- the tunnel should behave more like a routed overlay than an end-user VPN

## Pattern 4: Proxy Gateway Edge

Topology:

- client establishes tunnel
- local applications do not use the virtual NIC directly
- they connect to the local HTTP or SOCKS proxy exposed by the client runtime

Key features:

- `client.http-proxy.*`
- `client.socks-proxy.*`
- optional `server-proxy` when outbound connection itself must traverse an upstream proxy

Use when:

- application-level redirection is easier than route changes
- only selected apps should use the overlay

## Pattern 5: Reverse Service Exposure

Topology:

- a client behind NAT connects outward to the server
- the client registers mappings
- outside users or systems reach the mapped service through the server side

Key features:

- `client.mappings`
- server `mapping`
- FRP-style control actions in the tunnel protocol

Use when:

- internal services must be published without inbound access to the client site

## Pattern 6: WebSocket / WSS Tunnel Behind HTTP Infrastructure

Topology:

- server listens on WS or WSS
- reverse proxy or TLS edge fronts the service
- clients connect through HTTP-friendly paths

Key features:

- `websocket.listen.ws`
- `websocket.listen.wss`
- `websocket.host`
- `websocket.path`
- `websocket.http.request`
- `websocket.http.response`

Use when:

- the deployment must fit existing web ingress infrastructure
- TLS termination or L7 routing is already standardized

## Pattern 7: Multiplexed Multi-Flow Tunnel

Topology:

- one healthy session carries multiple logical channels
- repeated setup cost is reduced

Key features:

- `--tun-mux`
- `--tun-mux-acceleration`
- `mux.*`

Use when:

- many logical flows share one remote endpoint
- setup efficiency matters more than strict isolation between flows

## Pattern 8: Static UDP Path With Multi-Server Support

Topology:

- client uses static UDP-oriented behavior
- one or more upstream UDP servers are configured
- keepalive maintains path health

Key features:

- `--tun-static=yes`
- `udp.static.keep-alived`
- `udp.static.servers`
- `udp.static.aggligator`

Use when:

- you need datagram-oriented behavior
- the environment favors persistent UDP reachability

## Pattern 9: Managed Node With External Backend

Topology:

- server keeps the data plane locally
- server also connects to a Go backend over WebSocket/webhook style APIs

Key features:

- `server.backend`
- `server.backend-key`
- `go/` service

Use when:

- user policy, node policy, and traffic accounting must be centralized

## Pattern 10: IPv6-Capable Overlay

Topology:

- server allocates IPv6 state
- client requests or applies assigned IPv6 values
- Linux server side handles most complete IPv6 data-plane behavior

Key features:

- `server.ipv6.mode`
- `server.ipv6.cidr`
- `server.ipv6.gateway`
- `server.ipv6.dns1`
- `server.ipv6.dns2`
- `--tun-ipv6`

Use when:

- the overlay must carry IPv6 natively or present IPv6 service to clients

## Selection Guidance

Choose transport and topology by operational need:

- simplest deployment: TCP server + standard client mode
- easiest web integration: WSS
- strongest route control: split-tunnel with route lists and DNS rules
- service publishing: mappings
- best reuse of one session: MUX
- managed service model: backend integration

## Deployment Discipline

- Keep server and client configs separate
- Version route lists and DNS rules alongside deployment config
- Treat certificates, backend keys, proxy credentials, and DB secrets as environment secrets
- Do not enable IPv6, mappings, mux, static mode, and proxies all at once unless the site really needs them

## Related Documents

- [`CONFIGURATION.md`](CONFIGURATION.md)
- [`OPERATIONS.md`](OPERATIONS.md)
- [`SECURITY.md`](SECURITY.md)
