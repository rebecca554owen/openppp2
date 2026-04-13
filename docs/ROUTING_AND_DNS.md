# Routing And DNS Design

[中文版本](ROUTING_AND_DNS_CN.md)

## Why This Matters

In OPENPPP2, route and DNS behavior are central parts of the product, not side effects.

That is why there is dedicated code for:

- bypass IP lists
- route files
- remote route refresh
- DNS rule files
- DNS redirection
- DNS cache cooperation
- default-route protection

## Route Control Model

The client owns most route-steering logic.

Important inputs include:

- `--nic`
- `--ngw`
- `--bypass`
- `--bypass-ngw`
- `client.routes`
- `--virr`
- `--tun-vnet`
- `--tun-host`

The code uses these to decide:

- what traffic enters the tunnel
- what traffic stays on the local network
- how to prevent recursion toward the tunnel server itself

## Bypass Lists

Bypass files give the client a direct and explicit way to keep some destinations out of the overlay.

This is simpler and safer than trying to infer split-tunnel policy from application behavior.

## Route Files And vBGP-Style Lists

Client route entries can include:

- a local `path`
- a remote `vbgp` URL

This lets the client operate with file-driven route policy and periodic refresh instead of requiring a large live controller for all route decisions.

## Default Route Protection

The Linux client contains explicit protect-mode behavior. More generally, the client runtime tries to avoid self-recursive routing and accidental traffic black-holing.

This is a critical infrastructure concern. Overlay clients must avoid sending control traffic back into their own overlay path.

## DNS Rule Model

DNS rules let the client treat DNS as a traffic steering signal.

That is useful because in overlay systems many decisions are domain-driven, not only prefix-driven.

The client can therefore redirect or handle DNS flows differently from ordinary UDP flows.

## DNS Redirection

The client-side UDP path checks whether a packet is DNS traffic and can redirect it to a configured server.

This is not just optimization. It ensures name resolution can be made consistent with overlay policy.

## Namespace Cache On The Server

The server contains a namespace cache for DNS data. This gives the server a role in reducing repeated lookups and in helping tunnel-side name resolution behave predictably.

## Why Route And DNS Are Documented Together

Because in this system they are operationally linked.

Examples:

- a bypass route list may keep some destinations local
- a DNS rule may decide which names should use the overlay
- route installation may need DNS-server routes as special cases

If route policy and DNS policy are documented separately with no cross-reference, operators will miss how traffic actually gets classified.

## Infrastructure View

From a router-like perspective, route and DNS control are how the overlay becomes policy-aware.

Without them, OPENPPP2 would just be a protected transport. With them, it becomes an edge node capable of implementing real overlay network policy.
