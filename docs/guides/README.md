# Task Guides

> **Status:** Current
> **Type:** Guide index
> **Last verified:** Source audit, 2026-07-22
> **Parent index:** [Documentation](../README.md) · **Chinese:** [任务指南](README_CN.md)

Use these pages to operate features implemented in this repository. They describe current code paths and configuration boundaries; they are not a compatibility promise for undocumented internals or historical designs.

## Choose a task

| Task | Start here |
|---|---|
| Steer client traffic, route lists, or DNS | [Routing and DNS](ROUTING_AND_DNS.md) · [中文](ROUTING_AND_DNS_CN.md) |
| Run local HTTP/SOCKS proxies instead of normal desktop TUN policy setup | [Proxy-only mode](PROXY_MODE.md) · [中文](PROXY_MODE_CN.md) |
| Understand host/platform integration | [Platform integration](PLATFORMS.md) · [中文](PLATFORMS_CN.md) |
| Connect VPN peers to an IPv4 site prefix | [Peer-prefix routing](PEER_PREFIX_ROUTING.md) · [中文](PEER_PREFIX_ROUTING_CN.md) |
| Run the native Go manager or publish subscriptions | [Management backend](MANAGEMENT_BACKEND.md) · [中文](MANAGEMENT_BACKEND_CN.md) |
| Consume or publish a subscription-v1 document | [Remote subscription format](REMOTE_SUBSCRIPTION.md) · [中文](REMOTE_SUBSCRIPTION_CN.md) |
| Operate negotiated IPv6 client addressing | [IPv6 client assignment](IPV6_CLIENT_ASSIGNMENT.md) · [中文](IPV6_CLIENT_ASSIGNMENT_CN.md) |
| Operate Linux server IPv6 leases, NDP proxy, or transit | [IPv6 lease management](IPV6_LEASE_MANAGEMENT.md) · [NDP proxy](IPV6_NDP_PROXY.md) · [Transit plane](IPV6_TRANSIT_PLANE.md) |

## Current-document boundary

- These are current, source-backed guides for the `ppp` runtime and bundled surfaces in this tree.
- IPv6 server data-plane pages are explicitly Linux-server scoped; mobile and desktop client paths have different limits.
- The desktop subscription client is an experimental surface. Its behavior is documented only where its code implements it.
- Historical rationale, proposals, and superseded designs belong outside this current-guide index. Do not use them as an operator contract.

For process startup and hardening, continue with [Operations](../operations/README.md).