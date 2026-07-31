# Peer-prefix routing

> **Status:** Current, IPv4-only site-prefix feature
> **Type:** Guide
> **Last verified:** Peer-prefix configuration, INFO protocol, client manager, and server policy sources, 2026-07-22
> **Parent index:** [Task Guides](README.md) · **Chinese:** [Peer 前缀路由](PEER_PREFIX_ROUTING_CN.md)

## Purpose

Peer-prefix routing lets a connected gateway peer announce an IPv4 network reachable behind that peer. The server validates the announcement, records the gateway virtual IPv4 address, and can distribute a route-table snapshot to other peers. It does not configure the gateway host's LAN forwarding, NAT, or return route for you.

The feature is enabled only when both `server.subnet` and `server.peer-routing.enabled` are true.

## Server policy: fail closed

A server announces no prefix by default. `server.peer-routing.allowed-routes` is a per-client allow-list: a requested network/prefix must exactly match a row whose `guid` matches the gateway session GUID. An empty allow-list rejects every announcement. Default routes, invalid prefixes, and reserved ranges are rejected by the policy.

Example policy shape:

```json
{
  "server": {
    "subnet": true,
    "peer-routing": {
      "enabled": true,
      "distribute": true,
      "allowed-routes": [
        {
          "network": "10.20.0.0",
          "prefix": 24,
          "guid": "<gateway-client-guid>"
        }
      ]
    }
  }
}
```

`distribute` controls whether accepted table changes are pushed to connected peers. It does not remove the need for server-side validation.

## Gateway peer

A client sends an INFO `peer-route-announce` registration when `client.peer-route-announce` contains prefixes. The server replies with `registered` only for accepted entries, or `reject` when the feature/policy/virtual-address prerequisites are not met.

```json
{
  "client": {
    "peer-route-announce": [
      { "network": "10.20.0.0", "prefix": 24 }
    ],
    "peer-gateway-forward": true
  }
}
```

`client.peer-gateway-forward` permits the client-side forwarding path for received remote-prefix packets. It does not enable the host OS to forward traffic by itself.

## Access peer

An access peer can receive a dynamic `peer-route-table` snapshot when distribution is enabled. It can also configure static entries locally:

```json
{
  "client": {
    "peer-routes": [
      {
        "network": "10.20.0.0",
        "prefix": 24,
        "via": "10.1.0.2"
      }
    ]
  }
}
```

`via` is the gateway peer's virtual IPv4 address. Dynamic and static inputs are client route inputs; neither proves that the gateway LAN can return traffic.

## Operator checklist

1. Enable `server.subnet` and `server.peer-routing.enabled`.
2. Add exact network/prefix/GUID allow-list rows before allowing a gateway to announce anything.
3. Ensure the gateway peer has a valid virtual IPv4 address and its accepted route shows `registered`.
4. Enable host IP forwarding/NAT or install the necessary routes on the gateway and downstream LAN.
5. Provide a return path from the remote LAN back to the VPN subnet, or use an operator-owned NAT design.
6. Verify from an access peer only after the server table and host routing are both healthy.

## Limits

- Prefix entries are IPv4; this feature does not provide IPv6 site-prefix routing.
- Peer-prefix forwarding and the transport/P2P optimization path are distinct concerns.
- The server controls accepted announcements; a client configuration alone cannot authorize a prefix.

## Related pages

- [Routing and DNS](ROUTING_AND_DNS.md)
- [Deployment model](../operations/DEPLOYMENT.md)
- [Configuration reference](../reference/CONFIGURATION.md)