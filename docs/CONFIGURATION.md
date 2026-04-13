# Configuration Reference

[中文版本](CONFIGURATION_CN.md)

## Overview

OPENPPP2 loads runtime configuration from `appsettings.json` into `AppConfiguration`.

The configuration model is normalized in code, so missing fields are filled by defaults and some invalid values are corrected or disabled.

## Top-Level Groups

### `key`

Controls framing and cryptographic behavior.

Important fields:

- `kf`, `kh`, `kl`, `kx`, `sb`
- `protocol`, `protocol-key`
- `transport`, `transport-key`
- `masked`
- `plaintext`
- `delta-encode`
- `shuffle-data`

Use this group to decide how conservative or lightweight the protected transmission layer should be.

### `tcp`

Controls TCP listener and client behavior.

Important fields:

- `listen.port`
- `connect.timeout`
- `connect.nexcept`
- `inactive.timeout`
- `turbo`
- `backlog`
- `cwnd`, `rwnd`
- `fast-open`

### `udp`

Controls UDP listener, DNS handling, and static UDP mode.

Important fields:

- `listen.port`
- `inactive.timeout`
- `dns.timeout`
- `dns.ttl`
- `dns.cache`
- `dns.turbo`
- `dns.redirect`
- `static.keep-alived`
- `static.dns`
- `static.quic`
- `static.icmp`
- `static.aggligator`
- `static.servers`

### `mux`

Controls multiplexed logical channels.

Important fields:

- `connect.timeout`
- `inactive.timeout`
- `congestions`
- `keep-alived`

### `websocket`

Controls WS/WSS listeners and HTTP-facing behavior.

Important fields:

- `listen.ws`
- `listen.wss`
- `host`
- `path`
- `ssl.certificate-file`
- `ssl.certificate-key-file`
- `ssl.certificate-chain-file`
- `ssl.certificate-key-password`
- `ssl.ciphersuites`
- `http.request`
- `http.response`
- `http.error`

### `server`

Controls server-side node behavior.

Important fields:

- `node`
- `log`
- `subnet`
- `mapping`
- `backend`
- `backend-key`
- `ipv6.mode`
- `ipv6.cidr`
- `ipv6.gateway`
- `ipv6.dns1`
- `ipv6.dns2`
- `ipv6.lease-time`
- `ipv6.static-addresses`

### `client`

Controls client behavior and local services.

Important fields:

- `guid`
- `server`
- `server-proxy`
- `bandwidth`
- `reconnections.timeout`
- `http-proxy.bind`
- `http-proxy.port`
- `socks-proxy.bind`
- `socks-proxy.port`
- `socks-proxy.username`
- `socks-proxy.password`
- `mappings`
- `routes`
- `paper-airplane.tcp` on Windows

### `vmem`

Virtual memory workspace configuration:

- `size`
- `path`

### `ip`

Deployment address hints:

- `public`
- `interface`

## Route And Split-Tunnel Related Fields

Client route entries combine several concerns in one place:

- `nic`: preferred outgoing NIC on Linux
- `ngw`: preferred next-hop gateway
- `path`: local route list file
- `vbgp`: remote route list source

This is how OPENPPP2 implements many split-tunnel and policy-routing scenarios without requiring an external SD-WAN controller for every decision.

## Mapping Configuration

Each `client.mappings` item defines one exported service:

- `protocol`: `tcp` or `udp`
- `local-ip`
- `local-port`
- `remote-ip`
- `remote-port`

Use mappings when the overlay should expose a local service outward instead of only giving the client remote access.

## IPv6 Configuration

Server IPv6 configuration currently uses these modes:

- `none`
- `nat66`
- `gua`

When enabled, the server can assign IPv6 state to clients through information extensions. Linux has the deepest support for the server-side IPv6 data plane.

## CLI Overrides

Runtime CLI options can override parts of the JSON configuration.

Common examples:

- `--mode=[client|server]`
- `--config=<path>`
- `--dns=<ip-list>`
- `--nic=<interface>`
- `--ngw=<ip>`
- `--tun=<name>`
- `--tun-ip=<ip>`
- `--tun-ipv6=<ip>`
- `--tun-gw=<ip>`
- `--tun-mask=<bits>`
- `--tun-vnet=[yes|no]`
- `--tun-host=[yes|no]`
- `--tun-static=[yes|no]`
- `--tun-mux=<connections>`
- `--tun-mux-acceleration=<mode>`
- `--bypass=<file>`
- `--bypass-ngw=<ip>`
- `--dns-rules=<file>`
- `--firewall-rules=<file>`

Use CLI overrides for deployment-time adaptation. Keep stable policy in JSON.

## Minimal Configuration Guidance

### Minimal server

Set at least:

- `tcp.listen.port` or `udp.listen.port` or `websocket.listen.ws/wss`
- `key.*`
- `server.node`

### Minimal client

Set at least:

- `client.guid`
- `client.server`
- local TUN values through JSON or CLI

## Operational Recommendations

- Keep one environment-specific config per role and per site
- Avoid mixing sample secrets with production secrets
- Treat `server-proxy`, backend keys, database credentials, and certificate passwords as secrets
- Turn on only the transport and tunnel features you actually deploy

## Related Documents

- [`README.md`](../README.md)
- [`DEPLOYMENT.md`](DEPLOYMENT.md)
- [`OPERATIONS.md`](OPERATIONS.md)
