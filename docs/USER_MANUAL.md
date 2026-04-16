# User Manual

[中文版本](USER_MANUAL_CN.md)

## Position

This is the user-facing guide to OPENPPP2 as a network runtime.

## What OPENPPP2 Is

OPENPPP2 is a single-binary, multi-role, cross-platform virtual networking runtime. It can run as client or server and can combine routing, DNS steering, reverse mappings, static packet paths, MUX, platform integration, and an optional management backend.

## What To Decide First

Before writing config or running commands, decide:

- the node role
- the deployment shape
- the host platform
- whether the node is full-tunnel, split-tunnel, proxy edge, service-publishing edge, or IPv6-serving edge

## Basic Run Model

- `server` is the default role
- `client` is selected with `--mode=client`
- use an explicit config path
- run with administrator/root privilege

## What The Host Will Change

Depending on platform and role, OPENPPP2 may change:

- virtual adapters
- routes
- DNS behavior
- proxy behavior
- IPv6 behavior
- firewall or socket protection settings

## Recommended Reading Order

1. `ARCHITECTURE.md`
2. `STARTUP_AND_LIFECYCLE.md`
3. `CONFIGURATION.md`
4. `CLI_REFERENCE.md`
5. `PLATFORMS.md`
6. `DEPLOYMENT.md`
7. `OPERATIONS.md`

## Quick Start

### Server Quick Start

| Step | Action | Example |
|------|--------|---------|
| 1 | Obtain the release package | `openppp2-linux-amd64-simd.zip` |
| 2 | Extract and enter the directory | `mkdir -p openppp2 && cd openppp2` |
| 3 | Edit the server config | Set `server.backend` as needed |
| 4 | Start the runtime | `./ppp` |

### Client Quick Start

| Step | Action | Example |
|------|--------|---------|
| 1 | Create an install directory | `C:\openppp2` |
| 2 | Extract the release package | `openppp2-windows-amd64.zip` |
| 3 | Edit the client config | Set `client.guid`, `client.server`, and related fields |
| 4 | Start as administrator | `ppp --mode=client` |

## DNS Rules List

| Item | Description | Link |
|------|-------------|------|
| Main DNS rules list | Regularly updated Mainland China domain direct-connect rules | [github.com/liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt) |

## HTTPS Certificate Configuration

| Item | Description | Location / Link |
|------|-------------|-----------------|
| Runtime root certificate | Place `cacert.pem` in the runtime directory | `cacert.pem` |
| Mirror repository | Alternate certificate source | [github.com/liulilittle/cacert.pem](https://github.com/liulilittle/cacert.pem) |
| CURL CA bundle | Official CA extract page | [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html) |

## Configuration Reference Highlights

| Parameter | Type | Example Value | Description | Applicable |
|-----------|------|---------------|-------------|----------|
| `client.server` | string | `ppp://192.168.0.24:20000/` | Server connection address | `client` |
| `client.server-proxy` | string | `http://user:pass@192.168.0.18:8080/` | Proxy used to reach the server | `client` |
| `client.bandwidth` | int | `10000` | Bandwidth limit in Kbp/s | `client` |
| `server.backend` | string | `ws://192.168.0.24/ppp/webhook` | Optional management backend | `server` |
| `virr.update-interval` | int | `86400` | IP-list refresh interval in seconds | `client` |
| `vbgp.update-interval` | int | `3600` | vBGP refresh interval in seconds | `client` |

## Appendix 1: UDP Static Aggligator

| Parameter | Type | Example Value | Description | Applicable |
|-----------|------|---------------|-------------|----------|
| `udp.static.aggligator` | int | `4` | Aggregator link count | `client` |
| `udp.static.servers` | array[string] | `1.0.0.1:20000` | Aggregator or forwarding server list | `client` |

### Behavior

| Condition | Meaning |
|-----------|---------|
| `udp.static.aggligator > 0` | Enable aggregator mode and require `servers` |
| `udp.static.aggligator <= 0` | Enable static tunnel mode |

### Example

```json
"udp": {
  "static": {
    "aggligator": 2,
    "servers": ["192.168.1.100:6000", "10.0.0.2:6000"]
  }
}
```

## Appendix 2: Linux Routing Forwarding

### Enable IPv4 and IPv6 Forwarding

```conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
```

### Dual-NIC Routing Example

```bash
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j MASQUERADE
```

### Bypass SNAT Example

```bash
iptables -A FORWARD -s 192.168.0.0/24 -d 0.0.0.0/0 -j ACCEPT
iptables -A FORWARD -s 0.0.0.0/0 -d 192.168.0.0/24 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -A POSTROUTING -s 192.168.0.0/24 -j SNAT --to 192.168.0.20
```

## Appendix 3: Windows Soft Router Forwarding

### Example Tool

| Item | Example |
|------|---------|
| Virtual gateway tool | `VGW` |
| Download | [github.com/liulilittle/vgw-release](https://github.com/liulilittle/vgw-release) |

### Example Parameters

| Parameter | Type | Example Value | Description |
|-----------|------|---------------|-------------|
| `--ip` | string | `192.168.0.40` | Virtual gateway IP |
| `--ngw` | string | `192.168.0.1` | Main router gateway |
| `--mask` | string | `255.255.255.0` | Subnet mask |
| `--mac` | string | `30:fc:68:88:b4:a9` | Custom virtual MAC |
