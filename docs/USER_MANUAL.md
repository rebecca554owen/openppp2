# User Manual

[中文版本](USER_MANUAL_CN.md)

## Position

This is the user-facing guide to OPENPPP2 as a network runtime.
It covers what OPENPPP2 is, how to run it, how to configure it for common scenarios, and what host changes to expect.

---

## What OPENPPP2 Is

OPENPPP2 is a single-binary, multi-role, cross-platform virtual networking runtime. It can run as client or server and can combine routing, DNS steering, reverse mappings, static packet paths, MUX, platform integration, and an optional management backend.

```mermaid
flowchart TD
    A[OPENPPP2] --> B[Client Mode]
    A --> C[Server Mode]
    B --> D[Virtual NIC + tunnel]
    B --> E[Split or full tunnel routing]
    B --> F[DNS steering]
    B --> G[MUX / static UDP]
    C --> H[Session routing]
    C --> I[TCP + UDP forwarding]
    C --> J[IPv6 transit]
    C --> K[Optional Go backend]
```

---

## What To Decide First

Before writing config or running commands, decide:

| Decision | Options |
|----------|---------|
| Node role | `client` or `server` |
| Deployment shape | single node, multi-server, managed |
| Host platform | Linux, Windows, macOS, Android |
| Tunnel mode | full-tunnel, split-tunnel, proxy edge, service-publishing, IPv6-serving |

---

## Basic Run Model

| Scenario | Command |
|----------|---------|
| Start as server (default) | `./ppp` |
| Start as server with explicit config | `./ppp --config=/etc/openppp2/appsettings.json` |
| Start as client | `./ppp --mode=client` |
| Start as client with explicit config | `./ppp --mode=client --config=./appsettings.json` |

Requirements:
- Administrator on Windows; root on Linux/macOS/Android.
- Configuration file at an accessible path.

---

## What The Host Will Change

Depending on platform and role, OPENPPP2 may change:

| Host element | Client | Server |
|-------------|--------|--------|
| Virtual NIC | Created | Not created |
| OS routing table | Modified (routes added/protected) | Not modified |
| DNS configuration | May be overridden | Not modified |
| System HTTP proxy | May be set | Not set |
| IPv6 settings | If IPv6 enabled | If `server.ipv6` enabled |
| Firewall rules | Not modified | May set rules |

---

## Recommended Reading Order

1. [`ARCHITECTURE.md`](ARCHITECTURE.md) — overall system design
2. [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md) — how the process starts and stops
3. [`CONFIGURATION.md`](CONFIGURATION.md) — configuration file reference
4. [`CLI_REFERENCE.md`](CLI_REFERENCE.md) — command-line arguments
5. [`PLATFORMS.md`](PLATFORMS.md) — platform-specific notes
6. [`DEPLOYMENT.md`](DEPLOYMENT.md) — deployment checklist
7. [`OPERATIONS.md`](OPERATIONS.md) — troubleshooting

---

## Quick Start

### Server Quick Start

| Step | Action | Example |
|------|--------|---------|
| 1 | Obtain the release package | `openppp2-linux-amd64-simd.zip` |
| 2 | Extract and enter the directory | `mkdir -p openppp2 && cd openppp2` |
| 3 | Edit the server config | Set `tcp.listen.port`, `key.*` fields |
| 4 | Start the runtime | `sudo ./ppp` |

Minimal server config:

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true
  }
}
```

### Client Quick Start

| Step | Action | Example |
|------|--------|---------|
| 1 | Create an install directory | `mkdir -p /opt/openppp2` |
| 2 | Extract the release package | `unzip openppp2-linux-amd64.zip -d /opt/openppp2` |
| 3 | Edit the client config | Set `client.guid`, `client.server`, `key.*` to match server |
| 4 | Start as root | `sudo ./ppp --mode=client` |

Minimal client config:

```json
{
  "concurrent": 4,
  "key": {
    "kf": 154543927,
    "kx": 128,
    "kl": 10,
    "kh": 12,
    "protocol": "aes-128-cfb",
    "protocol-key": "OpenPPP2-Test-Protocol-Key",
    "transport": "aes-256-cfb",
    "transport-key": "OpenPPP2-Test-Transport-Key",
    "masked": false,
    "plaintext": false,
    "delta-encode": false,
    "shuffle-data": false
  },
  "client": {
    "guid": "{F4519CF1-7A8A-4B00-89C8-9172A87B96DB}",
    "server": "ppp://192.168.0.1:20000/"
  }
}
```

---

## Tunnel Mode Selection

```mermaid
flowchart TD
    A[Choose tunnel mode] --> B{All traffic via tunnel?}
    B -->|yes| C[Full tunnel mode]
    B -->|no| D{Domain-based steering?}
    D -->|yes| E[Split tunnel + DNS rules]
    D -->|no| F[Split tunnel by IP-list]
    C --> G[Set default route via tunnel]
    E --> H[Configure dns-rules file]
    F --> I[Configure bypass IP list]
```

| Mode | Description | Key config |
|------|-------------|-----------|
| Full tunnel | All traffic goes through tunnel | Default if no bypass list |
| Split tunnel | Selected IPs bypass tunnel | `client.bypass` IP list |
| DNS steering | Domain-based resolver selection | `client.dns-rules` |
| Service publishing | Server publishes local services via FRP | `server.mappings` |
| IPv6 serving | Server provides IPv6 transit | `server.ipv6` |

---

## Configuration Reference Highlights

### Core Fields

| Parameter | Type | Example | Description | Applies to |
|-----------|------|---------|-------------|-----------|
| `concurrent` | int | `4` | IO thread concurrency | both |
| `key.kf` | int | `154543927` | Protocol key factor | both |
| `key.protocol` | string | `"aes-128-cfb"` | Encryption cipher | both |
| `key.transport` | string | `"aes-256-cfb"` | Transport cipher | both |

### Client Fields

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `client.guid` | string | `"{F4519CF1-...}"` | Client unique identifier |
| `client.server` | string | `"ppp://192.168.0.1:20000/"` | Server connection address |
| `client.server-proxy` | string | `"http://user:pass@proxy:8080/"` | Proxy to reach server |
| `client.bandwidth` | int | `10000` | Bandwidth limit in Kbp/s |
| `client.bypass` | array | `["/etc/bypass.txt"]` | IP bypass list sources |
| `client.dns-rules` | array | `["rules:///etc/dns.txt"]` | DNS rules sources |

### Server Fields

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `server.node` | int | `1` | Server node ID |
| `tcp.listen.port` | int | `20000` | TCP tunnel listener port |
| `websocket.listen.ws` | int | `20080` | WebSocket listener port (0 = disabled) |
| `websocket.listen.wss` | int | `20443` | TLS WebSocket listener port (0 = disabled) |
| `server.backend` | string | `"ws://backend:80/ppp/webhook"` | Optional management backend |
| `server.ipv4-pool.network` | string | `"10.0.0.0"` | IPv4 address pool for client assignment |
| `server.ipv4-pool.mask` | string | `"255.255.255.0"` | IPv4 pool subnet mask |

---

## DNS Rules List

| Item | Description | Link |
|------|-------------|------|
| Main DNS rules list | Regularly updated Mainland China domain direct-connect rules | [github.com/liulilittle/dns-rules.txt](https://github.com/liulilittle/dns-rules.txt) |

DNS rules file format:

```
# Route these domains to local DNS
.example.com 192.168.1.1
.localnet.com 192.168.1.1

# Route these to specific upstream
.google.com 8.8.8.8
.cloudflare.com 1.1.1.1
```

---

## HTTPS Certificate Configuration

| Item | Description | Location |
|------|-------------|----------|
| Runtime root certificate | Place `cacert.pem` in the runtime directory | `cacert.pem` next to `ppp` |
| Mirror repository | Alternate certificate source | [github.com/liulilittle/cacert.pem](https://github.com/liulilittle/cacert.pem) |
| CURL CA bundle | Official CA extract page | [curl.se/docs/caextract.html](https://curl.se/docs/caextract.html) |

---

## Common Scenarios

### Scenario 1: Full Tunnel Client On Linux

```bash
# 1. Install
mkdir -p /opt/openppp2
cd /opt/openppp2
unzip openppp2-linux-amd64-simd.zip

# 2. Edit appsettings.json — set client.server, key fields

# 3. Run
sudo ./ppp --mode=client
```

Expected result: all traffic routes through the server.

### Scenario 2: Split Tunnel With China Bypass

```json
{
  "client": {
    "guid": "{...}",
    "server": "ppp://server-ip:20000/",
    "bypass": [
      "https://raw.githubusercontent.com/liulilittle/china-list/main/cidr.txt"
    ]
  }
}
```

Expected result: Mainland China IPs go direct; all other traffic through tunnel.

### Scenario 3: Server With Management Backend

```json
{
  "tcp": {
    "listen": { "port": 20000 }
  },
  "server": {
    "node": 1,
    "subnet": true,
    "backend": "ws://192.168.0.100/ppp/webhook"
  }
}
```

Expected result: client sessions authenticated and accounted by Go backend.

### Scenario 4: WebSocket Server Behind Nginx

```json
{
  "websocket": {
    "host": "your-domain.com",
    "path": "/tun",
    "listen": {
      "ws": 8080
    }
  }
}
```

Then configure Nginx to proxy WebSocket to port 8080.

Client connection string:

```
ppp://ws/192.168.0.1:443/
```

---

## Connection URL Formats

| Format | Protocol | Example |
|--------|----------|---------|
| `ppp://host:port/` | Raw TCP | `ppp://1.2.3.4:20000/` |
| `ppp://ws/host:port/` | WebSocket | `ppp://ws/1.2.3.4:443/` |
| `ppp://wss/host:port/` | TLS WebSocket | `ppp://wss/1.2.3.4:443/` |

---

## Appendix 1: UDP Static Aggregator

| Parameter | Type | Example | Description | Applies to |
|-----------|------|---------|-------------|-----------|
| `udp.static.aggligator` | int | `4` | Aggregator link count | `client` |
| `udp.static.servers` | array | `["1.0.0.1:20000"]` | Aggregator or forwarding server list | `client` |

| Condition | Meaning |
|-----------|---------|
| `udp.static.aggligator > 0` | Enable aggregator mode; `servers` required |
| `udp.static.aggligator <= 0` | Enable static tunnel mode |

```json
"udp": {
  "static": {
    "aggligator": 2,
    "servers": ["192.168.1.100:6000", "10.0.0.2:6000"]
  }
}
```

---

## Appendix 2: Linux Routing Forwarding

### Enable IPv4 and IPv6 Forwarding

Add to `/etc/sysctl.conf`:

```conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.lo.forwarding = 1
```

Apply:

```bash
sysctl -p
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

---

## Appendix 3: Windows Soft Router Forwarding

| Item | Example |
|------|---------|
| Virtual gateway tool | VGW |
| Download | [github.com/liulilittle/vgw-release](https://github.com/liulilittle/vgw-release) |

VGW example parameters:

| Parameter | Type | Example | Description |
|-----------|------|---------|-------------|
| `--ip` | string | `192.168.0.40` | Virtual gateway IP |
| `--ngw` | string | `192.168.0.1` | Main router gateway |
| `--mask` | string | `255.255.255.0` | Subnet mask |
| `--mac` | string | `30:fc:68:88:b4:a9` | Custom virtual MAC |

---

## Appendix 4: Android Deployment

Android deployment uses the VPNService API. OPENPPP2 is embedded as a native library:

```mermaid
flowchart TD
    A[Android App] --> B[VPNService]
    B --> C[JNI Bridge]
    C --> D[OPENPPP2 C++ Runtime]
    D --> E[Tunnel to server]
```

Key points:
- Requires `BIND_VPN_SERVICE` and `INTERNET` permissions in `AndroidManifest.xml`.
- JNI functions: `run(config_json)`, `stop()`, `release()`.
- No root required; uses Android VPNService framework.
- Error codes returned as integers mapping to `ppp::diagnostics::ErrorCode`.

---

## Appendix 5: IPv6 Transit (Server)

To enable IPv6 transit on the server:

```json
{
  "server": {
    "ipv6": {
      "cidr": "fdec:1234::/64"
    }
  }
}
```

This allows clients to receive IPv6 addresses and reach IPv6 destinations through the server.

See [`IPV6_TRANSIT_PLANE.md`](IPV6_TRANSIT_PLANE.md) for full details.

---

## Appendix 6: FRP Reverse Mapping (Service Publishing)

To publish a local service through the server:

```json
{
  "server": {
    "mappings": [
      {
        "local-ip": "127.0.0.1",
        "local-port": 22,
        "remote-port": 10022,
        "protocol": "tcp"
      }
    ]
  }
}
```

This publishes `localhost:22` on the server as `server-ip:10022`.

---

## Troubleshooting Quick Reference

| Symptom | Most likely cause | Fix |
|---------|-----------------|-----|
| Process exits immediately | Missing privilege | Run as root/administrator |
| "configuration not found" | Wrong config path | Use `--config=/absolute/path` |
| Cannot reach server | Network or firewall | Test with `nc` or `telnet` first |
| DNS not working through tunnel | DNS route missing | Check bypass list covers DNS servers |
| Sessions drop | Keepalive failure | Check `keepalive.*` config values |
| Routes not restored after exit | Forced kill | Use SIGTERM for graceful stop |

---

## Related Documents

- [`CONFIGURATION.md`](CONFIGURATION.md)
- [`CLI_REFERENCE.md`](CLI_REFERENCE.md)
- [`DEPLOYMENT.md`](DEPLOYMENT.md)
- [`OPERATIONS.md`](OPERATIONS.md)
- [`PLATFORMS.md`](PLATFORMS.md)
- [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md)
- [`SECURITY.md`](SECURITY.md)
- [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md)
