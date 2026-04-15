# CLI Reference

[中文版本](CLI_REFERENCE_CN.md)

## Position

This document explains the real `ppp` command line, not just the help banner. The CLI is a startup-time shaping layer, not the whole configuration model.

Anchors:

- `main.cpp::PrintHelpInformation()`
- `main.cpp::GetNetworkInterface()`
- `main.cpp::IsModeClientOrServer()`

## High-Level Groups

The CLI surface splits into:

- role selection
- runtime shaping
- client network shaping
- routing and DNS inputs
- server policy inputs
- platform helper commands
- utility commands

## Role Selection

### `--mode=[client|server]`

- Default: `server`
- Aliases: `--m`, `-mode`, `-m`
- Any value beginning with `c` selects client mode

This choice changes the whole startup branch:

- client mode creates/uses the virtual adapter path
- server mode opens the server-side listener/switcher path

Examples:

```bash
ppp --mode=server --config=./server.json
ppp --mode=client --config=./client.json
```

## Configuration File

### `--config=<path>`

Aliases:

- `-c`
- `--c`
- `-config`
- `--config`

Lookup order:

1. explicit CLI path
2. `./config.json`
3. `./appsettings.json`

Use an explicit path in production.

## Runtime Shaping

### `--rt=[yes|no]`

Process-level real-time preference.

### `--dns=<ip-list>`

Overrides the local DNS list for the current run. It writes to `NetworkInterface::DnsAddresses`; it does not replace DNS rules or server-side DNS logic.

### `--tun-flash=[yes|no]`

Sets the default flash/TOS tendency early in startup.

### `--auto-restart=<seconds>`

Process-level restart timer. `0` disables it.

### `--link-restart=<count>`

Restarts the process after too many link reconnections.

## Server Inputs

### `--block-quic=[yes|no]`

Blocks QUIC-related behavior for the current run.

### `--firewall-rules=<file>`

Firewall rules file. Help default: `./firewall_rules.txt`.

## Client Inputs

### `--lwip=[yes|no]`

Selects the client network stack behavior.

### `--vbgp=[yes|no]`

Enables vBGP route updates.

### `--nic=<interface>`

Physical interface hint.

### `--ngw=<ip>`

Gateway hint.

### `--tun=<name>`

Virtual adapter name.

### `--tun-ip=<ip>` / `--tun-ipv6=<ip>` / `--tun-gw=<ip>` / `--tun-mask=<bits>`

Virtual adapter addressing inputs.

### `--tun-vnet=[yes|no]`

Controls subnet-forwarding behavior.

### `--tun-host=[yes|no]`

Controls whether host-network behavior is preferred. Default: `yes`.

### `--tun-static=[yes|no]`

Enables static tunnel mode.

### `--tun-mux=<connections>`

MUX connection count. `0` disables it.

### `--tun-mux-acceleration=<mode>`

MUX acceleration mode.

### `--tun-promisc=[yes|no]`

Promiscuous mode on supported platforms.

### `--tun-ssmt=<threads>` or `--tun-ssmt=<N>[/<mode>]`

SSMT tuning. On Linux, `mq` opens one tun queue per worker.

### `--tun-route=[yes|no]`

Linux route-compatibility toggle.

### `--tun-protect=[yes|no]`

Linux route-protection toggle.

### `--tun-lease-time-in-seconds=<sec>`

Windows DHCP lease time.

## Routing Inputs

### `--bypass=<file1|file2>`

Bypass IP list file. Default: `./ip.txt`.

### `--bypass-nic=<interface>`

Interface used for bypass list processing on Linux.

### `--bypass-ngw=<ip>`

Gateway used for bypass list processing.

### `--virr=[file/country]`

Enables IP-list refresh behavior.

### `--dns-rules=<file>`

DNS rules file. Default: `./dns-rules.txt`.

## Platform Helpers

### Windows only

- `--system-network-reset`
- `--system-network-optimization`
- `--system-network-preferred-ipv4`
- `--system-network-preferred-ipv6`
- `--no-lsp <program>`

These are helper actions, not tunnel-start options.

## Utility Commands

### `--help`

Shows the help output.

### `--pull-iplist [file/country]`

Downloads an IP list and exits after the action completes.

## Defaults Worth Remembering

- `--mode` defaults to `server`
- `--dns` falls back to the preferred DNS pair if parsing fails
- `--bypass` falls back to `./ip.txt`
- `--dns-rules` falls back to `./dns-rules.txt`
- `--firewall-rules` falls back to `./firewall_rules.txt`

## Related Documents

- `CONFIGURATION.md`
- `TRANSMISSION.md`
- `ARCHITECTURE.md`
