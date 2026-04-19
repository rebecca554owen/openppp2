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

Firewall rules file. Help default: `./firewall-rules.txt`.

## Client Inputs

### `--lwip=[yes|no]`

Selects the client network stack behavior.

### `--vbgp=[yes|no]`

Enables vBGP route updates. Refresh cadence is controlled by `vbgp.update-interval` in the configuration file.

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

Promiscuous mode on Linux and macOS.

### `--tun-ssmt=<threads>` or `--tun-ssmt=<N>[/<mode>]`

SSMT tuning. On Linux, `mq` opens one tun queue per worker; macOS documents the thread-count form only.

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

Enables IP-list refresh behavior. Refresh cadence is controlled by `virr.update-interval` and `virr.retry-interval` in the configuration file.

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

## Console UI Commands And Layout

The runtime Console UI is a dedicated interactive surface, separate from startup CLI flags.

Anchors:

- `ppp/app/ConsoleUI.cpp::ExecuteCommand(...)`
- `ppp/app/ConsoleUI.cpp::RenderFrame(...)`
- `ppp/app/ConsoleUI.cpp::BuildStatusBarText(...)`

### Supported commands

- `help`: prints available commands.
- `restart`: requests process-level restart (`ShutdownApplication(true)`).
- `exit`: requests process shutdown (`ShutdownApplication(false)`).
- `clear`: clears buffered log lines and resets scroll offset.
- `status`: prints the same status-bar text rendered in the frame footer.

Scrolling and editor navigation are keyboard-driven in the interactive surface.

### Layout contract

Each rendered frame has:

1. scrollable body log area
2. fixed command editor line (`cmd> ...`)
3. fixed status bar line

Render and input are non-blocking and run on dedicated UI threads; main runtime I/O threads are not blocked by console repaint or key handling.

### Keyboard controls

- `Up` / `Down`: command history navigation.
- `Left` / `Right`: move cursor in editor.
- `Home` / `End`: jump cursor to line boundaries.
- `Backspace` / `Delete`: erase character before/at cursor.
- `PageUp` / `PageDown`: page scroll for body log area.
- `Ctrl+Up` / `Ctrl+Down`: line scroll for body log area.

Windows and non-Windows builds both support active editor input and history/scroll handling.

### Status bar semantics

Status bar text is composed as:

- `vpn:<state>`
- optional `note:<latest queued runtime status text>`
- `err:<FormatErrorString(snapshot)>`
- `err_age:<seconds>s` from `GetLastErrorTimestamp()` delta
- `diag_ts:<raw diagnostics timestamp>`

The status bar reads process-wide diagnostics snapshots and is intended to show last observed failure context without interrupting data-plane threads.

## Defaults Worth Remembering

- `--mode` defaults to `server`
- `--dns` falls back to the preferred DNS pair if parsing fails
- `--bypass` falls back to `./ip.txt`
- `--dns-rules` falls back to `./dns-rules.txt`
- `--firewall-rules` falls back to `./firewall-rules.txt`

## Related Documents

- `CONFIGURATION.md`
- `TRANSMISSION.md`
- `ARCHITECTURE.md`
- `ERROR_HANDLING_API.md`
