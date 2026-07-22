# CLI Reference
> Status: Active
> Type: Reference
> Last verified: 8c8a888
> Parent index: [Reference index](README.md)
> Peer link: [中文](CLI_REFERENCE_CN.md)

## Scope

This reference documents the current startup parser and Console UI. It complements [Configuration Reference](CONFIGURATION.md): JSON supplies durable settings, while CLI arguments shape one process launch. It is source-backed current behavior, not a formal option registry, exit-code table, or automation compatibility promise.

The parser accepts both `--name=value` and `--name value`. Quote arguments when the shell could interpret their contents.

## Startup order that affects behavior

`PreparedArgumentEnvironment()` processes the relevant inputs in this order:

1. Apply `--tun-flash`.
2. Read `--stats-json`; for a file path, open it with `"wb"` and close it.
3. Handle `--help`.
4. Load configuration.
5. Apply MUX/debug overrides, resolve mode, then apply proxy defaults and proxy-port overrides.
6. Build network-interface settings and configure telemetry.

Consequences:

- A `--stats-json` file can be created or **truncated before** help is printed or configuration is loaded. `stdout` is not pre-opened. When transmission statistics are available, each later sample is written as one NDJSON line; file destinations are reopened in append (`"ab"`) mode for that write.
- `--help` is handled before configuration loading. The current help path records `AppHelpRequested` and returns a nonzero preparation status; scripts must not assume `--help` exits with status `0`.
- Normal `--pull-iplist` use still needs a loadable configuration because argument preparation occurs before the one-shot pull action.

## Configuration file

### `--config=<path>`

Aliases: `-c`, `--c`, `-config`, `--config`.

The loader first tries a readable explicit path, then `./config.json`, then `./appsettings.json`. Use an explicit path for reproducible launches:

```bash
ppp --mode=server --config=./server.json
```

## Mode and proxy behavior

### `--mode=<value>`

Aliases: `--m`, `-mode`, `-m`. After trimming and lower-casing:

| Input | Selected mode |
|---|---|
| exact `proxy` | proxy |
| any value beginning with `c` | client |
| empty or any other value | server |

`--mode=proxy` is distinct from the `c` prefix rule. Proxy mode, and configuration with `client.proxy-only=true`, force the local HTTP and SOCKS listener bind addresses to `127.0.0.1`. Missing/non-positive proxy ports default to `8080` (HTTP) and `1080` (SOCKS); `--proxy-http-port` and `--proxy-socks-port` are applied afterwards.

Proxy-only client startup uses the proxy path instead of a real TUN and skips client route, bypass-list, DNS-rule, and geo-rule setup.

## Core launch options

| Option | Current behavior |
|---|---|
| `--tun-flash=[yes|no]` | Applied first during startup as the default flash/TOS setting. |
| `--stats-json=<path|stdout>` | Produces runtime NDJSON only when transmission statistics are available. A path is pre-opened with `wb` during startup, then each available runtime sample appends one line. |
| `--rt=[yes|no]` | Enables/disables the real-time scheduling preference; the parser defaults it to `yes`. |
| `--auto-restart=<seconds>` | Requests restart after the parsed non-negative interval; `0` disables it. |
| `--link-restart=<count>` | Parsed as decimal and stored in an 8-bit threshold. Malformed or negative input becomes `0`; use `0..255` and do not rely on wider values. |
| `--firewall-rules=<file>` | Firewall-rules path; default `./firewall-rules.txt`. |
| `--dns=<ip-list>` | Supplies the launch-local DNS address list. |

## Client and TUN options

| Option | Current behavior |
|---|---|
| `--block-quic=[yes|no]` | Client behavior. When enabled, UDP packets to destination port 443 are rejected with ICMP Port Unreachable so clients can fall back to TCP; it is not a general QUIC protocol decoder. |
| `--tun-ip=<IPv4>` | Defaults to `10.0.0.2`. Explicitly passing this option implicitly enables static mode, even if `--tun-static=no`. |
| `--tun-gw=<IPv4>` | Virtual gateway; default `10.0.0.1`. |
| `--tun-mask=<bits-or-netmask>` | Accepts a numeric prefix or an IPv4 netmask; default `255.255.255.252` (`/30`). |
| `--tun-static=[yes|no]` | Explicit static-tunnel switch. |
| `--tun-host=[yes|no]` / `--tun-vnet=[yes|no]` | Both default to `yes`. |
| `--tun-mux=<connections>` | Strict decimal count; malformed or negative input becomes `0` (disabled). Storage is `uint16_t`, so use `0..65535` and do not rely on wider values. |
| `--tun-mux-acceleration=<0..3>` | `0..3` are the supported settings. The parser first narrows a strict decimal input to an unsigned byte, then clears a resulting value above `3`; out-of-range input is not a validation API. |
| `--mux-mode=<compat|flow|balance|stripe>` / `--mux-mode-turbo=[yes|no]` | Launch-time MUX settings applied after configuration loading. `turbo` is meaningful only with `flow`; generated help lists `--mux-mode` but currently omits `--mux-mode-turbo`. |
| `--nic=<interface>` / `--ngw=<ip>` | Physical NIC and gateway hints. |
| `--tun-ipv6=<IPv6>` | Requests an IPv6 address when the supplied value parses as IPv6. |

Platform-specific options remain conditional: Linux has `--bypass-nic`, `--tun-route`, `--tun-protect`, and `--tun-ssmt`; macOS has `--tun-ssmt`; Linux/macOS have `--tun-promisc`; Windows has `--tun-lease-time-in-seconds` (default `7200`) and parser-accepted `--set-http-proxy=[yes|no]` for non-proxy client startup.

## Bypass lists, VIRR, and one-shot pulls

### `--bypass=<file1|file2>`

The default is `./ip.txt`. Multiple files are split on `|`. Quote the entire argument so the shell does not treat the pipe as a pipeline:

```bash
ppp --mode=client --config=./client.json \
  "--bypass=./cn.txt|./local.txt"
```

Bypass-route installation is skipped in proxy-only runtime.

### `--virr=<output-path/country>`

VIRR schedules client-side route-list refresh after the client is available. Its source-compatible argument form is `output-path/country`, for example:

```bash
ppp --mode=client --config=./client.json --virr=ip.txt/CN
```

The list is refreshed using `virr.update-interval` (default `86400` seconds) and retries use `virr.retry-interval` (default `300` seconds). The output file affects bypass routes only when it belongs to the active bypass set.

### `--pull-iplist=<output-path/country>`

This is the one-shot counterpart. Use a loadable configuration and the same form:

```bash
ppp --config=./appsettings.json --pull-iplist=ip.txt/CN
```

The parser splits the expression at its first `/`; `ip.txt/CN` is therefore the safe simple form. It also accepts `<` as an alternate separator when an output path itself contains `/` (quote that shell-sensitive form).

## Help and utility behavior

`--help` prints the generated option list. It is a help/diagnostic path, not a success-status guarantee; see the startup-order warning above. The banner is not the complete parser contract: it currently omits `--mux-mode-turbo` and Windows `--set-http-proxy`.

### Parser-supported MUX and Windows controls

| Option | Current parser boundary |
|---|---|
| `--mux-mode-turbo=[yes|no]` | Sets `mux.turbo` after configuration load. It is parser-supported but omitted from generated help. |
| `--debug-key=<secret>` | Sets `mux.debug.key` for the debug-only peer control path. |
| `--mux-mode-set=<value>` | Stores one transient debug-only peer mode request after launch. Help advertises `compat|flow`; the parser itself stores the supplied string and no separately versioned control API exists. |
| `--set-http-proxy=[yes|no]` | Windows-only parser input. It is used only for a non-proxy client startup and is omitted from generated help. |

Windows also exposes the documented network helper actions such as `--system-network-reset`, `--system-network-optimization`, protocol preference switches, and `--no-lsp <program>`. They are one-shot platform actions, not tunnel settings.

## Console UI commands

The full-screen Console UI is used only when enabled and stdout is a terminal; otherwise the application uses plain-text output. Its built-in commands are namespaced:

| Command | Action |
|---|---|
| `openppp2` or `openppp2 help` | Show command help. |
| `openppp2 restart` / `openppp2 reload` | Request restart. |
| `openppp2 exit` | Request exit. |
| `openppp2 info` | Print the latest cached runtime status lines. |
| `openppp2 clear` | Clear the command output pane. |
| `openppp2 telemetry ...` | Query/control in-process telemetry filters and minimum level (`status`, `help`, `log`, `metric`, `span`, `level`, `all`, `quiet`, `clear`). |

Unknown input is rejected with an error and a help hint. It is **never** passed to a system shell or executed as a shell command.

## Source anchors

- Startup preparation and interface parsing — `ppp/app/ApplicationConfig.cpp`
- Mode parsing and loopback proxy defaults — `ppp/app/ApplicationMode.cpp`
- Proxy-only bootstrap and skipped route/DNS/geo setup — `ppp/app/ApplicationClientBootstrap.cpp`
- Restart/statistics loop behavior — `ppp/app/ApplicationInitialize.cpp`, `ppp/app/ApplicationMainLoop.cpp`
- Bypass/VIRR/pull parsing — `ppp/app/ApplicationNetwork.cpp`
- One-shot pull and help dispatch — `ppp/app/PppApplication.cpp`
- Help text — `ppp/app/ApplicationHelp.cpp`
- Console UI command dispatch — `ppp/app/ConsoleUI.cpp`
