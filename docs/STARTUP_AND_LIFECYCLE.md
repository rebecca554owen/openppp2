# Startup And Lifecycle

[中文版本](STARTUP_AND_LIFECYCLE_CN.md)

## Entry Point

The process starts in `main.cpp`.

`PppApplication` is the top-level owner of:

- runtime configuration
- parsed network-interface overrides
- client or server runtime object
- periodic timer/tick behavior
- shutdown and restart behavior

## Startup Sequence

The high-level startup path is:

1. process entry
2. privilege check
3. single-instance guard
4. configuration load
5. mode decision
6. network override parsing
7. platform preparation
8. client or server runtime construction
9. periodic tick scheduling
10. event-loop run

## Configuration Loading

`LoadConfiguration(...)` searches for configuration using CLI and default paths.

The resulting `AppConfiguration` becomes the central runtime policy object. This is important because most later code reads from the configuration model rather than from ad hoc globals.

## Runtime Network Overrides

`GetNetworkInterface(...)` gathers runtime overrides such as:

- DNS servers
- physical NIC
- preferred gateway
- TUN name, IP, mask, gateway
- static mode
- vnet mode
- host-network preference
- bypass list and DNS/firewall rule files
- mux settings
- Linux SSMT and protect mode
- Windows lease time and optional proxy changes

This means OPENPPP2 expects deployment-time adaptation through CLI while still keeping stable policy in JSON.

## Mode Selection

`IsModeClientOrServer(...)` defaults to server mode unless a client mode flag is supplied.

That matches the codebase structure: one executable supports both roles, but the server role is treated as the default runtime identity.

## Client Startup Path

When running as client, startup proceeds roughly as follows:

1. create TUN/TAP adapter
2. create `VEthernetNetworkSwitcher`
3. inject runtime flags into the switcher
4. load bypass and route lists
5. load DNS rules
6. open the switcher on the adapter
7. let `VEthernetExchanger` asynchronously maintain the remote session

The switcher owns the local environment. The exchanger owns the remote relationship.

## Server Startup Path

When running as server, startup proceeds roughly as follows:

1. prepare Linux IPv6 environment when applicable
2. create `VirtualEthernetSwitcher`
3. load firewall rules
4. open listeners and auxiliary services
5. run accept loops
6. convert accepted transports into tunnel sessions

The server is therefore not just a listener. It is the top-level session switch for the whole overlay node.

## Periodic Tick Model

`PppApplication::OnTick(...)` is the recurring maintenance loop.

It is used for:

- status printing
- transmission statistics snapshots
- virr / route list refresh jobs
- vBGP-style route refresh jobs
- managed backend update calls
- restart and link supervision behavior

This is a common infrastructure pattern: rather than burying all maintenance in many scattered timers, the process keeps one visible periodic maintenance path.

## Shutdown And Disposal

Lifecycle teardown is explicit:

- `PppApplication::Dispose()` disposes client or server runtime
- client and server switchers dispose owned exchangers and connections
- transmissions close sockets and stop pending activity
- route and proxy state is restored or removed where platform code supports it

This explicit teardown matters because the process mutates host networking state. A networking infrastructure process that cannot unwind its own changes will be operationally unsafe.

## Restart Model

The process includes restart-oriented behavior in the main lifecycle layer, not only inside the client exchanger. This reflects the fact that resilience is treated as a system concern, not only as a socket concern.

## Reading Notes

When following startup code, keep these ownership boundaries in mind:

- `PppApplication` owns process lifecycle
- switchers own environment lifecycle
- exchangers own session lifecycle
- transmissions own connection lifecycle

If those boundaries are respected mentally, the rest of the code becomes much easier to follow.
