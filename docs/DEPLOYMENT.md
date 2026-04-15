# Deployment Model

[中文版本](DEPLOYMENT_CN.md)

## Scope

This document explains how OPENPPP2 is deployed according to the source tree.

## Main Deployment Facts

- The C++ runtime is a single executable: `ppp`
- It can run in client mode or server mode
- An optional Go backend can be linked by the server through `server.backend`

## Hard Requirements

- administrator/root privilege is required
- a real configuration file is required

`LoadConfiguration(...)` searches explicit `-c`/`--config` forms first, then `./config.json`, then `./appsettings.json`.

## Deployment Surfaces

OPENPPP2 deployment can be read as four surfaces:

- host surface: adapters, routes, DNS, privileges
- listener surface: TCP/UDP/WS/WSS ingress
- data plane surface: sessions, mappings, static path, IPv6 transit
- management surface: optional Go backend

## Client Deployment

The client deployment creates a virtual adapter, prepares route/DNS/bypass inputs, opens `VEthernetNetworkSwitcher`, and then establishes the remote exchanger session.

## Server Deployment

The server deployment opens listeners, firewall, namespace cache, datagram socket, optional managed backend, and optional IPv6 transit plumbing through `VirtualEthernetSwitcher`.

## Go Backend

The Go backend is optional and is used for managed deployments, not for the core data plane.

## Related Documents

- `CONFIGURATION.md`
- `PLATFORMS.md`
- `OPERATIONS.md`
