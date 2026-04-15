# Link-Layer Protocol Guide

[中文版本](LINKLAYER_PROTOCOL_CN.md)

## Scope

This document describes the internal tunnel opcode protocol implemented by `VirtualEthernetLinklayer`.

## Why This Layer Exists

OPENPPP2 needs one shared vocabulary for session information, keepalive, LAN/NAT signaling, TCP relay, UDP relay, reverse mappings, static path negotiation, and mux negotiation.

## Opcode Families

`VirtualEthernetLinklayer` defines these action families:

- `INFO`, `KEEPALIVED`
- `FRP_ENTRY`, `FRP_CONNECT`, `FRP_CONNECTOK`, `FRP_PUSH`, `FRP_DISCONNECT`, `FRP_SENDTO`
- `LAN`, `NAT`, `SYN`, `SYNOK`, `PSH`, `FIN`, `SENDTO`, `ECHO`, `ECHOACK`, `STATIC`, `STATICACK`
- `MUX`, `MUXON`

The actual opcode values in code are:

- `INFO = 0x7E`
- `KEEPALIVED = 0x7F`
- `FRP_ENTRY = 0x20` through `FRP_SENDTO = 0x25`
- `LAN = 0x28` through `STATICACK = 0x32`
- `MUX = 0x35`
- `MUXON = 0x36`

## What Each Family Means

- `INFO` carries session information and optional extension data
- `KEEPALIVED` is the heartbeat path
- `LAN` and `NAT` carry subnet and traversal signaling
- `SYN` / `SYNOK` / `PSH` / `FIN` model logical TCP relay inside the tunnel
- `SENDTO` carries UDP relay traffic
- `ECHO` / `ECHOACK` support echo-style health behavior
- `STATIC` / `STATICACK` negotiate the static packet path
- `MUX` / `MUXON` negotiate multiplexing
- `FRP_*` carry reverse-mapping control and data

## `INFO` Payload

`INFO` carries a base `VirtualEthernetInformation` object plus optional extension JSON. The extension path is used for things like IPv6 assignment and status fields.

## Directionality

The code does not accept every action in every direction. Client and server handlers enforce role legality, so unexpected directions are rejected.

## Why This Protocol Is Separate

This layer is the semantic center of the tunnel. It lets the runtime model control actions explicitly instead of hiding them inside a flat byte stream.

## Related Documents

- `TRANSMISSION.md`
- `TUNNEL_DESIGN.md`
- `PACKET_FORMATS.md`
