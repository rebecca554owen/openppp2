# Source Reading Guide

[中文版本](SOURCE_READING_GUIDE_CN.md)

## Goal

This guide helps engineers read OPENPPP2 in a useful order.

## Reading Order

1. `main.cpp`
2. `ppp/configurations/AppConfiguration.*`
3. `ppp/transmissions/ITransmission.*`
4. `ppp/app/protocol/VirtualEthernetLinklayer.*`
5. `ppp/app/protocol/VirtualEthernetPacket.*`
6. `ppp/app/client/*`
7. `ppp/app/server/*`
8. platform directories
9. `go/*` last

## What To Focus On

- startup and role selection
- configuration defaults and normalization
- handshake and framing
- tunnel action vocabulary
- client route and DNS steering
- server session switching and forwarding
- platform-specific host effects
- management backend only after the core runtime is clear

## Common Mistakes

- reading platform code before understanding the shared core
- confusing `ITransmission` framing with packet formats
- treating client and server exchangers as symmetric
- assuming the Go backend is the data plane

## Related Documents

- `ARCHITECTURE.md`
- `TUNNEL_DESIGN.md`
- `CLIENT_ARCHITECTURE.md`
- `SERVER_ARCHITECTURE.md`
