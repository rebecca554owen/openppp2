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

## Practical User Guidance

- start with the role first, not the command line
- treat configuration as node intent, not a throwaway script
- expect host changes; this is part of the runtime
- use the source reading guide if you need to verify behavior

## What Not To Assume

- do not assume client and server are symmetric
- do not assume the Go backend is required
- do not assume route and DNS changes are incidental
- do not assume the platform layer is interchangeable

## Related Documents

- `README.md`
- `SOURCE_READING_GUIDE.md`
