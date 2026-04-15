# Startup, Process Ownership, and Lifecycle Control

[中文版本](STARTUP_AND_LIFECYCLE_CN.md)

## Scope

This document explains how `ppp` starts, how process ownership is structured, how client and server diverge, and how maintenance and shutdown controls work.

## Why Startup Matters

OPENPPP2 startup is not just read-config-and-run. It has to handle privilege checks, single-instance protection, configuration loading, local host shaping, platform preparation, role selection, runtime startup, maintenance, and shutdown/restart control.

## Process Owner

`PppApplication` is the process owner. It coordinates configuration, network shaping, runtime creation, statistics, timers, and lifecycle control.

## Startup Pipeline

1. argument preparation
2. configuration loading
3. configuration normalization
4. single-instance check
5. platform preparation
6. role selection
7. runtime creation
8. tick loop
9. shutdown

## Environment Preparation

The startup phase prepares local host state before role-specific runtime begins. That includes CLI-shaped network inputs and platform-specific preparation.

## Role Selection

The client and server branches diverge early:

- client creates the virtual adapter path and client switcher
- server creates listener state and server switcher

## Lifecycle Control

The tick loop handles periodic maintenance. Restart and shutdown are controlled at the process level, not as side effects of individual connections.

## Ownership Model

| Level | Owner |
|---|---|
| Process | `PppApplication` |
| Environment | switchers |
| Session | exchangers |
| Connection | `ITransmission` |

## Related Documents

- `ARCHITECTURE.md`
- `CLIENT_ARCHITECTURE.md`
- `SERVER_ARCHITECTURE.md`
