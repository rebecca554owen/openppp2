# Operations And Troubleshooting

[中文版本](OPERATIONS_CN.md)

## Scope

This document explains operational behavior after build and deployment.

## Main Operational Model

Read the process as state transitions:

- configuration load
- environment preparation
- client or server open sequence
- steady-state tick loop
- optional restart or shutdown
- cleanup and rollback

## Startup Failure Classes

- privilege failure
- duplicate instance failure
- configuration discovery/load failure
- client local environment preparation failure
- server open-sequence failure

## Tick Loop

`PppApplication::OnTick(...)` is the main operational heartbeat. It handles:

- console refresh
- Windows working-set optimization
- auto restart
- link restart
- VIRR refresh
- vBGP refresh

## Restart Behavior

Restart can be deliberate. It may happen because of:

- `auto_restart`
- link reconnection threshold
- route-source update that rewrites route files

## Cleanup

`PppApplication::Dispose()` releases the server, restores Windows QUIC preference, clears system HTTP proxy if needed, disposes the client, and stops the tick timer.

## Related Documents

- `STARTUP_AND_LIFECYCLE.md`
- `DEPLOYMENT.md`
- `PLATFORMS.md`
