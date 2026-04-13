# Security Model

[中文版本](SECURITY_CN.md)

## Scope

This document describes the project from a defensive engineering perspective: trust boundaries, local enforcement points, attack surface, and deployment discipline.

## Security Goals

The codebase is trying to provide:

- protected tunnel transport
- explicit session identity
- local enforcement of session validity, quota, and bandwidth policy
- route and DNS steering under operator control
- controlled reverse access rather than unmanaged exposure
- platform-specific adapter and route integration without losing protocol uniformity

## Trust Boundaries

The important trust boundaries are:

- client host
- server host
- transport network between them
- optional management backend
- local operating system networking stack

Do not treat these as one trust domain. The design only works well when each boundary is configured deliberately.

## Main Enforcement Points

### 1. Transmission handshake and cipher state

Implemented around `ITransmission`.

This is the first gate for admitting a session and establishing protected state.

### 2. Session policy object

Implemented around `VirtualEthernetInformation`.

This carries:

- bandwidth limits
- remaining traffic
- expiry time

### 3. Server switch and firewall integration

Implemented around `VirtualEthernetSwitcher` and related firewall code.

This is where the server decides what a connected session is allowed to do.

### 4. Client route and DNS control

Implemented around `VEthernetNetworkSwitcher`.

This decides what enters the overlay and what stays on the local network.

### 5. Backend authentication and accounting

Implemented around `VirtualEthernetManagedServer` when enabled.

This allows external policy systems, but the data plane should still degrade gracefully if the backend link is unstable.

## Attack Surface

The exposed surface includes:

- TCP/UDP/WS/WSS listeners
- certificate and key files
- local proxy listeners
- reverse mappings
- route and DNS rule files
- backend credentials and URLs
- platform-specific network manipulation helpers

Each additional enabled feature increases the surface. Treat optional features as real exposure, not harmless extras.

## Secure Deployment Guidance

- Use only the transports you need
- Prefer WSS when the deployment already has a managed TLS edge
- Keep certificate files and backend keys out of public repositories
- Keep proxy credentials and database credentials outside shared sample configs
- Enable mappings only for services you intentionally publish
- Limit split-tunnel rules to clear business requirements
- Audit route files and DNS rules as policy artifacts

## Session Integrity And Availability

The code places emphasis on:

- timeouts
- reconnection behavior
- keepalive
- explicit session states
- statistics and accounting snapshots

These matter for security because unstable or ambiguous session state becomes an operational risk long before it becomes a cryptographic one.

## Defensive View Of Obfuscation And Formatting Features

Some transport formatting options exist to shape compatibility and traffic form. These should be understood as tunnel-format controls, not as a substitute for security architecture.

The real security posture still depends on:

- sound keys and certificates
- correct exposure of listeners
- correct route and DNS policy
- controlled mapping configuration
- backend credential hygiene

## Secret Management

Treat the following as secrets:

- `protocol-key`
- `transport-key`
- `server.backend-key`
- `client.server-proxy` credentials
- `websocket.ssl.certificate-key-password`
- Go backend database credentials
- Redis credentials if enabled

Do not keep real production values in repository-tracked example files.

## Operational Hardening Checklist

- verify the exact listeners that are enabled
- verify the exact mappings that are enabled
- verify whether split-tunnel or full-tunnel is intended
- verify route and DNS rule files before rollout
- verify WSS certificate chain and key permissions
- verify backend URLs and tokens
- verify platform route/firewall changes in staging first

## Security Philosophy

OPENPPP2 is strongest when operated as a deterministic network system:

- clear topology
- clear policy
- clear trust boundaries
- minimal enabled surface
- explicit verification on each target platform

That is the right posture for infrastructure software. Security here is mostly disciplined system design, not feature accumulation.
