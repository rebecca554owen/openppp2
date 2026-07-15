# ADR 0002: Gate P2P Direct Channels on an Authenticated Session Exporter

> Status: Accepted
> Type: ADR
> Last verified: df3c89c

## Context

The repository contains a self-contained `P2PChannel` scaffold, packet headers,
crypto helpers, replay protection, and socket protection adapters. It is not
wired into the production exchanger path. Its current comments assume that a
TLS master secret is available, but that assumption is false for raw TCP and
plaintext WebSocket sessions. `ITransmission` does not expose authenticated
exporter material, and the TLS WebSocket implementation does not publish its
native TLS exporter to the runtime.

Enabling a direct UDP path with keys derived from configuration secrets,
unauthenticated control messages, or a raw TCP session would create a second
channel that is not cryptographically bound to the authenticated relay session.

## Decision

P2P capability is false by default. A session is eligible only when its
transport supplies an authenticated, per-session exporter through an explicit
transport-independent interface. The exporter must be available only after the
relay handshake succeeds and must bind the authenticated peer, relay session
identifier, negotiated protocol version, and a fresh connection epoch.

The two clients do not share a TLS exporter. After both relay sessions qualify,
the server generates a fresh random pair seed. It derives a different wrapping
key from each client's session exporter and sends the same pair seed to each
client in a separately authenticated and encrypted relay offer. Direct-channel
keys are derived from the pair seed, not directly from either TLS exporter. The
pair seed is scoped to the two peer identities, both relay session identifiers,
the offer, version, and connection epoch. It is never sent in plaintext or
reused across offers.

TLS transports may implement that interface with the standard TLS exporter
after certificate and application authentication complete. Raw TCP, plaintext
WebSocket, TLS implementations without an exposed exporter, and any exporter
failure are relay-only. Code must not read or assume access to a TLS master
secret.

The server may coordinate candidates and issue bounded offers, but it cannot
override exporter eligibility. Both peers must authenticate a protected UDP
probe and acknowledgment before either reports or forwards on `direct`.
Probing, suspect recovery, and fallback retain the relay data path.

The wire and lifecycle requirements are defined in the
[protocol](../design/p2p-direct-channel/protocol.md),
[state machine](../design/p2p-direct-channel/state-machine.md), and
[threat model](../design/p2p-direct-channel/threat-model.md).

## Alternatives

- Derive from configured protocol or transport keys: rejected because those
  keys are deployment-wide and do not bind a direct channel to one authenticated
  relay session.
- Pass a TLS master secret into P2P: rejected because raw TCP has no such value,
  exposing it expands the trust boundary, and a standard exporter is the correct
  TLS interface.
- Enable direct mode from a server token alone: rejected because a bearer token
  does not prove both endpoints possess session-bound key material.
- Disable P2P permanently: safe, but it prevents a future authenticated direct
  path. The exporter gate preserves relay safety while allowing incremental work.

## Consequences

- Existing deployments and wire formats remain compatible and relay-only.
- The current P2P scaffold is not production evidence and must stay unreachable
  until the exporter, coordinator, capability, and platform gates are complete.
- TLS exporter support requires a separate reviewed transport change. Supporting
  raw TCP would require a separately accepted authenticated key agreement; it is
  not part of this decision.
- Failure, timeout, downgrade, restart, or unsupported peers never tear down the
  base VPN session.
