# P2P Networking — Manual Validation Scenarios

This document describes manual test scenarios for validating the P2P direct-path
networking feature. Each scenario includes setup, steps, and expected results.

Since there is no automated test harness for the C++ core, these scenarios serve
as the primary validation gate for P2P correctness.

---

## Integration Status

The P2P module (`ppp/p2p/`) implements the core data-plane components as a
self-contained subsystem. The following production integration hooks remain
TODO and must be wired before P2P direct path can carry live traffic:

1. **TLS master secret → HKDF**: `HKDFDeriveSessionKey()` requires the TLS
   handshake master secret. Wiring to the ITransmission SSL layer is pending.
2. **Channel ID assignment**: Tier-2 `channel_id` field must be assigned by the
   server in the P2P hint offer and communicated to both peers.
3. **TAP/TUN injection**: The `P2PFrameReceivedCallback` must be connected to
   the VEthernetExchanger's virtual Ethernet adapter injection path.
4. **UDP NAT observation**: Actual UDP relay traffic (static-echo, UDP sendto)
   must feed the NAT classifier. TCP control endpoints are intentionally NOT
   used for NAT classification.

When these hooks are not wired, `p2p.enabled=false` produces byte-identical
behavior to the current release.  When `p2p.enabled=true`, the server sends
P2P offer hints, but the client P2PChannel remains in Relay state and all
traffic uses the existing `DoNat()` relay forwarding path.

## NAT Classifier Behavior (H2)

The server-side NAT classifier (`P2PNatClassifier`) is designed to infer
UDP NAT types from actual relay traffic patterns.  It requires observations
from real UDP relay paths (static-echo, UDP sendto).  TCP control channel
endpoints are intentionally NOT used because they reflect TCP NAT mapping,
which does not predict UDP NAT behavior.

**Current state:** No actual UDP observation sources are wired to the
classifier yet.  All peers classify as `Unknown`.

**Conservative behavior:**
- `Unknown` → probing is allowed (server sends offers, clients attempt
  hole-punching; the probe path itself determines reachability).
- `Symmetric + Symmetric` → skip (only when both are positively classified
  from actual observations).
- `UdpBlocked` → skip (only when positively classified).
- `Unknown + Unknown` → allow (conservative: let probes decide).

This ensures that the classifier never blocks P2P attempts based on
absence of data — only based on positively observed incompatibility.

---

## Scenario 1: Relay Baseline (p2p.enabled=false)

**Goal:** Verify that disabling P2P produces byte-identical behavior to the current release.

**Setup:**
```json
{
  "p2p": {
    "enabled": false
  }
}
```

**Steps:**
1. Start server with `p2p.enabled=false`.
2. Connect two clients.
3. Send ping between clients via virtual subnet.
4. Verify NAT relay forwarding works.

**Expected:** All traffic flows through server relay. No P2P control messages in INFO. No UDP sockets created for P2P.

---

## Scenario 2: Direct LAN Success (<200ms)

**Goal:** Two clients on the same LAN establish direct path within 200ms.

**Setup:**
```json
{
  "p2p": {
    "enabled": true,
    "mode": "direct-preferred"
  }
}
```

Both clients on the same subnet (e.g., 192.168.1.x).

**Steps:**
1. Connect both clients to the server.
2. Observe P2P registration in server logs.
3. Trigger NAT traffic between clients.
4. Observe P2P offer with LAN candidates.
5. Observe state transition: Relay → Probing → Direct.

**Expected:**
- Server sends offer with LAN candidate (observed endpoint source = "observed").
- Client sends probes to LAN endpoint.
- First ACK received within ~50ms.
- State transitions to Direct.
- Subsequent data packets use Tier 2 minimal header (16 + 16 = 32 bytes overhead).

---

## Scenario 3: Full-Cone NAT Direct Success (<500ms)

**Goal:** Both clients behind full-cone NAT establish direct path.

**Setup:** Both clients behind different full-cone NATs.

**Steps:**
1. Connect both clients.
2. Server classifies NAT type as FullCone from relay traffic.
3. Server sends offer with observed endpoints.
4. Clients probe each other's observed endpoints.
5. First ACK wins.

**Expected:**
- NAT classification: FullCone (consistent IP:port).
- Single probe sufficient.
- Direct path established within 500ms.

---

## Scenario 4: Symmetric NAT Fallback (0ms, no attempt)

**Goal:** Skip hole punching for symmetric-symmetric NAT pair.

**Setup:** Both clients behind symmetric NAT (varies IP:port per destination).

**Steps:**
1. Connect both clients.
2. Generate relay traffic to classify NAT types.
3. Server classifies both as Symmetric.
4. Observe that OfferP2PPeerHints returns false.

**Expected:**
- NAT classification: Symmetric for both.
- `ShouldAttemptPunch()` returns false.
- Server log: "NAT classification skip offer ... Symmetric"
- No P2P offer sent. Traffic continues via relay with zero added latency.

---

## Scenario 5: Stale/Forged Token Rejection

**Goal:** Verify that packets with invalid tokens are rejected.

**Steps:**
1. Establish a direct P2P channel.
2. Manually send a Tier 1 packet with a corrupted token.
3. Observe that the packet is silently dropped.

**Expected:**
- Token verification fails (constant-time comparison mismatch).
- Packet is dropped without response.
- No state change on the receiving peer.

---

## Scenario 6: Replay Packet Rejection

**Goal:** Verify that replayed packets are dropped by the bitmap replay window.

**Steps:**
1. Establish a direct P2P channel.
2. Capture a valid Tier 2 data packet.
3. Replay the same packet.
4. Observe that the replayed packet is silently dropped.

**Expected:**
- First packet: accepted (replay_window_.Accept returns true).
- Second packet (same sequence): IsDuplicate returns true.
- Replayed packet is dropped.

---

## Scenario 7: Direct → Suspect → Relay Fallback (4s worst case)

**Goal:** Verify the worst-case failure detection time.

**Setup:** Use default timers: heartbeat_interval=1000ms, miss_max=2, suspect_timeout=2000ms.

**Steps:**
1. Establish a direct P2P channel.
2. Simulate peer loss (e.g., disconnect peer's network).
3. Measure time from last successful heartbeat to relay fallback.

**Expected:**
- Heartbeat miss detected after 2 × 1000ms = 2000ms.
- State: Direct → Suspect.
- Suspect timeout after 2000ms.
- State: Suspect → Relay.
- Total: 4000ms worst case.

---

## Scenario 8: NAT Rebind Migration (5s grace)

**Goal:** Verify connection migration on NAT rebind.

**Steps:**
1. Establish a direct P2P channel.
2. Trigger NAT rebind (e.g., WiFi→cellular handoff).
3. Peer receives packet from new source endpoint.
4. Peer sends challenge to new endpoint.
5. Challenge is ACKed within grace period.

**Expected:**
- Peer endpoint updated to new source.
- No data loss during migration.
- Migration completes within 5s grace period.

---

## Scenario 9: Zero-RTT Reconnect

**Goal:** Verify cached session reconnect.

**Steps:**
1. Establish a direct P2P channel.
2. Briefly disconnect (WiFi flap).
3. Client reconnects and sends first data packet using cached key.
4. Peer accepts (valid auth tag, sequence within window).

**Expected:**
- Direct channel resumes within 1 RTT.
- No server round-trip needed.
- Cache expires after 300s.

---

## Scenario 10: Coalesced Packet Demux

**Goal:** Verify coalesced Ethernet frames are correctly demuxed.

**Steps:**
1. Send 3 small Ethernet frames rapidly.
2. Observe that they are coalesced into 1 UDP datagram.
3. Verify all 3 frames are demuxed and injected on the receiving side.

**Expected:**
- 1 `sendto()` call instead of 3.
- All 3 frames delivered to the virtual Ethernet adapter.
- No frame loss or corruption.

---

## Scenario 11: Heartbeat Piggyback

**Goal:** Verify heartbeat ACK is piggybacked on data packets.

**Steps:**
1. Establish direct channel with active data flow.
2. Observe that dedicated heartbeat packets are NOT sent during active transfers.
3. Observe that HEARTBEAT_ACK is set on data packets when requested.

**Expected:**
- During idle: 1 heartbeat/s.
- During active: 0 dedicated heartbeats (piggybacked).
- Heartbeat overhead: zero when data is flowing.

---

## Scenario 12: Buffer Pool Zero-Allocation

**Goal:** Verify no malloc/free on the steady-state hot path.

**Steps:**
1. Establish direct channel.
2. Send 1000 packets.
3. Monitor heap allocation count (e.g., via jemalloc stats).

**Expected:**
- Pool pre-allocates 64 × 2048B = 128KB per channel.
- Hot path: zero malloc/free calls.
- Fallback allocation: only when pool exhausted.

---

## Build Verification Notes

Since automated tests are not run, manual build verification should include:

1. **cmake configure** succeeds with all new files in `ppp/p2p/`.
2. **cmake build** compiles all new `.cpp` files without errors.
3. **Link check** verifies all new symbols are resolved.
4. **Runtime check** verifies `p2p.enabled=false` produces no behavioral change.
5. **Runtime check** verifies `p2p.enabled=true` with server mode starts without errors.
