# Documentation Index

[中文版本](README_CN.md)

This directory is the documentation center for OPENPPP2.

The set is intentionally code-first. Each page is written from actual implementation boundaries rather than product slogans, so the docs stay tied to `main.cpp`, `ppp/configurations`, `ppp/transmissions`, `ppp/app/protocol`, `ppp/app/client`, `ppp/app/server`, the platform integration directories, and the optional Go backend.

## Reading Paths

### Whole System

1. [`../README.md`](../README.md)
2. [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md)
3. [`ARCHITECTURE.md`](ARCHITECTURE.md)
4. [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md)
5. [`TRANSMISSION.md`](TRANSMISSION.md)
6. [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md)
7. [`PACKET_FORMATS.md`](PACKET_FORMATS.md)
8. [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md)
9. [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md)
10. [`PACKET_LIFECYCLE.md`](PACKET_LIFECYCLE.md)
11. [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
12. [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
13. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md)
14. [`PLATFORMS.md`](PLATFORMS.md)
15. [`DEPLOYMENT.md`](DEPLOYMENT.md)
16. [`OPERATIONS.md`](OPERATIONS.md)

### Source Reading

1. [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md)
2. [`ARCHITECTURE.md`](ARCHITECTURE.md)
3. [`TRANSMISSION.md`](TRANSMISSION.md)
4. [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md)
5. `main.cpp`
6. `ppp/configurations/*`
7. `ppp/transmissions/*`
8. `ppp/app/protocol/*`
9. `ppp/app/client/*`
10. `ppp/app/server/*`
11. platform directories
12. `go/*` when managed deployment is used

### Deployment And Operations

1. [`CONFIGURATION.md`](CONFIGURATION.md)
2. [`CLI_REFERENCE.md`](CLI_REFERENCE.md)
3. [`PLATFORMS.md`](PLATFORMS.md)
4. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md)
5. [`DEPLOYMENT.md`](DEPLOYMENT.md)
6. [`OPERATIONS.md`](OPERATIONS.md)
7. [`SECURITY.md`](SECURITY.md)

## Document Map

| Area | English | Chinese |
|------|---------|---------|
| Foundation | [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md) | [`ENGINEERING_CONCEPTS_CN.md`](ENGINEERING_CONCEPTS_CN.md) |
| Foundation | [`ARCHITECTURE.md`](ARCHITECTURE.md) | [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md) |
| Foundation | [`CONCURRENCY_MODEL.md`](CONCURRENCY_MODEL.md) | [`CONCURRENCY_MODEL_CN.md`](CONCURRENCY_MODEL_CN.md) |
| Foundation | [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md) | [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md) |
| Transport | [`TRANSMISSION.md`](TRANSMISSION.md) | [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md) |
| Transport | [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md) | [`HANDSHAKE_SEQUENCE_CN.md`](HANDSHAKE_SEQUENCE_CN.md) |
| Transport | [`PACKET_FORMATS.md`](PACKET_FORMATS.md) | [`PACKET_FORMATS_CN.md`](PACKET_FORMATS_CN.md) |
| Transport | [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md) | [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md) |
| Protocol | [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md) | [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md) |
| Protocol | [`PACKET_LIFECYCLE.md`](PACKET_LIFECYCLE.md) | [`PACKET_LIFECYCLE_CN.md`](PACKET_LIFECYCLE_CN.md) |
| Runtime | [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md) | [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md) |
| Runtime | [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md) | [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md) |
| Runtime | [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md) | [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md) |
| Runtime | [`PEER_PREFIX_ROUTING.md`](PEER_PREFIX_ROUTING.md) | [`PEER_PREFIX_ROUTING_CN.md`](PEER_PREFIX_ROUTING_CN.md) |
| Platform | [`PLATFORMS.md`](PLATFORMS.md) | [`PLATFORMS_CN.md`](PLATFORMS_CN.md) |
| Configuration | [`CONFIGURATION.md`](CONFIGURATION.md) | [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md) |
| Configuration | [`CLI_REFERENCE.md`](CLI_REFERENCE.md) | [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md) |
| Operations | [`DEPLOYMENT.md`](DEPLOYMENT.md) | [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md) |
| Operations | [`OPERATIONS.md`](OPERATIONS.md) | [`OPERATIONS_CN.md`](OPERATIONS_CN.md) |
| Security | [`SECURITY.md`](SECURITY.md) | [`SECURITY_CN.md`](SECURITY_CN.md) |
| Management | [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md) | [`MANAGEMENT_BACKEND_CN.md`](MANAGEMENT_BACKEND_CN.md) |
| Usage | [`USER_MANUAL.md`](USER_MANUAL.md) | [`USER_MANUAL_CN.md`](USER_MANUAL_CN.md) |
| Reading | [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md) | [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md) |
| Architecture | [`EDSM_STATE_MACHINES.md`](EDSM_STATE_MACHINES.md) | [`EDSM_STATE_MACHINES_CN.md`](EDSM_STATE_MACHINES_CN.md) |
| TUI | [`TUI_DESIGN.md`](TUI_DESIGN.md) | [`TUI_DESIGN_CN.md`](TUI_DESIGN_CN.md) |
| Diagnostics | [`ERROR_CODES.md`](ERROR_CODES.md) | [`ERROR_CODES_CN.md`](ERROR_CODES_CN.md) |
| Diagnostics | [`ERROR_HANDLING_API.md`](ERROR_HANDLING_API.md) | [`ERROR_HANDLING_API_CN.md`](ERROR_HANDLING_API_CN.md) |
| Diagnostics | [`DIAGNOSTICS_ERROR_SYSTEM.md`](DIAGNOSTICS_ERROR_SYSTEM.md) | [`DIAGNOSTICS_ERROR_SYSTEM_CN.md`](DIAGNOSTICS_ERROR_SYSTEM_CN.md) |
| Diagnostics | `linux/ppp/tap/openppp2_sysnat.h` (C bridge helpers) | `linux/ppp/tap/openppp2_sysnat.h`（C 桥接辅助） |
| Protocol | [`TUNNEL_DESIGN.md`](TUNNEL_DESIGN.md) | [`TUNNEL_DESIGN_CN.md`](TUNNEL_DESIGN_CN.md) |
| IPv6 | [`IPV6_LEASE_MANAGEMENT.md`](IPV6_LEASE_MANAGEMENT.md) | [`IPV6_LEASE_MANAGEMENT_CN.md`](IPV6_LEASE_MANAGEMENT_CN.md) |
| IPv6 | [`IPV6_TRANSIT_PLANE.md`](IPV6_TRANSIT_PLANE.md) | [`IPV6_TRANSIT_PLANE_CN.md`](IPV6_TRANSIT_PLANE_CN.md) |
| IPv6 | [`IPV6_NDP_PROXY.md`](IPV6_NDP_PROXY.md) | [`IPV6_NDP_PROXY_CN.md`](IPV6_NDP_PROXY_CN.md) |
| IPv6 | [`IPV6_CLIENT_ASSIGNMENT.md`](IPV6_CLIENT_ASSIGNMENT.md) | [`IPV6_CLIENT_ASSIGNMENT_CN.md`](IPV6_CLIENT_ASSIGNMENT_CN.md) |
| IPv6 | [`IPV6_FIXES.md`](IPV6_FIXES.md) | [`IPV6_FIXES_CN.md`](IPV6_FIXES_CN.md) |
| Platform | [`MULTIQUEUE_TUN_MODEL.md`](MULTIQUEUE_TUN_MODEL.md) | [`MULTIQUEUE_TUN_MODEL_CN.md`](MULTIQUEUE_TUN_MODEL_CN.md) |
| Observability | [`OTEL_DESIGN.md`](OTEL_DESIGN.md) | [`OTEL_DESIGN_CN.md`](OTEL_DESIGN_CN.md) |
| Concurrency | [`ATOMIC_SHARED_PTR_HELPER_DESIGN.md`](ATOMIC_SHARED_PTR_HELPER_DESIGN.md) | [`ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md`](ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md) |
| Android | — | [`ANDROID_NETWORK_FOLLOWUP_GUARD_CN.md`](ANDROID_NETWORK_FOLLOWUP_GUARD_CN.md) |
| Governance | — | [`dns-server-list-governance-cn.md`](dns-server-list-governance-cn.md) |

## Specialized And Governance Documents

These pages are narrower than the main reading paths. Treat design, audit, and governance notes as implementation evidence only after checking their status lines and the current code.

| Area | Documents | Use |
|------|-----------|-----|
| Android design | [`android-dependency-upgrade-plan-cn.md`](android-dependency-upgrade-plan-cn.md), [`ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md`](ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md), [`ANDROID_TLS_SESSION_CACHE_DESIGN_CN.md`](ANDROID_TLS_SESSION_CACHE_DESIGN_CN.md) | Android-specific plans, constraints, and deferred designs. |
| DNS design | [`DNS_MODULE_DESIGN.md`](DNS_MODULE_DESIGN.md), [`DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md`](DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md), [`DNS_DOH_DOT_SLOT_REUSE_DESIGN_CN.md`](DNS_DOH_DOT_SLOT_REUSE_DESIGN_CN.md), [`dns-server-list-governance-cn.md`](dns-server-list-governance-cn.md) | Resolver behavior, structured DNS config, provider-list governance, and known future hardening. |
| Security and governance | [`openppp2-deep-code-audit-cn.md`](openppp2-deep-code-audit-cn.md), [`p1-governance-decisions-cn.md`](p1-governance-decisions-cn.md), [`p2-governance-decisions-cn.md`](p2-governance-decisions-cn.md), [`system-command-governance-pilot.md`](system-command-governance-pilot.md), [`SYSTEM_CALL_GOVERNANCE_DESIGN_CN.md`](SYSTEM_CALL_GOVERNANCE_DESIGN_CN.md) | Audit findings, accepted deferrals, and system-command governance decisions. |
| Engineering governance | [`governance/CODE_STYLE.md`](governance/CODE_STYLE.md), [`governance/DOCUMENTATION_STYLE.md`](governance/DOCUMENTATION_STYLE.md), [`adr/README.md`](adr/README.md), [`design/README.md`](design/README.md) | Code placement, prohibited dependencies, document metadata, ADR, and design-document rules. |
| Focused hardening | [`PER_FRAME_READ_TIMEOUT_DESIGN.md`](PER_FRAME_READ_TIMEOUT_DESIGN.md), [`PER_FRAME_READ_TIMEOUT_DESIGN_CN.md`](PER_FRAME_READ_TIMEOUT_DESIGN_CN.md), [`FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`](FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md), [`SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`](SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md), [`TCP_NAT_AUDIT_REPORT.md`](TCP_NAT_AUDIT_REPORT.md) | Targeted performance, timeout, firewall, TLS, and TCP NAT analysis. |
| MUX scheduling | [`MUX_PERFLOW_DELIVERY_DESIGN_CN.md`](MUX_PERFLOW_DELIVERY_DESIGN_CN.md) | VMUX receiver-side per-flow ordering (flow v2): negotiation, per-connection DSN, bounded reorder, fallback. Pairs with spec `.kiro/specs/mux-perflow-delivery/`. |
| MUX scheduling | [`MUX_DEFECTS_AND_FIXES.md`](MUX_DEFECTS_AND_FIXES.md) / [`MUX_DEFECTS_AND_FIXES_CN.md`](MUX_DEFECTS_AND_FIXES_CN.md) | Working ledger of VMUX defects (D1–D11), root causes, and the phased fix/optimization plan from the multi-link flow rework. Status-bound; verify against current code. |
| Compatibility and local notes | [`BOOST_187_COMPATIBILITY.md`](BOOST_187_COMPATIBILITY.md), [`SERVER_IPV4_ASSIGNMENT_CN.md`](SERVER_IPV4_ASSIGNMENT_CN.md) | Compatibility status and server-side IPv4 assignment notes. |

When adding a new document, put it in the main map if it is stable reference material. Put it in this section if it is a design note, audit record, migration plan, or governance decision.

## Reading Principle

Keep these layers separate while reading:

- carrier transport
- protected transmission and handshake
- tunnel action protocol
- client or server runtime behavior
- platform-specific host integration
- optional management backend

Mixing these layers is the main source of misunderstanding.
