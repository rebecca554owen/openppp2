# Documentation Index

[中文版本](README_CN.md)

This directory is the documentation center for OPENPPP2. The documents are organized as one-to-one English and Chinese pairs so that each topic can be read in either language without losing coverage or structure.

OPENPPP2 is a layered system built from code facts, not slogans. The documentation therefore follows the implementation boundary: startup, configuration, transmission, handshake, packet formats, link-layer protocol, client runtime, server runtime, routing and DNS, platform integration, deployment, operations, security, management backend, and source reading.

## Reading Paths

### Whole System

1. [`../README.md`](../README.md)
2. [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md)
3. [`ARCHITECTURE.md`](ARCHITECTURE.md)
4. [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md)
5. [`TRANSMISSION.md`](TRANSMISSION.md)
6. [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md)
7. [`PACKET_FORMATS.md`](PACKET_FORMATS.md)
8. [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md)
9. [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md)
10. [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md)
11. [`PLATFORMS.md`](PLATFORMS.md)
12. [`DEPLOYMENT.md`](DEPLOYMENT.md)
13. [`OPERATIONS.md`](OPERATIONS.md)

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
| Foundation | [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md) | [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md) |
| Transport | [`TRANSMISSION.md`](TRANSMISSION.md) | [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md) |
| Transport | [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md) | [`HANDSHAKE_SEQUENCE_CN.md`](HANDSHAKE_SEQUENCE_CN.md) |
| Transport | [`PACKET_FORMATS.md`](PACKET_FORMATS.md) | [`PACKET_FORMATS_CN.md`](PACKET_FORMATS_CN.md) |
| Transport | [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md) | [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md) |
| Protocol | [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md) | [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md) |
| Runtime | [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md) | [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md) |
| Runtime | [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md) | [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md) |
| Runtime | [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md) | [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md) |
| Platform | [`PLATFORMS.md`](PLATFORMS.md) | [`PLATFORMS_CN.md`](PLATFORMS_CN.md) |
| Configuration | [`CONFIGURATION.md`](CONFIGURATION.md) | [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md) |
| Configuration | [`CLI_REFERENCE.md`](CLI_REFERENCE.md) | [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md) |
| Operations | [`DEPLOYMENT.md`](DEPLOYMENT.md) | [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md) |
| Operations | [`OPERATIONS.md`](OPERATIONS.md) | [`OPERATIONS_CN.md`](OPERATIONS_CN.md) |
| Security | [`SECURITY.md`](SECURITY.md) | [`SECURITY_CN.md`](SECURITY_CN.md) |
| Management | [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md) | [`MANAGEMENT_BACKEND_CN.md`](MANAGEMENT_BACKEND_CN.md) |
| Usage | [`USER_MANUAL.md`](USER_MANUAL.md) | [`USER_MANUAL_CN.md`](USER_MANUAL_CN.md) |
| Reading | [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md) | [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md) |

## Reading Principle

Keep these layers separate while reading:

- carrier transport
- protected transmission and handshake
- tunnel action protocol
- client or server runtime behavior
- platform-specific host integration
- optional management backend

Mixing these layers is the main source of misunderstanding.
