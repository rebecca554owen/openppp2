# Error Codes Reference

[中文版本](ERROR_CODES_CN.md)

This page is generated from `ppp/diagnostics/ErrorCodes.def`, which is the single source of truth for `ppp::diagnostics::ErrorCode`.

**Live total: 595 error codes.**

Severity distribution: kInfo=8, kWarning=25, kError=539, kFatal=23.

`ERROR_CODES.md` currently keeps the original core taxonomy tables (220 baseline entries) for readability.
For the complete live catalog (including extended subsystem-specific entries and reserved slots),
use `ppp/diagnostics/ErrorCodes.def` as the single source of truth.

## API

```cpp
// Set thread-local error code and return false / -1 / NULLPTR
ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SomeCode);
bool ppp::diagnostics::SetLastError(ErrorCode);        // returns false
int  ppp::diagnostics::SetLastError<int>(ErrorCode);   // returns -1
T*   ppp::diagnostics::SetLastError<T*>(ErrorCode);    // returns NULLPTR

// Query
ErrorCode   ppp::diagnostics::GetLastErrorCode();           // thread-local
ErrorCode   ppp::diagnostics::GetLastErrorCodeSnapshot();   // last atomically published
uint64_t    ppp::diagnostics::GetLastErrorTimestamp();      // ms of last published error
const char* ppp::diagnostics::FormatErrorString(ErrorCode); // human-readable text
ppp::string ppp::diagnostics::FormatErrorTriplet(ErrorCode); // "<id> <name>: <message>"
bool ppp::diagnostics::IsValidErrorCodeValue(int);           // raw integer validation
```

---

## Category Map

```mermaid
graph TD
    A[ErrorCode] --> C0[Generic - 12]
    A[ErrorCode] --> C0H[Android Lib - 3]
    A[ErrorCode] --> C0A[Main Entry - 1]
    A[ErrorCode] --> C0B[Socket Runtime - 7]
    A[ErrorCode] --> C0C[VNetstack - 4]
    A[ErrorCode] --> C0D[SYSNAT - 14]
    A[ErrorCode] --> C0E[TapLinux - 3]
    A[ErrorCode] --> C0F[VEthernet Switcher - 1]
    A[ErrorCode] --> C0G[VEthernet Exchanger - 1]
    A[ErrorCode] --> C1[Application - 8]
    A[ErrorCode] --> C2[Configuration - 11]
    A[ErrorCode] --> C3[Runtime - 12]
    A[ErrorCode] --> C4[Memory - 6]
    A[ErrorCode] --> C5[File - 10]
    A[ErrorCode] --> C6[Network - 12]
    A[ErrorCode] --> C7[Socket - 14]
    A[ErrorCode] --> C8[TCP - 4]
    A[ErrorCode] --> C9[UDP - 5]
    A[ErrorCode] --> C10[DNS - 5]
    A[ErrorCode] --> C11[HTTP - 5]
    A[ErrorCode] --> C12[WebSocket - 3]
    A[ErrorCode] --> C13[Tunnel - 12]
    A[ErrorCode] --> C14[Firewall - 1]
    A[ErrorCode] --> C15[Route - 6]
    A[ErrorCode] --> C16[IPv6 - 30]
    A[ErrorCode] --> C17[Session - 9]
    A[ErrorCode] --> C18[Protocol - 5]
    A[ErrorCode] --> C19[Mapping - 3]
    A[ErrorCode] --> C20[Windows Platform - 4]
    A[ErrorCode] --> C21[Thread Synchronization - 1]
    A[ErrorCode] --> C22[Cryptography - 1]
    A[ErrorCode] --> C23[Authentication - 3]
    A[ErrorCode] --> C24[Timer - 1]
    A[ErrorCode] --> C25[Resource Exhaustion - 2]
    A[ErrorCode] --> C26[Internal Logic - 1]
```

---

## Category: Generic (12)

| Name | Description | Severity |
|------|-------------|----------|
| `Success` | Success | `kInfo` |
| `GenericUnknown` | Generic unknown error | `kError` |
| `GenericInvalidArgument` | Invalid argument | `kError` |
| `GenericInvalidState` | Invalid state | `kError` |
| `GenericNotSupported` | Operation not supported | `kFatal` |
| `GenericAlreadyExists` | Requested item already exists | `kError` |
| `GenericInsufficientBuffer` | Insufficient buffer size | `kError` |
| `GenericOutOfMemory` | Out of memory | `kError` |
| `GenericOperationFailed` | Operation failed | `kError` |
| `GenericParseFailed` | Parse failed | `kError` |
| `GenericConflict` | Resource conflict | `kError` |
| `GenericOverflow` | Numeric overflow | `kError` |

---

## Category: Main Entry (1)

| Name | Description | Severity |
|------|-------------|----------|
| `AppMainRunFailedWithoutSpecificError` | Application run returned failure without publishing a specific error code | `kFatal` |

---

## Category: Android Lib (3)

| Name | Description | Severity |
|------|-------------|----------|
| `AndroidLibInvalidState` | Android libopenppp2 state is invalid for this operation | `kError` |
| `AndroidLibUnknownFailure` | Android libopenppp2 returned an unknown failure | `kError` |
| `AndroidLibNullCallback` | Android libopenppp2 callback is null | `kError` |

---

## Category: Socket Runtime (7)

| Name | Description | Severity |
|------|-------------|----------|
| `SocketInvalidHandle` | Socket handle is invalid | `kError` |
| `SocketNotOpen` | Socket is not open | `kError` |
| `SocketInvalidState` | Socket state is invalid for this operation | `kError` |
| `SocketNativeHandleQueryFailed` | Failed to query native socket handle | `kError` |
| `SocketNullInstance` | Socket instance is null | `kError` |
| `SocketNullAcceptCallback` | Socket accept callback is null | `kError` |
| `StreamDescriptorNull` | Stream descriptor pointer is null | `kError` |

---

## Category: VNetstack (4)

| Name | Description | Severity |
|------|-------------|----------|
| `VNetstackNullPacketInput` | VNetstack received null packet or invalid packet length | `kError` |
| `VNetstackNullLinkInput` | VNetstack received null link reference | `kError` |
| `VNetstackNullSocketInput` | VNetstack received null accepted socket | `kError` |
| `VNetstackSyncAckInvalidState` | VNetstack sync-ack state transition is invalid | `kError` |

---

## Category: SYSNAT (14)

| Name | Description | Severity |
|------|-------------|----------|
| `SysnatUnknownFailure` | SYSNAT returned an unknown failure code | `kError` |
| `SysnatInvalidInterfaceName` | SYSNAT interface name is invalid | `kError` |
| `SysnatBpfObjectOpenFailed` | SYSNAT failed to open BPF object file | `kError` |
| `SysnatBpfProgramNotFound` | SYSNAT required BPF program was not found | `kError` |
| `SysnatBpfLoadFailed` | SYSNAT failed to load BPF object | `kError` |
| `SysnatMapPinFailed` | SYSNAT failed to pin BPF map | `kError` |
| `SysnatTcHookCreateFailed` | SYSNAT failed to create TC hook | `kError` |
| `SysnatTcAttachFailed` | SYSNAT failed to attach TC program | `kError` |
| `SysnatTcDetachFailed` | SYSNAT failed to detach TC program | `kError` |
| `SysnatMapOpenFailed` | SYSNAT failed to open pinned map | `kError` |
| `SysnatMapUpdateFailed` | SYSNAT failed to update map rule | `kError` |
| `SysnatMapDeleteFailed` | SYSNAT failed to delete map rule | `kError` |
| `SysnatAlreadyAttached` | SYSNAT program is already attached | `kWarning` |
| `SysnatNotAttached` | SYSNAT program is not attached | `kWarning` |

---

## Category: TapLinux (3)

| Name | Description | Severity |
|------|-------------|----------|
| `TapLinuxCommandEmpty` | TapLinux shell command is empty | `kError` |
| `TapLinuxUnsafeToken` | TapLinux input contains unsafe shell token | `kError` |
| `TapLinuxInterfaceNameTooLong` | TapLinux interface name exceeds kernel limit | `kError` |

---

## Category: VEthernet Switcher (1)

| Name | Description | Severity |
|------|-------------|----------|
| `VEthernetNetworkSwitcherDnsRulesEmpty` | VEthernetNetworkSwitcher DNS rule input is empty | `kError` |

---

## Category: VEthernet Exchanger (1)

| Name | Description | Severity |
|------|-------------|----------|
| `VEthernetExchangerTimeoutEntryConflict` | VirtualEthernetExchanger timeout entry already exists | `kError` |

---

## Category: Application (8)

| Name | Description | Severity |
|------|-------------|----------|
| `AppAlreadyRunning` | Application already running | `kWarning` |
| `AppLockAcquireFailed` | Application lock acquisition failed | `kError` |
| `AppLockReleaseFailed` | Application lock release failed | `kWarning` |
| `AppInvalidCommandLine` | Invalid command-line arguments | `kWarning` |
| `AppConfigurationMissing` | Application configuration missing | `kFatal` |
| `AppContextUnavailable` | Application context unavailable | `kError` |
| `AppPrivilegeRequired` | Administrator or root privilege required | `kError` |
| `AppPreflightCheckFailed` | Startup preflight check failed | `kFatal` |

---

## Category: Configuration (11)

| Name | Description | Severity |
|------|-------------|----------|
| `ConfigLoadFailed` | Failed to load configuration | `kFatal` |
| `ConfigFileNotFound` | Configuration file not found | `kFatal` |
| `ConfigFileUnreadable` | Configuration file unreadable | `kFatal` |
| `ConfigFileMalformed` | Configuration file malformed | `kFatal` |
| `ConfigFieldMissing` | Required configuration field missing | `kFatal` |
| `ConfigFieldInvalid` | Configuration field invalid | `kFatal` |
| `ConfigValueOutOfRange` | Configuration value out of range | `kFatal` |
| `ConfigTypeMismatch` | Configuration type mismatch | `kFatal` |
| `ConfigPathInvalid` | Configuration path invalid | `kFatal` |
| `ConfigDnsRuleLoadFailed` | Failed to load DNS rules | `kError` |
| `ConfigRouteLoadFailed` | Failed to load route list | `kError` |

---

## Category: Runtime (12)

| Name | Description | Severity |
|------|-------------|----------|
| `RuntimeInitializationFailed` | Runtime initialization failed | `kFatal` |
| `RuntimeEnvironmentInvalid` | Runtime environment invalid | `kFatal` |
| `RuntimeIoContextMissing` | I/O context unavailable | `kError` |
| `RuntimeSchedulerUnavailable` | Scheduler unavailable | `kError` |
| `RuntimeTimerCreateFailed` | Timer creation failed | `kError` |
| `RuntimeTimerStartFailed` | Timer start failed | `kError` |
| `RuntimeEventDispatchFailed` | Event dispatch failed | `kError` |
| `RuntimeTaskPostFailed` | Task post failed | `kError` |
| `RuntimeCoroutineSpawnFailed` | Coroutine spawn failed | `kError` |
| `RuntimeThreadStartFailed` | Thread start failed | `kError` |
| `RuntimeThreadJoinFailed` | Thread join failed | `kError` |
| `RuntimeStateTransitionInvalid` | Invalid runtime state transition | `kError` |

---

## Category: Memory (6)

| Name | Description | Severity |
|------|-------------|----------|
| `MemoryAllocationFailed` | Memory allocation failed | `kFatal` |
| `MemoryPoolCreateFailed` | Memory pool creation failed | `kFatal` |
| `MemoryPoolExhausted` | Memory pool exhausted | `kError` |
| `MemoryBufferNull` | Memory buffer is null | `kError` |
| `MemoryMapFailed` | Memory mapping failed | `kError` |
| `MemoryUnmapFailed` | Memory unmapping failed | `kError` |

---

## Category: File (10)

| Name | Description | Severity |
|------|-------------|----------|
| `FileOpenFailed` | File open failed | `kError` |
| `FileCreateFailed` | File creation failed | `kError` |
| `FileReadFailed` | File read failed | `kError` |
| `FileWriteFailed` | File write failed | `kError` |
| `FileFlushFailed` | File flush failed | `kError` |
| `FileDeleteFailed` | File delete failed | `kError` |
| `FileStatFailed` | File stat failed | `kError` |
| `FilePathInvalid` | File path invalid | `kError` |
| `FileDirectoryCreateFailed` | Directory creation failed | `kError` |
| `FileDirectoryEnumerateFailed` | Directory enumeration failed | `kError` |

---

## Category: Network (12)

| Name | Description | Severity |
|------|-------------|----------|
| `NetworkInterfaceUnavailable` | Network interface unavailable | `kError` |
| `NetworkInterfaceOpenFailed` | Network interface open failed | `kError` |
| `NetworkInterfaceConfigureFailed` | Network interface configuration failed | `kError` |
| `NetworkAddressInvalid` | Network address invalid | `kError` |
| `NetworkMaskInvalid` | Network mask invalid | `kError` |
| `NetworkGatewayInvalid` | Network gateway invalid | `kError` |
| `NetworkPortInvalid` | Network port invalid | `kError` |
| `NetworkProtocolUnsupported` | Network protocol unsupported | `kError` |
| `NetworkFirewallBlocked` | Network blocked by firewall | `kWarning` |
| `NetworkAddressFamilyMismatch` | Network address family mismatch | `kError` |
| `NetworkPacketMalformed` | Malformed network packet | `kError` |
| `NetworkPacketTooLarge` | Network packet too large | `kError` |

---

## Category: Socket (14)

| Name | Description | Severity |
|------|-------------|----------|
| `SocketCreateFailed` | Socket creation failed | `kError` |
| `SocketOpenFailed` | Socket open failed | `kError` |
| `SocketBindFailed` | Socket bind failed | `kError` |
| `SocketListenFailed` | Socket listen failed | `kError` |
| `SocketAcceptFailed` | Socket accept failed | `kError` |
| `SocketConnectFailed` | Socket connect failed | `kError` |
| `SocketReadFailed` | Socket read failed | `kError` |
| `SocketWriteFailed` | Socket write failed | `kError` |
| `SocketOptionSetFailed` | Socket option set failed | `kError` |
| `SocketOptionGetFailed` | Socket option get failed | `kError` |
| `SocketAddressInvalid` | Socket address invalid | `kError` |
| `SocketDisconnected` | Socket disconnected | `kWarning` |
| `SocketTimeout` | Socket timeout | `kWarning` |
| `SocketRefused` | Socket connection refused | `kError` |

---

## Category: TCP (4)

| Name | Description | Severity |
|------|-------------|----------|
| `TcpConnectFailed` | TCP connect failed | `kError` |
| `TcpConnectTimeout` | TCP connect timeout | `kWarning` |
| `TcpReceiveFailed` | TCP receive failed | `kError` |
| `TCPLinkDeadlockDetected` | TCP link deadlock detected | `kFatal` |

---

## Category: UDP (5)

| Name | Description | Severity |
|------|-------------|----------|
| `UdpOpenFailed` | UDP socket open failed | `kError` |
| `UdpSendFailed` | UDP send failed | `kError` |
| `UdpRelayFailed` | UDP relay failed | `kError` |
| `UdpMappingFailed` | UDP mapping failed | `kError` |
| `UdpPacketInvalid` | UDP packet invalid | `kError` |

---

## Category: DNS (5)

| Name | Description | Severity |
|------|-------------|----------|
| `DnsResolveFailed` | DNS resolve failed | `kError` |
| `DnsCacheFailed` | DNS cache operation failed | `kError` |
| `DnsPacketInvalid` | DNS packet invalid | `kError` |
| `DnsResponseInvalid` | DNS response invalid | `kError` |
| `DnsAddressInvalid` | DNS address invalid | `kError` |

---

## Category: HTTP (5)

| Name | Description | Severity |
|------|-------------|----------|
| `HttpRequestFailed` | HTTP request failed | `kError` |
| `HttpResponseInvalid` | HTTP response invalid | `kError` |
| `HttpProxyApplyFailed` | HTTP proxy apply failed | `kError` |
| `HttpHeaderInvalid` | HTTP header invalid | `kError` |
| `HttpConnectTunnelFailed` | HTTP CONNECT tunnel failed | `kError` |

---

## Category: WebSocket (3)

| Name | Description | Severity |
|------|-------------|----------|
| `WebSocketHandshakeFailed` | WebSocket handshake failed | `kError` |
| `WebSocketReadFailed` | WebSocket read failed | `kError` |
| `WebSocketWriteFailed` | WebSocket write failed | `kError` |

---

## Category: Tunnel (12)

| Name | Description | Severity |
|------|-------------|----------|
| `TunnelOpenFailed` | Tunnel open failed | `kError` |
| `TunnelListenFailed` | Tunnel listen failed | `kError` |
| `TunnelReadFailed` | Tunnel read failed | `kError` |
| `TunnelWriteFailed` | Tunnel write failed | `kError` |
| `TunnelDeviceMissing` | Tunnel device missing | `kError` |
| `TunnelDeviceConfigureFailed` | Tunnel device configuration failed | `kError` |
| `TunnelDeviceUnsupported` | Tunnel device unsupported | `kFatal` |
| `TunnelAddressConfigureFailed` | Tunnel address configuration failed | `kError` |
| `TunnelMtuConfigureFailed` | Tunnel MTU configuration failed | `kError` |
| `TunnelProtectionConfigureFailed` | Tunnel protection mode configuration failed | `kError` |
| `TunnelLoopbackSetupFailed` | Tunnel loopback setup failed | `kError` |
| `TunnelPacketInjectFailed` | Tunnel packet injection failed | `kError` |

---

## Category: Firewall (1)

| Name | Description | Severity |
|------|-------------|----------|
| `FirewallCreateFailed` | Firewall creation failed | `kError` |

---

## Category: Route (6)

| Name | Description | Severity |
|------|-------------|----------|
| `RouteQueryFailed` | Route query failed | `kError` |
| `RouteTableUnavailable` | Route table unavailable | `kError` |
| `RouteAddFailed` | Route add failed | `kError` |
| `RouteDeleteFailed` | Route delete failed | `kError` |
| `RouteReplaceFailed` | Route replace failed | `kError` |
| `RouteInterfaceInvalid` | Route interface invalid | `kError` |

---

## Category: IPv6 (30)

| Name | Description | Severity |
|------|-------------|----------|
| `IPv6Unsupported` | IPv6 is unsupported on this platform | `kFatal` |
| `IPv6ServerPrepareFailed` | IPv6 server environment preparation failed | `kError` |
| `IPv6ClientAddressApplyFailed` | IPv6 client address apply failed | `kError` |
| `IPv6ClientRouteApplyFailed` | IPv6 client route apply failed | `kError` |
| `IPv6ClientDnsApplyFailed` | IPv6 client DNS apply failed | `kError` |
| `IPv6PrefixInvalid` | IPv6 prefix invalid | `kError` |
| `IPv6CidrInvalid` | IPv6 CIDR invalid | `kError` |
| `IPv6AddressInvalid` | IPv6 address invalid | `kError` |
| `IPv6AddressUnsafe` | IPv6 address rejected by safety policy | `kError` |
| `IPv6GatewayInvalid` | The IPv6 gateway address received from the server is malformed or is not a valid unicast address. | `kError` |
| `IPv6GatewayMissing` | IPv6 gateway missing | `kError` |
| `IPv6GatewayNotReachable` | IPv6 gateway not reachable | `kError` |
| `IPv6ModeInvalid` | IPv6 mode invalid | `kError` |
| `PlatformNotSupportGUAMode` | Platform does not support IPv6 GUA mode | `kFatal` |
| `IPv6Nat66Unavailable` | IPv6 NAT66 backend unavailable | `kError` |
| `IPv6ForwardingEnableFailed` | IPv6 forwarding enable failed | `kError` |
| `IPv6ForwardRuleApplyFailed` | IPv6 forward rule apply failed | `kError` |
| `IPv6SubnetForwardFailed` | IPv6 subnet forward failed | `kError` |
| `IPv6TransitTapOpenFailed` | IPv6 transit TAP open failed | `kError` |
| `IPv6TransitRouteAddFailed` | IPv6 transit route add failed | `kError` |
| `IPv6TransitRouteDeleteFailed` | IPv6 transit route delete failed | `kError` |
| `IPv6NeighborProxyEnableFailed` | IPv6 neighbor proxy enable failed | `kError` |
| `IPv6NeighborProxyAddFailed` | IPv6 neighbor proxy add failed | `kError` |
| `IPv6NeighborProxyDeleteFailed` | IPv6 neighbor proxy delete failed | `kError` |
| `IPv6NDPProxyFailed` | The kernel NDP proxy entry for the assigned IPv6 address could not be installed via netlink. | `kError` |
| `IPv6LeaseConflict` | IPv6 lease conflict | `kError` |
| `IPv6LeaseUnavailable` | No IPv6 lease is currently active for this session; the session may not have completed IPv6 negotiation. | `kWarning` |
| `IPv6LeaseExpired` | The IPv6 lease has passed its expiry deadline and has been evicted from the active lease table. | `kWarning` |
| `IPv6PacketRejected` | IPv6 packet rejected | `kError` |
| `IPv6SubnetMaskInvalid` | The IPv6 subnet mask or prefix length derived from the server assignment does not produce a valid network boundary. | `kError` |

---

## Category: Session (9)

| Name | Description | Severity |
|------|-------------|----------|
| `SessionCreateFailed` | Session creation failed | `kError` |
| `SessionOpenFailed` | Session open failed | `kError` |
| `SessionAuthFailed` | Session authentication failed | `kError` |
| `SessionHandshakeFailed` | Session handshake failed | `kError` |
| `SessionDisposed` | Session already disposed | `kError` |
| `SessionNotFound` | Session not found | `kError` |
| `SessionQuotaExceeded` | Session quota exceeded | `kError` |
| `SessionIdInvalid` | Session ID invalid | `kError` |
| `SessionTransportMissing` | Session transport missing | `kError` |

---

## Category: Protocol (5)

| Name | Description | Severity |
|------|-------------|----------|
| `ProtocolFrameInvalid` | Protocol frame invalid | `kError` |
| `ProtocolPacketActionInvalid` | Protocol packet action invalid | `kError` |
| `ProtocolDecodeFailed` | Protocol decode failed | `kError` |
| `ProtocolEncodeFailed` | Protocol encode failed | `kError` |
| `ProtocolMuxFailed` | Protocol multiplexer failure | `kError` |

---

## Category: Mapping (3)

| Name | Description | Severity |
|------|-------------|----------|
| `MappingCreateFailed` | Mapping creation failed | `kError` |
| `MappingOpenFailed` | Mapping open failed | `kError` |
| `MappingEntryConflict` | Mapping entry conflict | `kError` |

---

## Category: Windows Platform (4)

| Name | Description | Severity |
|------|-------------|----------|
| `WindowsServiceStartFailed` | Windows service start failed | `kError` |
| `WindowsServiceStopFailed` | Windows service stop failed | `kError` |
| `WindowsWintunCreateFailed` | Windows Wintun create failed | `kError` |
| `WindowsWintunSessionStartFailed` | Windows Wintun session start failed | `kError` |

---

## Category: Thread Synchronization (1)

| Name | Description | Severity |
|------|-------------|----------|
| `ThreadSyncConditionWaitFailed` | Thread sync condition wait failed | `kError` |

---

## Category: Cryptography (1)

| Name | Description | Severity |
|------|-------------|----------|
| `CryptoAlgorithmUnsupported` | Crypto algorithm unsupported | `kError` |

---

## Category: Authentication (3)

| Name | Description | Severity |
|------|-------------|----------|
| `AuthCredentialMissing` | Auth credential missing | `kError` |
| `AuthCredentialInvalid` | Auth credential invalid | `kError` |
| `AuthChallengeFailed` | Auth challenge failed | `kError` |

---

## Category: Timer (1)

| Name | Description | Severity |
|------|-------------|----------|
| `TimerResolutionInvalid` | Timer resolution invalid | `kError` |

---

## Category: Resource Exhaustion (2)

| Name | Description | Severity |
|------|-------------|----------|
| `ResourceExhaustedFileDescriptors` | Resource exhausted: file descriptors | `kError` |
| `ResourceExhaustedSockets` | Resource exhausted: sockets | `kError` |

---

## Category: Internal Logic (1)

| Name | Description | Severity |
|------|-------------|----------|
| `InternalLogicNullPointer` | Internal logic null pointer | `kFatal` |

---

## Category: Security Posture Warnings (6)

Non-fatal warnings emitted during configuration validation.
These never block startup -- legacy settings remain functional for backward compatibility.

| Name | Description | Severity |
|------|-------------|----------|
| `ConfigWeakKeyDefault` | Protocol or transport key equals the well-known default value ("ppp"); insecure for production use | `kWarning` |
| `ConfigWeakKeyShort` | Protocol or transport key is shorter than 8 bytes; trivially brute-forced | `kWarning` |
| `ConfigPlaintextEnabled` | Plaintext mode is enabled (key.plaintext=true); no encryption applied | `kWarning` |
| `ConfigLegacyCipherAlgorithm` | Protocol or transport cipher uses a legacy algorithm (RC4, DES/3DES, Blowfish, CAST5, SEED, IDEA) | `kWarning` |
| `ConfigLegacyCipherShortKey` | Cipher key length is below 128 bits | `kWarning` |
| `ConfigLegacyKdfMd5` | Key derivation uses MD5 internally (EVP_BytesToKey); legacy KDF | `kWarning` |

---

## Maintenance Rules

1. Edit only `ppp/diagnostics/ErrorCodes.def` for add/remove/rename operations.
2. Keep every failure branch as: detect -> `SetLastErrorCode(...)` -> return sentinel.
3. Remove codes that are no longer referenced by any C/C++ source path.
4. Keep this page and `ERROR_CODES_CN.md` synchronized after every change.

## Add New Error Code

```c
// ErrorCodes.def
X(MyNewErrorCode, "Human-readable description", ErrorSeverity::kError)
```

```cpp
// Failure path usage example
return ppp::diagnostics::SetLastError<bool>(
    ppp::diagnostics::ErrorCode::MyNewErrorCode);
```
