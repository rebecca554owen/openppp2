# Error Codes Reference

All error codes are defined in `ppp/diagnostics/ErrorCodes.def` via the X-macro pattern
and exposed as `ppp::diagnostics::ErrorCode` (enum class, `uint32_t` underlying type).

## API

```cpp
// Set thread-local error code and return false / -1 / NULLPTR
ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SomeCode);
bool ppp::diagnostics::SetLastError(ErrorCode);        // returns false
int  ppp::diagnostics::SetLastError<int>(ErrorCode);   // returns -1
T*   ppp::diagnostics::SetLastError<T*>(ErrorCode);    // returns NULLPTR

// Query
ErrorCode ppp::diagnostics::GetLastErrorCode();              // thread-local
ErrorCode ppp::diagnostics::GetLastErrorCodeSnapshot();      // last atomically published
uint64_t  ppp::diagnostics::GetLastErrorTimestamp();         // ms of last published error
const char* ppp::diagnostics::FormatErrorString(ErrorCode);  // human-readable text
```

---

## Category: Generic

| Name                        | Description                                  |
|-----------------------------|----------------------------------------------|
| `Success`                   | No error                                     |
| `GenericUnknown`            | Unknown / unclassified error                 |
| `GenericInvalidArgument`    | Invalid argument                             |
| `GenericNotSupported`       | Operation not supported                      |
| `GenericPermissionDenied`   | Permission denied                            |
| `GenericTimeout`            | Operation timed out                          |
| `GenericCanceled`           | Operation was cancelled                      |
| `GenericOperationFailed`    | Generic operation failure                    |
| `GenericNotFound`           | Entity not found                             |
| `GenericAlreadyExists`      | Entity already exists                        |
| `GenericNotReady`           | Not ready for the requested operation        |
| `GenericOverflow`           | Buffer or counter overflow                   |
| `GenericUnderflow`          | Buffer underflow                             |
| `GenericOutOfRange`         | Value out of acceptable range                |
| `GenericBadState`           | Object is in a bad or inconsistent state     |
| `GenericVersionMismatch`    | Version incompatibility                      |
| `GenericResourceBusy`       | Resource is currently locked or in use       |
| `GenericInterrupted`        | Interrupted by signal or external event      |
| `GenericDeadlockDetected`   | Deadlock condition detected                  |
| `GenericIOError`            | Low-level I/O error                          |
| `GenericFormatError`        | Data format error                            |
| `GenericChecksumFailed`     | Checksum mismatch                            |
| `GenericNotImplemented`     | Feature not yet implemented                  |
| `GenericDependencyFailed`   | Dependency or prerequisite failed            |
| `GenericUnavailable`        | Service or resource unavailable              |

---

## Category: Application

| Name                        | Description                                  |
|-----------------------------|----------------------------------------------|
| `AppStartupFailed`          | Application startup failed                   |
| `AppAlreadyRunning`         | Another instance is already running          |
| `AppPrivilegeRequired`      | Administrator/root privileges required       |
| `AppLockAcquireFailed`      | Could not acquire the prevent-rerun lock     |
| `AppPreflightCheckFailed`   | Pre-flight environment check failed          |
| `AppPreflightCheckNotReady` | Pre-flight check not yet complete            |
| `AppShutdownRequested`      | Graceful shutdown was requested              |
| `AppRestartRequested`       | Application restart was requested            |
| `AppResourceInitFailed`     | A required resource could not be initialized |
| `AppConfigurationInvalid`   | Configuration is invalid or incomplete       |
| `AppDependencyMissing`      | A required dependency is missing             |
| `AppSignalHandlerFailed`    | Signal handler installation failed           |
| `AppPlatformNotSupported`   | Platform is not supported for this feature   |
| `AppEventLoopFailed`        | Event loop did not start or terminated early |
| `AppNetworkInitFailed`      | Network subsystem initialization failed      |

---

## Category: Configuration

| Name                        | Description                                  |
|-----------------------------|----------------------------------------------|
| `ConfigLoadFailed`          | Configuration file could not be loaded       |
| `ConfigFileNotFound`        | Configuration file was not found             |
| `ConfigParseError`          | Configuration JSON/syntax parse error        |
| `ConfigValidationFailed`    | Configuration validation check failed        |
| `ConfigMissingField`        | Required configuration field is missing      |
| `ConfigInvalidValue`        | A configuration value is invalid             |
| `ConfigSaveError`           | Could not save configuration to disk         |
| `ConfigPathNotResolvable`   | Configuration path could not be resolved     |
| `ConfigCertificateInvalid`  | Certificate in configuration is invalid      |
| `ConfigEncryptionFailed`    | Configuration encryption step failed         |
| `ConfigDecryptionFailed`    | Configuration decryption step failed         |
| `ConfigVersionNotSupported` | Config file version is not supported         |
| `ConfigCipherNotSupported`  | Cipher suite not supported                   |
| `ConfigTokenInvalid`        | Authentication token is invalid              |
| `ConfigServerEndpointInvalid` | Server endpoint is malformed               |
| `ConfigDnsInvalid`          | DNS address configuration is invalid         |
| `ConfigNetworkInterfaceInvalid` | NIC identifier is invalid                |
| `ConfigSubnetInvalid`       | Subnet mask configuration is invalid         |
| `ConfigConcurrencyInvalid`  | Concurrency limit is invalid                 |

---

## Category: Runtime

| Name                              | Description                            |
|-----------------------------------|----------------------------------------|
| `RuntimeInitializationFailed`     | Runtime environment init failed        |
| `RuntimeThreadStartFailed`        | Worker thread could not be started     |
| `RuntimeTimerStartFailed`         | Timer could not be armed               |
| `RuntimeCoroutineSpawnFailed`     | Coroutine could not be spawned         |
| `RuntimeEventLoopStopped`         | Event loop stopped unexpectedly        |
| `RuntimeSignalHandlerFailed`      | POSIX signal handler error             |
| `RuntimeResourceExhausted`        | Runtime resource limit reached         |
| `RuntimeInternalQueueFull`        | Internal queue is full                 |
| `RuntimeCallbackFailed`           | Registered callback returned failure   |
| `RuntimeDependencyTimeout`        | Dependency startup timed out           |
| `RuntimeInvalidOperation`         | Invalid operation in current state     |
| `RuntimeConfigReloadFailed`       | Configuration hot-reload failed        |
| `RuntimeSandboxFailed`            | Sandbox/isolation setup failed         |
| `RuntimeHeartbeatFailed`          | Heartbeat check failed                 |
| `RuntimeStateCorrupted`           | Detected runtime state corruption      |
| `RuntimeInvariantViolation`       | Internal invariant was violated        |

---

## Category: Memory

| Name                        | Description                                  |
|-----------------------------|----------------------------------------------|
| `MemoryAllocationFailed`    | Memory allocation failed                     |
| `MemoryAccessViolation`     | Memory access violation detected             |
| `MemoryPoolExhausted`       | Memory pool is exhausted                     |
| `MemoryLimitExceeded`       | Memory limit exceeded                        |
| `MemoryLeakDetected`        | Memory leak detected                         |
| `MemoryCorruptionDetected`  | Memory corruption detected                   |
| `MemoryAlignmentError`      | Misaligned memory access                     |
| `MemoryMapFailed`           | Memory map operation failed                  |
| `MemoryUnmapFailed`         | Memory unmap operation failed                |
| `MemoryProtectFailed`       | Memory protection change failed              |

---

## Category: Network

| Name                              | Description                            |
|-----------------------------------|----------------------------------------|
| `NetworkInitializeFailed`         | Network stack initialization failed    |
| `NetworkInterfaceNotFound`        | NIC not found                          |
| `NetworkInterfaceUnavailable`     | NIC exists but is unavailable          |
| `NetworkInterfaceConfigureFailed` | NIC configuration step failed          |
| `NetworkAddressConflict`          | IP address conflict detected           |
| `NetworkRoutingFailed`            | Route installation failed              |
| `NetworkDnsConfigureFailed`       | DNS configuration failed               |
| `NetworkFirewallBlocked`          | Firewall blocked the operation         |
| `NetworkNatConfigureFailed`       | NAT rule installation failed           |
| `NetworkBandwidthExceeded`        | Bandwidth limit exceeded               |
| `NetworkPacketTooLarge`           | Packet exceeds MTU                     |
| `NetworkPacketMalformed`          | Malformed packet received              |
| `NetworkPacketChecksumFailed`     | Packet checksum validation failed      |
| `NetworkChecksumOffloadFailed`    | Checksum offload operation failed      |
| `NetworkFragmentationFailed`      | IP fragmentation failed                |
| `NetworkReassemblyFailed`         | IP reassembly failed                   |
| `NetworkConnectionRefused`        | Peer refused the connection            |
| `NetworkConnectionReset`          | Connection was reset by peer           |
| `NetworkConnectionAborted`        | Connection was aborted locally         |
| `NetworkHostUnreachable`          | Host is unreachable                    |
| `NetworkNetworkUnreachable`       | Network is unreachable                 |
| `NetworkPortUnreachable`          | Destination port is unreachable        |
| `NetworkTimedOut`                 | Network operation timed out            |
| `NetworkAddressInUse`             | Address/port is already in use         |
| `NetworkTooManyConnections`       | Too many simultaneous connections      |
| `NetworkPacketDirectionInvalid`   | Packet has invalid direction           |

---

## Category: IPv6

| Name                            | Description                              |
|---------------------------------|------------------------------------------|
| `IPv6Unsupported`               | IPv6 is not supported in this context    |
| `IPv6ServerPrepareFailed`       | Server IPv6 prerequisites failed         |
| `IPv6ClientPrepareFailed`       | Client IPv6 prerequisites failed         |
| `IPv6AddressInvalid`            | IPv6 address is invalid                  |
| `IPv6PrefixInvalid`             | IPv6 prefix/CIDR is invalid              |
| `IPv6RouteAddFailed`            | IPv6 route addition failed               |
| `IPv6RouteDeleteFailed`         | IPv6 route deletion failed               |
| `IPv6DnsConfigFailed`           | IPv6 DNS configuration failed            |
| `IPv6TunnelOpenFailed`          | IPv6 tunnel could not be opened          |
| `IPv6TunnelConfigFailed`        | IPv6 tunnel configuration failed         |
| `IPv6NdpFailed`                 | NDP / neighbor discovery failed          |
| `IPv6ForwardingDisabled`        | IPv6 forwarding is disabled              |
| `IPv6AddressAssignFailed`       | Address assignment to interface failed   |
| `IPv6StatelessAutoconf`         | SLAAC configuration failed               |
| `IPv6DhcpFailed`                | DHCPv6 operation failed                  |
| `IPv6PacketRejected`            | IPv6 packet was rejected                 |
| `PlatformNotSupportGUAMode`     | GUA mode unsupported on this platform    |
| `IPv6Nat66Unavailable`          | NAT66 is unavailable                     |
| `IPv6ForwardingEnableFailed`    | Could not enable IPv6 forwarding         |
| `IPv6LeaseConflict`             | IPv6 lease address conflict              |
| `IPv6LeaseUnavailable`          | No IPv6 lease address available          |
| `IPv6LeaseExpired`              | IPv6 lease has expired                   |
| `IPv6DataPlaneInstallFailed`    | Data plane rule installation failed      |
| (+ 12 more in full def file)    | ...                                      |

---

## Category: ThreadSync

| Name                              | Description                            |
|-----------------------------------|----------------------------------------|
| `ThreadSyncMutexInitFailed`       | Mutex initialization failed            |
| `ThreadSyncCondVarInitFailed`     | Condition variable init failed         |
| `ThreadSyncLockFailed`            | Lock acquisition failed                |
| `ThreadSyncUnlockFailed`          | Lock release failed                    |
| `ThreadSyncSignalFailed`          | Signal/notify operation failed         |
| `ThreadSyncWaitFailed`            | Wait operation failed                  |
| `ThreadSyncTimeoutFailed`         | Timed-wait timed out                   |
| `ThreadSyncBarrierFailed`         | Barrier synchronization failed         |
| `ThreadSyncSemaphoreInitFailed`   | Semaphore init failed                  |
| `ThreadSyncSemaphorePostFailed`   | Semaphore post failed                  |
| `ThreadSyncSemaphoreWaitFailed`   | Semaphore wait failed                  |
| `ThreadSyncSpinlockFailed`        | Spin-lock operation failed             |
| `ThreadSyncAtomicOperationFailed` | Atomic CAS operation failed            |
| `ThreadSyncDeadlockDetected`      | Deadlock detected by runtime check     |

---

## Category: TCP

| Name                        | Description                                  |
|-----------------------------|----------------------------------------------|
| `TcpConnectFailed`          | TCP outbound connect failed                  |
| `TcpAcceptFailed`           | TCP accept from listener failed              |
| `TcpHandshakeFailed`        | TCP 3-way handshake failed                   |
| `TcpNatPortExhausted`       | NAT port range exhausted                     |
| `TcpNatLinkNotFound`        | NAT translation entry not found              |
| `TcpNatAllocFailed`         | NAT entry allocation failed                  |
| `TcpRetransmitFailed`       | SYN/ACK retransmission failed                |
| `TcpWindowScaleFailed`      | TCP window scaling negotiation failed        |
| `TcpPacketInvalid`          | Invalid TCP packet received                  |
| `TcpStateInvalid`           | Invalid TCP state machine transition         |
| `TCPLinkDeadlockDetected`   | TCP link internal deadlock detected          |

---

## How to add a new error code

1. Open `ppp/diagnostics/ErrorCodes.def`.
2. Add a new line in the appropriate category:
   ```c
   X(MyNewError, "Human readable description")
   ```
3. Use the code in your error path:
   ```cpp
   return ppp::diagnostics::SetLastError<bool>(
       ppp::diagnostics::ErrorCode::MyNewError);
   ```
4. Update this document.

## How to use error codes correctly

Every failure branch must:

1. **Detect** the error condition.
2. **Set** the error code: `ppp::diagnostics::SetLastErrorCode(...)`.
3. **Return** the appropriate sentinel (`false`, `-1`, or `NULLPTR`).

A sentinel-only return without setting an error code is insufficient.  Unused error
codes (defined in the `.def` file but never referenced in any `.cpp`) should be removed.
