# 错误码参考手册

[English Version](ERROR_CODES.md)

所有错误码通过 X-macro 模式定义在 `ppp/diagnostics/ErrorCodes.def` 中，
以 `ppp::diagnostics::ErrorCode`（`enum class`，底层类型 `uint32_t`）形式暴露。

**共计 466 个错误码，分 22 个大类。**

## API 接口

```cpp
// 设置线程本地错误码并返回 false / -1 / NULLPTR
ppp::diagnostics::SetLastErrorCode(ppp::diagnostics::ErrorCode::SomeCode);
bool ppp::diagnostics::SetLastError(ErrorCode);        // 返回 false
int  ppp::diagnostics::SetLastError<int>(ErrorCode);   // 返回 -1
T*   ppp::diagnostics::SetLastError<T*>(ErrorCode);    // 返回 NULLPTR

// 查询
ErrorCode   ppp::diagnostics::GetLastErrorCode();           // 线程本地值
ErrorCode   ppp::diagnostics::GetLastErrorCodeSnapshot();   // 最后原子发布值
uint64_t    ppp::diagnostics::GetLastErrorTimestamp();      // 最后发布错误的毫秒时间戳
const char* ppp::diagnostics::FormatErrorString(ErrorCode); // 可读文本描述
```

---

## 分类总览

```mermaid
graph TD
    A[ErrorCode] --> B[Generic 通用 - 25]
    A --> C[App 应用 - 15]
    A --> D[Config 配置 - 21]
    A --> E[Runtime 运行时 - 15]
    A --> F[Memory 内存 - 10]
    A --> G[File 文件 - 19]
    A --> H[Network 网络 - 25]
    A --> I[Socket 套接字 - 18]
    A --> J[TCP - 11]
    A --> K[UDP - 10]
    A --> L[DNS - 10]
    A --> M[HTTP - 10]
    A --> N[WebSocket - 10]
    A --> O[TLS - 10]
    A --> P[Tunnel 隧道 - 19]
    A --> Q[Firewall 防火墙 - 10]
    A --> R[Route 路由 - 10]
    A --> S[IPv6 - 36]
    A --> T[IPv4 - 12]
    A --> U[Session 会话 - 15]
    A --> V[Protocol 协议 - 10]
    A --> W[Mapping 映射 - 10]
    A --> X2[PPP/LCP/IPCP - 18]
    A --> Y[Linux 平台 - 14]
    A --> Z[Windows 平台 - 16]
    A --> AA[ThreadSync 线程同步 - 14]
    A --> BB[Crypto 密码学 - 14]
    A --> CC[Auth 认证 - 14]
    A --> DD[Timer 定时器 - 14]
    A --> EE[Resource 资源耗尽 - 14]
    A --> FF[InternalLogic 内部逻辑 - 14]
```

---

## 类别：Generic 通用（25 个）

| 名称 | 描述 |
|------|------|
| `Success` | 成功 |
| `GenericUnknown` | 未知错误 |
| `GenericInvalidArgument` | 参数无效 |
| `GenericInvalidState` | 状态无效 |
| `GenericNotSupported` | 操作不支持 |
| `GenericTimeout` | 操作超时 |
| `GenericCanceled` | 操作被取消 |
| `GenericNotFound` | 请求的对象不存在 |
| `GenericAlreadyExists` | 请求的对象已存在 |
| `GenericBusy` | 资源繁忙 |
| `GenericInsufficientBuffer` | 缓冲区不足 |
| `GenericOutOfMemory` | 内存耗尽 |
| `GenericOperationFailed` | 操作失败 |
| `GenericParseFailed` | 解析失败 |
| `GenericChecksumMismatch` | 校验和不匹配 |
| `GenericPermissionDenied` | 权限拒绝 |
| `GenericAccessDenied` | 访问拒绝 |
| `GenericResourceExhausted` | 资源耗尽 |
| `GenericConflict` | 资源冲突 |
| `GenericOverflow` | 数值溢出 |
| `GenericUnderflow` | 数值下溢 |
| `GenericDataTruncated` | 数据被截断 |
| `GenericDataCorrupted` | 数据损坏 |
| `GenericRateLimited` | 速率受限 |
| `GenericUnavailable` | 服务不可用 |

---

## 类别：Application 应用（15 个）

| 名称 | 描述 |
|------|------|
| `AppStartupFailed` | 应用启动失败 |
| `AppShutdownFailed` | 应用关闭失败 |
| `AppRestartFailed` | 应用重启失败 |
| `AppAlreadyRunning` | 应用已在运行 |
| `AppLockAcquireFailed` | 应用锁获取失败 |
| `AppLockReleaseFailed` | 应用锁释放失败 |
| `AppInvalidCommandLine` | 命令行参数无效 |
| `AppConfigurationMissing` | 应用配置缺失 |
| `AppConfigurationInvalid` | 应用配置无效 |
| `AppContextUnavailable` | 应用上下文不可用 |
| `AppThreadPoolInitFailed` | 线程池初始化失败 |
| `AppSignalHandlerInstallFailed` | 信号处理器安装失败 |
| `AppPrivilegeRequired` | 需要管理员或 root 权限 |
| `AppFeatureDisabled` | 请求的功能已禁用 |
| `AppPreflightCheckFailed` | 启动预检失败 |

---

## 类别：Configuration 配置（21 个）

| 名称 | 描述 |
|------|------|
| `ConfigLoadFailed` | 加载配置失败 |
| `ConfigFileNotFound` | 配置文件未找到 |
| `ConfigFileUnreadable` | 配置文件不可读 |
| `ConfigFileMalformed` | 配置文件格式错误 |
| `ConfigSchemaMismatch` | 配置架构不匹配 |
| `ConfigFieldMissing` | 必填配置字段缺失 |
| `ConfigFieldInvalid` | 配置字段无效 |
| `ConfigValueOutOfRange` | 配置值超出范围 |
| `ConfigTypeMismatch` | 配置类型不匹配 |
| `ConfigDuplicateKey` | 重复的配置键 |
| `ConfigUnknownKey` | 未知的配置键 |
| `ConfigPathInvalid` | 配置路径无效 |
| `ConfigPathNotAbsolute` | 配置路径非绝对路径 |
| `ConfigDnsRuleLoadFailed` | DNS 规则加载失败 |
| `ConfigFirewallRuleLoadFailed` | 防火墙规则加载失败 |
| `ConfigRouteLoadFailed` | 路由列表加载失败 |
| `ConfigCipherInvalid` | 加密算法配置无效 |
| `ConfigCertificateInvalid` | 证书配置无效 |
| `ConfigKeyInvalid` | 密钥配置无效 |
| `ConfigConcurrencyInvalid` | 并发配置无效 |

---

## 类别：Runtime 运行时（15 个）

| 名称 | 描述 |
|------|------|
| `RuntimeInitializationFailed` | 运行时初始化失败 |
| `RuntimeEnvironmentInvalid` | 运行时环境无效 |
| `RuntimeIoContextMissing` | I/O 上下文不可用 |
| `RuntimeSchedulerUnavailable` | 调度器不可用 |
| `RuntimeTimerCreateFailed` | 定时器创建失败 |
| `RuntimeTimerStartFailed` | 定时器启动失败 |
| `RuntimeEventDispatchFailed` | 事件分发失败 |
| `RuntimeTaskPostFailed` | 任务投递失败 |
| `RuntimeCoroutineSpawnFailed` | 协程创建失败 |
| `RuntimeThreadStartFailed` | 线程启动失败 |
| `RuntimeThreadJoinFailed` | 线程 join 失败 |
| `RuntimeThreadNameFailed` | 线程命名失败 |
| `RuntimePauseUnsupported` | 暂停操作不支持 |
| `RuntimeStateTransitionInvalid` | 无效的运行时状态迁移 |
| `RuntimeInvariantViolation` | 运行时不变量被违反 |

---

## 类别：Memory 内存（10 个）

| 名称 | 描述 |
|------|------|
| `MemoryAllocationFailed` | 内存分配失败 |
| `MemoryReallocationFailed` | 内存重分配失败 |
| `MemoryAlignmentInvalid` | 内存对齐无效 |
| `MemoryPoolCreateFailed` | 内存池创建失败 |
| `MemoryPoolExhausted` | 内存池耗尽 |
| `MemoryBufferNull` | 内存缓冲区为空 |
| `MemoryBufferTooSmall` | 内存缓冲区过小 |
| `MemoryCopyFailed` | 内存复制失败 |
| `MemoryMapFailed` | 内存映射失败 |
| `MemoryUnmapFailed` | 内存取消映射失败 |

---

## 类别：File 文件（19 个）

| 名称 | 描述 |
|------|------|
| `FileOpenFailed` | 文件打开失败 |
| `FileCreateFailed` | 文件创建失败 |
| `FileReadFailed` | 文件读取失败 |
| `FileWriteFailed` | 文件写入失败 |
| `FileFlushFailed` | 文件刷新失败 |
| `FileCloseFailed` | 文件关闭失败 |
| `FileDeleteFailed` | 文件删除失败 |
| `FileRenameFailed` | 文件重命名失败 |
| `FileStatFailed` | 文件 stat 失败 |
| `FileSeekFailed` | 文件定位失败 |
| `FileTruncateFailed` | 文件截断失败 |
| `FileLockFailed` | 文件加锁失败 |
| `FileUnlockFailed` | 文件解锁失败 |
| `FilePermissionInvalid` | 文件权限无效 |
| `FilePathInvalid` | 文件路径无效 |
| `FilePathTooLong` | 文件路径过长 |
| `FileDirectoryMissing` | 目录不存在 |
| `FileDirectoryCreateFailed` | 目录创建失败 |
| `FileDirectoryEnumerateFailed` | 目录枚举失败 |
| `FileRotationFailed` | 日志轮转失败 |

---

## 类别：Network 网络（25 个）

| 名称 | 描述 |
|------|------|
| `NetworkInitializeFailed` | 网络初始化失败 |
| `NetworkInterfaceUnavailable` | 网络接口不可用 |
| `NetworkInterfaceOpenFailed` | 网络接口打开失败 |
| `NetworkInterfaceConfigureFailed` | 网络接口配置失败 |
| `NetworkInterfaceRouteFailed` | 网络接口路由配置失败 |
| `NetworkInterfaceDnsFailed` | 网络接口 DNS 配置失败 |
| `NetworkAddressInvalid` | 网络地址无效 |
| `NetworkMaskInvalid` | 网络掩码无效 |
| `NetworkGatewayInvalid` | 网络网关无效 |
| `NetworkGatewayUnreachable` | 网络网关不可达 |
| `NetworkPortInvalid` | 网络端口无效 |
| `NetworkProtocolUnsupported` | 网络协议不支持 |
| `NetworkMtuInvalid` | 网络 MTU 无效 |
| `NetworkMssInvalid` | 网络 MSS 无效 |
| `NetworkFirewallBlocked` | 被防火墙拦截 |
| `NetworkRouteNotFound` | 网络路由未找到 |
| `NetworkRouteAddFailed` | 添加网络路由失败 |
| `NetworkRouteDeleteFailed` | 删除网络路由失败 |
| `NetworkAddressConflict` | 网络地址冲突 |
| `NetworkAddressFamilyMismatch` | 网络地址族不匹配 |
| `NetworkPacketMalformed` | 网络数据包格式错误 |
| `NetworkPacketTooLarge` | 网络数据包过大 |
| `NetworkPacketDrop` | 网络数据包丢弃 |
| `NetworkPacketChecksumFailed` | 网络数据包校验和失败 |
| `NetworkPacketDirectionInvalid` | 网络数据包方向无效 |

---

## 类别：Socket 套接字（18 个）

| 名称 | 描述 |
|------|------|
| `SocketCreateFailed` | 套接字创建失败 |
| `SocketOpenFailed` | 套接字打开失败 |
| `SocketBindFailed` | 套接字绑定失败 |
| `SocketListenFailed` | 套接字监听失败 |
| `SocketAcceptFailed` | 套接字接受连接失败 |
| `SocketConnectFailed` | 套接字连接失败 |
| `SocketReadFailed` | 套接字读取失败 |
| `SocketWriteFailed` | 套接字写入失败 |
| `SocketShutdownFailed` | 套接字关闭失败 |
| `SocketCloseFailed` | 套接字销毁失败 |
| `SocketOptionSetFailed` | 套接字选项设置失败 |
| `SocketOptionGetFailed` | 套接字选项获取失败 |
| `SocketAddressInvalid` | 套接字地址无效 |
| `SocketWouldBlock` | 套接字会阻塞 |
| `SocketDisconnected` | 套接字已断开 |
| `SocketTimeout` | 套接字超时 |
| `SocketRefused` | 套接字连接被拒绝 |
| `SocketReset` | 套接字连接被重置 |
| `SocketSslHandshakeFailed` | 套接字 SSL 握手失败 |
| `SocketSslVerificationFailed` | 套接字 SSL 验证失败 |

---

## 类别：TCP（11 个）

| 名称 | 描述 |
|------|------|
| `TcpConnectFailed` | TCP 连接失败 |
| `TcpConnectTimeout` | TCP 连接超时 |
| `TcpAcceptFailed` | TCP 接受连接失败 |
| `TcpSendFailed` | TCP 发送失败 |
| `TcpReceiveFailed` | TCP 接收失败 |
| `TcpKeepAliveFailed` | TCP keep-alive 失败 |
| `TcpMssClampFailed` | TCP MSS 限制失败 |
| `TcpWindowSizeSetFailed` | TCP 窗口大小配置失败 |
| `TcpFastOpenFailed` | TCP Fast Open 配置失败 |
| `TcpCongestionControlFailed` | TCP 拥塞控制配置失败 |
| `TCPLinkDeadlockDetected` | TCP 链路死锁检测 |

---

## 类别：UDP（10 个）

| 名称 | 描述 |
|------|------|
| `UdpOpenFailed` | UDP 套接字打开失败 |
| `UdpBindFailed` | UDP 套接字绑定失败 |
| `UdpSendFailed` | UDP 发送失败 |
| `UdpReceiveFailed` | UDP 接收失败 |
| `UdpRelayFailed` | UDP 中继失败 |
| `UdpNamespaceLookupFailed` | UDP 命名空间查找失败 |
| `UdpDnsRedirectFailed` | UDP DNS 重定向失败 |
| `UdpMappingFailed` | UDP 映射失败 |
| `UdpPortUnavailable` | UDP 端口不可用 |
| `UdpPacketInvalid` | UDP 数据包无效 |

---

## 类别：DNS（10 个）

| 名称 | 描述 |
|------|------|
| `DnsResolveFailed` | DNS 解析失败 |
| `DnsCacheFailed` | DNS 缓存操作失败 |
| `DnsRuleRejected` | DNS 查询被规则拒绝 |
| `DnsPacketInvalid` | DNS 数据包无效 |
| `DnsServerUnavailable` | DNS 服务器不可用 |
| `DnsTimeout` | DNS 查询超时 |
| `DnsResponseInvalid` | DNS 响应无效 |
| `DnsAddressInvalid` | DNS 地址无效 |
| `DnsMergeFailed` | DNS 合并操作失败 |
| `DnsApplyFailed` | DNS 配置应用失败 |

---

## 类别：HTTP（10 个）

| 名称 | 描述 |
|------|------|
| `HttpRequestFailed` | HTTP 请求失败 |
| `HttpStatusInvalid` | HTTP 状态码无效 |
| `HttpResponseInvalid` | HTTP 响应无效 |
| `HttpProxyConfigureFailed` | HTTP 代理配置失败 |
| `HttpProxyApplyFailed` | HTTP 代理应用失败 |
| `HttpHeaderInvalid` | HTTP 头部无效 |
| `HttpBodyInvalid` | HTTP 请求体无效 |
| `HttpUpgradeFailed` | HTTP 协议升级失败 |
| `HttpAuthenticationFailed` | HTTP 认证失败 |
| `HttpConnectTunnelFailed` | HTTP CONNECT 隧道失败 |

---

## 类别：WebSocket（10 个）

| 名称 | 描述 |
|------|------|
| `WebSocketHandshakeFailed` | WebSocket 握手失败 |
| `WebSocketFrameInvalid` | WebSocket 帧无效 |
| `WebSocketReadFailed` | WebSocket 读取失败 |
| `WebSocketWriteFailed` | WebSocket 写入失败 |
| `WebSocketCloseFailed` | WebSocket 关闭失败 |
| `WebSocketProtocolInvalid` | WebSocket 协议无效 |
| `WebSocketMaskInvalid` | WebSocket 掩码无效 |
| `WebSocketCompressionFailed` | WebSocket 压缩失败 |
| `WebSocketPingFailed` | WebSocket Ping 失败 |
| `WebSocketPongTimeout` | WebSocket Pong 超时 |

---

## 类别：TLS（10 个）

| 名称 | 描述 |
|------|------|
| `TlsContextCreateFailed` | TLS 上下文创建失败 |
| `TlsCertificateLoadFailed` | TLS 证书加载失败 |
| `TlsPrivateKeyLoadFailed` | TLS 私钥加载失败 |
| `TlsCaLoadFailed` | TLS CA 证书包加载失败 |
| `TlsCipherConfigureFailed` | TLS 密码套件配置失败 |
| `TlsHandshakeFailed` | TLS 握手失败 |
| `TlsVerifyFailed` | TLS 验证失败 |
| `TlsRenegotiationFailed` | TLS 重协商失败 |
| `TlsShutdownFailed` | TLS 关闭失败 |
| `TlsSessionReuseFailed` | TLS 会话复用失败 |

---

## 类别：Tunnel 隧道（19 个）

| 名称 | 描述 |
|------|------|
| `TunnelCreateFailed` | 隧道创建失败 |
| `TunnelOpenFailed` | 隧道打开失败 |
| `TunnelListenFailed` | 隧道监听失败 |
| `TunnelReadFailed` | 隧道读取失败 |
| `TunnelWriteFailed` | 隧道写入失败 |
| `TunnelDeviceMissing` | 隧道设备缺失 |
| `TunnelDevicePermissionDenied` | 隧道设备权限拒绝 |
| `TunnelDeviceConfigureFailed` | 隧道设备配置失败 |
| `TunnelDeviceUnsupported` | 隧道设备不支持 |
| `TunnelAddressConfigureFailed` | 隧道地址配置失败 |
| `TunnelRouteConfigureFailed` | 隧道路由配置失败 |
| `TunnelDnsConfigureFailed` | 隧道 DNS 配置失败 |
| `TunnelMtuConfigureFailed` | 隧道 MTU 配置失败 |
| `TunnelPromiscConfigureFailed` | 隧道混杂模式配置失败 |
| `TunnelProtectionConfigureFailed` | 隧道保护模式配置失败 |
| `TunnelLoopbackSetupFailed` | 隧道环回设置失败 |
| `TunnelPacketInjectFailed` | 隧道数据包注入失败 |
| `TunnelPacketCaptureFailed` | 隧道数据包捕获失败 |
| `TunnelDisposeFailed` | 隧道销毁失败 |
| `TunnelSessionMismatch` | 隧道会话不匹配 |

---

## 类别：Firewall 防火墙（10 个）

| 名称 | 描述 |
|------|------|
| `FirewallCreateFailed` | 防火墙创建失败 |
| `FirewallLoadFailed` | 防火墙规则加载失败 |
| `FirewallApplyFailed` | 防火墙应用失败 |
| `FirewallRollbackFailed` | 防火墙回滚失败 |
| `FirewallRuleInvalid` | 防火墙规则无效 |
| `FirewallRuleConflict` | 防火墙规则冲突 |
| `FirewallPortBlocked` | 防火墙拦截目标端口 |
| `FirewallSegmentBlocked` | 防火墙拦截目标网段 |
| `FirewallDomainBlocked` | 防火墙拦截目标域名 |
| `FirewallBackendUnavailable` | 防火墙后端不可用 |

---

## 类别：Route 路由（10 个）

| 名称 | 描述 |
|------|------|
| `RouteQueryFailed` | 路由查询失败 |
| `RouteTableUnavailable` | 路由表不可用 |
| `RouteAddFailed` | 路由添加失败 |
| `RouteDeleteFailed` | 路由删除失败 |
| `RouteReplaceFailed` | 路由替换失败 |
| `RouteFlushFailed` | 路由刷新失败 |
| `RoutePrefixInvalid` | 路由前缀无效 |
| `RouteGatewayInvalid` | 路由网关无效 |
| `RouteMetricInvalid` | 路由 Metric 无效 |
| `RouteInterfaceInvalid` | 路由接口无效 |

---

## 类别：IPv6（36 个）

| 名称 | 描述 |
|------|------|
| `IPv6Unsupported` | 该平台不支持 IPv6 |
| `IPv6ServerPrepareFailed` | IPv6 服务端环境准备失败 |
| `IPv6ServerFinalizeFailed` | IPv6 服务端环境清理失败 |
| `IPv6ClientStateCaptureFailed` | IPv6 客户端状态捕获失败 |
| `IPv6ClientAddressApplyFailed` | IPv6 客户端地址应用失败 |
| `IPv6ClientRouteApplyFailed` | IPv6 客户端路由应用失败 |
| `IPv6ClientDnsApplyFailed` | IPv6 客户端 DNS 应用失败 |
| `IPv6ClientRestoreFailed` | IPv6 客户端配置恢复失败 |
| `IPv6DuplicateGUID` | 检测到重复的 IPv6 GUID |
| `IPv6PrefixInvalid` | IPv6 前缀无效 |
| `IPv6CidrInvalid` | IPv6 CIDR 无效 |
| `IPv6AddressInvalid` | IPv6 地址无效 |
| `IPv6AddressUnsafe` | IPv6 地址被安全策略拒绝 |
| `IPv6GatewayInvalid` | IPv6 网关无效 |
| `IPv6GatewayMissing` | IPv6 网关缺失 |
| `IPv6GatewayNotReachable` | IPv6 网关不可达 |
| `IPv6GatewayUnreachable` | IPv6 网关无法到达 |
| `IPv6ModeInvalid` | IPv6 模式无效 |
| `PlatformNotSupportGUAMode` | 平台不支持 IPv6 GUA 模式 |
| `IPv6Nat66Unavailable` | IPv6 NAT66 后端不可用 |
| `IPv6ForwardingEnableFailed` | IPv6 转发启用失败 |
| `IPv6ForwardRuleApplyFailed` | IPv6 转发规则应用失败 |
| `IPv6SubnetForwardFailed` | IPv6 子网转发失败 |
| `IPv6TransitTapOpenFailed` | IPv6 传输 TAP 打开失败 |
| `IPv6TransitRouteAddFailed` | IPv6 传输路由添加失败 |
| `IPv6TransitRouteDeleteFailed` | IPv6 传输路由删除失败 |
| `IPv6NeighborProxyEnableFailed` | IPv6 邻居代理启用失败 |
| `IPv6NeighborProxyAddFailed` | IPv6 邻居代理添加失败 |
| `IPv6NeighborProxyDeleteFailed` | IPv6 邻居代理删除失败 |
| `IPv6NDPProxyFailed` | IPv6 NDP 代理失败 |
| `IPv6ExternalAccessFailed` | IPv6 外部访问失败 |
| `IPv6LeaseConflict` | IPv6 租约冲突 |
| `IPv6LeaseUnavailable` | IPv6 租约不可用 |
| `IPv6LeaseExpired` | IPv6 租约已过期 |
| `IPv6DataPlaneInstallFailed` | IPv6 数据平面安装失败 |
| `IPv6PacketRejected` | IPv6 数据包被拒绝 |

---

## 类别：IPv4（12 个）

| 名称 | 描述 |
|------|------|
| `IPv4AddressInvalid` | IPv4 地址无效 |
| `IPv4MaskInvalid` | IPv4 网络掩码无效 |
| `IPv4GatewayInvalid` | IPv4 网关无效 |
| `IPv4GatewayNotReachable` | IPv4 网关不可达 |
| `IPv4RouteAddFailed` | IPv4 路由添加失败 |
| `IPv4RouteDeleteFailed` | IPv4 路由删除失败 |
| `IPv4FragmentationRequired` | 需要 IPv4 分片 |
| `IPv4HeaderInvalid` | IPv4 头部无效 |
| `IPv4ChecksumFailed` | IPv4 校验和失败 |
| `IPv4OptionUnsupported` | IPv4 选项不支持 |
| `IPv4ArpResolveFailed` | IPv4 ARP 解析失败 |
| `IPv4MtuDiscoveryFailed` | IPv4 MTU 发现失败 |

---

## 类别：Session 会话（15 个）

| 名称 | 描述 |
|------|------|
| `SessionCreateFailed` | 会话创建失败 |
| `SessionOpenFailed` | 会话打开失败 |
| `SessionAuthFailed` | 会话认证失败 |
| `SessionHandshakeFailed` | 会话握手失败 |
| `SessionInformationInvalid` | 会话信息无效 |
| `SessionUpdateFailed` | 会话更新失败 |
| `SessionCloseFailed` | 会话关闭失败 |
| `SessionDisposed` | 会话已销毁 |
| `SessionNotFound` | 会话未找到 |
| `SessionQuotaExceeded` | 会话配额超限 |
| `SessionBandwidthExceeded` | 会话带宽配额超限 |
| `SessionTrafficExceeded` | 会话流量配额超限 |
| `SessionExpired` | 会话已过期 |
| `SessionIdInvalid` | 会话 ID 无效 |
| `SessionTransportMissing` | 会话传输层缺失 |

---

## 类别：Protocol 协议（10 个）

| 名称 | 描述 |
|------|------|
| `ProtocolFrameInvalid` | 协议帧无效 |
| `ProtocolPacketActionInvalid` | 协议数据包动作无效 |
| `ProtocolVersionMismatch` | 协议版本不匹配 |
| `ProtocolCipherMismatch` | 协议密码套件不匹配 |
| `ProtocolDecodeFailed` | 协议解码失败 |
| `ProtocolEncodeFailed` | 协议编码失败 |
| `ProtocolCompressionFailed` | 协议压缩失败 |
| `ProtocolDecompressionFailed` | 协议解压失败 |
| `ProtocolKeepAliveTimeout` | 协议 keep-alive 超时 |
| `ProtocolMuxFailed` | 协议多路复用器失败 |

---

## 类别：Mapping 映射（10 个）

| 名称 | 描述 |
|------|------|
| `MappingCreateFailed` | 映射创建失败 |
| `MappingBindFailed` | 映射绑定失败 |
| `MappingOpenFailed` | 映射打开失败 |
| `MappingConnectFailed` | 映射连接失败 |
| `MappingSendFailed` | 映射发送失败 |
| `MappingReceiveFailed` | 映射接收失败 |
| `MappingEntryConflict` | 映射条目冲突 |
| `MappingPortUnavailable` | 映射端口不可用 |
| `MappingDisposeFailed` | 映射销毁失败 |
| `MappingBackendUnavailable` | 映射后端不可用 |

---

## 类别：PPP / LCP / IPCP / IPv6CP（18 个）

| 名称 | 描述 |
|------|------|
| `PppFrameInvalid` | PPP 帧无效 |
| `PppProtocolFieldInvalid` | PPP 协议字段无效 |
| `PppFcsInvalid` | PPP FCS 无效 |
| `PppPayloadTooShort` | PPP 负载过短 |
| `LcpPacketInvalid` | LCP 数据包无效 |
| `LcpCodeUnsupported` | LCP 代码不支持 |
| `LcpOptionInvalid` | LCP 选项无效 |
| `LcpMagicNumberMismatch` | LCP 魔术数字不匹配 |
| `LcpEchoTimeout` | LCP 回显超时 |
| `IpcpPacketInvalid` | IPCP 数据包无效 |
| `IpcpOptionInvalid` | IPCP 选项无效 |
| `IpcpAddressRejected` | IPCP 地址被拒绝 |
| `IpcpDnsRejected` | IPCP DNS 被拒绝 |
| `IpcpNegotiationFailed` | IPCP 协商失败 |
| `Ipv6cpPacketInvalid` | IPv6CP 数据包无效 |
| `Ipv6cpOptionInvalid` | IPv6CP 选项无效 |
| `Ipv6cpInterfaceIdInvalid` | IPv6CP 接口标识符无效 |
| `Ipv6cpNegotiationFailed` | IPv6CP 协商失败 |

---

## 类别：Linux 平台（14 个）

| 名称 | 描述 |
|------|------|
| `LinuxNetlinkOpenFailed` | Linux Netlink 打开失败 |
| `LinuxNetlinkSendFailed` | Linux Netlink 发送失败 |
| `LinuxNetlinkReceiveFailed` | Linux Netlink 接收失败 |
| `LinuxIptablesApplyFailed` | Linux iptables 应用失败 |
| `LinuxNftablesApplyFailed` | Linux nftables 应用失败 |
| `LinuxIpRuleAddFailed` | Linux ip rule 添加失败 |
| `LinuxIpRuleDeleteFailed` | Linux ip rule 删除失败 |
| `LinuxSysctlReadFailed` | Linux sysctl 读取失败 |
| `LinuxSysctlWriteFailed` | Linux sysctl 写入失败 |
| `LinuxProcReadFailed` | Linux procfs 读取失败 |
| `LinuxProcWriteFailed` | Linux procfs 写入失败 |
| `LinuxCapabilityMissing` | Linux 能力（Capability）缺失 |
| `LinuxNamespaceEnterFailed` | Linux 命名空间进入失败 |
| `LinuxNamespaceCreateFailed` | Linux 命名空间创建失败 |

---

## 类别：Windows 平台（16 个）

| 名称 | 描述 |
|------|------|
| `WindowsWfpEngineOpenFailed` | Windows WFP 引擎打开失败 |
| `WindowsWfpFilterAddFailed` | Windows WFP 过滤器添加失败 |
| `WindowsWfpFilterDeleteFailed` | Windows WFP 过滤器删除失败 |
| `WindowsWinDivertOpenFailed` | Windows WinDivert 打开失败 |
| `WindowsWinDivertRecvFailed` | Windows WinDivert 接收失败 |
| `WindowsWinDivertSendFailed` | Windows WinDivert 发送失败 |
| `WindowsRouteAddFailed` | Windows 路由添加失败 |
| `WindowsRouteDeleteFailed` | Windows 路由删除失败 |
| `WindowsAdapterQueryFailed` | Windows 网卡查询失败 |
| `WindowsAdapterConfigureFailed` | Windows 网卡配置失败 |
| `WindowsRegistryReadFailed` | Windows 注册表读取失败 |
| `WindowsRegistryWriteFailed` | Windows 注册表写入失败 |
| `WindowsServiceStartFailed` | Windows 服务启动失败 |
| `WindowsServiceStopFailed` | Windows 服务停止失败 |
| `WindowsWintunCreateFailed` | Windows Wintun 创建失败 |
| `WindowsWintunSessionStartFailed` | Windows Wintun 会话启动失败 |

---

## 类别：Thread Synchronization 线程同步（14 个）

| 名称 | 描述 |
|------|------|
| `ThreadSyncMutexInitFailed` | 互斥锁初始化失败 |
| `ThreadSyncMutexLockFailed` | 互斥锁加锁失败 |
| `ThreadSyncMutexUnlockFailed` | 互斥锁解锁失败 |
| `ThreadSyncRwLockInitFailed` | 读写锁初始化失败 |
| `ThreadSyncRwLockReadLockFailed` | 读写锁读锁失败 |
| `ThreadSyncRwLockWriteLockFailed` | 读写锁写锁失败 |
| `ThreadSyncRwLockUnlockFailed` | 读写锁解锁失败 |
| `ThreadSyncConditionInitFailed` | 条件变量初始化失败 |
| `ThreadSyncConditionWaitFailed` | 条件变量等待失败 |
| `ThreadSyncConditionSignalFailed` | 条件变量信号失败 |
| `ThreadSyncSemaphoreInitFailed` | 信号量初始化失败 |
| `ThreadSyncSemaphoreWaitFailed` | 信号量等待失败 |
| `ThreadSyncSemaphorePostFailed` | 信号量发布失败 |
| `ThreadSyncDeadlockDetected` | 检测到线程死锁 |

---

## 类别：Cryptography 密码学（14 个）

| 名称 | 描述 |
|------|------|
| `CryptoCertificateParseFailed` | 证书解析失败 |
| `CryptoCertificateExpired` | 证书已过期 |
| `CryptoCertificateNotYetValid` | 证书尚未生效 |
| `CryptoCertificateRevoked` | 证书已吊销 |
| `CryptoCertificateChainInvalid` | 证书链无效 |
| `CryptoCertificateSubjectMismatch` | 证书主体不匹配 |
| `CryptoCertificateIssuerUnknown` | 证书颁发者未知 |
| `CryptoCertificateKeyUsageInvalid` | 证书密钥用途无效 |
| `CryptoPrivateKeyParseFailed` | 私钥解析失败 |
| `CryptoPrivateKeyMismatch` | 私钥不匹配 |
| `CryptoSignatureVerifyFailed` | 签名验证失败 |
| `CryptoRandomDeviceFailed` | 随机数设备失败 |
| `CryptoAlgorithmUnsupported` | 加密算法不支持 |
| `CryptoOcspCheckFailed` | OCSP 检查失败 |

---

## 类别：Authentication 认证（14 个）

| 名称 | 描述 |
|------|------|
| `AuthUserNotFound` | 用户未找到 |
| `AuthCredentialMissing` | 凭据缺失 |
| `AuthCredentialInvalid` | 凭据无效 |
| `AuthPasswordExpired` | 密码已过期 |
| `AuthTokenMissing` | Token 缺失 |
| `AuthTokenExpired` | Token 已过期 |
| `AuthTokenInvalid` | Token 无效 |
| `AuthTokenSignatureInvalid` | Token 签名无效 |
| `AuthChallengeFailed` | 认证挑战失败 |
| `AuthMfaRequired` | 需要多因素认证 |
| `AuthMfaInvalid` | 多因素认证无效 |
| `AuthPolicyDenied` | 策略拒绝 |
| `AuthPermissionDenied` | 权限拒绝 |
| `AuthRoleMissing` | 角色缺失 |

---

## 类别：Timer 定时器（14 个）

| 名称 | 描述 |
|------|------|
| `TimerWheelInitFailed` | 时间轮初始化失败 |
| `TimerScheduleFailed` | 定时器调度失败 |
| `TimerCancelFailed` | 定时器取消失败 |
| `TimerCallbackFailed` | 定时器回调失败 |
| `TimerResolutionInvalid` | 定时器精度无效 |
| `TimerQueueOverflow` | 定时器队列溢出 |
| `TimerSystemClockSkew` | 检测到系统时钟偏移 |
| `TimerHandshakeTimeout` | 握手定时器超时 |
| `TimerKeepAliveTimeout` | Keep-alive 定时器超时 |
| `TimerReconnectTimeout` | 重连定时器超时 |
| `TimerIdleTimeout` | 空闲定时器超时 |
| `TimerShutdownTimeout` | 关闭定时器超时 |
| `TimerDrainTimeout` | 排空定时器超时 |
| `TimerDnsQueryTimeout` | DNS 查询定时器超时 |

---

## 类别：Resource Exhaustion 资源耗尽（14 个）

| 名称 | 描述 |
|------|------|
| `ResourceExhaustedThreads` | 资源耗尽：线程 |
| `ResourceExhaustedFileDescriptors` | 资源耗尽：文件描述符 |
| `ResourceExhaustedSockets` | 资源耗尽：套接字 |
| `ResourceExhaustedPorts` | 资源耗尽：端口 |
| `ResourceExhaustedEphemeralPorts` | 资源耗尽：临时端口 |
| `ResourceExhaustedBandwidth` | 资源耗尽：带宽 |
| `ResourceExhaustedCpu` | 资源耗尽：CPU |
| `ResourceExhaustedDisk` | 资源耗尽：磁盘 |
| `ResourceExhaustedInodes` | 资源耗尽：inode |
| `ResourceExhaustedPacketBuffers` | 资源耗尽：数据包缓冲区 |
| `ResourceExhaustedNatTable` | 资源耗尽：NAT 表 |
| `ResourceExhaustedConntrack` | 资源耗尽：conntrack 表 |
| `ResourceExhaustedSessionSlots` | 资源耗尽：会话槽 |
| `ResourceExhaustedRouteTable` | 资源耗尽：路由表 |

---

## 类别：Internal Logic 内部逻辑（14 个）

| 名称 | 描述 |
|------|------|
| `InternalLogicAssertionFailed` | 内部逻辑断言失败 |
| `InternalLogicNullPointer` | 内部逻辑空指针 |
| `InternalLogicStateCorrupted` | 内部逻辑状态损坏 |
| `InternalLogicUnexpectedBranch` | 内部逻辑意外分支 |
| `InternalLogicInvariantBroken` | 内部逻辑不变量被破坏 |
| `InternalLogicReentrancyDetected` | 检测到内部逻辑重入 |
| `InternalLogicOwnershipViolation` | 内部逻辑所有权违规 |
| `InternalLogicSequenceError` | 内部逻辑序列错误 |
| `InternalLogicCacheInconsistent` | 内部逻辑缓存不一致 |
| `InternalLogicDuplicateDispatch` | 内部逻辑重复分发 |
| `InternalLogicMessageOrderInvalid` | 内部逻辑消息顺序无效 |
| `InternalLogicCounterOverflow` | 内部逻辑计数器溢出 |
| `InternalLogicUnexpectedEof` | 内部逻辑意外 EOF |
| `InternalLogicUnreachableCode` | 内部逻辑不可达代码 |

---

## 如何添加新错误码

1. 打开 `ppp/diagnostics/ErrorCodes.def`。
2. 在适当的类别块中添加一行：
   ```c
   X(MyNewError, "Human readable description")
   ```
3. 在错误路径中使用该错误码：
   ```cpp
   return ppp::diagnostics::SetLastError<bool>(
       ppp::diagnostics::ErrorCode::MyNewError);
   ```
4. 同步更新本文档和 `ERROR_CODES.md`。

## 错误码正确使用规范

每个失败分支必须：

1. **检测**错误条件。
2. **设置**错误码：`ppp::diagnostics::SetLastErrorCode(...)`。
3. **返回**适当的哨兵值（`false`、`-1` 或 `NULLPTR`）。

仅返回哨兵值而不设置错误码是不完整的。`.def` 文件中定义但在任何 `.cpp` 中未被引用的错误码应当删除。

---

## 错误码架构深度解析

### X-Macro 展开机制

整个错误码枚举由单一源文件 `ppp/diagnostics/ErrorCodes.def` 通过 X-macro 模式生成：

```cpp
// ErrorCodes.def（节选）
X(Success,                     "Success")
X(GenericUnknown,              "Generic unknown error")
X(AppStartupFailed,            "Application startup failed")
// ... 还有 463 条 ...

// ErrorCode.h — 展开为 enum class
enum class ErrorCode : uint32_t
{
#define X(name, desc) name,
#include "ppp/diagnostics/ErrorCodes.def"
#undef X
};

// Error.cpp — 展开为字符串表
static const char* s_error_strings[] = {
#define X(name, desc) desc,
#include "ppp/diagnostics/ErrorCodes.def"
#undef X
};
```

这意味着添加新错误码只需编辑一个 `.def` 文件——枚举成员、字符串表条目和 `FormatErrorString()` 查找均自动派生。

### 线程本地存储 vs. 原子快照

两种错误存储机制并存：

```mermaid
graph TD
    SETLAST["SetLastErrorCode(code)"] --> TL["线程本地存储\nGetLastErrorCode()"]
    SETLAST --> ATOMIC["std::atomic<uint64_t>\nGetLastErrorCodeSnapshot()\nGetLastErrorTimestamp()"]

    TL --> DESC1["线程局部：跟踪此线程上最近的错误"]
    ATOMIC --> DESC2["跨线程：最后一次全局发布的显著错误"]
```

`SetLastErrorCode()` 始终更新线程本地值。同时有条件地更新全局原子快照——条件通常是错误码非零（非成功）。原子快照将错误码与时间戳打包进单个 64 位值：高 32 位 = 截断为 32 位的毫秒时间戳，低 32 位 = 错误码值。

`GetLastErrorTimestamp()` 返回最近一次发布的非成功错误的毫秒时间戳，供 TUI 状态栏显示最近问题的发生时间。

### `SetLastError` 模板变体

模板重载使错误路径模式极为简洁：

```cpp
// 设置错误码后返回 false — 用于返回 bool 的函数
bool result = ppp::diagnostics::SetLastError(ErrorCode::SocketConnectFailed);
// result == false

// 设置错误码后返回 -1 — 用于返回 int 的函数
int fd = ppp::diagnostics::SetLastError<int>(ErrorCode::SocketCreateFailed);
// fd == -1

// 设置错误码后返回 NULLPTR — 用于返回指针的函数
SomeObject* ptr = ppp::diagnostics::SetLastError<SomeObject*>(ErrorCode::MemoryAllocationFailed);
// ptr == NULLPTR
```

所有三种变体均先调用 `SetLastErrorCode()`，然后返回哨兵值。这消除了两行模式：

```cpp
// 旧模式（冗长）
SetLastErrorCode(ErrorCode::SocketConnectFailed);
return false;

// 新模式（简洁）
return SetLastError(ErrorCode::SocketConnectFailed);
```

---

## 各子系统的错误码使用模式

### 启动流水线错误码

启动流水线（`PppApplication::Main()` 和 `PreparedLoopbackEnvironment()`）使用严格线性的错误码递进：每个步骤失败时仅设置一个错误码：

```mermaid
flowchart TD
    A["IsUserAnAdministrator() 失败"] --> E1["AppPrivilegeRequired"]
    B["prevent_rerun_.Exists() 为真"] --> E2["AppAlreadyRunning"]
    C["prevent_rerun_.Open() 失败"] --> E3["AppLockAcquireFailed"]
    D["Windows TAP 驱动检查失败"] --> E4["NetworkInterfaceConfigureFailed"]
    F["ITap::Create() 返回 null"] --> E5["TunnelOpenFailed"]
    G["ITap::Open() 失败"] --> E6["TunnelListenFailed"]
    H["VEthernet::Open() 失败，NIC 为 null"] --> E7["NetworkInterfaceUnavailable"]
    I["VEthernet::Open() 失败，NIC 非 null"] --> E5
    J["ipv6::PrepareServerEnvironment 失败"] --> E8["IPv6ServerPrepareFailed"]
    K["VirtualEthernetSwitcher::Open 失败"] --> E5
    L["VirtualEthernetSwitcher::Run 失败"] --> E6
    M["NextTickAlwaysTimeout 失败"] --> E9["RuntimeTimerStartFailed"]
```

### 会话生命周期错误码

会话经历多个生命周期阶段，每个潜在失败点对应特定错误码：

| 阶段 | 失败条件 | 错误码 |
|------|---------|--------|
| 握手 NOP 读取 | 读取超时 | `TimerHandshakeTimeout` |
| 握手 NOP 读取 | 解密失败 | `ProtocolDecodeFailed` |
| 握手会话 ID | 值无效 | `SessionIdInvalid` |
| 握手密码重建 | 不支持的密码 | `ProtocolCipherMismatch` |
| INFO 帧接收 | 帧格式错误 | `SessionInformationInvalid` |
| INFO 帧接收 | 配额超出 | `SessionQuotaExceeded` |
| INFO 帧接收 | 会话已过期 | `SessionExpired` |
| 数据循环读取 | 套接字断开 | `SocketDisconnected` |
| 数据循环读取 | WebSocket 帧无效 | `WebSocketFrameInvalid` |
| 心跳检查 | 超过截止时间无 RX | `ProtocolKeepAliveTimeout` |
| 管理服务器认证 | 认证被拒绝 | `AuthCredentialInvalid` 或 `AuthTokenExpired` |
| IPv6 分配 | 租约冲突 | `IPv6LeaseConflict` |
| IPv6 分配 | 无可用地址 | `IPv6LeaseUnavailable` |

### 协议层错误码

协议错误（操作码违规、解码失败）使用 `Protocol*` 类别。这些通常表明客户端与服务端版本不兼容、网络损坏或存在主动攻击者：

| 错误码 | 典型原因 |
|--------|---------|
| `ProtocolFrameInvalid` | 帧头部解码失败（种子字节或长度错误）|
| `ProtocolPacketActionInvalid` | 收到未知操作码字节 |
| `ProtocolVersionMismatch` | 客户端和服务端编译了不兼容的协议版本 |
| `ProtocolCipherMismatch` | 密钥材料交换导致派生密钥不同 |
| `ProtocolDecodeFailed` | 解密或校验和验证失败 |
| `ProtocolKeepAliveTimeout` | 远端对等节点停止发送心跳 |
| `ProtocolMuxFailed` | MUX 通道协商失败 |

---

## 错误码诊断工作流

### 第一步 — 捕获快照

问题发生时，第一步是在快照被覆盖之前捕获错误码：

```cpp
ErrorCode   code = ppp::diagnostics::GetLastErrorCodeSnapshot();
uint64_t    ts   = ppp::diagnostics::GetLastErrorTimestamp();
const char* msg  = ppp::diagnostics::FormatErrorString(code);

printf("[%llu ms] 最近错误: %s (0x%08X)\n", ts, msg, (uint32_t)code);
```

### 第二步 — 映射至类别

错误码值是连续整数（从 0 开始的枚举）。可通过查阅 `ERROR_CODES_CN.md` 或直接检查 `ErrorCodes.def` 文件来识别类别。前 25 个条目是 Generic，后 15 个是 App，以此类推。

### 第三步 — 与 TUI 关联

TUI 状态栏在底部状态行显示最新快照。若 TUI 不可用（重定向了 stdout），启动摘要文本会在进程退出前包含最后一个错误。

### 第四步 — 追踪至源码

每个错误码仅在一处（或极少几处）被设置。使用 `grep` 或 IDE 搜索查找所有 `SetLastErrorCode(ErrorCode::XYZ)` 调用点并检查周围逻辑：

```bash
# 查找特定错误码的所有调用点
grep -rn "TunnelOpenFailed" ppp/ linux/ windows/ android/ darwin/
```

### 第五步 — 区分线程本地值与快照

若快照显示的错误与预期不同，请记住：
- 快照反映**所有线程中最后一次发布的非成功错误**。
- 线程本地值反映**被检查的特定线程上的最后一个错误**。
- 在竞争情况下，两个线程可能同时设置不同的错误；快照捕获赢得原子 CAS 的那个。

---

## 正常运行期间的错误码频率

在有活跃会话的健康运行实例中，以下错误码定期出现，**不表示问题**：

| 错误码 | 正常出现原因 |
|--------|------------|
| `GenericCanceled` | 每次 `timer->cancel()` 调用时 | 定时器在销毁时被取消 |
| `GenericTimeout` | DNS 查询超时时 | 上游 DNS 可能较慢 |
| `SocketDisconnected` | 任何对等节点关闭连接时 | 正常 TCP 生命周期 |
| `SessionDisposed` | 每次会话拆除后 | 正常生命周期 |
| `FirewallSegmentBlocked` | 出站受阻的目标时 | 正常防火墙策略 |

以下错误码表示**实际问题**，应调查：

| 错误码 | 严重性 | 可能原因 |
|--------|--------|---------|
| `AppPrivilegeRequired` | 致命（启动）| 进程未以 root/管理员身份运行 |
| `AppAlreadyRunning` | 致命（启动）| 锁文件残留或重复进程 |
| `TunnelOpenFailed` | 致命（启动）| TAP 驱动未安装 |
| `ProtocolKeepAliveTimeout` | 会话丢失 | 网络中断或远端崩溃 |
| `ProtocolCipherMismatch` | 会话失败 | 客户端/服务端密钥不匹配 |
| `IPv6LeaseConflict` | IPv6 故障 | 地址池中 IP 冲突 |
| `ResourceExhaustedSessionSlots` | 容量 | 服务端已达最大连接数 |
| `ResourceExhaustedEphemeralPorts` | 中继失败 | NAT 表耗尽 |
| `AuthCredentialInvalid` | 认证失败 | 密码或令牌错误 |
| `InternalLogicStateCorrupted` | 程序错误 | 向开发者报告 |

---

## 错误处理器注册 API

除错误码存储 API 外，OPENPPP2 还提供了一个用于结构化错误通知的错误处理器派发机制：

```cpp
// 使用稳定的键注册处理器
ppp::diagnostics::ErrorHandler::RegisterErrorHandler(
    "my-module",
    [](ErrorCode code, uint64_t timestamp_ms) noexcept
    {
        // 当显著错误被发布时调用
        // 必须是 noexcept — 此处的异常会被静默吞掉
    });

// 移除处理器
ppp::diagnostics::ErrorHandler::RegisterErrorHandler("my-module", nullptr);
```

处理器注册详见 `ERROR_HANDLING_API_CN.md`。错误码消费者的关键注意事项：

- 处理器在调用 `SetLastErrorCode()` 的线程上派发。
- 处理器接收错误码和错误的毫秒时间戳。
- 处理器不得递归调用 `SetLastErrorCode()`——这会导致无限派发。
- 所有处理器必须在 worker 线程启动之前注册（在启动初始化窗口内）。

---

## 与诊断错误系统的集成

本文档描述错误码**值**。更高层次的诊断架构——错误如何传播、快照环如何维护以及 TUI 如何消费诊断信息——记录在 [`DIAGNOSTICS_ERROR_SYSTEM.md`](DIAGNOSTICS_ERROR_SYSTEM.md) 中。

两份文档的关系：

```mermaid
graph LR
    A["ErrorCodes.def\n（X-macro 源文件）"] --> B["ErrorCode 枚举\n（ErrorCode.h）"]
    B --> C["SetLastErrorCode()\nGetLastErrorCode()\nGetLastErrorCodeSnapshot()"]
    C --> D["ERROR_CODES_CN.md\n（本文档）\n值参考手册"]
    C --> E["DIAGNOSTICS_ERROR_SYSTEM.md\n架构与传播"]
    E --> F["TUI 状态栏\n（ConsoleUI）"]
    E --> G["ErrorHandler 派发\n（结构化通知）"]
```

---

## 常用错误码速查（按功能领域）

### VPN 隧道建立

```
TunnelOpenFailed           — TAP 设备无法创建或打开
TunnelListenFailed         — 服务端无法绑定/监听端口
TunnelDevicePermissionDenied — /dev/net/tun 不可访问
NetworkInterfaceUnavailable — 指定 NIC 不存在
NetworkInterfaceConfigureFailed — 无法在 TAP 上配置 IP/GW/DNS
```

### 会话握手

```
SessionHandshakeFailed     — 通用握手失败
TimerHandshakeTimeout      — 握手在超时内未完成
ProtocolDecodeFailed       — 握手帧解密/解析失败
ProtocolCipherMismatch     — 密钥派生产生了不同的密码
SessionIdInvalid           — 收到的会话 ID 为 0 或超出范围
```

### 进行中的会话

```
ProtocolKeepAliveTimeout   — 在心跳窗口内未收到数据
SocketDisconnected         — 远端 TCP 连接断开
WebSocketFrameInvalid      — WebSocket 帧损坏或意外
SessionQuotaExceeded       — 会话带宽或流量限制已达
SessionExpired             — 会话生存时间超出
```

### 认证（管理服务器）

```
AuthUserNotFound           — 用户名不在后端数据库中
AuthCredentialInvalid      — 密码或令牌错误
AuthTokenExpired           — JWT 或会话令牌已过期
AuthPolicyDenied           — 基于 IP 或时间的策略拒绝登录
AuthMfaRequired            — 需要 MFA 步骤但未提供
```

### IPv6

```
IPv6ServerPrepareFailed    — 无法设置 NDP 代理或 IPv6 转发
IPv6LeaseConflict          — 请求的 IPv6 地址已在使用中
IPv6LeaseUnavailable       — IPv6 地址池已耗尽
IPv6ForwardingEnableFailed — 无法启用 ip6_forwarding sysctl
IPv6NeighborProxyAddFailed — netlink NDP 代理添加命令失败
```

### 平台专属

```
LinuxIptablesApplyFailed   — iptables/nftables 规则无法应用
LinuxNetlinkOpenFailed     — netlink 套接字无法打开
WindowsWintunCreateFailed  — Wintun 适配器创建失败
WindowsWfpEngineOpenFailed — Windows 过滤平台不可用
WindowsRegistryReadFailed  — TAP 组件 ID 注册表查找失败
```
