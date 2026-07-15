# 文档总索引

[English Version](README.md)

这里是 OPENPPP2 的文档中心。文档按英中一对一配对组织，任何主题都可以分别用英文版和中文版阅读，且结构保持一致。

OPENPPP2 是一个由代码事实决定分层边界的系统，不是口号式产品说明。因此文档也按实现边界组织：启动、配置、传输、握手、包格式、link-layer 协议、客户端运行时、服务端运行时、路由与 DNS、平台集成、部署、运维、安全、管理后端和源码阅读。

## 阅读路径

### 整体理解系统

1. [`../README_CN.md`](../README_CN.md)
2. [`ENGINEERING_CONCEPTS_CN.md`](ENGINEERING_CONCEPTS_CN.md)
3. [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
4. [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md)
5. [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)
6. [`HANDSHAKE_SEQUENCE_CN.md`](HANDSHAKE_SEQUENCE_CN.md)
7. [`PACKET_FORMATS_CN.md`](PACKET_FORMATS_CN.md)
8. [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md)
9. [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md)
10. [`PACKET_LIFECYCLE_CN.md`](PACKET_LIFECYCLE_CN.md)
11. [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md)
12. [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md)
13. [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)
14. [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
15. [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
16. [`OPERATIONS_CN.md`](OPERATIONS_CN.md)

### 高效阅读源码

1. [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md)
2. [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md)
3. [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md)
4. [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md)
5. `main.cpp`
6. `ppp/configurations/*`
7. `ppp/transmissions/*`
8. `ppp/app/protocol/*`
9. `ppp/app/client/*`
10. `ppp/app/server/*`
11. 各平台目录
12. 需要 managed deployment 时再看 `go/*`

### 部署与运维

1. [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
2. [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md)
3. [`PLATFORMS_CN.md`](PLATFORMS_CN.md)
4. [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md)
5. [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
6. [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
7. [`SECURITY_CN.md`](SECURITY_CN.md)

## 文档总表

| 领域 | English | 中文 |
|------|---------|------|
| 基础 | [`ENGINEERING_CONCEPTS.md`](ENGINEERING_CONCEPTS.md) | [`ENGINEERING_CONCEPTS_CN.md`](ENGINEERING_CONCEPTS_CN.md) |
| 基础 | [`ARCHITECTURE.md`](ARCHITECTURE.md) | [`ARCHITECTURE_CN.md`](ARCHITECTURE_CN.md) |
| 基础 | [`CONCURRENCY_MODEL.md`](CONCURRENCY_MODEL.md) | [`CONCURRENCY_MODEL_CN.md`](CONCURRENCY_MODEL_CN.md) |
| 基础 | [`STARTUP_AND_LIFECYCLE.md`](STARTUP_AND_LIFECYCLE.md) | [`STARTUP_AND_LIFECYCLE_CN.md`](STARTUP_AND_LIFECYCLE_CN.md) |
| 传输 | [`TRANSMISSION.md`](TRANSMISSION.md) | [`TRANSMISSION_CN.md`](TRANSMISSION_CN.md) |
| 传输 | [`HANDSHAKE_SEQUENCE.md`](HANDSHAKE_SEQUENCE.md) | [`HANDSHAKE_SEQUENCE_CN.md`](HANDSHAKE_SEQUENCE_CN.md) |
| 传输 | [`PACKET_FORMATS.md`](PACKET_FORMATS.md) | [`PACKET_FORMATS_CN.md`](PACKET_FORMATS_CN.md) |
| 传输 | [`TRANSMISSION_PACK_SESSIONID.md`](TRANSMISSION_PACK_SESSIONID.md) | [`TRANSMISSION_PACK_SESSIONID_CN.md`](TRANSMISSION_PACK_SESSIONID_CN.md) |
| 协议 | [`LINKLAYER_PROTOCOL.md`](LINKLAYER_PROTOCOL.md) | [`LINKLAYER_PROTOCOL_CN.md`](LINKLAYER_PROTOCOL_CN.md) |
| 协议 | [`PACKET_LIFECYCLE.md`](PACKET_LIFECYCLE.md) | [`PACKET_LIFECYCLE_CN.md`](PACKET_LIFECYCLE_CN.md) |
| 运行时 | [`CLIENT_ARCHITECTURE.md`](CLIENT_ARCHITECTURE.md) | [`CLIENT_ARCHITECTURE_CN.md`](CLIENT_ARCHITECTURE_CN.md) |
| 运行时 | [`SERVER_ARCHITECTURE.md`](SERVER_ARCHITECTURE.md) | [`SERVER_ARCHITECTURE_CN.md`](SERVER_ARCHITECTURE_CN.md) |
| 运行时 | [`ROUTING_AND_DNS.md`](ROUTING_AND_DNS.md) | [`ROUTING_AND_DNS_CN.md`](ROUTING_AND_DNS_CN.md) |
| 运行时 | [`reference/UI_RUNTIME_CONTRACT.md`](reference/UI_RUNTIME_CONTRACT.md) | [`reference/UI_RUNTIME_CONTRACT_CN.md`](reference/UI_RUNTIME_CONTRACT_CN.md) |
| 运行时 | [`reference/VMUX_VALIDATION.md`](reference/VMUX_VALIDATION.md) | [`reference/VMUX_VALIDATION_CN.md`](reference/VMUX_VALIDATION_CN.md) |
| 运行时 | [`PEER_PREFIX_ROUTING.md`](PEER_PREFIX_ROUTING.md) | [`PEER_PREFIX_ROUTING_CN.md`](PEER_PREFIX_ROUTING_CN.md) |
| 平台 | [`PLATFORMS.md`](PLATFORMS.md) | [`PLATFORMS_CN.md`](PLATFORMS_CN.md) |
| 配置 | [`CONFIGURATION.md`](CONFIGURATION.md) | [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md) |
| 配置 | [`CLI_REFERENCE.md`](CLI_REFERENCE.md) | [`CLI_REFERENCE_CN.md`](CLI_REFERENCE_CN.md) |
| 运维 | [`DEPLOYMENT.md`](DEPLOYMENT.md) | [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md) |
| 运维 | [`OPERATIONS.md`](OPERATIONS.md) | [`OPERATIONS_CN.md`](OPERATIONS_CN.md) |
| 安全 | [`SECURITY.md`](SECURITY.md) | [`SECURITY_CN.md`](SECURITY_CN.md) |
| 管理 | [`MANAGEMENT_BACKEND.md`](MANAGEMENT_BACKEND.md) | [`MANAGEMENT_BACKEND_CN.md`](MANAGEMENT_BACKEND_CN.md) |
| 使用 | [`USER_MANUAL.md`](USER_MANUAL.md) | [`USER_MANUAL_CN.md`](USER_MANUAL_CN.md) |
| 阅读 | [`SOURCE_READING_GUIDE.md`](SOURCE_READING_GUIDE.md) | [`SOURCE_READING_GUIDE_CN.md`](SOURCE_READING_GUIDE_CN.md) |
| 架构 | [`EDSM_STATE_MACHINES.md`](EDSM_STATE_MACHINES.md) | [`EDSM_STATE_MACHINES_CN.md`](EDSM_STATE_MACHINES_CN.md) |
| UI | [`TUI_DESIGN.md`](TUI_DESIGN.md) | [`TUI_DESIGN_CN.md`](TUI_DESIGN_CN.md) |
| 诊断 | [`ERROR_CODES.md`](ERROR_CODES.md) | [`ERROR_CODES_CN.md`](ERROR_CODES_CN.md) |
| 诊断 | [`ERROR_HANDLING_API.md`](ERROR_HANDLING_API.md) | [`ERROR_HANDLING_API_CN.md`](ERROR_HANDLING_API_CN.md) |
| 诊断 | [`DIAGNOSTICS_ERROR_SYSTEM.md`](DIAGNOSTICS_ERROR_SYSTEM.md) | [`DIAGNOSTICS_ERROR_SYSTEM_CN.md`](DIAGNOSTICS_ERROR_SYSTEM_CN.md) |
| 诊断 | `linux/ppp/tap/openppp2_sysnat.h`（C 桥接辅助） | `linux/ppp/tap/openppp2_sysnat.h`（C 桥接辅助） |
| 协议 | [`TUNNEL_DESIGN.md`](TUNNEL_DESIGN.md) | [`TUNNEL_DESIGN_CN.md`](TUNNEL_DESIGN_CN.md) |
| IPv6 | [`IPV6_LEASE_MANAGEMENT.md`](IPV6_LEASE_MANAGEMENT.md) | [`IPV6_LEASE_MANAGEMENT_CN.md`](IPV6_LEASE_MANAGEMENT_CN.md) |
| IPv6 | [`IPV6_TRANSIT_PLANE.md`](IPV6_TRANSIT_PLANE.md) | [`IPV6_TRANSIT_PLANE_CN.md`](IPV6_TRANSIT_PLANE_CN.md) |
| IPv6 | [`IPV6_NDP_PROXY.md`](IPV6_NDP_PROXY.md) | [`IPV6_NDP_PROXY_CN.md`](IPV6_NDP_PROXY_CN.md) |
| IPv6 | [`IPV6_CLIENT_ASSIGNMENT.md`](IPV6_CLIENT_ASSIGNMENT.md) | [`IPV6_CLIENT_ASSIGNMENT_CN.md`](IPV6_CLIENT_ASSIGNMENT_CN.md) |
| IPv6 | [`IPV6_FIXES.md`](IPV6_FIXES.md) | [`IPV6_FIXES_CN.md`](IPV6_FIXES_CN.md) |
| 平台 | [`MULTIQUEUE_TUN_MODEL.md`](MULTIQUEUE_TUN_MODEL.md) | [`MULTIQUEUE_TUN_MODEL_CN.md`](MULTIQUEUE_TUN_MODEL_CN.md) |
| 可观测性 | [`OTEL_DESIGN.md`](OTEL_DESIGN.md) | [`OTEL_DESIGN_CN.md`](OTEL_DESIGN_CN.md) |
| 并发 | [`ATOMIC_SHARED_PTR_HELPER_DESIGN.md`](ATOMIC_SHARED_PTR_HELPER_DESIGN.md) | [`ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md`](ATOMIC_SHARED_PTR_HELPER_DESIGN_CN.md) |
| Android | — | [`ANDROID_NETWORK_FOLLOWUP_GUARD_CN.md`](ANDROID_NETWORK_FOLLOWUP_GUARD_CN.md) |
| 治理 | — | [`dns-server-list-governance-cn.md`](dns-server-list-governance-cn.md) |

## 专项与治理文档

这些文档比主阅读路径更窄。阅读设计、审计和治理记录时，先看文档状态说明，再回到当前代码核实；不要把规划文档直接当作已实现事实。

| 领域 | 文档 | 用途 |
|------|------|------|
| Android 设计 | [`android-dependency-upgrade-plan-cn.md`](android-dependency-upgrade-plan-cn.md), [`ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md`](ANDROID_ICMP_ERROR_FORWARDING_DESIGN_CN.md), [`ANDROID_TLS_SESSION_CACHE_DESIGN_CN.md`](ANDROID_TLS_SESSION_CACHE_DESIGN_CN.md) | Android 专项计划、约束和暂缓设计。 |
| DNS 设计 | [`DNS_MODULE_DESIGN.md`](DNS_MODULE_DESIGN.md), [`DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md`](DNS_COMPLETION_STATE_TYPE_SAFETY_DESIGN_CN.md), [`DNS_DOH_DOT_SLOT_REUSE_DESIGN_CN.md`](DNS_DOH_DOT_SLOT_REUSE_DESIGN_CN.md), [`dns-server-list-governance-cn.md`](dns-server-list-governance-cn.md) | Resolver 行为、结构化 DNS 配置、提供商列表治理和后续加固项。 |
| 安全与治理 | [`openppp2-deep-code-audit-cn.md`](openppp2-deep-code-audit-cn.md), [`p1-governance-decisions-cn.md`](p1-governance-decisions-cn.md), [`p2-governance-decisions-cn.md`](p2-governance-decisions-cn.md), [`system-command-governance-pilot.md`](system-command-governance-pilot.md), [`SYSTEM_CALL_GOVERNANCE_DESIGN_CN.md`](SYSTEM_CALL_GOVERNANCE_DESIGN_CN.md) | 审计发现、已接受的暂缓项和系统命令治理决策。 |
| 工程治理 | [`governance/CODE_STYLE.md`](governance/CODE_STYLE.md), [`governance/DOCUMENTATION_STYLE.md`](governance/DOCUMENTATION_STYLE.md), [`adr/README.md`](adr/README.md), [`design/README.md`](design/README.md) | 代码归属、禁止依赖、文档元数据、ADR 与设计文档规则。 |
| 定向加固 | [`PER_FRAME_READ_TIMEOUT_DESIGN.md`](PER_FRAME_READ_TIMEOUT_DESIGN.md), [`PER_FRAME_READ_TIMEOUT_DESIGN_CN.md`](PER_FRAME_READ_TIMEOUT_DESIGN_CN.md), [`FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md`](FIREWALL_RCU_RULE_SNAPSHOT_DESIGN_CN.md), [`SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md`](SSL_CTX_INIT_LOCK_REDUCTION_DESIGN_CN.md), [`TCP_NAT_AUDIT_REPORT.md`](TCP_NAT_AUDIT_REPORT.md) | 超时、Firewall RCU、TLS 初始化、TCP NAT 等专项分析。 |
| 兼容与本地说明 | [`BOOST_187_COMPATIBILITY.md`](BOOST_187_COMPATIBILITY.md), [`SERVER_IPV4_ASSIGNMENT_CN.md`](SERVER_IPV4_ASSIGNMENT_CN.md) | 兼容状态和服务端 IPv4 下发说明。 |
| MUX 调度 | [`MUX_PERFLOW_DELIVERY_DESIGN_CN.md`](MUX_PERFLOW_DELIVERY_DESIGN_CN.md), [`MUX_DEFECTS_AND_FIXES_CN.md`](MUX_DEFECTS_AND_FIXES_CN.md), [`MUX_DEFECTS_AND_FIXES.md`](MUX_DEFECTS_AND_FIXES.md) | VMUX 按流定序（flow v2）设计；以及多链路 flow 改造引出的缺陷台账（D1–D11）、根因与分阶段修复/优化方案。状态性文档，需对照当前代码核实。 |

新增文档时，稳定参考资料放入“文档总表”；设计稿、审计记录、迁移计划或治理决策放入本节。

## 阅读原则

阅读 OPENPPP2 时，需要始终分开这几层：

- carrier transport
- protected transmission 与 handshake
- tunnel action protocol
- client 或 server runtime behavior
- platform-specific host integration
- optional management backend

把这些层混在一起理解，是最容易产生误判的地方。
