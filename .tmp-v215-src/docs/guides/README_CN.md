# 任务指南

> **状态：**当前有效
> **类型：**指南索引
> **最后核对：**源码审计，2026-07-22
> **上一层索引：**[文档索引](../README_CN.md) · **English：**[Task Guides](README.md)

本节面向本仓库已实现的功能。内容以当前代码路径和配置边界为准；未公开的内部实现和历史设计不构成兼容性承诺。

## 按任务选择

| 任务 | 从这里开始 |
|---|---|
| 配置客户端分流、路由列表或 DNS | [路由与 DNS](ROUTING_AND_DNS_CN.md) · [English](ROUTING_AND_DNS.md) |
| 使用本地 HTTP/SOCKS 代理，而不是普通桌面 TUN 策略初始化 | [Proxy-only 模式](PROXY_MODE_CN.md) · [English](PROXY_MODE.md) |
| 了解宿主机与平台集成 | [平台集成](PLATFORMS_CN.md) · [English](PLATFORMS.md) |
| 通过 VPN peer 访问 IPv4 站点前缀 | [Peer 前缀路由](PEER_PREFIX_ROUTING_CN.md) · [English](PEER_PREFIX_ROUTING.md) |
| 运行原生 Go 管理器或下发订阅 | [管理后端](MANAGEMENT_BACKEND_CN.md) · [English](MANAGEMENT_BACKEND.md) |
| 使用或发布 subscription v1 文档 | [远程订阅格式](REMOTE_SUBSCRIPTION_CN.md) · [English](REMOTE_SUBSCRIPTION.md) |
| 使用协商式 IPv6 客户端地址 | [IPv6 客户端地址分配](IPV6_CLIENT_ASSIGNMENT_CN.md) · [English](IPV6_CLIENT_ASSIGNMENT.md) |
| 运维 Linux 服务端 IPv6 租约、NDP 代理或中继 | [IPv6 租约管理](IPV6_LEASE_MANAGEMENT_CN.md) · [NDP 代理](IPV6_NDP_PROXY_CN.md) · [中继平面](IPV6_TRANSIT_PLANE_CN.md) |

## 当前文档边界

- 本节是本树中 `ppp` 运行时及其随附表面的、经过源码核对的当前指南。
- IPv6 服务端数据平面页面明确限定为 Linux 服务端；移动端与桌面客户端路径有不同限制。
- 桌面订阅客户端属于实验性表面，只记录其代码中已实现的行为。
- 历史原因、提案和已替代的设计不属于本索引，不能作为运维契约。

进程启动和加固请继续阅读[部署与运维](../operations/README_CN.md)。