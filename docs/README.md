# Documentation by Task
> Status: Active
> Type: Reference
> Last verified: 63fc030

> **Purpose:** Describe the current behavior, configuration, or implementation boundary for this topic.
> **Audience:** OPENPPP2 users, operators, and developers.
> **Status:** Current.
> **Last verified against:** Current repository structure, implementation paths, and documentation links, 2026-07-18.
> **Parent index:** [Back to index](../README.md) · **Chinese:** [按任务查找文档](README_CN.md)


[中文版](README_CN.md)

Use this page as the current documentation entry point. Historical designs, plans, audits, and status records are isolated under [`archive/`](archive/README.md).

## Start Here

| Task | Current document |
|---|---|
| Install and build | [Build and first run](getting-started/USER_MANUAL.md#quick-start) |
| Create the minimum configuration | [Minimum client and server configuration](getting-started/USER_MANUAL.md#quick-start) |
| Start server or client | [Run commands](getting-started/USER_MANUAL.md#quick-start) |
| Verify the tunnel | [Operational checklist](operations/OPERATIONS.md#operational-checklist) |
| Configure routing and DNS | [Routing and DNS guide](guides/ROUTING_AND_DNS.md) |
| Use proxy-only mode | [Proxy-only mode](guides/PROXY_MODE.md) |
| Manage subscriptions and the admin UI | [Management backend](guides/MANAGEMENT_BACKEND.md) |
| Deploy as a service | [Deployment](operations/DEPLOYMENT.md) |
| Troubleshoot a failure | [Operations and troubleshooting](operations/OPERATIONS.md#troubleshooting-by-phase) |
| Discover every project interface and known gap | [Project interface map](reference/PROJECT_INTERFACE_MAP.md) |

## Browse by Responsibility

- [Getting started](getting-started/README.md): installation, minimum configuration, startup, and first verification.
- [Guides](guides/README.md): routing, DNS, proxy, subscriptions, management, IPv6, and platforms.
- [Reference](reference/README.md): complete configuration, CLI, errors, protocol, and data formats.
- [Project interface map](reference/PROJECT_INTERFACE_MAP.md), [项目接口全景图](reference/PROJECT_INTERFACE_MAP_CN.md): stable, experimental, internal, deprecated, and missing interfaces across the whole repository.
- [Runtime contracts and rollout gates](reference/UI_RUNTIME_CONTRACT.md), [UI runtime contract (CN)](reference/UI_RUNTIME_CONTRACT_CN.md), [VMUX validation](reference/VMUX_VALIDATION.md), and [VMUX validation (CN)](reference/VMUX_VALIDATION_CN.md): current platform-facing contracts and release evidence.
- [Architecture](architecture/README.md): current runtime, protocol, transport, and subsystem models.
- [Development](development/README.md): source reading, builds, testing, and compatibility.
- [Operations](operations/README.md): deployment, production operations, security, and troubleshooting.
- [Archive](archive/README.md): historical designs, plans, audits, and status records.

## Documentation Policy

Current documents describe behavior that can be used today. Archived documents preserve rationale and evidence but must not be treated as current configuration guidance. Stable English and Chinese documents remain paired, and each page links back to its parent index.
