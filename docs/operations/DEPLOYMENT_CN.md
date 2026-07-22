# 部署模型

> **状态：**当前实现边界
> **类型：**运维指南
> **最后核对：**应用模式/配置启动、服务端/客户端启动、CMake 与管理器源码，2026-07-22
> **上一层索引：**[部署与运维](README_CN.md) · **English：**[Deployment Model](DEPLOYMENT.md)

## 先选择角色

`ppp` 可执行文件通过 CLI 模式选择角色，不解析 JSON `mode` 字段：

```bash
./ppp --mode=server --config=./server.json
./ppp --mode=client --config=./client.json
./ppp --mode=proxy  --config=./client.json
```

| 角色 | 部署效果 |
|---|---|
| `server` | 打开已配置的服务端运行时/监听表面及可选托管/IPv6 功能。 |
| `client` | 使用普通客户端网络行为；运行时/配置启用时会进行宿主机路由/DNS 集成。 |
| `proxy` | 选择桌面代理运行时；非移动端使用 `TapStub`，跳过普通客户端 TUN 路由/DNS 规则/bypass 初始化。 |

配置查找接受 `-c`、`--c`、`-config`、`--config`。未提供时，按当前工作目录中的 `./config.json`、`./appsettings.json` 顺序查找。

## 宿主机前提

普通客户端/服务端运行可能创建或使用虚拟接口，并变更宿主机路由或 DNS。启动前应针对目标 OS 规划所需权限和能力。桌面 proxy 模式特意走不同应用路径，但仍需要可用网络、有效客户端配置和到远端服务端的访问能力。

本树构建 `ppp`，但不提供统一服务安装器、service unit 或网络策略配置。以下事项应由运维控制：

- 服务守护和重启策略；
- 端口/防火墙策略；
- DNS 服务交互和路由持久化；
- 配置文件所有权和秘密存储；
- 管理/订阅发布所需的 TLS 终止。

## 服务端部署检查清单

1. 选择明确配置文件并使用 `--mode=server`。
2. 只启用并暴露当前配置参考中描述的监听表面；在宿主机验证绑定地址/端口所有权。
3. 使用原生 Go 托管认证时，配置 `server.node >= 1`、`server.backend`、`server.backend-key`，并在原生管理器中使用匹配值和 managed 模式。
4. 需要规则文件时，通过已实现 CLI 表面 `--firewall-rules=<file>` 提供。`server.firewall` 不是当前解析的 JSON 键。
5. 服务端 IPv6 仅限 Linux（排除 Android），上线前单独验证。参阅[IPv6 中继平面](../guides/IPV6_TRANSIT_PLANE_CN.md)。
6. 将管理/订阅服务绑定到预期网络边界；直接 Go 服务不是 TLS 终止。

## 客户端部署检查清单

1. 使用已验证配置路径启动 `--mode=client`。
2. 核对所选宿主机的虚拟接口和路由/DNS 权限。
3. 确保服务端端点在路由策略变更期间仍可达。
4. 保持路由/DNS 规则输入在本地，并在启动前审查它们。
5. 连接后检查宿主机状态并测试流量，不能把进程启动当成策略成功的证据。

桌面本地代理请使用 `--mode=proxy`；不能假设仅 `client.proxy-only` 就会选择该进程路径。参阅[Proxy-only 模式](../guides/PROXY_MODE_CN.md)。

## 最小验证顺序

1. 确认进程选择了预期角色和配置文件。
2. 确认服务端监听器或本地代理监听器只绑定在预期位置。
3. 通过运行时快照/诊断确认客户端到达 `connected`。
4. 确认流量和宿主机路由/DNS 状态符合部署意图。
5. 确认秘密、管理器端点和公开订阅 URL 没有超出规划边界暴露。

## 相关页面

- [运维与故障排查](OPERATIONS_CN.md)
- [安全模型](SECURITY_CN.md)
- [平台集成](../guides/PLATFORMS_CN.md)
- [管理后端](../guides/MANAGEMENT_BACKEND_CN.md)
- [配置参考](../reference/CONFIGURATION_CN.md)