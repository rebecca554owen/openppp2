# 路由与 DNS

> **状态：**当前有效
> **类型：**指南
> **最后核对：**客户端配置、启动、路由与 DNS 源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[Routing and DNS](ROUTING_AND_DNS.md)

## 范围

普通客户端模式会根据 CLI 输入、已解析的配置、协商会话状态和宿主网络事实生成路由/DNS 计划。这是宿主机集成，并不是防火墙或防泄漏保证：不同平台、权限和网络状态下，路由/DNS 修改均可能失败或表现不同。

`--mode=proxy` 走另一条路径，会跳过普通 TUN 路由、bypass 列表、DNS 规则和 geo-rule 初始化。请参阅 [Proxy-only 模式](PROXY_MODE_CN.md)。

## 选择输入方式

| 需求 | 支持的接口 | 说明 |
|---|---|---|
| 加载本地 bypass 列表 | `--bypass=<path>` | CLI 默认路径为 `./ip.txt`。 |
| 加载本地 DNS 规则文件 | `--dns-rules=<path>` | CLI 默认路径为 `./dns-rules.txt`；启动时检查本地文件。 |
| 启动时指定 DNS 地址 | `--dns=<address>` | 接受形式见 CLI 参考。 |
| 在配置中定义路由列表输入 | `client.routes` | 每个可用来源包含 `ngw` 和 `path`；Linux 还接受 `nic`。 |
| 远程刷新路由列表 | `client.routes[].vbgp` | `vbgp` 是单条路由的远程 URL，不是顶层 `vbgp.url`。 |
| 启用 VIRR 路径 | `--virr=...` | 这是内置国家列表流程，不是任意 URL 设置。 |
| 启用 vBGP 刷新行为 | `--vbgp=yes|no` | 刷新时间由 `vbgp.update-interval` 配置。 |

不要使用 `client.bypass`、`client.dns-rules`、`virr.url` 或 `vbgp.url` 等 JSON 键：它们不是当前解析接口。

## 最小路由来源示例

配置形式需要网关（`ngw`）和本地路由列表路径。在验证宿主拓扑前，请只使用文档地址和相对路径。

```json
{
  "client": {
    "routes": [
      {
        "ngw": "192.0.2.1",
        "path": "./routes.txt"
      }
    ]
  }
}
```

普通客户端显式提供本地列表文件的启动方式：

```bash
./ppp --mode=client --config=./client.json \
  --bypass=./bypass.txt \
  --dns-rules=./dns-rules.txt
```

该命令只选择输入来源，并不证明每条路由或每项 resolver 修改都成功。连接后应检查宿主机路由/DNS 状态和运行时诊断。

## 已解析的 DNS 设置

当前解析器包含以下分组：

- `udp.dns.timeout`、`udp.dns.ttl`、`udp.dns.turbo`、`udp.dns.cache`、`udp.dns.redirect`；
- `dns.servers.domestic` 和 `dns.servers.foreign`（provider/server 条目）；
- `dns.intercept-unmatched`；
- `dns.ecs.enabled` 和 `dns.ecs.override-ip`；
- `dns.tls.verify-peer`、`dns.stun.candidates`、`dns.fake-ip.{enabled,range}`。

这些设置用于 DNS 策略和可达性规划。它们不表示每个 resolver 总会经固定物理网卡可达，也不能替代宿主机防火墙策略。

## 运维顺序

1. 用明确配置路径启动普通客户端，而不是 proxy 模式。
2. 将 bypass/DNS 规则文件保留在本地，并在启动前检查其权限和内容。
3. 确保 VPN 服务端/控制端点不会被正在修改的路由递归影响。
4. 连接后检查生成的宿主机路由、解析行为和 `ppp` 诊断。
5. 路由/DNS 操作失败应作为连通性问题处理，不能把它理解为已自动 fail-closed。

## 相关页面

- [配置参考](../reference/CONFIGURATION_CN.md)
- [CLI 参考](../reference/CLI_REFERENCE_CN.md)
- [Proxy-only 模式](PROXY_MODE_CN.md)
- [运维与故障排查](../operations/OPERATIONS_CN.md)