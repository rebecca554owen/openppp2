# Proxy-only 模式

> **状态：**当前有效；桌面行为已按源码核对，Android 行为受平台限制
> **类型：**指南
> **最后核对：**应用模式、客户端启动、配置与 Android VPN Service 源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[Proxy-only mode](PROXY_MODE.md)

## 使用正确的开关

桌面端应明确选择进程模式：

```bash
./ppp --mode=proxy --config=./client.json
```

`--mode=proxy` 不是 `client.proxy-only=true` 的简单别名：

| 选择 | 应用行为 |
|---|---|
| `--mode=proxy` | 选择客户端代理运行时；非移动端使用 `TapStub`，跳过普通 TUN 路由/DNS 规则/bypass/geo-rule 初始化，并走 proxy 模式的权限路径。 |
| `--mode=client` 加 `client.proxy-only: true` | 在客户端配置内启用 proxy-only 行为，但不会自行选择 client 模式，也不会设置应用级 `proxy_mode_` 标记。 |

若运维意图是桌面本地代理会话，推荐使用 `--mode=proxy`。

## 本地监听器

Proxy-only 在连接到已配置的 VPN 服务端后，会暴露本地 HTTP 和 SOCKS5 转发监听器。

| 监听器 | 配置字段 | Proxy 模式默认值 |
|---|---|---|
| HTTP | `client.http-proxy.bind`、`client.http-proxy.port` | `127.0.0.1:8080` |
| SOCKS5 | `client.socks-proxy.bind`、`client.socks-proxy.port` | `127.0.0.1:1080` |
| SOCKS5 凭据 | `client.socks-proxy.username`、`client.socks-proxy.password` | 可选配置字段 |

桌面 CLI proxy 模式会强制两个监听地址为 loopback，并把缺失/非法端口规范为 `8080` 和 `1080`。不要把该模式当成局域网或公网代理服务，也不要试图通过公开绑定地址暴露它。

`client.server-proxy` 是另一项配置：它用于通过上游代理连接 VPN 服务端，并不配置本地监听器。

## 安全的配置形态

端点和凭据不应提交到版本控制。下面仅使用文档专用端点：

```json
{
  "client": {
    "server": "ppp://vpn.example.invalid:20000/",
    "proxy-only": true,
    "http-proxy": { "bind": "127.0.0.1", "port": 8080 },
    "socks-proxy": { "bind": "127.0.0.1", "port": 1080 }
  }
}
```

该 JSON 字段可用于客户端配置，但不能替代推荐的桌面启动方式 `--mode=proxy`。

## Static transport 边界

对于普通客户端，显式传入 `--tun-ip` 会隐式请求 static mode，即使同时指定 `--tun-static=no`。Proxy-only 启动会把最终设置重新规范为关闭，因为它不应使用 static transport。因此，proxy-only 启动不会发起该模式原本会触发的 `STATIC`/`STATICACK` 交互。服务端启用 IPv4 地址分配时，同一规范化设置会请求自动 IPv4 分配，而不是把本地 TUN 地址作为手动请求提交。

## 本地验证

客户端到达 connected 状态后，只测试 loopback 端点：

```bash
curl -x http://127.0.0.1:8080 https://example.com
curl -x socks5h://127.0.0.1:1080 https://example.com
```

监听器已打开并不证明隧道、上游服务端、凭据或远程路由均正常。请求失败时应查看运行时诊断。

## Android 边界

Android 随附应用使用 `vpnOptions.proxyOnly`。它仍会建立 `VpnService` 接口，并执行平台特定的窄路由/DNS 处理。不要把桌面端“没有普通路由或 DNS 初始化”的描述套用到 Android。

## 相关页面

- [路由与 DNS](ROUTING_AND_DNS_CN.md)
- [配置参考](../reference/CONFIGURATION_CN.md)
- [CLI 参考](../reference/CLI_REFERENCE_CN.md)
- [运维与故障排查](../operations/OPERATIONS_CN.md)