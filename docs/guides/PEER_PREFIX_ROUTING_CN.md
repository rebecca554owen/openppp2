# Peer 前缀路由

> **状态：**当前有效，IPv4-only 站点前缀功能
> **类型：**指南
> **最后核对：**Peer 前缀配置、INFO 协议、客户端管理器与服务端策略源码，2026-07-22
> **上一层索引：**[任务指南](README_CN.md) · **English：**[Peer-prefix routing](PEER_PREFIX_ROUTING.md)

## 用途

Peer 前缀路由允许已连接的网关 peer 宣告该 peer 背后可达的 IPv4 网络。服务端会校验宣告、记录网关虚拟 IPv4，并可向其他 peer 下发路由表快照。它不会替你配置网关宿主机的 LAN 转发、NAT 或回程路由。

只有 `server.subnet` 和 `server.peer-routing.enabled` 同时为 true 时才启用该功能。

## 服务端策略：默认拒绝

服务端默认不接受任何前缀。`server.peer-routing.allowed-routes` 是按客户端的允许列表：请求的网络/前缀必须与某一条目的 `guid`（网关会话 GUID）和网络/前缀完全一致。空允许列表会拒绝所有宣告。默认路由、无效前缀和保留地址范围也会被策略拒绝。

配置形态示例：

```json
{
  "server": {
    "subnet": true,
    "peer-routing": {
      "enabled": true,
      "distribute": true,
      "allowed-routes": [
        {
          "network": "10.20.0.0",
          "prefix": 24,
          "guid": "<gateway-client-guid>"
        }
      ]
    }
  }
}
```

`distribute` 控制是否把已接受的表变更推送给已连接 peer；它不会替代服务端校验。

## 网关 peer

当 `client.peer-route-announce` 含有前缀时，客户端会发送 INFO `peer-route-announce` 注册。只有已接受的条目才会收到 `registered`；功能、策略或虚拟地址前提不满足时会收到 `reject`。

```json
{
  "client": {
    "peer-route-announce": [
      { "network": "10.20.0.0", "prefix": 24 }
    ],
    "peer-gateway-forward": true
  }
}
```

`client.peer-gateway-forward` 允许客户端转发收到的远程前缀数据包，但不会自行开启宿主机 OS 的转发能力。

## 访问 peer

开启分发时，访问 peer 可以收到动态 `peer-route-table` 快照，也可以配置本地静态条目：

```json
{
  "client": {
    "peer-routes": [
      {
        "network": "10.20.0.0",
        "prefix": 24,
        "via": "10.1.0.2"
      }
    ]
  }
}
```

`via` 是网关 peer 的虚拟 IPv4 地址。动态和静态输入都属于客户端路由输入；二者都不能证明网关背后的 LAN 已具备回程能力。

## 运维检查清单

1. 启用 `server.subnet` 和 `server.peer-routing.enabled`。
2. 在允许网关宣告前，添加精确的网络/前缀/GUID 允许列表项。
3. 确认网关 peer 拥有有效虚拟 IPv4，且已接受路由显示为 `registered`。
4. 在网关启用宿主机 IP 转发/NAT，或安装必要的路由。
5. 为远程 LAN 到 VPN 子网提供回程路由，或使用由运维维护的 NAT 设计。
6. 仅在服务端表和宿主机路由均健康后，从访问 peer 验证连通性。

## 限制

- 前缀条目仅支持 IPv4；本功能不提供 IPv6 站点前缀路由。
- Peer 前缀转发与传输/P2P 优化属于不同关注点。
- 服务端决定是否接受宣告；只有客户端配置不能授权一个前缀。

## 相关页面

- [路由与 DNS](ROUTING_AND_DNS_CN.md)
- [部署模型](../operations/DEPLOYMENT_CN.md)
- [配置参考](../reference/CONFIGURATION_CN.md)