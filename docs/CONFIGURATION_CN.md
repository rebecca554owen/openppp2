# 配置参考

[English Version](CONFIGURATION.md)

## 总览

OPENPPP2 从 `appsettings.json` 读取运行时配置，并装载到 `AppConfiguration`。

配置模型会在代码中完成规范化处理，因此缺失字段会回填默认值，部分非法值也会被修正或直接禁用。

## 顶层配置组

### `key`

控制帧行为与加密行为。

重要字段：

- `kf`、`kh`、`kl`、`kx`、`sb`
- `protocol`、`protocol-key`
- `transport`、`transport-key`
- `masked`
- `plaintext`
- `delta-encode`
- `shuffle-data`

这个配置组用于决定受保护传输层是更保守还是更轻量。

### `tcp`

控制 TCP 监听与客户端行为。

重要字段：

- `listen.port`
- `connect.timeout`
- `connect.nexcept`
- `inactive.timeout`
- `turbo`
- `backlog`
- `cwnd`、`rwnd`
- `fast-open`

### `udp`

控制 UDP 监听、DNS 处理和静态 UDP 模式。

重要字段：

- `listen.port`
- `inactive.timeout`
- `dns.timeout`
- `dns.ttl`
- `dns.cache`
- `dns.turbo`
- `dns.redirect`
- `static.keep-alived`
- `static.dns`
- `static.quic`
- `static.icmp`
- `static.aggligator`
- `static.servers`

### `mux`

控制多路复用逻辑通道。

重要字段：

- `connect.timeout`
- `inactive.timeout`
- `congestions`
- `keep-alived`

### `websocket`

控制 WS/WSS 监听和 HTTP 风格入口行为。

重要字段：

- `listen.ws`
- `listen.wss`
- `host`
- `path`
- `ssl.certificate-file`
- `ssl.certificate-key-file`
- `ssl.certificate-chain-file`
- `ssl.certificate-key-password`
- `ssl.ciphersuites`
- `http.request`
- `http.response`
- `http.error`

### `server`

控制服务端节点行为。

重要字段：

- `node`
- `log`
- `subnet`
- `mapping`
- `backend`
- `backend-key`
- `ipv6.mode`
- `ipv6.cidr`
- `ipv6.gateway`
- `ipv6.dns1`
- `ipv6.dns2`
- `ipv6.lease-time`
- `ipv6.static-addresses`

### `client`

控制客户端行为与本地服务。

重要字段：

- `guid`
- `server`
- `server-proxy`
- `bandwidth`
- `reconnections.timeout`
- `http-proxy.bind`
- `http-proxy.port`
- `socks-proxy.bind`
- `socks-proxy.port`
- `socks-proxy.username`
- `socks-proxy.password`
- `mappings`
- `routes`
- Windows 下的 `paper-airplane.tcp`

### `vmem`

虚拟内存工作区配置：

- `size`
- `path`

### `ip`

部署地址提示：

- `public`
- `interface`

## 路由与分流相关字段

客户端 `routes` 条目在一个地方组合了几类决策：

- `nic`：Linux 下的首选出接口
- `ngw`：首选下一跳网关
- `path`：本地路由列表文件
- `vbgp`：远程路由列表来源

这是 OPENPPP2 实现分流与策略路由的重要方式之一，不需要把每次决策都交给外部 SD-WAN 控制器。

## 映射配置

每个 `client.mappings` 项定义一个要导出的服务：

- `protocol`：`tcp` 或 `udp`
- `local-ip`
- `local-port`
- `remote-ip`
- `remote-port`

如果覆盖网络除了远程接入，还要把本地服务向外暴露，就应使用 mappings。

## IPv6 配置

服务端 IPv6 当前支持这些模式：

- `none`
- `nat66`
- `gua`

启用后，服务端可通过信息扩展向客户端分配 IPv6 状态。当前 Linux 是服务端 IPv6 数据面支持最完整的平台。

## CLI 覆盖

运行时命令行参数可以覆盖 JSON 配置中的部分字段。

常用示例：

- `--mode=[client|server]`
- `--config=<path>`
- `--dns=<ip-list>`
- `--nic=<interface>`
- `--ngw=<ip>`
- `--tun=<name>`
- `--tun-ip=<ip>`
- `--tun-ipv6=<ip>`
- `--tun-gw=<ip>`
- `--tun-mask=<bits>`
- `--tun-vnet=[yes|no]`
- `--tun-host=[yes|no]`
- `--tun-static=[yes|no]`
- `--tun-mux=<connections>`
- `--tun-mux-acceleration=<mode>`
- `--bypass=<file>`
- `--bypass-ngw=<ip>`
- `--dns-rules=<file>`
- `--firewall-rules=<file>`

建议把稳定策略放在 JSON 中，把部署时适配放在 CLI 覆盖中。

## 最小配置建议

### 最小服务端

至少设置：

- `tcp.listen.port` 或 `udp.listen.port` 或 `websocket.listen.ws/wss`
- `key.*`
- `server.node`

### 最小客户端

至少设置：

- `client.guid`
- `client.server`
- 本地 TUN 参数可通过 JSON 或 CLI 指定

## 运维建议

- 每个角色、每个站点单独维护一份环境配置
- 不要把样例中的密钥直接当作生产密钥
- `server-proxy`、backend key、数据库凭据、证书密码都应按敏感信息处理
- 只启用实际部署需要的传输和隧道功能

## 相关文档

- [`README_CN.md`](../README_CN.md)
- [`DEPLOYMENT_CN.md`](DEPLOYMENT_CN.md)
- [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
