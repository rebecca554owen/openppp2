# 部署模式

[English Version](DEPLOYMENT.md)

## 文档范围

本文总结 OPENPPP2 作为 VPN / SD-WAN 组件时的实际部署玩法。

## 模式 1：基础远程接入 VPN

拓扑：

- 一个服务端节点
- 多个客户端
- 每个客户端创建虚拟网卡，并把选定流量或全量流量送往服务端

适用场景：

- 用户需要访问远程内网
- 希望入口简单、运维面收敛

最小组成：

- 服务端监听 TCP、UDP、WS 或 WSS
- 客户端 `client.server`
- TUN 参数

## 模式 2：企业分流接入

拓扑：

- 客户端公网流量留在本地
- 只有私网前缀、路由文件或 DNS 选中的目的进入覆盖网络

关键能力：

- `client.routes`
- `--bypass`
- `--bypass-ngw`
- `--dns-rules`
- `--virr` 与路由列表刷新流程

适用场景：

- 希望降低带宽成本
- 只有部分业务系统必须走隧道

## 模式 3：站点到站点覆盖网络

拓扑：

- 固定客户端或分支节点接入中心服务端
- 开启子网转发
- 通过路由策略决定哪些远端子网可达

关键能力：

- `server.subnet`
- `--tun-vnet=yes`
- 客户端路由列表

适用场景：

- 分支机构之间需要稳定互联
- 隧道更像“覆盖路由网络”而不是终端用户 VPN

## 模式 4：代理网关边缘

拓扑：

- 客户端先建立隧道
- 本地应用不直接使用虚拟网卡
- 本地应用连接客户端暴露出的 HTTP 或 SOCKS 代理

关键能力：

- `client.http-proxy.*`
- `client.socks-proxy.*`
- 当出站建链本身也要经过上级代理时，可配 `server-proxy`

适用场景：

- 应用层重定向比改路由更容易
- 只有部分应用应走覆盖网络

## 模式 5：反向服务暴露

拓扑：

- 位于 NAT 后的客户端主动向外连接服务端
- 客户端注册 mappings
- 外部用户或系统通过服务端访问这些映射服务

关键能力：

- `client.mappings`
- 服务端 `mapping`
- 隧道协议中的 FRP 风格控制动作

适用场景：

- 客户端站点无法做入站开放，但仍需对外暴露内部服务

## 模式 6：位于 HTTP 基础设施后的 WebSocket / WSS 隧道

拓扑：

- 服务端监听 WS 或 WSS
- 前面接反向代理或 TLS 边缘层
- 客户端通过 HTTP 友好路径接入

关键能力：

- `websocket.listen.ws`
- `websocket.listen.wss`
- `websocket.host`
- `websocket.path`
- `websocket.http.request`
- `websocket.http.response`

适用场景：

- 必须接入现有 Web 入口设施
- TLS 终止或七层路由已标准化

## 模式 7：多流复用隧道

拓扑：

- 一条健康会话承载多个逻辑通道
- 降低重复建链开销

关键能力：

- `--tun-mux`
- `--tun-mux-acceleration`
- `mux.*`

适用场景：

- 大量逻辑流共享同一远端入口
- 更关注建链效率而非流之间的强隔离

## 模式 8：静态 UDP 路径与多服务器支持

拓扑：

- 客户端启用偏静态的 UDP 行为
- 配置一个或多个上游 UDP 服务端
- 通过保活维持路径健康

关键能力：

- `--tun-static=yes`
- `udp.static.keep-alived`
- `udp.static.servers`
- `udp.static.aggligator`

适用场景：

- 需要偏数据报的运行风格
- 环境更适合长期可达的 UDP 路径

## 模式 9：带外部后端的受管节点

拓扑：

- 服务端本地承载数据面
- 同时通过 WebSocket / webhook 风格接口接入 Go 管理后端

关键能力：

- `server.backend`
- `server.backend-key`
- `go/` 服务

适用场景：

- 用户策略、节点策略、流量记账需要集中化

## 模式 10：支持 IPv6 的覆盖网络

拓扑：

- 服务端分配 IPv6 状态
- 客户端请求或应用分配结果
- Linux 服务端侧具备最完整的 IPv6 数据面实现

关键能力：

- `server.ipv6.mode`
- `server.ipv6.cidr`
- `server.ipv6.gateway`
- `server.ipv6.dns1`
- `server.ipv6.dns2`
- `--tun-ipv6`

适用场景：

- 覆盖网络需要原生承载 IPv6
- 需要向客户端提供 IPv6 服务能力

## 选型建议

按运维目标选择传输和拓扑：

- 最简单部署：TCP 服务端 + 标准客户端模式
- 最容易接 Web 基础设施：WSS
- 路由控制最强：分流 + 路由列表 + DNS 规则
- 服务发布：mappings
- 单会话复用效率优先：MUX
- 受管服务模型：后端集成

## 部署纪律

- 服务端配置与客户端配置分离维护
- 路由列表和 DNS 规则与部署配置一起版本化
- 证书、backend key、代理凭据、数据库凭据都按环境密钥管理
- 除非站点确有需求，不要把 IPv6、mappings、mux、静态模式和代理全部同时开启

## 相关文档

- [`CONFIGURATION_CN.md`](CONFIGURATION_CN.md)
- [`OPERATIONS_CN.md`](OPERATIONS_CN.md)
- [`SECURITY_CN.md`](SECURITY_CN.md)
