# OpenPPP2 OpenTelemetry 接入设计说明

## 1. 目标

为 openppp2 增加 OpenTelemetry 能力时，目标不是简单替换日志输出，而是提供一套适合网络数据面项目的可观测性方案。

第一阶段重点是：

- 结构化日志
- 可控的 DEBUG / TRACE 诊断能力
- 不干涉报文处理逻辑

后续再视需要补充：

- Metrics
- Traces

## 2. 设计原则

### 2.1 OTel 不应干涉报文处理逻辑

这是最重要的原则。

接入 OpenTelemetry 时必须保证：

- 不改变协议逻辑分支。
- 不改变报文处理时序。
- 不引入阻塞式 exporter 调用。
- 不因为日志/trace 导致转发路径锁竞争加剧。
- 不因为 telemetry 反向影响 queue/fd 亲和、线程绑定和收发调度。

换句话说：

> telemetry 是旁路观察者，而不是数据面驱动者。

### 2.2 TRACE 必须是强受限能力

TRACE 不是“更详细的 DEBUG”，而应该是：

- 默认关闭
- 明确按模块开启
- 支持采样
- 支持限速
- 支持丢弃
- 绝不能阻塞主路径

对于 openppp2 这种网络项目，应当默认认为：

- TRACE 可能显著影响性能
- 开启 TRACE 时优先保证转发，不保证 trace 完整性

### 2.3 业务先执行，telemetry 后旁路投递

主路径里最多做：

- 级别判断
- 少量字段提取
- 轻量事件构造
- 非阻塞投递到异步队列

主路径里不做：

- 同步导出
- 大量字符串拼接
- 阻塞等待
- 为了日志而改变原始处理流程

## 3. 日志级别建议

项目内部建议保留以下级别语义：

### INFO

- 默认最少
- 记录启动、配置摘要、监听成功、连接建立/断开、关键状态变化

### VERB

- 略高于 INFO
- 记录重要分支选择、路由/策略命中、管理面交互摘要、队列分配等

### DEBUG

- 用于调试网络问题
- 记录握手、隧道状态、mux、transit tun、queue/fd 亲和命中、NAT/IPv6 分配等关键细节

### TRACE

- 极其详细
- 需要主动限制性能影响
- 仅用于短时间、定点、定模块调试

## 4. TRACE 的限制策略

建议至少具备以下能力：

1. 按模块开启
2. 按 session / connection / user 过滤
3. 按比例采样
4. 每秒限速
5. 队列满时丢弃
6. exporter 异步处理

建议优先支持的过滤维度：

- `session.id`
- `connection.id`
- `user.id`
- `component`
- `protocol`

## 5. 建议采集的结构化字段

### 基础字段

- `service.name`
- `service.version`
- `host.name`
- `process.pid`
- `thread.id`
- `thread.name`
- `log.level`
- `component`
- `mode`
- `platform`

### 网络调试关键字段

- `session.id`
- `node.id`
- `user.id`
- `connection.id`
- `remote.address`
- `local.address`
- `protocol`
- `tap.name`
- `tun.fd`
- `queue.id`
- `preferred_tun_fd`
- `ipv6.address`
- `ipv6.gateway`
- `packet.direction`
- `packet.family`
- `packet.proto`
- `packet.length`

## 6. 优先接入模块

建议第一阶段先接入这些高价值模块：

1. `ppp/transmissions`
2. `ppp/app/mux`
3. `ppp/app/server/VirtualEthernetSwitcher`
4. `ppp/app/client/VEthernetNetworkSwitcher`
5. `go/ppp`

原因是这些模块最适合反映：

- 握手
- 重连
- 会话建立
- 多路复用
- transit tun
- 管理面鉴权与流量同步

## 7. 推荐实现形态

不建议在业务代码中直接散落大量 OTel SDK 调用。

更合理的做法是增加项目自己的 telemetry facade，例如：

- `Telemetry::Log(...)`
- `Telemetry::TracePacket(...)`
- `Telemetry::EmitCounter(...)`

由这一层决定：

- 当前级别是否启用
- 是否采样
- 是否限速
- 是否异步入队
- 是否丢弃
- 是否导出到 OTel

这样可以保证：

- 报文处理逻辑保持清晰
- OTel 细节不会污染协议代码

## 8. 与 queue/fd 亲和的关系

当前项目已经在推进 Linux 多队列 tun 和 `preferred_tun_fd` 相关设计。

Telemetry 可以观察这些状态，但不应驱动它们。

也就是说：

- 可以记录 `queue.id`
- 可以记录 `tun.fd`
- 可以记录 `preferred_tun_fd`

但不应：

- 反向决定包走哪个 queue
- 干扰 queue/fd 粘性
- 因 tracing 改变报文流向

## 9. 阶段性落地建议

### 第一阶段

- 统一日志入口
- 接入 OTel Logs
- 保留 INFO / VERB / DEBUG / TRACE 四级语义

### 第二阶段

- 增加 Metrics
- 重点关注连接数、session 数、queue 命中率、握手失败数、重连数

### 第三阶段

- 有选择地增加 Traces
- 主要用于：会话建立、管理面鉴权、关键错误链路排查

## 10. 总结

openppp2 的 OTel 接入不应以“记录越多越好”为目标，而应以：

- 不干涉报文处理逻辑
- TRACE 强约束
- 结构化日志优先
- 异步、可丢弃、可限速

为基础原则。

对于当前项目阶段，最合理的路径是：

- 先做 OTel Logs
- 再补 Metrics
- 最后再考虑 Trace

并始终保证 telemetry 是数据面的旁路观察能力，而不是数据面行为的一部分。
