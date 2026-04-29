# OpenPPP2 可观测性设计说明

[English Version](OTEL_DESIGN.md)

## 1. 定位

OPENPPP2 已经具备一套**零开销错误码诊断系统**（`ppp::diagnostics::ErrorCode`、线程局部快照、原子传播）。这是主力可观测手段，在所有机器上——包括低端硬件——默认可用，无运行时开销。

Telemetry（结构化日志 / OTel）是**可选补充层**，不是错误码的替代。

| 能力 | 错误码 | Telemetry（日志/指标/追踪） |
|------|--------|---------------------------|
| 运行时开销 | 接近零 | 非零（必须可开关） |
| 默认状态 | 始终开启 | **默认关闭** |
| 低端硬件 | 完全可用 | 默认禁用 |
| 粒度 | 错误路径覆盖 | 事件级细节 |
| 适用场景 | 生产故障检测 | 调试 / 性能分析 / 托管部署 |

> **上游原话**：「别用日志，用错误代码来代替。日志开销大，低端机器跑起来性能低。如果要加日志，就需要添加开关，可以关闭，这样子低端机器还能跑的快。」

---

## 当前实现状态

本文档描述的 telemetry 系统已完全实现：

- **`ppp/diagnostics/Telemetry.h`** — 零开销门面。当 `PPP_TELEMETRY=0` 时提供内联空操作存根，确保禁用时无运行时开销。暴露 `SetEnabled(bool)`、`SetMinLevel(int)`、`SetCountEnabled(bool)`、`SetSpanEnabled(bool)`、`Configure(const char* endpoint)`、`SetLogFile(const char* path)`、`Flush(int timeout_ms)`、`Histogram(...)` 以及 RAII `SpanScope` 用于运行期控制和追踪。
- **`ppp/diagnostics/Telemetry.cpp`** — 异步后端，使用有界队列（4096 条目）、满时丢弃策略及后台工作线程。支持三种输出目标：内置 stderr 后端（默认）、HTTP OTLP exporter（`HttpOtlpExporter`）和可选的文件输出。OTLP exporter 批量收集最多 256 个事件并以 OTLP/JSON HTTP POST 发送至配置的采集器端点，支持日志、计数器、Gauge、Histogram 和完成态 Span。OTLP 输出现在包含资源/服务元数据以及每个事件的结构化属性，例如 `service.name`、`thread.id`、日志的 `log.level` / `component`，以及 span 在非空时的 `session.id`。使用原始 POSIX socket（Windows 上为 WinSock2），无外部依赖。
- **CMake 选项 `PPP_TELEMETRY`** — 编译期开关，默认 `OFF`。
- **插桩覆盖** — 已有 13 个模块完成插桩：transmission、protocol、server switcher、server exchanger、client switcher、client exchanger、mux、tap、vnetstack、ITap、tcpip、websocket、managed。
- **运行期配置** — 从 `appsettings.json` 加载，路径为 `AppConfiguration::telemetry.*` → `telemetry::SetEnabled/SetMinLevel/SetCountEnabled/SetSpanEnabled/Configure/SetLogFile()`。
- **级别过滤** — `Log` 事件在调用点（快速路径）和后端线程（防御性）均按级别过滤，确保运行期降低级别时不会有 TRACE 事件漏过。
- **Count/Span 独立开关** — `appsettings.json` 中的 `telemetry.count` 和 `telemetry.span` 独立控制指标类事件和追踪事件是否发出。
- **文件输出** — `appsettings.json` 新增 `telemetry.log-file` 字段。设置后（如 `"./telemetry.log"`），所有 telemetry 输出会同时写入 stderr 和该文件。
- **优雅关闭** — `Flush(int timeout_ms)` API 在进程退出前等待队列中的事件被刷出。已接入 `PppApplication::Dispose()`。
- **追踪模型** — `SpanScope` 已实现真实 `traceId`/`spanId` 生成，并通过线程局部 trace 栈传递父子 span 关系。一次性 `TraceSpan(...)` 也会发出带 ID 的 span。
- **属性增强** — OTLP 导出现在包含全局 `service.name=openppp2`、每事件 `thread.id`、日志的 `log.level` / `component`，以及 span 在存在时的 `session.id`。

> **注意：** 后端支持多种输出目标（stderr、OTLP HTTP 和文件），可通过 `Configure()` 和 `SetLogFile()` 在运行期控制。更换后端或添加 exporter 无需修改任何已插桩的模块。

---

## 2. 设计原则

### 2.1 错误码是基础

现有错误码系统是地面真值：

- `SetLastErrorCode()` —— 线程局部，无分配，无字符串格式化。
- `ErrorHandler::Dispatch()` —— 原子快照，带截断时间戳。
- 覆盖所有子系统：传输、隧道、协议、客户端、服务端、平台。

Telemetry **不得** 重复错误码的语义。它只记录错误码**不覆盖**的事件：时序、速率、队列状态、会话生命周期。

### 2.2 Telemetry 必须可开关

这是不可妥协的。

- **编译期**：`#ifdef PPP_TELEMETRY` 或 CMake 选项。
- **运行期**：配置项 `telemetry.enabled = false` 为默认值。
- **按模块**：每个子系统可独立开启。
- **热关闭**：禁用时 telemetry facade 编译为空操作。

低端机器应完全编译掉 telemetry，或在运行期彻底禁用。

### 2.3 Telemetry 不得干涉报文处理

即使开启时也必须保证：

- 热路径上无阻塞式 exporter 调用。
- 报文转发循环内无字符串格式化。
- 不与 `syncobj_`、队列分发、fd 亲和性竞争锁。
- Telemetry 只观察，从不驱动队列选择、路由或协议决策。

---

## 3. 何时用错误码，何时用 Telemetry

### 用错误码

- 任何异常分支（失败、超时、校验拒绝）。
- 资源耗尽（fd 上限、内存上限、队列满）。
- 协议违规（非预期 opcode、校验和失败）。
- 安全事件（重放、认证失败、防火墙拦截）。

### 用 Telemetry（可选）

- 会话建立耗时（不是失败，而是延迟）。
- 队列命中率、fd 亲和命中率。
- 连接数、吞吐速率（Metrics）。
- 需要跨模块关联的罕见事件序列（Traces）。

---

## 4. 日志级别建议（仅在 Telemetry 开启时）

如果 telemetry 被编译进且运行期开启，推荐以下级别：

| 级别 | 默认 | 用途 |
|------|------|------|
| INFO | 开启 | 启动、配置摘要、监听成功、关键状态变化 |
| VERB | 关闭 | 分支决策、策略命中、管理面交互 |
| DEBUG | 关闭 | 握手、mux 状态、transit tun、队列/fd 亲和、NAT/IPv6 分配 |
| TRACE | 关闭 | 逐包细节；严格按模块范围、限速 |

INFO 以上的所有级别必须按模块显式开启。

---

## 5. TRACE 约束

TRACE 是风险最高的级别。开启时必须支持：

1. 按模块开启
2. 按会话 / 按连接过滤
3. 采样（如 1%）
4. 速率限制（事件/秒）
5. 队列满时丢弃（绝不阻塞）
6. 异步 exporter

---

## 6. 结构化字段（仅 Telemetry）

Telemetry 导出事件时，推荐包含以下字段：

**基础**
- `service.name`, `service.version`, `host.name`, `process.pid`
- `thread.id`, `log.level`, `component`, `mode`, `platform`

**网络**
- `session.id`, `node.id`, `user.id`, `connection.id`
- `remote.address`, `local.address`, `protocol`
- `tap.name`, `tun.fd`, `queue.id`, `preferred_tun_fd`
- `ipv6.address`, `ipv6.gateway`
- `packet.direction`, `packet.family`, `packet.proto`, `packet.length`

错误码已经携带 `error_code` 和 `timestamp`；telemetry 提供上下文，而非替代。

---

## 7. 实现门面（Facade）

不要在协议代码里直接散落 OTel SDK 调用。

使用位于 `ppp/diagnostics/Telemetry.h` 的项目内部门面（异步后端位于 `ppp/diagnostics/Telemetry.cpp`），禁用时编译为空操作：

```cpp
namespace ppp::telemetry {
    void Log(Level level, const char* component, const char* fmt, ...) noexcept;
    void Count(const char* metric, int64_t delta) noexcept;
    void Gauge(const char* metric, int64_t value) noexcept;
    void Histogram(const char* metric, int64_t value) noexcept;
    void TraceSpan(const char* name, const char* session_id) noexcept;
    void SetEnabled(bool enabled) noexcept;
    void SetMinLevel(int level) noexcept;
    void SetCountEnabled(bool enabled) noexcept;
    void SetSpanEnabled(bool enabled) noexcept;
    void Configure(const char* endpoint) noexcept;
    void SetLogFile(const char* path) noexcept;
    void Flush(int timeout_ms = 3000) noexcept;
    class SpanScope;
}
```

当 `PPP_TELEMETRY` 未定义时，这些函数是内联空函数 —— 零开销。

---

## 8. 与队列 / FD 亲和性的关系

Telemetry 可以记录：

- `queue.id`
- `tun.fd`
- `preferred_tun_fd`

但**绝不**可以：

- 影响队列选择。
- 破坏 fd 亲和性。
- 改变报文流向。

---

## 9. 阶段性落地

### 第一阶段 —— 门面 + 插桩 ✅

- 编译期 telemetry 开关 `PPP_TELEMETRY` 已添加（默认 OFF）。
- 零开销门面已在 `ppp/diagnostics/Telemetry.h` 中实现。
- 异步后端已在 `ppp/diagnostics/Telemetry.cpp` 中实现（有界队列 4096、满时丢弃、stderr 输出、后台工作线程）。
- 已为 13 个模块添加插桩：transmission、protocol、server switcher、server exchanger、client switcher、client exchanger、mux、tap、vnetstack、ITap、tcpip、websocket、managed。

### 第二阶段 —— 可选 OTel 日志 ✅（已完成）

- ✅ 异步 OTel exporter 已实现 stderr、OTLP HTTP 和文件输出后端。
- ✅ 运行期配置 `telemetry.enabled`、`telemetry.level`、`telemetry.count`、`telemetry.span`、`telemetry.endpoint`、`telemetry.log-file` 已从 `appsettings.json` 加载。
- ✅ `HttpOtlpExporter` 支持批量 POST 至 OTLP 采集器，支持日志、计数器、Gauge、Histogram 和追踪。
- ✅ 运行期 API：`SetEnabled(bool)`、`SetMinLevel(int)`、`SetCountEnabled(bool)`、`SetSpanEnabled(bool)`、`Configure(const char* endpoint)`、`SetLogFile(const char* path)`。
- ✅ 独立的 Count/Span 开关和防御性后端级别过滤。

> **注意：** 由于所有插桩均通过 `Telemetry.h` 门面调用，更换后端或添加 exporter 无需修改任何已插桩的模块。

### 第三阶段 —— 可选 Metrics ✅

- `Gauge()` API 已添加到 `Telemetry.h`（禁用时为零开销空操作）。
- OTLP `BuildGaugeJson()` 实现了 OTel Gauge 数据模型（每次数据点报告瞬时值）。
- Gauge 插桩：`server.active_sessions`、`server.exchanger_count`、`tap.active_fds`、`tap.ipv6_routes`、`tap.neighbor_proxies`。
- `Histogram()` API 已添加到 `Telemetry.h`，OTLP `BuildHistogramJson()` 已可导出直方图样本。
- Histogram 插桩：`websocket.handshake.us`、`websocket.wss.handshake.us`、`managed.auth.us`。
- Histogram 插桩还覆盖：`server.session.establish.us`、`server.ipv6.assign.us`、`server.route.add.us`、`server.route.delete.us`、`client.connect.us`、`client.proxy.setup.us`、`client.route.apply.us`、`client.dns.apply.us`、`managed.sync.us`、`mux.link.setup.us`、`tap.ipv6.route.add.us`、`tap.ipv6.neighbor.add.us`、`tap.ipv6.neighbor.delete.us`、`tap.interface.state.us`、`vnetstack.connect.us`、`transmission.handshake.us`。
- 当前桶聚合仍较轻量；现阶段实现为带固定边界的一样本 histogram 点。

### 第四阶段 —— 可选 Traces ✅

- `SpanScope` RAII 追踪已在 `Telemetry.h` / `Telemetry.cpp` 中实现。
- OTLP span 导出现在包含生成的 `traceId`、`spanId`、`parentSpanId`、`startTimeUnixNano` 和 `endTimeUnixNano`。
- Scoped span 已插桩到 websocket 握手路径、managed 认证路径和协议认证处理路径。
- Scoped span 还已插桩到 server 会话建立、server IPv6 回收、server route add / delete、client connect、client route apply、client DNS apply、client proxy setup、managed sync、mux link setup、tap IPv6 route add / neighbor add / neighbor delete、vnetstack connect、transmission lifecycle close、exchanger static echo allocation 等路径。
- 剩余工作主要是更高层的 trace 覆盖率和更丰富的属性透传，而不是核心 tracing 管线。

---

## 10. 总结

1. **错误码是主力。** 始终开启、零开销、上游优先推荐。
2. **Telemetry 是可选。** 必须在编译期和运行期可开关，默认关闭。
3. **低端机器只用错误码。** Telemetry 仅用于调试、性能分析或有富余资源的托管部署。
4. **绝不干涉。** Telemetry 是被动观察者，绝不驱动协议、路由或队列行为。
5. **门面 + 空操作回退。** 所有 telemetry 调用在禁用时编译消失。
