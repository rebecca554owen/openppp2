# UI Runtime 契约

> Status: Stable
> Type: Reference
> Last verified: d8ddd71

本文定义原生 OpenPPP2 Runtime 与桌面 TUI、Android、iOS UI 之间的版本 1
状态边界。

## Snapshot 字段

| 字段 | 要求 |
|---|---|
| `schema_version` | 必须为 `1`；其他版本明确失败。 |
| `generation` | 每次启动递增；旧 generation 事件被丢弃。 |
| `monotonic_ms` | generation 内递增；重复或更旧事件被丢弃。 |
| `phase` | 唯一权威生命周期阶段。 |
| `role`、`server`、`transport` | Runtime 身份与传输选择。 |
| `requested_mux_mode`、`effective_mux_mode` | 请求及实际协商的 MUX 行为。 |
| `mux_fallback_reason` | 实际 MUX 模式发生回退的原因。 |
| `p2p_state`、`effective_path` | P2P 状态和 relay/direct 路径；未支持时为空。 |
| `last_error` | 错误码、严重度、可重试性、消息键和诊断详情。 |

消费者忽略未知可选字段。必需排序字段或 phase 缺失、phase 字符串未知、
schema 版本不支持时必须报错。

## 阶段序列

`starting` → `preparing_host` → `connecting` → `handshaking` →
`applying_policy` → `connected`。

链路恢复使用 `reconnecting`。停止使用 `stopping`，最终进入 `idle` 或
`failed`。`unknown` 是 snapshot 无效或不可用时的 UI 展示态，不表示原生
清理成功。

## Connected 门禁

以下五项必须全部为真：

1. session 已建立；
2. TAP/TUN adapter 已创建且处于 open 状态；
3. Route 策略已应用，或当前模式明确不需要 Route；
4. DNS 策略已配置且 session 活跃，或当前模式明确不需要 DNS 拦截；
5. 协商策略信息已就绪。

在此之前，对 `connected` 的请求会发布为 `applying_policy`。任一 readiness
事实丢失后，展示态也会回到 `applying_policy`。

服务端 readiness 来自实际监听器运行态；仅有一个尚未 Dispose 的服务端对象
并不足以表示 Connected。

## 订阅与 UI 规则

`PppApplication` 提供 snapshot 获取、JSON 获取、订阅和取消订阅接口。
publisher 回调接收不可变副本，并在 publisher 锁外执行。

所有 UI 使用 [ADR 0001](../adr/0001-runtime-ui-contract.md) 的 phase 控件映射。
启动/停止回调及旧 link-state 信号只能用于命令或诊断，不能更新生命周期文案。
解码失败且包含有效 generation/timestamp 时，按顺序应用 `unknown`；缺少排序元数据的
坏包只报告错误，不得修改更新的状态。

## 共享 fixtures

规范样例位于 `tests/contracts/runtime-snapshot/`。C++、Dart、Swift 使用同一组
fixtures，`tools/check_runtime_fixture_hashes.py` 校验其 hash。
