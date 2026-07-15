# VMUX 验证与发布门槛

> Status: Stable
> Type: Reference
> Last verified: 2566750

[English version](VMUX_VALIDATION.md)

本文定义修改 VMUX 生产调度默认值所需的证据，不代表当前已通过性能门槛。
`compat` 继续作为默认值，`stripe` 继续保持实验性。

## 验收门槛

以下门槛必须全部满足，并由
[`../../benchmarks/vmux/`](../../benchmarks/vmux/README.md) 中的可重复 harness
生成工件：

| 门槛 | 必须达到的结果 |
|---|---|
| 单流吞吐 | `flow-one-flow` 吞吐不低于对应 `off-one-flow` 基线的 95%。 |
| 等质量链路尾时延 | 等质量链路下，`flow-one-flow` p99 不得超过对应 `off-one-flow` p99 的 110%。 |
| 有界重排内存 | 缓冲字节始终不超过 `mux.flow.reorder.bytes`，且不超过派生的重排条目数上限。 |
| 旧 peer 兼容 | 对端不支持 FLOW_V2 时，`balance` / `stripe` 必须协商为 `effective_mode=compat`、`receiver_ordering=compat`，并给出 `fallback_reason=peer_missing_flow_v2`；`flow` 保持 `effective_mode=flow`，但使用 `receiver_ordering=compat`。 |
| 链路 churn 安全 | 100 次 grow/shrink 在 ASan/UBSan 下完成，且无错误、泄漏、计数下溢、断线或在途链路提前 retire。 |

对比运行必须具有相同的环境指纹、除被测模式外相同的配置、时长、flow 数量和
netem profile。harness smoke 只证明能够采集证据，不属于性能证据。

## 平台与工件要求

修改默认值前，必须同时附上以下真实平台结果：

1. 固定 Linux x86-64 基准机上的 Linux desktop；
2. 至少一个真实移动平台，即 Android 或 iOS。

证据包必须包含原始结果 JSON、环境与配置指纹、parser 输出、sanitizer 日志、
旧 peer 兼容结果，以及两端被测 commit。共享 CI、WSL、虚拟机、dry-run 和合成
telemetry 可用于正确性诊断，但不能满足此门槛。

## 默认值变更规则

在所有门槛均有合格的双平台证据前，`compat` 保持生产默认值。修改默认值必须使用
独立 PR，附 benchmark artifacts 和 compatibility results，并说明任何排除项；不得
与调度器实现修改捆绑。`stripe` 不参与默认值门槛，继续保持实验性。

## 当前证据边界

当前实现基线已经提供：

- 协商后的 requested/effective 状态与旧 peer fallback（`7719c5f`）；
- effective mode 与 fallback 诊断 UI（`b991cd1`）；
- benchmark harness、schema、parser 与 tooling tests（`62c7441`）；
- negotiation、有界重排、in-flight retire 和 100-cycle drain-state 单元回归测试（`2566750`）。

100-cycle drain-state 单元测试还在 2026-07-15 使用
`-fsanitize=address,undefined` 本地运行（4 个 test cases，未发现 ASan/UBSan
错误）。该测试没有驱动真实 `vmux_net` grow/shrink 或异步承载 I/O，因此真实
churn sanitizer 门槛仍未完成。

这些 commit 建立了测量和兼容机制。仓库中尚无证明吞吐与 p99 门槛达标的真实
Linux + mobile baseline，因此不得修改生产默认值。
