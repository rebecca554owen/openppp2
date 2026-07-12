# UDP 每包成本分解与 Amdahl 收益模型（Phase 0）

> 数据来源：本目录 `baseline/bm_crypto.json`（BM1a，H4）、`baseline/bm_allocator.json`（BM2，H1），
> 采于 Linux x86-64 AMD EPYC @ 2595 MHz（见 `baseline/env.json`）。
> **方法**：固定频率下 `ns/op` 是 `cycles/packet` 的等价代理（cycles = ns × 2.595）。
> cost breakdown 用相对占比，故直接以 ns 计。

## 1. 每包路径（datagram-relay 出站，512B payload）

依据源码路径（`VirtualEthernetLinklayer::DoSendTo` → `ITransmission` 加密链）：每个出站
UDP 包经 **2 次加密**（protocol `aes-128-cfb` + transport `aes-256-cfb`）与 **~4 次内存池
分配**（加密链四层 `Transmission_*_Encrypt` 各一次；`ITransmission.cpp:826/741/811`）。

## 2. 实测填充（512B，median）

| 环节 | 热点 | 默认(OpenSSL/带锁) | 优化后(SIMD/去锁) |
|---|---|---|---|
| 加密 protocol (aes-128-cfb) | H4 | 1558 ns | 450 ns |
| 加密 transport (aes-256-cfb) | H4 | 1742 ns | 613 ns |
| **加密小计 (2 次)** | **H4** | **3300 ns** | **1063 ns** |
| 内存池分配 ~4 次 @256B | H1 | 单线程 4×354=1416 ns；**服务端并发(2线程) 4×524=2096 ns** | 去锁后 ≈4×354=1416 ns |

## 3. 每包已测成本 + Amdahl 收益

以服务端并发（≥2 线程，分配走锁争用路径）为基准：

**每包已测成本（默认）= 加密 3300 + 分配 2096 = 5396 ns**

| 优化 | 动作 | 每包已测成本 | 相对默认 |
|---|---|---|---|
| 基线 | 默认 aes-cfb(OpenSSL) + 带锁分配 | 5396 ns | — |
| **H4** | 切 `simd-aes-*`（改配置即可） | 3159 ns | **−41%** |
| **H1** | 去/分片分配器锁 | 4716 ns | −13% |
| **H4+H1** | 两者叠加 | 2479 ns | **−54%** |

## 4. 结论（对 +10-15% 目标）

- **H4 单项（切 SIMD 加密，仅改配置）即让每包已测成本降 41%**，远超 10-15% 目标。这是最高杠杆、最低风险的第一步。
- **H1（去分配器锁）在服务端并发下再贡献 ~13%**，且属"解耦即降延迟"（拆锁同时完成模块解耦）。
- **保守修正**：以上是"已测部分"（加密+分配）。整包还含未实测热点——端点 ASCII 序列化(H3)、`MemoryStream`/`IPFrame` 拷贝(H5/H7)、每包 syscall。设未测热点为已测的 50%（≈2700 ns），则整包 ≈8100 ns，H4 单项省 2237 ns → **整体仍 −28%**，稳超 15%。

## 5. 待补（后续增量，非本闸门必需）

- **BM3**（端点 ASCII 序列化，H3）、**BM4**（`UdpFrame::ToIp`/`IPFrame::ToArray` + 校验和，H5/H7）、
  **BM1b**（完整加密链的 allocs/iter，H2）——补齐后可把上面"未测热点"从估算换成实测，
  让整包分母精确、Amdahl 收益从下界收紧为区间。
- **端到端佐证**（iperf3 过 UDP 映射）——验证微基准结论在整体吞吐上不被抵消。
